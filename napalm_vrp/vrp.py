# -*- coding: utf-8 -*-
# Copyright 2016 Dravetech AB. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

"""
Napalm driver for huawei Enterprise switch, the vrp software.

Read https://napalm.readthedocs.io for more information.
"""
from napalm.base import NetworkDriver
import napalm.base.helpers
from napalm.base.utils import py23_compat
from napalm.base.netmiko_helpers import netmiko_args
import napalm.base.constants as c
from netmiko import FileTransfer, InLineTransfer
from napalm.base.exceptions import (
    ConnectionException,
    SessionLockedException,
    MergeConfigException,
    ReplaceConfigException,
    CommandErrorException,
    ConnectionClosedException,
    CommitError,
)

from datetime import datetime
import socket
import re
import telnetlib
import os
import tempfile
import paramiko
import uuid
import hashlib

# Easier to store these as constants
HOUR_SECONDS = 3600
DAY_SECONDS = 24 * HOUR_SECONDS
WEEK_SECONDS = 7 * DAY_SECONDS
YEAR_SECONDS = 365 * DAY_SECONDS


class VRPDriver(NetworkDriver):
    """Napalm driver for Huawei vrp."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Constructor.
        :param hostname:
        :param username:
        :param password:
        :param timeout:
        :param optional_args:
        """
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        if optional_args is None:
            optional_args = {}

        # Netmiko possible arguments
        netmiko_argument_map = {
            'port': None,
            'verbose': False,
            'timeout': self.timeout,
            'global_delay_factor': 1,
            'use_keys': False,
            'key_file': None,
            'ssh_strict': False,
            'system_host_keys': False,
            'alt_host_keys': False,
            'alt_key_file': '',
            'ssh_config_file': None,
            'allow_agent': False,
            'keepalive': 30
        }

        # Build dict of any optional Netmiko args
        self.netmiko_optional_args = {
            k: optional_args.get(k, v)
            for k, v in netmiko_argument_map.items()
        }

        self.transport = optional_args.get('transport', 'ssh')
        self.port = optional_args.get('port', 22)

        self.changed = False
        self.loaded = False
        self.backup_file = ''
        self.replace = False
        self.merge_candidate = ''
        self.replace_file = ''
        self.profile = ["vrp"]

        # netmiko args
        self.netmiko_optional_args = netmiko_args(optional_args)

        # Set the default port if not set
        default_port = {"ssh": 22, "telnet": 23}
        self.netmiko_optional_args.setdefault("port", default_port[self.transport])

        # Control automatic execution of 'file prompt quiet' for file operations
        self.auto_file_prompt = optional_args.get("auto_file_prompt", True)

        # Track whether 'file prompt quiet' has been changed by NAPALM.
        self.prompt_quiet_changed = False
        # Track whether 'file prompt quiet' is known to be configured
        self.prompt_quiet_configured = None

    # ok
    def open(self):
        """Open a connection to the device.
        """
        device_type = "huawei"
        if self.transport == "telnet":
            device_type = "huawei_telent"
        self.device = self._netmiko_open(
            device_type, netmiko_optional_args=self.netmiko_optional_args
        )

    # ok
    def close(self):
        """Close the connection to the device and do the necessary cleanup."""

        # Return file prompt quiet to the original state
        if self.auto_file_prompt and self.prompt_quiet_changed is True:
            self.device.send_config_set(["no file prompt quiet"])
            self.prompt_quiet_changed = False
            self.prompt_quiet_configured = False
        self._netmiko_close()

    # ok
    def is_alive(self):
        """ Returns a flag with the state of the connection."""
        if self.device is None:
            return {'is_alive': False}
        try:
            if self.transport == 'telnet':
                # Try sending IAC + NOP (IAC is telnet way of sending command
                # IAC = Interpret as Command (it comes before the NOP)
                self.device.write_channel(telnetlib.IAC + telnetlib.NOP)
                return {'is_alive': True}
            else:
                # SSH
                # Try sending ASCII null byte to maintain the connection alive
                null = chr(0)
                self.device.write_channel(null)
                return {
                    'is_alive': self.device.remote_conn.transport.is_active()
                }
        except (socket.error, EOFError, OSError):
            # If unable to send, we can tell for sure that the connection is unusable
            return {'is_alive': False}

    # ok
    def cli(self, commands):
        """Execute a list of commands and return the output in a dictionary format using the command
        Example input:
        ['dis version', 'dis cu']
        """

        cli_output = dict()
        if type(commands) is not list:
            raise TypeError("Please enter a valid list of commands!")

        for command in commands:
            output = self.device.send_command(command)
            cli_output.setdefault(command, {})
            cli_output[command] = output

        return cli_output

    # develop
    def get_facts(self):
        """Return a set of facts from the devices."""
        # default values.
        vendor = u'Huawei'
        uptime = -1
        serial_number, fqdn, os_version, hostname, model = (u'Unknown', u'Unknown', u'Unknown', u'Unknown', u'Unknown')

        # obtain output from device
        show_ver = self.device.send_command('display version')
        show_hostname = self.device.send_command('display current-configuration | inc sysname')
        show_int_status = self.device.send_command('display interface brief')

        # serial_number/IOS version/uptime/model
        for line in show_ver.splitlines():
            if 'VRP (R) software' in line:
                search_result = re.search(r"\((?P<serial_number>S\S+)\s+(?P<os_version>V\S+)\)", line)
                if search_result is not None:
                    serial_number = search_result.group('serial_number')
                    os_version = search_result.group('os_version')

            if 'HUAWEI' in line and 'uptime is' in line:
                search_result = re.search(r"CE\S+", line)
                if search_result is not None:
                    model = search_result.group(0)
                uptime = self._parse_uptime(line)
                break

        if 'sysname ' in show_hostname:
            _, hostname = show_hostname.split("sysname ")
            hostname = hostname.strip()

        # interface_list filter
        interface_list = []
        if 'Interface' in show_int_status:
            _, interface_part = show_int_status.split("Interface")
            re_intf = r"(?P<interface>\S+)\s+(?P<physical_state>down|up|offline|\*down)\s+" \
                      r"(?P<protocal_state>down|up|\*down)"
            search_result = re.findall(re_intf, interface_part, flags=re.M)
            for interface_info in search_result:
                interface_list.append(interface_info[0])

        return {
            'uptime': int(uptime),
            'vendor': vendor,
            'os_version': py23_compat.text_type(os_version),
            'serial_number': py23_compat.text_type(serial_number),
            'model': py23_compat.text_type(model),
            'hostname': py23_compat.text_type(hostname),
            'fqdn': fqdn,  # ? fqdn(fully qualified domain name)
            'interface_list': interface_list
        }

    # develop
    def get_environment(self):
        """
        Return environment details.

        Sample output:
        {
            "cpu": {
                "0": {
                    "%usage": 18.0
                }
            },
            "fans": {
                "FAN1": {
                    "status": true
                }
            },
            "memory": {
                "available_ram": 3884224,
                "used_ram": 784552
            },
            "power": {
                "PWR1": {
                    "capacity": 600.0,
                    "output": 92.0,
                    "status": true
                }
            },
            "temperature": {
                "CPU": {
                    "is_alert": false,
                    "is_critical": false,
                    "temperature": 45.0
                }
            }
        }
        """
        environment = {}

        fan_cmd = 'display device fan'
        power_cmd = 'display device power'
        temp_cmd = 'display device temperature all'
        cpu_cmd = 'display cpu'
        mem_cmd = 'display memory'

        output = self.device.send_command(fan_cmd)
        environment.setdefault('fans', {})
        match = re.findall(r"(?P<id>FAN\S+).+(?P<status>Normal|Abnormal)", output, re.M)
        # if match:
        for fan in match:
            status = True if fan[1] == "Normal" else False
            environment['fans'].setdefault(fan[0], {})['status'] = status

        output = self.device.send_command(power_cmd)
        environment.setdefault('power', {})
        re_power = r"(?P<id>PWR\S+).+(?P<status>Supply|NotSupply|Sleep)\s+\S+\s+\S+\s+" \
                   r"(?P<output>\d+)\s+(?P<capacity>\d+)"
        match = re.findall(re_power, output, re.M)

        for power in match:
            status = True if power[1] == "Supply" else False
            environment['power'].setdefault(power[0], {})['status'] = status
            environment['power'][power[0]]['output'] = float(power[2])
            environment['power'][power[0]]['capacity'] = float(power[3])

        output = self.device.send_command(temp_cmd)
        environment.setdefault('temperature', {})
        re_temp = r"(?P<name>\S+)\s+(?P<status>NORMAL|MAJOR|FATAL|ABNORMAL)\s+\S+\s+\S+\s+(?P<temperature>\d+)"
        match = re.findall(re_temp, output, re.M)

        for temp in match:
            environment['temperature'].setdefault(temp[0], {})
            name = temp[0]
            is_alert = True if temp[1] == "MAJOR" else False
            is_critical = True if temp[1] == "FATAL" else False
            environment['temperature'][name]['temperature'] = float(temp[2])
            environment['temperature'][name]['is_alert'] = is_alert
            environment['temperature'][name]['is_critical'] = is_critical

        output = self.device.send_command(cpu_cmd)
        environment.setdefault('cpu', {})
        match = re.findall(r"cpu(?P<id>\d+)\s+(?P<usage>\d+)%", output, re.M)

        for cpu in match:
            usage = float(cpu[1])
            environment['cpu'].setdefault(cpu[0], {})['%usage'] = usage

        output = self.device.send_command(mem_cmd)
        environment.setdefault('memory', {'available_ram': 0, 'used_ram': 0})
        match = re.search(r"System Total Memory:\s+(?P<available_ram>\d+)", output, re.M)
        if match is not None:
            environment['memory']['available_ram'] = int(match.group("available_ram"))

        match = re.search(r"Total Memory Used:\s+(?P<used_ram>\d+)", output, re.M)
        if match is not None:
            environment['memory']['used_ram'] = int(match.group("used_ram"))
        return environment

    # ok
    def get_config(self, retrieve="all", full=False):
        """
        Get config from device.

        Returns the running configuration as dictionary.
        The candidate and startup are always empty string for now,
        since CE does not support candidate configuration.
        """
        config = {
            'startup': '',
            'running': '',
            'candidate': ''
        }

        if retrieve.lower() in ('running', 'all'):
            command = 'display current-configuration'
            config['running'] = py23_compat.text_type(self.device.send_command(command))
        if retrieve.lower() in ('startup', 'all'):
            # command = 'display saved-configuration last'
            # config['startup'] = py23_compat.text_type(self.device.send_command(command))
            pass
        return config

    # ok
    def ping(self, destination, source=c.PING_SOURCE, ttl=c.PING_TTL, timeout=c.PING_TIMEOUT, size=c.PING_SIZE,
             count=c.PING_COUNT, vrf=c.PING_VRF):
        """Execute ping on the device."""
        ping_dict = {}
        command = 'ping'
        # Timeout in milliseconds to wait for each reply, the default is 2000
        command += ' -t {}'.format(timeout*1000)
        # Specify the number of data bytes to be sent
        command += ' -s {}'.format(size)
        # Specify the number of echo requests to be sent
        command += ' -c {}'.format(count)
        if source != '':
            command += ' -a {}'.format(source)
        command += ' {}'.format(destination)
        output = self.device.send_command(command)

        if 'Error' in output:
            ping_dict['error'] = output
        elif 'PING' in output:
            ping_dict['success'] = {
                                'probes_sent': 0,
                                'packet_loss': 0,
                                'rtt_min': 0.0,
                                'rtt_max': 0.0,
                                'rtt_avg': 0.0,
                                'rtt_stddev': 0.0,
                                'results': []
            }

            match_sent = re.search(r"(\d+).+transmitted", output, re.M)
            match_received = re.search(r"(\d+).+received", output, re.M)

            try:
                probes_sent = int(match_sent.group(1))
                probes_received = int(match_received.group(1))
                ping_dict['success']['probes_sent'] = probes_sent
                ping_dict['success']['packet_loss'] = probes_sent - probes_received
            except Exception:
                msg = "Unexpected output data:\n{}".format(output)
                raise ValueError(msg)

            match = re.search(r"min/avg/max = (\d+)/(\d+)/(\d+)", output, re.M)
            if match:
                ping_dict['success'].update({
                    'rtt_min': float(match.group(1)),
                    'rtt_avg': float(match.group(2)),
                    'rtt_max': float(match.group(3)),
                })

                results_array = []
                match = re.findall(r"Reply from.+time=(\d+)", output, re.M)
                for i in match:
                    results_array.append({'ip_address': py23_compat.text_type(destination),
                                          'rtt': float(i)})
                ping_dict['success'].update({'results': results_array})
        return ping_dict

    # ok
    def get_interfaces(self):
        """
        Get interface details (last_flapped is not implemented).

        Sample Output:
        {
            "Vlanif3000": {
                "is_enabled": false,
                "description": "Route Port,The Maximum Transmit Unit is 1500",
                "last_flapped": -1.0,
                "is_up": false,
                "mac_address": "0C:45:BA:7D:83:E6",
                "speed": -1
            },
            "Vlanif100": {
                "is_enabled": false,
                "description": "Route Port,The Maximum Transmit Unit is 1500",
                "last_flapped": -1.0,
                "is_up": false,
                "mac_address": "0C:45:BA:7D:83:E4",
                "speed": -1
            }
        }
        """
        interfaces = {}
        output = self.device.send_command('display interface')
        if not output:
            return {}

        separator = r"(^(?!Line protocol).*current state.*$)"
        re_intf_name_state = r"^(?!Line protocol)(?P<intf_name>\S+).+current state\W+(?P<intf_state>.+)$"
        re_protocol = r"Line protocol current state\W+(?P<protocol>.+)$"
        re_mac = r"Hardware address is\W+(?P<mac_address>\S+)"
        re_speed = r"^Speed\W+(?P<speed>\d+|\w+)"
        re_description = r"^Description\W+(?P<description>.*)$"

        new_interfaces = self._separate_section(separator, output)
        for interface in new_interfaces:
            interface = interface.strip()
            match_intf = re.search(re_intf_name_state, interface, flags=re.M)
            match_proto = re.search(re_protocol, interface, flags=re.M)

            if match_intf is None or match_proto is None:
                msg = "Unexpected interface format: {}".format(interface)
                raise ValueError(msg)
            intf_name = match_intf.group('intf_name')
            intf_state = match_intf.group('intf_state')
            is_enabled = bool('up' in intf_state.lower())

            protocol = match_proto.group('protocol')
            is_up = bool('up' in protocol.lower())

            match_mac = re.search(re_mac, interface, flags=re.M)
            if match_mac:
                mac_address = match_mac.group('mac_address')
                mac_address = napalm.base.helpers.mac(mac_address)
            else:
                mac_address = ""

            speed = -1
            match_speed = re.search(re_speed, interface, flags=re.M)
            if match_speed:
                speed = match_speed.group('speed')
                if speed.isdigit():
                    speed = int(speed)

            description = ''
            match = re.search(re_description, interface, flags=re.M)
            if match:
                description = match.group('description')

            interfaces.update({
                intf_name: {
                    'description': description,
                    'is_enabled': is_enabled,
                    'is_up': is_up,
                    'last_flapped': -1.0,
                    'mac_address': mac_address,
                    'speed': speed}
            })
        return interfaces

    # ok
    def get_interfaces_ip(self):
        """
        Get interface IP details. Returns a dictionary of dictionaries.

        Sample output:
        {
            "LoopBack0": {
                "ipv4": {
                    "192.168.0.9": {
                        "prefix_length": 32
                    }
                }
            },
            "Vlanif2000": {
                "ipv4": {
                    "192.168.200.3": {
                        "prefix_length": 24
                    },
                    "192.168.200.6": {
                        "prefix_length": 24
                    },
                    "192.168.200.8": {
                        "prefix_length": 24
                    }
                },
                "ipv6": {
                    "FC00::1": {
                        "prefix_length": 64
                    }
                }
            }
        }
        """
        interfaces_ip = {}
        output_v4 = self.device.send_command('display ip interface')
        output_v6 = self.device.send_command('display ipv6 interface')

        v4_interfaces = {}
        separator = r"(^(?!Line protocol).*current state.*$)"
        new_v4_interfaces = self._separate_section(separator, output_v4)
        for interface in new_v4_interfaces:
            re_intf_name_state = r"^(?!Line protocol)(?P<intf_name>\S+).+current state\W+(?P<intf_state>.+)$"
            re_intf_ip = r"Internet Address is\s+(?P<ip_address>\d+.\d+.\d+.\d+)\/(?P<prefix_length>\d+)"

            match_intf = re.search(re_intf_name_state, interface, flags=re.M)
            if match_intf is None:
                msg = "Unexpected interface format: {}".format(interface)
                raise ValueError(msg)
            intf_name = match_intf.group('intf_name')
            # v4_interfaces[intf_name] = {}
            match_ip = re.findall(re_intf_ip, interface, flags=re.M)

            for ip_info in match_ip:
                val = {'prefix_length': int(ip_info[1])}
                # v4_interfaces[intf_name][ip_info[0]] = val
                v4_interfaces.setdefault(intf_name, {})[ip_info[0]] = val

        v6_interfaces = {}
        separator = r"(^(?!IPv6 protocol).*current state.*$)"
        new_v6_interfaces = self._separate_section(separator, output_v6)
        for interface in new_v6_interfaces:
            re_intf_name_state = r"^(?!IPv6 protocol)(?P<intf_name>\S+).+current state\W+(?P<intf_state>.+)$"
            re_intf_ip = r"(?P<ip_address>\S+), subnet is.+\/(?P<prefix_length>\d+)"

            match_intf = re.search(re_intf_name_state, interface, flags=re.M)
            if match_intf is None:
                msg = "Unexpected interface format: {}".format(interface)
                raise ValueError(msg)
            intf_name = match_intf.group('intf_name')
            match_ip = re.findall(re_intf_ip, interface, flags=re.M)

            for ip_info in match_ip:
                val = {'prefix_length': int(ip_info[1])}
                v6_interfaces.setdefault(intf_name, {})[ip_info[0]] = val

        # Join data from intermediate dictionaries.
        for interface, data in v4_interfaces.items():
            interfaces_ip.setdefault(interface, {'ipv4': {}})['ipv4'] = data

        for interface, data in v6_interfaces.items():
            interfaces_ip.setdefault(interface, {'ipv6': {}})['ipv6'] = data

        return interfaces_ip

    # ok
    def get_interfaces_counters(self):
        """Return interfaces counters."""
        def process_counts(tup):
            for item in tup:
                if item != "":
                    return int(item)
            return 0

        interfaces = {}
        # command "display interface counters" lacks of some keys
        output = self.device.send_command('display interface')
        if not output:
            return {}

        separator = r"(^(?!Line protocol).*current state.*$)"
        re_intf_name_state = r"^(?!Line protocol)(?P<intf_name>\S+).+current state\W+(?P<intf_state>.+)$"
        re_unicast = r"Unicast:\s+(\d+)|(\d+)\s+unicast"
        re_multicast = r"Multicast:\s+(\d+)|(\d+)\s+multicast"
        re_broadcast = r"Broadcast:\s+(\d+)|(\d+)\s+broadcast"
        re_dicards = r"Discard:\s+(\d+)|(\d+)\s+discard"
        re_rx_octets = r"Input.+\s+(\d+)\sbytes|Input:.+,(\d+)\sbytes"
        re_tx_octets = r"Output.+\s+(\d+)\sbytes|Output:.+,(\d+)\sbytes"
        re_errors = r"Total Error:\s+(\d+)|(\d+)\s+errors"

        new_interfaces = self._separate_section(separator, output)
        for interface in new_interfaces:
            interface = interface.strip()
            match_intf = re.search(re_intf_name_state, interface, flags=re.M)

            if match_intf is None:
                msg = "Unexpected interface format: {}".format(interface)
                raise ValueError(msg)
            intf_name = match_intf.group('intf_name')
            intf_counter = {
                    'tx_errors': 0,
                    'rx_errors': 0,
                    'tx_discards': 0,
                    'rx_discards': 0,
                    'tx_octets': 0,
                    'rx_octets': 0,
                    'tx_unicast_packets': 0,
                    'rx_unicast_packets': 0,
                    'tx_multicast_packets': 0,
                    'rx_multicast_packets': 0,
                    'tx_broadcast_packets': 0,
                    'rx_broadcast_packets': 0
                }

            match = re.findall(re_errors, interface, flags=re.M)
            if match:
                intf_counter['rx_errors'] = process_counts(match[0])
            if len(match) == 2:
                intf_counter['tx_errors'] = process_counts(match[1])

            match = re.findall(re_dicards, interface, flags=re.M)
            if len(match) == 2:
                intf_counter['rx_discards'] = process_counts(match[0])
                intf_counter['tx_discards'] = process_counts(match[1])

            match = re.findall(re_unicast, interface, flags=re.M)
            if len(match) == 2:
                intf_counter['rx_unicast_packets'] = process_counts(match[0])
                intf_counter['tx_unicast_packets'] = process_counts(match[1])

            match = re.findall(re_multicast, interface, flags=re.M)
            if len(match) == 2:
                intf_counter['rx_multicast_packets'] = process_counts(match[0])
                intf_counter['tx_multicast_packets'] = process_counts(match[1])

            match = re.findall(re_broadcast, interface, flags=re.M)
            if len(match) == 2:
                intf_counter['rx_broadcast_packets'] = process_counts(match[0])
                intf_counter['tx_broadcast_packets'] = process_counts(match[1])

            match = re.findall(re_rx_octets, interface, flags=re.M)
            if match:
                intf_counter['rx_octets'] = process_counts(match[0])

            match = re.findall(re_tx_octets, interface, flags=re.M)
            if match:
                intf_counter['tx_octets'] = process_counts(match[0])

            interfaces.update({
                intf_name: intf_counter
            })
        return interfaces

    # ok
    def load_merge_candidate(self, filename=None, config=None):
        """Open the candidate config and merge."""
        if not filename and not config:
            raise MergeConfigException('filename or config param must be provided.')

        self.merge_candidate += '\n'  # insert one extra line
        if filename is not None:
            with open(filename, "r") as f:
                self.merge_candidate += f.read()
        else:
            self.merge_candidate += config

        self.replace = False
        self.loaded = True

    # develop
    def load_replace_candidate(self, filename=None, config=None):
        """Open the candidate config and replace."""
        if not filename and not config:
            raise ReplaceConfigException('filename or config param must be provided.')

        self._replace_candidate(filename, config)
        self.replace = True
        self.loaded = True

    # ok
    def commit_config(self, message=""):
        """Commit configuration."""
        if self.loaded:
            try:
                self.backup_file = 'config_' + datetime.now().strftime("%Y%m%d_%H%M") + '.cfg'
                if self._check_file_exists(self.backup_file):
                    self._delete_file(self.backup_file)
                self._save_config(self.backup_file)
                if self.replace:
                    self._load_config(self.replace_file.split('/')[-1])
                else:
                    self._commit_merge()
                    self.merge_candidate = ''  # clear the merge buffer

                self.changed = True
                self.loaded = False
                self._save_config()
            except Exception as e:
                raise CommitError(str(e))
        else:
            raise CommitError('No config loaded.')

    # ok
    def compare_config(self):
        """Compare candidate config with running."""
        if self.loaded:
            if not self.replace:
                return self._get_merge_diff()
                # return self.merge_candidate
            diff = self._get_diff(self.replace_file.split('/')[-1])
            return diff
        return ''

    # ok
    def discard_config(self):
        """Discard changes."""
        if self.loaded:
            self.merge_candidate = ''  # clear the buffer
        if self.loaded and self.replace:
            self._delete_file(self.replace_file)
        self.loaded = False

    # develop
    def rollback(self):
        """Rollback to previous commit."""
        if self.changed:
            self._load_config(self.backup_file)
            self.changed = False
            self._save_config()

    # ok
    def get_lldp_neighbors(self):
        """
        Return LLDP neighbors details.

        Sample output:
        {
            "10GE4/0/1": [
                {
                    "hostname": "HUAWEI",
                    "port": "10GE4/0/25"
                },
                {
                    "hostname": "HUAWEI2",
                    "port": "10GE4/0/26"
                }
            ]
        }
        """
        results = {}
        command = 'display lldp neighbor brief'
        output = self.device.send_command(command)
        re_lldp = r"(?P<local>\S+)\s+\d+\s+(?P<port>\S+)\s+(?P<hostname>\S+)"
        match = re.findall(re_lldp, output, re.M)
        for neighbor in match:
            local_iface = neighbor[0]
            if local_iface not in results:
                results[local_iface] = []

            neighbor_dict = dict()
            neighbor_dict['port'] = py23_compat.text_type(neighbor[1])
            neighbor_dict['hostname'] = py23_compat.text_type(neighbor[2])
            results[local_iface].append(neighbor_dict)
        return results

    # develop
    def get_lldp_neighbors_detail(self, interface=""):
        pass
        """
        Return a detailed view of the LLDP neighbors as a dictionary.

        Sample output:
        {
        'TenGigE0/0/0/8': [
            {
                'parent_interface': u'Bundle-Ether8',
                'remote_chassis_id': u'8c60.4f69.e96c',
                'remote_system_name': u'switch',
                'remote_port': u'Eth2/2/1',
                'remote_port_description': u'Ethernet2/2/1',
                'remote_system_description': u'''huawei os''',
                'remote_system_capab': u'B, R',
                'remote_system_enable_capab': u'B'
            }
        ]
        }
        """
        lldp_neighbors = {}
        return lldp_neighbors


    # ---------------------------
    # Planned to development function
    # ---------------------------
    def get_mac_address_table(self):
        pass

    def pre_connection_tests(self):
        pass

    def connection_tests(self):
        pass

    def post_connection_tests(self):
        pass

    def get_arp_table(self, vrf=""):
        pass

    def get_route_to(self, destination="", protocol=""):
        pass

    def get_snmp_information(self):
        snmp_information = {}
        # command = 'display snmp-agent sys-info'
        # output = self.device.send_command(command)

        snmp_information = {
            'contact': py23_compat.text_type(''),
            'location': py23_compat.text_type(''),
            'community': {},
            'chassis_id': py23_compat.text_type('')
        }
        return snmp_information
        pass

    def get_probes_config(self):
        pass

    def get_probes_results(self):
        pass

    def traceroute(self, destination, source=c.TRACEROUTE_SOURCE, ttl=c.TRACEROUTE_TTL, timeout=c.TRACEROUTE_TIMEOUT,
                   vrf=c.TRACEROUTE_VRF):
        pass

    def get_users(self):
        pass

    def get_optics(self):
        pass

    def get_network_instances(self, name=""):
        pass

    def get_ipv6_neighbors_table(self):
        pass

    def get_ntp_peers(self):
        """
        Return the NTP peers configuration as dictionary.

        Sample output:
        {
            '192.168.0.1': {},
            '17.72.148.53': {},
            '37.187.56.220': {},
            '162.158.20.18': {}
        }
        """
        ntp_server = {}
        # command = "display ntp session"
        # output = self.device.send_command(command)
        return ntp_server

    def get_ntp_servers(self):
        """
        Return the NTP servers configuration as dictionary.

        Sample output:
        {
            '192.168.0.1': {},
            '17.72.148.53': {},
            '37.187.56.220': {},
            '162.158.20.18': {}
        }
        """
        ntp_server = {}
        # command = "display ntp trace"
        # output = self.device.send_command(command)
        return ntp_server

    def get_ntp_stats(self):
        ntp_stats = []
        # command = "display ntp status"
        # output = self.device.send_command(command)
        return ntp_stats






    @staticmethod
    def _separate_section(separator, content):
        if content == "":
            return []

        # Break output into per-interface sections
        interface_lines = re.split(separator, content, flags=re.M)

        if len(interface_lines) == 1:
            msg = "Unexpected output data:\n{}".format(interface_lines)
            raise ValueError(msg)

        # Get rid of the blank data at the beginning
        interface_lines.pop(0)

        # Must be pairs of data (the separator and section corresponding to it)
        if len(interface_lines) % 2 != 0:
            msg = "Unexpected output data:\n{}".format(interface_lines)
            raise ValueError(msg)

        # Combine the separator and section into one string
        intf_iter = iter(interface_lines)

        try:
            new_interfaces = [line + next(intf_iter, '') for line in intf_iter]
        except TypeError:
            raise ValueError()
        return new_interfaces

    def _delete_file(self, filename):
        command = 'delete /unreserved /quiet {0}'.format(filename)
        self.device.send_command(command)

    def _save_config(self, filename=''):
        """Save the current running config to the given file."""
        command = 'save {}'.format(filename)
        save_log = self.device.send_command(command, max_loops=10, expect_string=r'Y/N')
        # Search pattern will not be detected when set a new hostname, so don't use auto_find_prompt=False
        save_log += self.device.send_command('y', expect_string=r'<.+>')
        search_result = re.search("successfully", save_log, re.M)
        if search_result is None:
            msg = "Failed to save config. Command output:{}".format(save_log)
            raise CommandErrorException(msg)

    def _load_config(self, config_file):
        command = 'rollback configuration to file {0}'.format(config_file)
        rollback_result = self.device.send_command(command, expect_string=r'Y/N')
        rollback_result += self.device.send_command('y', expect_string=r'[<\[].+[>\]]')
        search_result = re.search("clear the information", rollback_result, re.M)
        if search_result is not None:
            rollback_result += self.device.send_command('y', expect_string=r'<.+>')

        search_result = re.search("succeeded|finished", rollback_result, re.M)
        if search_result is None:
            msg = "Failed to load config. Command output:{}".format(rollback_result)
            raise CommandErrorException(msg)

    def _replace_candidate(self, filename, config):
        if not filename:
            filename = self._create_tmp_file(config)
        else:
            if not os.path.isfile(filename):
                raise ReplaceConfigException("File {} not found".format(filename))

        self.replace_file = filename

        if not self._enough_space(self.replace_file):
            msg = 'Could not transfer file. Not enough space on device.'
            raise ReplaceConfigException(msg)

        need_transfer = True
        if self._check_file_exists(self.replace_file):
            if self._check_md5(self.replace_file):
                need_transfer = False
        if need_transfer:
            dest = os.path.basename(self.replace_file)
            # full_remote_path = 'flash:/{}'.format(dest)
            with paramiko.SSHClient() as ssh:
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(hostname=self.hostname, username=self.username, password=self.password, port=self.port,
                            look_for_keys=False)

                try:
                    with paramiko.SFTPClient.from_transport(ssh.get_transport()) as sftp_client:
                        sftp_client.put(self.replace_file, dest)
                    # with SCPClient(ssh.get_transport()) as scp_client:
                    #     scp_client.put(self.replace_file, dest)
                except Exception as e:
                    msg = 'Could not transfer file. There was an error during transfer:' + str(e)
                    raise ReplaceConfigException(msg)
        self.config_replace = True
        if config and os.path.isfile(self.replace_file):
            os.remove(self.replace_file)

    def _verify_remote_file_exists(self, dst, file_system='flash:'):
        command = 'dir {0}/{1}'.format(file_system, dst)
        output = self.device.send_command(command)
        if 'No file found' in output:
            raise ReplaceConfigException('Could not transfer file.')

    def _check_file_exists(self, cfg_file):
        command = 'dir {}'.format(cfg_file)
        output = self.device.send_command(command)
        if 'No file found' in output:
            return False
        return True

    def _check_md5(self, dst):
        dst_hash = self._get_remote_md5(dst)
        src_hash = self._get_local_md5(dst)
        if src_hash == dst_hash:
            return True
        return False

    @staticmethod
    def _get_local_md5(dst, blocksize=2**20):
        md5 = hashlib.md5()
        local_file = open(dst, 'rb')
        buf = local_file.read(blocksize)
        while buf:
            md5.update(buf)
            buf = local_file.read(blocksize)
        local_file.close()
        return md5.hexdigest()

    def _get_remote_md5(self, dst):
        command = 'display system file-md5 {0}'.format(dst)
        output = self.device.send_command(command)
        filename = os.path.basename(dst)
        match = re.search(filename + r'\s+(?P<md5>\w+)', output, re.M)
        if match is None:
            msg = "Unexpected format: {}".format(output)
            raise ValueError(msg)
        return match.group('md5')

    def _commit_merge(self):
        commands = [command for command in self.merge_candidate.splitlines() if command]
        output = ''

        try:
            output += self.device.send_command('system-view', expect_string=r'\[.+\]')
            for command in commands:
                output += self.device.send_command(command, expect_string=r'\[.+\]')

            if self.device.check_config_mode():
                check_error = re.search("error", output, re.IGNORECASE)
                if check_error is not None:
                    return_log = self.device.send_command('return', expect_string=r'[<\[].+[>\]]')
                    if 'Uncommitted configurations' in return_log:
                        # Discard uncommitted configuration
                        return_log += self.device.send_command('n', expect_string=r'<.+>')
                    output += return_log
                    raise MergeConfigException('Error while applying config!')
                output += self.device.send_command('commit', expect_string=r'\[.+\]')
                output += self.device.send_command('return', expect_string=r'<.+>')
            else:
                raise MergeConfigException('Not in configuration mode.')
        except Exception as e:
            msg = str(e) + '\nconfiguration output: ' + output
            raise MergeConfigException(msg)

    def _get_merge_diff(self):
        diff = []
        running_config = self.get_config(retrieve='running')['running']
        running_lines = running_config.splitlines()
        for line in self.merge_candidate.splitlines():
            if line not in running_lines and line:
                if line[0].strip() != '!':
                    diff.append(line)
        return '\n'.join(diff)

    def _get_diff(self, filename=None):
        """Get a diff between running config and a proposed file."""
        if filename is None:
            return self.device.send_command('display configuration changes')
        return self.device.send_command('display configuration changes running file ' + filename)

    def _enough_space(self, filename):
        flash_size = self._get_flash_size()
        file_size = os.path.getsize(filename)
        if file_size > flash_size:
            return False
        return True

    def _get_flash_size(self):
        command = 'dir {}'.format('flash:')
        output = self.device.send_command(command)

        match = re.search(r'\(\d.*KB free\)', output, re.M)
        if match is None:
            msg = "Failed to get free space of flash (not match). Log: {}".format(output)
            raise ValueError(msg)

        kbytes_free = 0
        num_list = map(int, re.findall(r'\d+', match.group()))
        for index, val in enumerate(reversed([num_list])):
            kbytes_free += val * (1000 ** index)
        bytes_free = kbytes_free * 1024
        return bytes_free

    @staticmethod
    def _parse_uptime(uptime_str):
        """Return the uptime in seconds as an integer."""
        (years, weeks, days, hours, minutes, seconds) = (0, 0, 0, 0, 0, 0)

        years_regx = re.search(r"(?P<year>\d+)\syear", uptime_str)
        if years_regx is not None:
            years = int(years_regx.group(1))
        weeks_regx = re.search(r"(?P<week>\d+)\sweek", uptime_str)
        if weeks_regx is not None:
            weeks = int(weeks_regx.group(1))
        days_regx = re.search(r"(?P<day>\d+)\sday", uptime_str)
        if days_regx is not None:
            days = int(days_regx.group(1))
        hours_regx = re.search(r"(?P<hour>\d+)\shour", uptime_str)
        if hours_regx is not None:
            hours = int(hours_regx.group(1))
        minutes_regx = re.search(r"(?P<minute>\d+)\sminute", uptime_str)
        if minutes_regx is not None:
            minutes = int(minutes_regx.group(1))
        seconds_regx = re.search(r"(?P<second>\d+)\ssecond", uptime_str)
        if seconds_regx is not None:
            seconds = int(seconds_regx.group(1))

        uptime_sec = (years * YEAR_SECONDS) + (weeks * WEEK_SECONDS) + (days * DAY_SECONDS) + \
                     (hours * 3600) + (minutes * 60) + seconds
        return uptime_sec

    @staticmethod
    def _create_tmp_file(config):
        tmp_dir = tempfile.gettempdir()
        rand_fname = py23_compat.text_type(uuid.uuid4())
        filename = os.path.join(tmp_dir, rand_fname)
        with open(filename, 'wt') as fobj:
            fobj.write(config)
        return filename

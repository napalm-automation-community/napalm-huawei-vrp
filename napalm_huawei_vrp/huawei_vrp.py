# -*- coding: utf-8 -*-
# Copyright 2020 2016 Dravetech AB. All rights reserved.
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
NAPALM Driver for Huawei VRP5/VRP8 Routers and Switches.
Author: Locus Li (locus@byto.top)
Maintainers: Locus Li (locus@byto.top), Michael Alvarez(codingnetworks@gmail.com)
Read https://napalm.readthedocs.io for more information.
"""

import socket
import re
import telnetlib
import os
import tempfile
import paramiko
import uuid
import hashlib
import napalm.base.helpers
import napalm.base.constants as c

from datetime import datetime
from napalm.base import NetworkDriver
from napalm.base.netmiko_helpers import netmiko_args
from napalm.base.exceptions import (
    MergeConfigException,
    ReplaceConfigException,
    CommandErrorException,
    CommitError,
)
from .utils.utils import pretty_mac

# Easier to store these as constants
HOUR_SECONDS = 3600
DAY_SECONDS = 24 * HOUR_SECONDS
WEEK_SECONDS = 7 * DAY_SECONDS
YEAR_SECONDS = 365 * DAY_SECONDS

# STD REGEX PATTERNS
IP_ADDR_REGEX = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
IPV4_ADDR_REGEX = IP_ADDR_REGEX
IPV6_ADDR_REGEX_1 = r"::"
IPV6_ADDR_REGEX_2 = r"[0-9a-fA-F:]{1,39}::[0-9a-fA-F:]{1,39}"
IPV6_ADDR_REGEX_3 = (
    r"[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:"
    "[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}"
)
INTERFACE_REGEX = r"(?:[0-9]*GE[0-9\/\.]+)|(?:LoopBack\d+)|(?:Eth-Trunk[0-9\.]+)|(?:Vlanif[0-9\.]+)"

# Should validate IPv6 address using an IP address library after matching with this regex
IPV6_ADDR_REGEX = "(?:{}|{}|{})".format(
    IPV6_ADDR_REGEX_1, IPV6_ADDR_REGEX_2, IPV6_ADDR_REGEX_3
)

# Period needed for 32-bit AS Numbers
ASN_REGEX = r"[\d\.]+"

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
        self.profile = ["huawei_vrp"]

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

    # verified
    def open(self):
        """Open a connection to the device.
        """
        device_type = "huawei"
        if self.transport == "telnet":
            device_type = "huawei_telnet"
        self.device = self._netmiko_open(
            device_type, netmiko_optional_args=self.netmiko_optional_args
        )

    # verified
    def close(self):
        """Close the connection to the device and do the necessary cleanup."""

        # Return file prompt quiet to the original state
        if self.auto_file_prompt and self.prompt_quiet_changed is True:
            self.device.send_config_set(["no file prompt quiet"])
            self.prompt_quiet_changed = False
            self.prompt_quiet_configured = False
        self._netmiko_close()

    # verified
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

    # verified
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

    # verified
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
        show_esn = self.device.send_command('display esn')

        # os_version/uptime/model
        for line in show_ver.splitlines():
            if 'VRP (R) software' in line:
                search_result = re.search(r"\(S\S+\s+(?P<os_version>V\S+)\)", line)
                if search_result is not None:
                    os_version = search_result.group('os_version')

            if 'HUAWEI' in line and 'uptime is' in line:
                search_result = re.search(r"S\S+", line)
                if search_result is not None:
                    model = search_result.group(0)
                uptime = self._parse_uptime(line)
                break

        # get serial_number,due to the stack have multiple SN, so show it in a list
        # 由于堆叠设备会有多少个SN，所以这里用列表展示
        re_sn = r"ESN\s+of\s+slot\s+\S+\s+(?P<serial_number>\S+)"
        serial_number = re.findall(re_sn, show_esn, flags=re.M)

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
            'os_version': os_version,
            'serial_number': serial_number,
            'model': model,
            'hostname': hostname,
            'fqdn': fqdn,  # ? fqdn(fully qualified domain name)
            'interface_list': interface_list
        }

    # developing
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
        # 空包
        environment = {}
        # 定义执行命令
        fan_cmd = 'display fan'
        """
         Slot  FanID   Online    Status    Speed     Mode     Airflow            
        -------------------------------------------------------------------------
         0     1       Present   Normal    55%       Auto     Side-to-Back
         1     1       Present   Normal    55%       Auto     Side-to-Back
        """
        power_cmd = 'display power'
        """
        ------------------------------------------------------------
         Slot    PowerID  Online   Mode   State      Power(W)
        ------------------------------------------------------------
         0       PWR1     Present  AC     Supply     600.00     
         0       PWR2     Present  AC     Supply     600.00     
         1       PWR1     Present  AC     Supply     600.00     
         1       PWR2     Present  AC     Supply     600.00  
        """
        temp_cmd = 'display temperature all'
        """
        -------------------------------------------------------------------------------
         Slot  Card  Sensor Status    Current(C) Lower(C) Lower     Upper(C) Upper
                                                          Resume(C)          Resume(C)
        -------------------------------------------------------------------------------
         0     NA    NA     Normal     37        0        4         63       59
         1     NA    NA     Normal     39        0        4         63       59
         """
        cpu_cmd = 'display cpu-usage'
        """
        CPU Usage Stat. Cycle: 60 (Second)
        CPU Usage            : 28% Max: 87%
        CPU Usage Stat. Time : 2022-01-13  18:57:06 
        CPU utilization for five seconds: 28%: one minute: 28%: five minutes: 20%
        Max CPU Usage Stat. Time : 2021-10-05 17:50:44.
        """
        mem_cmd = 'display memory-usage'
        """
         Memory utilization statistics at 2022-01-13 18:57:37+08:00
         System Total Memory Is: 1598029824 bytes
         Total Memory Used Is: 188593436 bytes
         Memory Using Percentage Is: 11%
        """
        # 发送命令
        fan_output = self.device.send_command(fan_cmd)
        power_cmd = self.device.send_command(power_cmd)
        temp_cmd = self.device.send_command(temp_cmd)
        cpu_cmd = self.device.send_command(cpu_cmd)
        mem_cmd = self.device.send_command(mem_cmd)
        # 设备风扇情况
        environment.setdefault('fans', {})
        for i in fan_output.split('\n'):
            match = re.match(r"\s+(\d+).+(Normal|Abnormal).+", i)
            if match:
                slot = match.group(1)
                status = True if match.group(2) == "Normal" else False
                environment['fans'][slot] = {'status': status}

        # 设备电源情况
        environment.setdefault('power', {})
        for i in power_cmd.split('\n'):
            # match = re.match(r"\s+(\d+).+(Normal|Abnormal).+", i)
            match = re.match(r"\s+(\d+)\s+(\w+\d+)\s+(\w+).+\s+(\w+)\s+(\d+\.\d+)", i)
            if match:
                environment['power'][f"{match.group(2)}-{match.group(1)}"] = {
                    "capacity": float(match.group(5)),
                    "output": None,
                    "status": True if match.group(4) == 'Supply' else False

                }
        # 设备温度情况
        environment.setdefault('temperature', {})
        for i in temp_cmd.split('\n'):
            match = re.split('\s+', i)
            if len(match) == 10:
                if 'Upper' not in match:
                    environment['temperature']['slot' + match[1]] = {
                        "is_alert": False if match[4] == "Normal" else True,
                        "is_critical": False if match[4] == "Normal" else True,
                        "temperature": float(match[-1])
                    }

        # CPU使用率
        environment.setdefault('cpu', {})
        cpu_use = re.search(r'CPU utilization for five seconds: \d+%: one minute: \d+%: five minutes: (\d+)%', cpu_cmd)
        environment['cpu'] = {
            "0": {
                "usage": cpu_use.group(1)
            }

        }
        # 内存使用情况
        environment.setdefault('memory', {})
        memory_use = re.findall(r'(\d+) bytes', mem_cmd)
        environment['memory'] = {
            "available_ram": int(memory_use[0]) - int(memory_use[1]),
            "used_ram": int(memory_use[1])
        }
        return environment

    # verified
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
            config['running'] = self.device.send_command(command)
        if retrieve.lower() in ('startup', 'all'):
            # command = 'display saved-configuration last'
            # config['startup'] = py23_compat.text_type(self.device.send_command(command))
            pass
        return config

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

    # developing
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

    # developing
    def rollback(self):
        """Rollback to previous commit."""
        if self.changed:
            self._load_config(self.backup_file)
            self.changed = False
            self._save_config()

    # verified
    def ping(self, destination, source=c.PING_SOURCE, ttl=c.PING_TTL, timeout=c.PING_TIMEOUT, size=c.PING_SIZE,
             count=c.PING_COUNT, vrf=c.PING_VRF):
        """Execute ping on the device."""
        ping_dict = {}
        command = 'ping'
        # Timeout in milliseconds to wait for each reply, the default is 2000
        command += ' -t {}'.format(timeout * 1000)
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
                    results_array.append({'ip_address': destination,
                                          'rtt': float(i)})
                ping_dict['success'].update({'results': results_array})
        return ping_dict

    # developing
    def traceroute(self):
        pass

    # get information from network device
    # verified
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

    # verified
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

    # verified
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

    # verified
    def get_lldp_neighbors(self):
        """
        Return LLDP neighbors brief info.

        Sample input:
            <device-vrp>dis lldp neighbor brief
            Local Intf    Neighbor Dev          Neighbor Intf             Exptime(s)
            XGE0/0/1      huawei-S5720-01       XGE0/0/1                  96
            XGE0/0/3      huawei-S5720-POE      XGE0/0/1                  119
            XGE0/0/46     Aruba-7210-M          GE0/0/2                   95

        Sample output:
        {
            'XGE0/0/1': [
                {
                    'hostname': 'huawei-S5720-01',
                    'port': 'XGE0/0/1'
                },
            'XGE0/0/3': [
                {
                    'hostname': 'huawei-S5720-POE',
                    'port': 'XGE0/0/1'
                },
            'XGE0/0/46': [
                {
                    'hostname': 'Aruba-7210-M',
                    'port': 'GE0/0/2'
                },
            ]
        }
        """
        results = {}
        command = 'display lldp neighbor brief'
        output = self.device.send_command(command)
        re_lldp = r"(?P<local>\S+)\s+(?P<hostname>\S+)\s+(?P<port>\S+)\s+\d+\s+"
        match = re.findall(re_lldp, output, re.M)
        for neighbor in match:
            local_intf = neighbor[0]
            if local_intf not in results:
                results[local_intf] = []

            neighbor_dict = dict()
            neighbor_dict['hostname'] = neighbor[1]
            neighbor_dict['port'] = neighbor[2]
            results[local_intf].append(neighbor_dict)
        return results

    # develop
    def get_lldp_neighbors_detail(self, interface=""):
        pass
        """
        Return a detailed view of the LLDP neighbors as a dictionary.

        Sample output:
        {
        }
        """
        lldp_neighbors = {}
        return lldp_neighbors

    # verified
    def get_arp_table(self, vrf=""):
        """
                Get arp table information.

                Return a list of dictionaries having the following set of keys:
                    * interface (string)
                    * mac (string)
                    * ip (string)
                    * age (float) (not support)

                Sample output:
                    [
                        {
                            'interface' : 'MgmtEth0/RSP0/CPU0/0',
                            'mac'       : '5c:5e:ab:da:3c:f0',
                            'ip'        : '172.17.17.1',
                            'age'       : -1
                        },
                        {
                            'interface': 'MgmtEth0/RSP0/CPU0/0',
                            'mac'       : '66:0e:94:96:e0:ff',
                            'ip'        : '172.17.17.2',
                            'age'       : -1
                        }
                    ]
                """
        arp_table = []
        output = self.device.send_command('display arp')
        re_arp = r"(?P<ip_address>\d+\.\d+\.\d+\.\d+)\s+(?P<mac>\S+)\s+(?P<exp>\d+|)\s+" \
                 r"(?P<type>I|D|S|O)\S+\s+(?P<interface>\S+)"
        match = re.findall(re_arp, output, flags=re.M)

        for arp in match:
            # if arp[2].isdigit():
            #     exp = float(arp[2]) * 60
            # else:
            #     exp = 0

            entry = {
                'interface': arp[4],
                'mac': pretty_mac(arp[1]),
                'ip': arp[0],
                'age': -1.0,
            }
            arp_table.append(entry)
        return arp_table

    # verified
    def get_mac_address_table(self):
        """
        Return the MAC address table.

        Sample output:
        [
            {
                "active": true,
                "interface": "10GE1/0/1",
                "last_move": -1.0,
                "mac": "00:00:00:00:00:33",
                "moves": -1,
                "static": false,
                "vlan": 100
            },
            {
                "active": false,
                "interface": "10GE1/0/2",
                "last_move": -1.0,
                "mac": "00:00:00:00:00:01",
                "moves": -1,
                "static": true,
                "vlan": 200
            }
        ]
        MAC type:
            标识MAC地址的类型：
                static：     静态MAC地址表项。由用户手工配置，表项不会被老化。
                blackhole：  标识黑洞MAC地址表项，由用户手工配置，表项不会被老化。可以通过命令mac-address blackhole配置。
                dynamic：    标识动态MAC地址表项，由设备通过源MAC地址学习获得，表项有老化时间，可被老化。
                security：   标识安全动态MAC表项，由接口使能端口安全功能后学习到的MAC地址表项。
                sec-config： 标识安全静态MAC表项，由命令port-security mac-address配置的MAC地址表项。
                sticky：     标识Sticky MAC表项，由接口使能Sticky MAC功能后学习到的MAC地址表项。
                mux：        标识MUX MAC表项，当接口使能MUX VLAN功能后，该接口学习到的MAC地址表项会记录到mux类型的MAC地址表项中。
                snooping：   根据DHCP Snooping绑定表生成的静态MAC表项类型。
                authen：     已获取到IP地址的NAC认证用户（无法生成MAC地址的三层Portal认证用户和直接转发模式下的无线用户除外）对应的MAC地址表项。
                pre-authen： 用户使能NAC认证功能后，处于预连接状态且未获取到IP地址的NAC认证用户对应的MAC地址表项。
                evpn：       标识EVPN网络中存在的MAC地址表项。
        """
        mac_address_table = []
        command = 'display mac-address'
        output = self.device.send_command(command)
        re_mac = r"(?P<mac>\S+)\s+(?P<vlan>\d+|-)\S+\s+(?P<interface>\S+)\s+(?P<type>\w+)\s+"
        match = re.findall(re_mac, output, re.M)

        for mac_info in match:
            mac_dict = {
                'mac': napalm.base.helpers.mac(mac_info[0]),
                'interface': mac_info[2],
                'vlan': int(mac_info[1]),
                'static': True if mac_info[3] == "static" else False,
                'active': True if mac_info[3] == "dynamic" else False,
                'authen': True if mac_info[3] == "authen" else False,
                'moves': -1,
                'last_move': -1.0
            }
            mac_address_table.append(mac_dict)
        return mac_address_table


    # developing
    def get_probes_config(self):
        pass

    # developing
    def get_probes_results(self):
        pass

    # verified
    def get_bgp_neighbors(self):
        """
        {
            "global": {
                "router_id": "192.168.21.102",
                "peers": {
                    "172.17.1.1": {
                        "local_as": 200,
                        "remote_as": 100,
                        "remote_id": "192.168.21.101",
                        "is_up": true,
                        "is_enabled": true,
                        "description": "",
                        "uptime": 142,
                        "address_family": {
                            "ipv4 unicast": {
                                "received_prefixes": 5,
                                "accepted_prefixes": 5,
                                "sent_prefixes": 2
                            }
                        }
                    }
                }
            }
        }
        """
        bgp_neighbors = {}

        command_bgp_peer = "display bgp peer"
        command_bgp_ipv6 = "display bgp ipv6 peer"
        command_bgp_vpnv4 = "display bgp vpnv4 all peer"
        command_bgp_vpnv6 = "display bgp vpnv6 all peer"
        command_bgp_vpntarget = "display bgp vpn-target peer"

        output_peer = self.device.send_command(command_bgp_peer)
        output_peer_ipv6 = self.device.send_command(command_bgp_peer)
        output_vpnv4 = self.device.send_command(command_bgp_vpnv4)
        output_vpnv6 = self.device.send_command(command_bgp_vpnv6)
        output_vpntarget = self.device.send_command(command_bgp_vpntarget)


        if output_peer == "" and output_vpnv4 == "" and output_vpnv6 == "" and output_peer_ipv6 == "" and \
            output_vpntarget == "":
            return bgp_neighbors

        #Regular Expressions
        re_separator = r"\n\s*(?=VPN-Instance\s+)"

        #
        re_global_router_id = r"BGP local router ID :\s+(?P<glob_router_id>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        re_global_local_as = r"Local AS number :\s+(?P<local_as>{})".format(ASN_REGEX)
        re_vrf_router_id = r"VPN-Instance\s+(?P<vrf>[-_a-zA-Z0-9]+), [rR]outer ID\s+" \
                              r"(?P<vrf_router_id>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        re_peers = r"(?P<peer_ip>({})|({}))\s+(?P<bgp_version>\d)\s+" \
                   r"(?P<as>{})\s+\d+\s+\d+\s+\d+\s+(?P<updown_time>[a-zA-Z0-9:]+)\s+" \
                   r"(?P<state>[a-zA-Z0-9\(\)]+)\s+(?P<received_prefixes>\d+)".format(
                            IPV4_ADDR_REGEX, IPV6_ADDR_REGEX, ASN_REGEX)

        re_remote_rid = r"Remote router ID\s+(?P<remote_rid>{})".format(IPV4_ADDR_REGEX)
        re_peer_description = r"Peer's description:\s+\"(?P<peer_description>.*)\""
        re_advertised_routes = r"Advertised total routes:\s*(?P<sent_prefixes>\d+)"


        if output_peer != "":

            bgp_global_router_id = ""
            bgp_global_local_as = ""

            match_afi = re.search(re_global_router_id,output_peer, flags=re.M)
            match_local_as = re.search(re_global_local_as,output_peer, flags=re.M)
            if match_afi is not None:
                bgp_global_router_id = match_afi.group('glob_router_id')
                bgp_global_local_as = match_local_as.group('local_as')

            #IPv4 Unicast y IPv6 Unicas Peerings
            bgp_neighbors.update({"global": {"router_id": bgp_global_router_id, "peers" : {}}})

            for peer in output_peer.splitlines():

                match_peer = re.search(re_peers, peer, flags=re.M)
                
                if match_peer:

                    peer_bgp_command = "display bgp peer {} verbose".format(match_peer.group('peer_ip'))
                    
                    #Send Display BGP Peer Vervose
                    peer_detail = self.device.send_command(peer_bgp_command)

                    match_remote_rid = re.search(re_remote_rid, peer_detail, flags=re.M)
                    match_peer_description = re.search(re_peer_description, peer_detail, flags=re.M)
                    match_advertised_routes = re.search(re_advertised_routes, peer_detail, flags=re.M)

                    bgp_neighbors["global"]["peers"].update( { 
                    match_peer.group('peer_ip'): { 
                    "local_as": int(bgp_global_local_as), 
                    "remote_as": int(match_peer.group('as')), 
                    "remote_id": "" if match_remote_rid is None else match_remote_rid.group('remote_rid'), 
                    "is_up": True if "Established" in match_peer.group('state') else False, 
                    "is_enabled": False if "Admin" in match_peer.group('state') else True, 
                    "description": "" if match_peer_description is None else match_peer_description.group('peer_description'), 
                    "uptime": int(self.bgp_time_conversion(match_peer.group('updown_time'))), 
                    "address_family": { 
                            "ipv4 unicast": { 
                            "is_up": True if "Established" in match_peer.group('state') else False,
                            "received_prefixes": int(match_peer.group('received_prefixes')), 
                            "accepted_prefixes": -1, 
                            "sent_prefixes": int(match_advertised_routes.group('sent_prefixes')) if match_advertised_routes is not None else "Unknown", 
                                        }
                                    }
                            }
                        })
        if output_vpnv4 != "":

            if output_peer == "":
                bgp_global_router_id = ""
                bgp_global_local_as = ""

                match_afi = re.search(re_global_router_id,output_vpnv4, flags=re.M)
                match_local_as = re.search(re_global_local_as,output_vpnv4, flags=re.M)
                if match_afi is not None:
                    bgp_global_router_id = match_afi.group('glob_router_id')
                    bgp_global_local_as = match_local_as.group('local_as')

                #IPv4 Unicast y IPv6 Unicas Peerings
                bgp_neighbors.update({"global": {"router_id": bgp_global_router_id, "peers" : {}}})

            #Separation of AFIs VPNv4
            afi_list = re.split(re_separator, output_vpnv4, flags=re.M)
            #       
            for vpn_peers in afi_list:
 
                if "VPN-Instance " not in vpn_peers:
                    for peer in vpn_peers.splitlines():
                        match_peer = re.search(re_peers,peer, flags=re.M)
                        if match_peer:

                            peer_bgp_command = "display bgp vpnv4 all peer {} verbose".format(match_peer.group('peer_ip'))            
                            peer_detail = self.device.send_command(peer_bgp_command)
                            match_advertised_routes = re.search(re_advertised_routes, peer_detail, flags=re.M)

                            #If the Peer Already Exist, just add the info of the new vpnv4.
                            if match_peer.group('peer_ip') in bgp_neighbors["global"]["peers"]:
                                bgp_neighbors["global"]["peers"][match_peer.group('peer_ip')]["address_family"].update(
                                { 
                                    "vpnv4 unicast": { 
                                    "is_up": True if "Established" in match_peer.group('state') else False,
                                    "received_prefixes": int(match_peer.group('received_prefixes')), 
                                    "accepted_prefixes": -1, 
                                    "sent_prefixes": int(match_advertised_routes.group('sent_prefixes')) if match_advertised_routes is not None else "Unknown"
                                                }
                                            }
                                ) 
                            else:

                                match_remote_rid = re.search(re_remote_rid, peer_detail, flags=re.M)
                                match_peer_description = re.search(re_peer_description, peer_detail, flags=re.M)
                                
                                bgp_neighbors["global"]["peers"].update( { 
                                match_peer.group('peer_ip'): { 
                                "local_as": int(bgp_global_local_as), 
                                "remote_as": int(match_peer.group('as')), 
                                "remote_id": "" if match_remote_rid is None else match_remote_rid.group('remote_rid'), 
                                "is_up": True if "Established" in match_peer.group('state') else False, 
                                "is_enabled": False if "Admin" in match_peer.group('state') else True, 
                                "description": "" if match_peer_description is None else match_peer_description.group('peer_description'), 
                                "uptime": int(self.bgp_time_conversion(match_peer.group('updown_time'))), 
                                "address_family": { 
                                    "vpnv4 unicast": { 
                                        "is_up": True if "Established" in match_peer.group('state') else False,
                                        "received_prefixes": int(match_peer.group('received_prefixes')), 
                                        "accepted_prefixes": -1, 
                                        "sent_prefixes": int(match_advertised_routes.group('sent_prefixes')) if match_advertised_routes is not None else "Unknown"
                                                    }
                                                }
                                        }
                                    })
                else:
                    match_vrf_router_id = re.search(re_vrf_router_id, vpn_peers, flags=re.M)

                    if match_vrf_router_id is None:
                        msg = "No Match Found"
                        raise ValueError(msg)

                    peer_vpn_instance = match_vrf_router_id.group('vrf')
                    peer_router_id = match_vrf_router_id.group('vrf_router_id')

                    bgp_neighbors.update({peer_vpn_instance: {
                                    "router_id": peer_router_id, "peers" : {}}})

                    for peer in vpn_peers.splitlines():
                                
                        match_peer = re.search(re_peers, peer, flags=re.M)
                        if match_peer:

                            peer_bgp_command = ""
                            afi_vrf = ""
                            peer_bgp_command = "display bgp vpnv4 vpn-instance {} peer {} verbose".format(peer_vpn_instance, match_peer.group('peer_ip'))
                            afi_vrf = "ipv4 unicast"
                            
                            peer_detail = self.device.send_command(peer_bgp_command)

                            match_remote_rid = re.search(re_remote_rid, peer_detail, flags=re.M)
                            match_peer_description = re.search(re_peer_description, peer_detail, flags=re.M)
                            match_advertised_routes = re.search(re_advertised_routes, peer_detail, flags=re.M)

                            bgp_neighbors[peer_vpn_instance]["peers"].update( { 
                            match_peer.group('peer_ip'): { 
                            "local_as": int(bgp_global_local_as), 
                            "remote_as": int(match_peer.group('as')), 
                            "remote_id": "" if match_remote_rid is None else match_remote_rid.group('remote_rid'), 
                            "is_up": True if "Established" in match_peer.group('state') else False, 
                            "is_enabled": False if "Admin" in match_peer.group('state') else True, 
                            "description": "" if match_peer_description is None else match_peer_description.group('peer_description'), 
                            "uptime": int(self.bgp_time_conversion(match_peer.group('updown_time'))),         
                            "address_family": { 
                                afi_vrf: { 
                                    "is_up": True if "Established" in match_peer.group('state') else False,
                                    "received_prefixes": int(match_peer.group('received_prefixes')), 
                                    "accepted_prefixes": -1, 
                                    "sent_prefixes": int(match_advertised_routes.group('sent_prefixes')) if match_advertised_routes is not None else "Unknown"
                                            }
                                        }
                                    }
                            })

        if output_vpnv6 != "":
            if output_peer == "" and output_vpnv4 == "":
                bgp_global_router_id = ""
                bgp_global_local_as = ""

                match_afi = re.search(re_global_router_id,output_vpnv6, flags=re.M)
                match_local_as = re.search(re_global_local_as,output_vpnv6, flags=re.M)
                if match_afi is not None:
                    bgp_global_router_id = match_afi.group('glob_router_id')
                    bgp_global_local_as = match_local_as.group('local_as')

                #IPv4 Unicast y IPv6 Unicas Peerings
                bgp_neighbors.update({"global": {"router_id": bgp_global_router_id, "peers" : {}}})

            afi_list = re.split(re_separator, output_vpnv6, flags=re.M)

            #       
            for vpn_peers in afi_list:
 
                if "VPN-Instance " not in vpn_peers:
                    for peer in vpn_peers.splitlines():
                        match_peer = re.search(re_peers,peer, flags=re.M)
                        if match_peer:

                            peer_bgp_command = "display bgp vpnv6 all peer {} verbose".format(match_peer.group('peer_ip'))            
                            peer_detail = self.device.send_command(peer_bgp_command)
                            match_advertised_routes = re.search(re_advertised_routes, peer_detail, flags=re.M)

                            #If the Peer Already Exist, just add the info of the new vpnv6.
                            if match_peer.group('peer_ip') in bgp_neighbors["global"]["peers"]:
                                bgp_neighbors["global"]["peers"][match_peer.group('peer_ip')]["address_family"].update(
                                { 
                                    "vpnv6 unicast": {
                                    "is_up": True if "Established" in match_peer.group('state') else False, 
                                    "received_prefixes": int(match_peer.group('received_prefixes')), 
                                    "accepted_prefixes": -1, 
                                    "sent_prefixes": int(match_advertised_routes.group('sent_prefixes')) if match_advertised_routes is not None else "Unknown"
                                                }
                                            }
                                ) 
                            else:

                                match_remote_rid = re.search(re_remote_rid, peer_detail, flags=re.M)
                                match_peer_description = re.search(re_peer_description, peer_detail, flags=re.M)
                                
                                bgp_neighbors["global"]["peers"].update( { 
                                match_peer.group('peer_ip'): { 
                                "local_as": int(bgp_global_local_as), 
                                "remote_as": int(match_peer.group('as')), 
                                "remote_id": "" if match_remote_rid is None else match_remote_rid.group('remote_rid'), 
                                "is_up": True if "Established" in match_peer.group('state') else False, 
                                "is_enabled": False if "Admin" in match_peer.group('state') else True, 
                                "description": "" if match_peer_description is None else match_peer_description.group('peer_description'), 
                                "uptime": int(self.bgp_time_conversion(match_peer.group('updown_time'))), 
                                "address_family": { 
                                    "vpnv4 unicast": { 
                                        "is_up": True if "Established" in match_peer.group('state') else False,
                                        "received_prefixes": int(match_peer.group('received_prefixes')), 
                                        "accepted_prefixes": -1, 
                                        "sent_prefixes": int(match_advertised_routes.group('sent_prefixes')) if match_advertised_routes is not None else "Unknown"
                                                    }
                                                }
                                        }
                                    })
                else:
                    match_vrf_router_id = re.search(re_vrf_router_id, vpn_peers, flags=re.M)

                    if match_vrf_router_id is None:
                        msg = "No Match Found"
                        raise ValueError(msg)

                    peer_vpn_instance = match_vrf_router_id.group('vrf')
                    peer_router_id = match_vrf_router_id.group('vrf_router_id')

                    bgp_neighbors.update({peer_vpn_instance: {
                                    "router_id": peer_router_id, "peers" : {}}})

                    for peer in vpn_peers.splitlines():
                                
                        match_peer = re.search(re_peers, peer, flags=re.M)
                        if match_peer:

                            peer_bgp_command = ""
                            afi_vrf = ""
                            peer_bgp_command = "display bgp vpnv6 vpn-instance {} peer {} verbose".format(peer_vpn_instance, match_peer.group('peer_ip'))
                            afi_vrf = "ipv6 unicast"
                            
                            peer_detail = self.device.send_command(peer_bgp_command)

                            match_remote_rid = re.search(re_remote_rid, peer_detail, flags=re.M)
                            match_peer_description = re.search(re_peer_description, peer_detail, flags=re.M)
                            match_advertised_routes = re.search(re_advertised_routes, peer_detail, flags=re.M)

                            bgp_neighbors[peer_vpn_instance]["peers"].update( { 
                            match_peer.group('peer_ip'): { 
                            "local_as": int(bgp_global_local_as), 
                            "remote_as": int(match_peer.group('as')), 
                            "remote_id": "" if match_remote_rid is None else match_remote_rid.group('remote_rid'), 
                            "is_up": True if "Established" in match_peer.group('state') else False, 
                            "is_enabled": False if "Admin" in match_peer.group('state') else True, 
                            "description": "" if match_peer_description is None else match_peer_description.group('peer_description'), 
                            "uptime": int(self.bgp_time_conversion(match_peer.group('updown_time'))),         
                            "address_family": { 
                                afi_vrf: { 
                                    "is_up": True if "Established" in match_peer.group('state') else False,
                                    "received_prefixes": int(match_peer.group('received_prefixes')), 
                                    "accepted_prefixes": -1, 
                                    "sent_prefixes": int(match_advertised_routes.group('sent_prefixes')) if match_advertised_routes is not None else "Unknown"
                                            }
                                        }
                                    }
                            })

        if output_vpntarget != "":
    
            if output_peer == "" and output_vpnv4 == "" and output_vpnv6 == "":
                bgp_global_router_id = ""
                bgp_global_local_as = ""

                match_afi = re.search(re_global_router_id,output_vpnv6, flags=re.M)
                match_local_as = re.search(re_global_local_as,output_vpnv6, flags=re.M)
                if match_afi is not None:
                    bgp_global_router_id = match_afi.group('glob_router_id')
                    bgp_global_local_as = match_local_as.group('local_as')

                #IPv4 Unicast y IPv6 Unicas Peerings
                bgp_neighbors.update({"global": {"router_id": bgp_global_router_id, "peers" : {}}})

            match_afi = re.search(re_global_router_id,output_vpntarget, flags=re.M)
            match_local_as = re.search(re_global_local_as,output_vpntarget, flags=re.M)

            if match_afi is not None:
                bgp_global_router_id = match_afi.group('glob_router_id')
                bgp_global_local_as = match_local_as.group('local_as')

            #IPv4 VPN-Target 
            #bgp_neighbors.update({"global": {"router_id": bgp_global_router_id, "peers" : {}}})

            for peer in output_vpntarget.splitlines():

                match_peer = re.search(re_peers, peer, flags=re.M)
                
                if match_peer:

                    peer_bgp_command = "display bgp vpn-target peer {} verbose".format(match_peer.group('peer_ip'))
                    
                    #Send Display BGP Peer Vervose
                    peer_detail = self.device.send_command(peer_bgp_command)

                    match_remote_rid = re.search(re_remote_rid, peer_detail, flags=re.M)
                    match_peer_description = re.search(re_peer_description, peer_detail, flags=re.M)
                    match_advertised_routes = re.search(re_advertised_routes, peer_detail, flags=re.M)



                    #If the Peer Already Exist, just add the info of the new vpnv4.
                    if match_peer.group('peer_ip') in bgp_neighbors["global"]["peers"]:
                        bgp_neighbors["global"]["peers"][match_peer.group('peer_ip')]["address_family"].update(
                        { 
                            "vpn_target": { 
                            "is_up": True if "Established" in match_peer.group('state') else False,
                            "received_prefixes": int(match_peer.group('received_prefixes')), 
                            "accepted_prefixes": -1, 
                            "sent_prefixes": int(match_advertised_routes.group('sent_prefixes')) if match_advertised_routes is not None else "Unknown"
                                        }
                                    }
                        ) 
                    else:

                        match_remote_rid = re.search(re_remote_rid, peer_detail, flags=re.M)
                        match_peer_description = re.search(re_peer_description, peer_detail, flags=re.M)
                        
                        bgp_neighbors["global"]["peers"].update( { 
                        match_peer.group('peer_ip'): { 
                        "local_as": int(bgp_global_local_as), 
                        "remote_as": int(match_peer.group('as')), 
                        "remote_id": "" if match_remote_rid is None else match_remote_rid.group('remote_rid'), 
                        "is_up": True if "Established" in match_peer.group('state') else False, 
                        "is_enabled": False if "Admin" in match_peer.group('state') else True, 
                        "description": "" if match_peer_description is None else match_peer_description.group('peer_description'), 
                        "uptime": int(self.bgp_time_conversion(match_peer.group('updown_time'))), 
                        "address_family": { 
                            "vpn_target": { 
                                "is_up": True if "Established" in match_peer.group('state') else False,
                                "received_prefixes": int(match_peer.group('received_prefixes')), 
                                "accepted_prefixes": -1, 
                                "sent_prefixes": int(match_advertised_routes.group('sent_prefixes')) if match_advertised_routes is not None else "Unknown"
                                            }
                                        }
                                }
                            })

        return bgp_neighbors

    # develop
    def get_bgp_neighbors_detail(self):
        pass

    # develop
    def get_bgp_config(self):
        pass

    # develop
    def get_network_instances(self):
        pass

    # to verify
    def get_ntp_peers(self):
        """
        Return the NTP peers configuration as list of dictionaries.

        Sample output:
        [
           {
                'clock source': '172.22.81.11',
                'clock stratum': 2,
                'clock status': 'configured, master, sane, valid',
                'reference clock id': '172.27.116.16',
                'reach': '255',
                'current poll': '64',
                'now': '33',
                'offset': '-283.6776 ms',
                'delay': '2.18 ms',
                'disper': '1.41 ms'
            }
        ]
        """
        ntp_peer = []
        command = "display ntp session"
        output = self.device.send_command(command)
        re_ntp = r"clock source:\s+(?P<clock_source>\S+)$\n.*" \
                 r"clock stratum:\s+(?P<clock_strat>\S+)$\n.*" \
                 r"clock status:\s+(?P<sync_status>.+)$\n.*" \
                 r"reference clock ID:\s(?P<ntp_ref_id>\S+)$\n.*" \
                 r"reach:\s(?P<reach>\S+)$\n.*" \
                 r"current poll:\s(?P<cur_poll>\S+)$\n.*" \
                 r"now:\s(?P<now>\S+)$\n.*" \
                 r"offset:\s(?P<offset>.+)$\n.*" \
                 r"delay:\s(?P<delay>.+)$\n.*" \
                 r"disper:\s(?P<disper>.+)$"

        match = re.findall(re_ntp, output, re.MULTILINE)
        for ntp_info in match:
            ntp_dict = {
                'clock source': ntp_info[0],
                'clock stratum': int(ntp_info[1]),
                'clock status': ntp_info[2],
                'reference clock id': ntp_info[3],
                'reach': ntp_info[4],
                'current poll': ntp_info[5],
                'now': ntp_info[6],
                'offset': ntp_info[7],
                'delay': ntp_info[8],
                'disper': ntp_info[9]
            }
            ntp_peer.append(ntp_dict)
        return ntp_peer

    # to modify
    def get_ntp_servers(self):
        """
        Return the NTP active servers status as a list of dictionaries.

        Sample output:
        {
            '172.22.81.11' : {
                        'clock stratum': 2,
                        'offset': '0.0000 s',
                        'synch distanc': '0.012'
                        },
            '192.168.81.15' : {
                        'clock stratum': 1,
                        'offset': '0.0000 s',
                        'synch distanc': '0.012'
                        },
        }
        """
        ntp_server = {}
        command = "display ntp-service sessions"
        output = self.device.send_command(command)
        re_ntp = r"server\s+(?P<ntp_server>\S+),.*" \
                 r"stratum\s+(?P<clock_strat>\S+),\s*" \
                 r"offset\s+(?P<offset>.+),\s.*" \
                 r"synch distance\s(?P<synch_distance>\S+)"

        match = re.findall(re_ntp, output, re.MULTILINE)

        for ntp_info in match:
            ntp_dict = {
                'server': ntp_info[0],
                'clock stratum': int(ntp_info[1]),
                'offset': ntp_info[2],
                'synch distanc': ntp_info[3]
            }
            ntp_server.append(ntp_dict)
        return ntp_server

    # to modify
    def get_ntp_stats(self):
        """
        Return the NTP Status as dictionary.

        Sample output:
        {
            "remote": "196.3.81.12",
            "synchronized": true,
            "referenceid": "172.27.52.31",
            "stratum": 2,
            "type": "-",
            "when": "599",
            "hostpoll": 1024,
            "reachability": 377,
            "delay": 3.946,
            "offset": 2.425,
            "jitter": 4.028
        }
        """
        ntp_stats = {}
        command = "display ntp status"
        output = self.device.send_command(command)
        re_ntp = r"clock status:\s+(?P<sync_status>\S+).*" \
                 r"clock stratum:\s+(?P<clock_strat>\S+).*" \
                 r"reference clock ID:\s(?P<ntp_ref_id>\S+).*" \
                 r"reference time:\s(?P<ref_time>.+\))"
        match = re.search(re_ntp, output, re.DOTALL)
        if match is None:
            msg = "No Match Found"
            raise ValueError(msg)
        else:
            ntp_dict = {
                'clock_status': match.group('sync_status'),
                'clock_stratum': int(match.group('clock_strat')),
                'ntp_reference_id': match.group('ntp_ref_id'),
                'reference_time': match.group('ref_time')
            }
        ntp_stats.update(ntp_dict)
        return ntp_stats

    # developing
    def get_optics(self):
        pass

    # developing
    def get_route_to(self, destination="", protocol=""):
        pass

    # developing
    def get_snmp_information(self):

        '''
        {
            "chassis_id": "FOC1713Z00J",
            "community": {
                "sdve44Kurkdd": {
                    "mode": "ro",
                    "acl": "10"
                },
                "Kurkdd": {
                    "mode": "rw",
                    "acl": "11"
                },
                "xyyze454n6RD4": {
                    "mode": "ro",
                    "acl": "12"
                }
            },
            "contact": "unknown",
            "location": "Street 21, Santiago"
        }
        '''
        # snmp_information = {}
        # command = 'display snmp-agent sys-info'
        # output = self.device.send_command(command)
        re_contact = r"managed node:\n\s+(?P<contact>[&,\.a-zA-Z0-9_ ]+)"
        re_location = r"physical location of this node:\n\s+(?P<location>[&,\.a-zA-Z0-9_ ]+)"
        re_snmp_version = r" SNMP version running in the system:\n\s+(?P<location>[&,\.a-zA-Z0-9_ ]+)"

        snmp_information = {
            'contact': '',
            'location': '',
            'community': {},
            'chassis_id': ''
        }
        return snmp_information

    # IN developing
    def get_users(self):
        """
        {
            "netconf": {
                "level": 1,
                "password": "",
                "sshkeys": [],
                "state" : "active",
                "type" : "S",

            },
        }
        """
        local_users = []

        command = "display local-user"
        output = self.device.send_command(command)


        if not output:
            return []

        re_local_users = r"^\s+(?P<username>\w+)\s+(?P<state>\w+)\s+(?P<type>\w+)"

        for user in output.splitlines():

            match_user = re.search(re_local_users, user, flags=re.M)

            if match_user is None:
                continue
            elif match_user.group('username') == 'Username':
                continue
            
            local_users.append(
                {"username": match_user.group('username'),
                "state" : match_user.group('state'),
                "type" : match_user.group('type')
            })

        return local_users



    # developing
    def get_vlans(self):
        pass
        '''
        {
            "1": {
                "name": "default",
                "interfaces": [
                    "GigabitEthernet0/9",
                    "GigabitEthernet0/12",
                    "GigabitEthernet0/22",
                    "GigabitEthernet0/25",
                    "TenGigabitEthernet0/1",
                    "TenGigabitEthernet0/2"
                ]
            },
            "603": {
                "name": "Kuku",
                "interfaces": [
                    "GigabitEthernet0/10"
                ]
            "800": {
                "name": "coopero",
                "interfaces": [
                    "GigabitEthernet0/19"
                ]
            }
        }
        '''
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
    def _get_local_md5(dst, blocksize=2 ** 20):
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
        rand_fname = str(uuid.uuid4())
        filename = os.path.join(tmp_dir, rand_fname)
        with open(filename, 'wt') as fobj:
            fobj.write(config)
        return filename

    @staticmethod
    def bgp_time_conversion(bgp_uptime):
        """
        Convert string time to seconds.
        Examples
        00:14:23
        00:13:40
        00:00:21
        00:00:13
        00:00:49
        1d11h
        1d17h
        1w0d
        8w5d
        1y28w
        never
        """
        bgp_uptime = bgp_uptime.strip()
        uptime_letters = set(["w", "h", "d"])

        if "never" in bgp_uptime:
            return -1
        # Check if any letters 'w', 'h', 'd' are in the time string
        elif uptime_letters & set(bgp_uptime):
            form1 = r"(\d+)d:?(\d+)h"  # 1d17h
            form2 = r"(\d+)w:?(\d+)d"  # 8w5d
            form3 = r"(\d+)y:?(\d+)w"  # 1y28w
            form4 = r"(\d+)h:?(\d+)m"  # 0025h12m
            match = re.search(form1, bgp_uptime)
            if match:
                days = int(match.group(1))
                hours = int(match.group(2))
                return (days * DAY_SECONDS) + (hours * 3600)
            match = re.search(form2, bgp_uptime)
            if match:
                weeks = int(match.group(1))
                days = int(match.group(2))
                return (weeks * WEEK_SECONDS) + (days * DAY_SECONDS)
            match = re.search(form3, bgp_uptime)
            if match:
                years = int(match.group(1))
                weeks = int(match.group(2))
                return (years * YEAR_SECONDS) + (weeks * WEEK_SECONDS)
            match = re.search(form4, bgp_uptime)
            if match:
                hours = int(match.group(1))
                minutes = int(match.group(2))
                return (hours * 3600) + (minutes * 60)
        elif ":" in bgp_uptime:
            times = bgp_uptime.split(":")
            times = [int(x) for x in times]
            hours, minutes, seconds = times
            return (hours * 3600) + (minutes * 60) + seconds

        raise ValueError(
            "Unexpected value for BGP uptime string: {}".format(bgp_uptime)
        )

    @staticmethod
    def interface_format_conversion(interface):
        """
        Convert GE to GigabitEthernet format
        """
        interface = interface.strip()

        re_giga = r"^GE(?P<port>[A-Za-z0-9\/\.]+)"
        re_ether = r"Ether(?P<port>\d[A-Za-z0-9\/\.]+)"

        match_giga = re.search(re_giga, interface ,flags=re.M)
        match_ether = re.search(re_ether,interface,flags=re.M)

        if match_giga:
            return 'GigabitEthernet' + match_giga.group('port')
        elif match_ether:
            return 'Ethernet' + match_ether.group('port')
        else:
            return interface


    @staticmethod
    def interface_bw_conversion(bandwidth):
        """
        Convert Bandwidth to kbps
        100M = 100000
        1G = 1000000
        10G = 10000000
        100G = 1000000000
        """
        bandwidth = bandwidth.strip()

        if bandwidth == '':
            return '0'

        if bandwidth == '1G':
            return '1000000'
        elif bandwidth == '10G':
            return '10000000'
        elif bandwidth == '25G':
            return '25000000'
        elif bandwidth == '50G':
            return '50000000'
        elif bandwidth == '100G':
            return '100000000'
        elif bandwidth == '100M':
            return '100000'
        elif bandwidth == '10M':
            return '10000'
            
        raise ValueError(
            "BW Conversion: Unexpected Bandwidth for GigabitEthernet: {}".format(bandwidth)
        )
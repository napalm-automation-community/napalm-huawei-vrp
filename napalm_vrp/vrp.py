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
from napalm.base.utils import py23_compat
from napalm.base.netmiko_helpers import netmiko_args
import napalm.base.constants as c
from napalm.base.exceptions import (
    ConnectionException,
    SessionLockedException,
    MergeConfigException,
    ReplaceConfigException,
    CommandErrorException,
    ConnectionClosedException,
)

from datetime import datetime
import socket
import re
import telnetlib
import os
import tempfile
import uuid
import hashlib

# Easier to store these as constants
HOUR_SECONDS = 3600
DAY_SECONDS = 24 * HOUR_SECONDS
WEEK_SECONDS = 7 * DAY_SECONDS
YEAR_SECONDS = 365 * DAY_SECONDS


class VRPDriver(NetworkDriver):
    """Napalm driver for huawei vrp."""

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

    def open(self):
        """Open a connection to the device.
        """
        device_type = "huawei"
        if self.transport == "telnet":
            device_type = "huawei_telent"
        self.device = self._netmiko_open(
            device_type, netmiko_optional_args=self.netmiko_optional_args
        )

    def close(self):
        """Close the connection to the device and do the necessary cleanup."""

        # Return file prompt quiet to the original state
        if self.auto_file_prompt and self.prompt_quiet_changed is True:
            self.device.send_config_set(["no file prompt quiet"])
            self.prompt_quiet_changed = False
            self.prompt_quiet_configured = False
        self._netmiko_close()

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

    def cli(self, commands):
        """Execute a list of commands and return the output in a dictionary format using the command
        as the key.

        Example input:
        ['dis version', 'dis cu']

        Output example:
        {   'show calendar': u'22:02:01 UTC Thu Feb 18 2016',
            'show clock': u'*22:01:51.165 UTC Thu Feb 18 2016'}
        """
        # cli_output = {}
        # if type(commands) is not list:
        #     raise TypeError('Please enter a valid list of commands!')
        #
        # for command in commands:
        #     output = self.device.send_command(command)
        #     cli_output[py23_compat.text_type(command)] = output
        # return cli_output

        cli_output = dict()
        if type(commands) is not list:
            raise TypeError("Please enter a valid list of commands!")

        for command in commands:
            output = self.device.send_command(command)
            cli_output.setdefault(command, {})
            cli_output[command] = output

        return cli_output

    # unfinished，need to fix
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

    # unfinished，need to fix
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

    # Need to verify
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

    # ---------------------------
    # Planned to development function
    # ---------------------------
    def get_mac_address_table(self):
        pass

    def get_lldp_neighbors(self):
        pass

    def get_lldp_neighbors_detail(self, interface=""):
        pass

    def pre_connection_tests(self):
        pass

    def connection_tests(self):
        pass

    def post_connection_tests(self):
        pass

    def load_replace_candidate(self, filename=None, config=None):
        pass

    def load_merge_candidate(self, filename=None, config=None):
        pass

    def compare_config(self):
        pass

    def commit_config(self, message=""):
        pass

    def discard_config(self):
        pass

    def rollback(self):
        pass

    def get_interfaces(self):
        pass

    def get_interfaces_counters(self):
        pass

    def get_bgp_config(self, group="", neighbor=""):
        pass

    def get_bgp_neighbors(self):
        pass

    def get_bgp_neighbors_detail(self, neighbor_address=""):
        pass

    def get_arp_table(self, vrf=""):
        pass

    def get_ntp_peers(self):
        pass

    def get_ntp_servers(self):
        pass

    def get_ntp_stats(self):
        pass

    def get_interfaces_ip(self):
        pass

    def get_route_to(self, destination="", protocol=""):
        pass

    def get_snmp_information(self):
        pass

    def get_probes_config(self):
        pass

    def get_probes_results(self):
        pass

    def ping(self, destination, source=c.PING_SOURCE, ttl=c.PING_TTL, timeout=c.PING_TIMEOUT, size=c.PING_SIZE,
             count=c.PING_COUNT, vrf=c.PING_VRF):
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

    def get_firewall_policies(self):
        pass

    def get_ipv6_neighbors_table(self):
        pass

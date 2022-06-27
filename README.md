[![PyPI](https://img.shields.io/pypi/v/napalm-huawei-vrp.svg)](https://pypi.python.org/pypi/napalm-huawei-vrp)
[![PyPI](https://img.shields.io/pypi/dm/napalm-huawei-vrp.svg)](https://pypi.python.org/pypi/napalm-huawei-vrp)

# NAPALM Huawei VRP

It's a NAPALM Community Driver for Huawei VRP5/VRP8 Enterprise/Service Provider Routers and Switches.

This repository is reference [NAPALM-CE](https://github.com/napalm-automation-community/napalm-ce) and Cisco IOS code, thanks for thdDaniel's contribution
[中文版](README-ZH.md)

## Supported Huawei Network Devices

* NE Series: 
    * 40E, 8000
* AR Series:
    * 2200
* ATN 900 Series:
    * 910B, 910C and 910D
* S Switch Series:
    * S5700, S6700

This driver is not limited to these models and series, these are just devices where the driver have been tested.

## Instructions

The driver is under development and iteration.

### Get info
| API   | Description  |
|--------|-----|
|  get_facts()                |  Return general device information |
|  get_config()               |  Read config |
|  get_arp_table()            |  Get device ARP table |
|  get_mac_address_table()    |  Get mac table of connected devices |
|  get_interfaces()           |  Get interface information |
|  get_interfaces_ip()        |  Get interface IP information  |
|  get_interfaces_counters()  |  Get interface counters  |
|  get_lldp_neighbors()       |  Fetch LLDP neighbor information |


### Config

| API   | Description  |
|--------|-----|
|  cli()                      |  Send any cli commands  |
|  load_merge_candidate()     |  Load config |
|  compare_config()           |  A string showing the difference between the running configuration and the candidate configuration |
|  discard_config()           |  Discards the configuration loaded into the candidate |
|  commit_config()            |  Commits the changes requested by the method load_replace_candidate or load_merge_candidate |


### Other tools
| API   | Description  |
|--------|-----|
|  is_active()                |  get devices active status  |
|  ping()                     |  Ping remote ip  |


### Plans to develop

* get_bgp_config
* get_bgp_neighbors
* get_bgp_neighbors_detail
* get_environment
* get_ipv6_neighbors_table
* get_lldp_neighbors_detail
* get_network_instances
* get_ntp_peers
* get_ntp_servers
* get_ntp_stats
* get_optics
* get_route_to
* get_snmp_information
* get_users
* get_vlans


## How to Install

You can install napalm-huawei-vrp with pip:

`pip install napalm-huawei-vrp`

That will install napalm and huawei_vrp driver currently available.

## How to upgrade

You can upgrade napalm-huawei-vrp with pip once the new version released:

`pip install --upgrade napalm-huawei-vrp`

check the package version.

`pip list | grep napalm-huawei-vrp`


## Quick start

```python
from napalm import get_network_driver
driver = get_network_driver('huawei_vrp')
device = driver(hostname='192.168.76.10', username='admin', password='this_is_not_a_secure_password')
device.open()

# Send Any CLI command
send_command = device.cli(['dis version'])

#  Return general device information
get_facts = device.get_facts()
print(get_facts)

# other API
device.get_config()
device.get_arp_table()
device.get_mac_address_table()
device.get_interfaces()
device.get_interfaces_ip()
device.get_interfaces_counters()
device.get_lldp_neighbors()

```
## Contact
### Slack

Slack is probably the easiest way to get help with NAPALM. You can find us in the channel napalm on the [network.toCode()](https://networktocode.herokuapp.com/) team.

## News
### YouTube Videos
* [NAPALM Network Automation Python: Working with Huawei VRP](https://youtu.be/40Z-hcPHY_M) by Michael Alvarez
* [NAPALM Network Automation Python: Collect Data from Multiple Vendors. Cisco and Huawei](https://youtu.be/wBuKua1QsUE) by Michael Alvarez
* [NAPALM Network Automation Python: Making Configurations in a Multivendor Network. Cisco and Huawei](https://youtu.be/QnXhCzaSvBw) by Michael Alvarez

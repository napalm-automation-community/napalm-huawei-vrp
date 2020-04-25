# napalm-huawei-vrp

NAPALM driver for HUAWEI Campus Network Switch, support the S5700,S6700 etc.


## Instructions

The driver is functional and can be used to poll status information:

* get_facts(): Return general device information
* cli(): send any cli commands
* get_lldp_neighbors(): Fetch LLDP neighbor information
* get_config(): Read config
* is_active(): get devices active status
* ping(): Ping remote ip
* get_arp_table(): Get device ARP table
* get_mac_address_table(): Get mac table of connected devices
* get_interfaces_ip(): Get interface IP
* get_interfaces_counters(): Get interface counters

## How to Install

Install napalm and install napalm-huawei-vrp via pip:

`pip install napalm napalm-huawei-vrp`

## Quick start

```python
from napalm import get_network_driver
driver = get_network_driver('huawei-vrp')
device = driver(hostname='192.168.76.10', username='admin', password='this_is_not_a_secure_password')
device.open()

get_facts = device.get_facts()
print(get_facts)

send_command = device.cli(['dis ver', 'dis cu'])
```
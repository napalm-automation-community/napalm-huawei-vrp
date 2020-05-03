[![PyPI](https://img.shields.io/pypi/v/napalm-huawei-vrp.svg)](https://pypi.python.org/pypi/napalm-huawei-vrp)
[![PyPI](https://img.shields.io/pypi/dm/napalm-huawei-vrp.svg)](https://pypi.python.org/pypi/napalm-huawei-vrp)

# napalm-huawei-vrp [中文版](README-ZH.md)

NAPALM driver for HUAWEI Campus Network Switch, support the S5700,S6700 etc.


## Instructions

The driver is under development and iteration.

### Supported

| API   | Description  |
|--------|-----|
|  load_merge_candidate()     |  Load config |
|  compare_config()           |  A string showing the difference between the running configuration and the candidate configuration |
|  discard_config()           |  Discards the configuration loaded into the candidate |
|  commit_config()            |  Commits the changes requested by the method load_replace_candidate or load_merge_candidate |
|  cli()                      |  Send any cli commands  |
|  get_facts()                |  Return general device information |
|  get_lldp_neighbors()       |  Fetch LLDP neighbor information |
|  get_config()               |  Read config |
|  is_active()                |  get devices active status  |
|  ping()                     |  Ping remote ip  |
|  get_arp_table()            |  Get device ARP table |
|  get_mac_address_table()    |  Get mac table of connected devices |
|  get_interfaces()           |  Get interface information |
|  get_interfaces_ip()        |  Get interface IP information  |
|  get_interfaces_counters()  |  Get interface counters  |

### Plans to develop

* get_environment()
* get_lldp_neighbors_detail()
* get_snmp_information()
* get_users()

## How to Install

You can install napalm-huawei-vrp with pip:

`pip install napalm-huawei-vrp`

That will install napalm and huawei_vrp driver currently available.

## How to upgrade

You can upgrade napalm-huawei-vrp with pip once the new version released:

`pip install --upgrade napalm-huawei-vrp`

## Quick start

```python
from napalm import get_network_driver
driver = get_network_driver('huawei_vrp')
device = driver(hostname='192.168.76.10', username='admin', password='this_is_not_a_secure_password')
device.open()

get_facts = device.get_facts()
print(get_facts)

send_command = device.cli(['dis ver', 'dis cu'])
```
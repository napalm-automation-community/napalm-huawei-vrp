[![PyPI](https://img.shields.io/pypi/v/napalm-huawei-vrp.svg)](https://pypi.python.org/pypi/napalm-huawei-vrp)
[![PyPI](https://img.shields.io/pypi/dm/napalm-huawei-vrp.svg)](https://pypi.python.org/pypi/napalm-huawei-vrp)

# napalm-huawei-vrp [English](README.md)

NAPALM华为S系列园区网交换机驱动，支持S5700,S6700等.


## 介绍

这个驱动目前支持以下功能

* load_merge_candidate(): 加载给定的配置文件
* compare_config(): 比较加载的配置和当前运行配置
* discard_config():删除加载的配置文件
* commit_config():执行加载的配置文件到设备
* get_facts(): 获取设备基础信息
* cli(): 发送任何命令到设备中
* get_lldp_neighbors(): 获取LLDP邻居信息
* get_config(): 获取配置信息
* is_alive(): 返回连接状态的标志
* ping(): 从设备中ping远端设备
* get_arp_table(): 获取设备APR表
* get_mac_address_table(): 获取设备MAC地址表
* get_interfaces(): 获取接口信息
* get_interfaces_ip(): 获取接口IP信息
* get_interfaces_counters(): 获取接口统计信息

## 如何安装

使用PIP来安装napalm-huawei-vrp

`pip install napalm-huawei-vrp`

## 快速开始

```python
from napalm import get_network_driver
driver = get_network_driver('huawei_vrp')
device = driver(hostname='192.168.76.10', username='admin', password='this_is_not_a_secure_password')
device.open()

get_facts = device.get_facts()
print(get_facts)

send_command = device.cli(['dis ver', 'dis cu'])
```

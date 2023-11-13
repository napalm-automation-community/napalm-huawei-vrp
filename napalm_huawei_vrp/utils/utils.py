# -*- coding: utf-8 -*-
# !/usr/bin/env python3
"""
@author: zhuyuehui
@time: 2022/1/13 4:46 下午
"""


def pretty_mac(mac: str) -> str:
    new_mac = mac.replace("-", "")
    two_step_mac_list = [
        new_mac[0:2],
        new_mac[2:4],
        new_mac[4:6],
        new_mac[6:8],
        new_mac[8:10],
        new_mac[10:12],
    ]

    return ":".join(two_step_mac_list)


class SafeList(list):
    def get(self, index, default=None):
        try:
            return self.__getitem__(index)
        except IndexError:
            return default

    def get_not_none(self, index, default=None):
        try:
            value = self.__getitem__(index)[0]
            if not value:
                value = self.__getitem__(index)[1]
            return value
        except IndexError:
            return default


if __name__ == "__main__":
    res = pretty_mac("aaaa-bbbb-cccc")
    print(res)

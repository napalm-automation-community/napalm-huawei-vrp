"""Tests for getters."""

__version__ = "0.0.3"
__date__ = "2026-03-17"

from napalm.base.test.getters import BaseTestGetters


import pytest


@pytest.mark.usefixtures("set_device_parameters")
class TestGetter(BaseTestGetters):
    def _set_mock_context(self, test_name, test_case='vrp5'):
        self.device.device.current_test = test_name
        self.device.device.current_test_case = test_case

    def test_get_network_instances(self):
        self._set_mock_context('test_get_network_instances')
        result = self.device.get_network_instances()
        expected = self.device.device.expected_result
        assert result == expected

    def test_get_lldp_neighbors_detail(self):
        self._set_mock_context('test_get_lldp_neighbors_detail')
        result = self.device.get_lldp_neighbors_detail()
        expected = self.device.device.expected_result
        assert result == expected

    def test_get_interfaces_mtu(self):
        self._set_mock_context('test_get_interfaces_mtu')
        result = self.device.get_interfaces()
        expected = self.device.device.expected_result
        # Проверяем только MTU для интерфейса MEth0/0/1
        assert result['MEth0/0/1']['mtu'] == expected['MEth0/0/1']['mtu']

    def test_get_environment(self):
        self._set_mock_context('test_get_environment')
        result = self.device.get_environment()
        expected = self.device.device.expected_result
        assert result == expected

    def test_get_arp_table_vrf(self):
        self._set_mock_context('test_get_arp_table_vrf')
        result = self.device.get_arp_table(vrf="MGMT")
        expected = self.device.device.expected_result
        # Сортируем по ip и интерфейсу для стабильности
        result_sorted = sorted(result, key=lambda x: (x['ip'], x['interface']))
        expected_sorted = sorted(expected, key=lambda x: (x['ip'], x['interface']))
        # Распечатаем результат для отладки
        import json
        print("\nRESULT:", json.dumps(result, indent=2))
        print("EXPECTED:", json.dumps(expected, indent=2))
        assert result_sorted == expected_sorted

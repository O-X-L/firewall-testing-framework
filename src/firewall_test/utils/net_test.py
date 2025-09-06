import pytest
from ipaddress import ip_address

from testdata_test import TEST_WAN_IP4, TEST_WAN_IP6


@pytest.mark.parametrize(
    'ip,result',
    [
        ('1.1.1.1', False),
        ('127.0.0.1', True),
        (TEST_WAN_IP4, True),
        ('192.168.0.1', True),
        ('::1', True),
        ('2003::2', False),
        (TEST_WAN_IP6, False),
    ]
)
def test_util_ip_is_bogon(ip, result):
    from utils.net import ip_is_bogon
    assert ip_is_bogon(ip_address(ip)) == result
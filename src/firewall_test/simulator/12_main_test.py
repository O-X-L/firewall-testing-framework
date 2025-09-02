import pytest
from ipaddress import ip_network

from testdata_test import TESTDATA_FILE_ROUTES, TESTDATA_FILE_ROUTE_RULES, TESTDATA_FILE_NIS, TESTDATA_FILE_NF_RULESET

from simulator.main import SimulatorRun


def _init_test(src: str, dst: str) -> SimulatorRun:
    from simulator.loader import load
    from simulator.packet import PacketIP
    from simulator.main import Simulator

    packet = PacketIP(src=src, dst=dst, l3_proto='ip4')
    loaded = load(
        system='linux_netfilter',
        file_interfaces=TESTDATA_FILE_NIS,
        file_routes=TESTDATA_FILE_ROUTES,
        file_route_rules=TESTDATA_FILE_ROUTE_RULES,
        file_ruleset=TESTDATA_FILE_NF_RULESET,
    )
    s = Simulator(**loaded)
    r = s.run(packet)
    return r


def test_basic():
    from simulator.main import FLOW_FORWARD

    r = _init_test(src='172.17.10.5', dst='1.1.1.1')
    assert not r.local_src
    assert not r.local_dst
    assert r.packet.ni_in == 'docker0'
    assert r.packet.ni_out == 'wan'
    assert r.flow_type == FLOW_FORWARD

    assert r.route_src.net == ip_network('172.17.0.0/16')
    assert r.route_src.ni == 'docker0'
    assert r.route_dst.net == ip_network('0.0.0.0/0')
    assert r.route_dst.ni == 'wan'


@pytest.mark.parametrize(
    'src,dst,ni_in,ni_out',
    [
        ('127.0.0.1', '1.1.1.1', 'lo', 'wan'),
        ('127.0.0.1', '127.0.0.1', 'lo', 'lo'),
        ('10.255.255.48', '1.1.1.1', 'wan', 'wan'),
        ('10.255.255.49', '1.1.1.1', 'wan', 'wan'),
        ('192.168.0.1', '10.255.255.48', 'wan', 'wan'),
        ('192.168.0.1', '10.255.255.49', 'wan', 'wan'),
        ('::1', '::1', 'lo', 'lo'),
        ('::1', '2003::2', 'lo', 'wan'),
        ('2003::2', '2003::1', 'wan', 'wan'),
        ('172.17.10.5', '1.1.1.1', 'docker0', 'wan'),
        ('172.17.10.5', '10.255.255.48', 'docker0', 'wan'),
    ]
)
def test_packet_ni_in_out(src, dst, ni_in, ni_out):
    r = _init_test(src=src, dst=dst)
    assert r.packet.ni_in == ni_in == r.route_src.ni
    assert r.packet.ni_out == ni_out == r.route_dst.ni


@pytest.mark.parametrize(
    'src,dst,local_src,local_dst',
    [
        ('127.0.0.1', '1.1.1.1', True, False),
        ('127.0.0.1', '127.0.0.1', True, True),
        ('10.255.255.48', '1.1.1.1', True, False),
        ('10.255.255.49', '1.1.1.1', False, False),
        ('192.168.0.1', '10.255.255.48', False, True),
        ('192.168.0.1', '10.255.255.49', False, False),
        ('::1', '::1', True, True),
        ('::1', '2003::2', True, False),
        ('2003::2', '2003::1', False, False),
    ]
)
def test_ni_local(src, dst, local_src, local_dst):
    r = _init_test(src=src, dst=dst)
    assert r.local_src == local_src
    assert r.local_dst == local_dst


@pytest.mark.parametrize(
    'src,dst,flow',
    [
        ('127.0.0.1', '1.1.1.1', 'output'),
        ('127.0.0.1', '127.0.0.1', 'output'),
        ('10.255.255.48', '1.1.1.1', 'output'),
        ('10.255.255.49', '1.1.1.1', 'forward'),
        ('192.168.0.1', '10.255.255.48', 'input'),
        ('192.168.0.1', '10.255.255.49', 'forward'),
        ('::1', '::1', 'output'),
        ('::1', '2003::2', 'output'),
        ('2003::2', '2003::1', 'forward'),
    ]
)
def test_flow_type(src, dst, flow):
    r = _init_test(src=src, dst=dst)
    assert r.flow_type == flow


@pytest.mark.parametrize(
    'src,dst,dst_wan_bogon',
    [
        ('127.0.0.1', '1.1.1.1', False),
        ('127.0.0.1', '127.0.0.1', False),
        ('10.255.255.48', '1.1.1.1', False),
        ('10.255.255.49', '1.1.1.1', False),
        ('192.168.0.1', '10.255.255.48', False),
        ('192.168.0.1', '10.255.255.49', False),
        ('::1', '::1', False),
        ('::1', '2003::2', False),
        ('2003::2', '2003::1', False),
        ('10.255.255.48', '192.168.0.1', True),
    ]
)
def test_bogon_to_wan(src, dst, dst_wan_bogon):
    r = _init_test(src=src, dst=dst)
    assert r._is_bogon_to_wan() == dst_wan_bogon

# todo: test for edge-case errors (no routes found, ip4/ip6 mixup, etc)

from ipaddress import ip_network

from testdata_test import TESTDATA_FILE_ROUTES, TESTDATA_FILE_ROUTE_RULES, TESTDATA_FILE_NIS


def test_basic():
    from simulator.loader import load
    from simulator.packet import PacketIP
    from simulator.main import Simulator, FLOW_FORWARD

    packet = PacketIP(src='172.17.10.5', dst='1.1.1.1', l3_proto='ip4')
    loaded = load(
        system='linux_netfilter',
        file_interfaces=TESTDATA_FILE_NIS,
        file_routes=TESTDATA_FILE_ROUTES,
        file_route_rules=TESTDATA_FILE_ROUTE_RULES,
    )
    s = Simulator(**loaded)
    r = s.run(packet)
    assert not r.local_src
    assert not r.local_dst
    assert r.packet.ni_in == 'docker0'
    assert r.packet.ni_out == 'wan'
    assert r.flow_type == FLOW_FORWARD

    assert r.route_src[0].net == ip_network('172.17.0.0/16')
    assert r.route_src[0].ni == 'docker0'
    assert r.route_dst[0].net == ip_network('0.0.0.0/0')
    assert r.route_dst[0].ni == 'wan'

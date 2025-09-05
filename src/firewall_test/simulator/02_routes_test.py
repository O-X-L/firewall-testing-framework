from ipaddress import ip_network

from testdata_test import TESTDATA_FILE_ROUTES, TESTDATA_FILE_ROUTE_RULES

with open(TESTDATA_FILE_ROUTES, 'r', encoding='utf-8') as f:
    TESTDATA_ROUTES = f.read()

with open(TESTDATA_FILE_ROUTE_RULES, 'r', encoding='utf-8') as f:
    TESTDATA_RULES = f.read()


def test_router_dst_route():
    from simulator.routes import Router
    from simulator.packet import PacketIP
    from plugins.translate.linux import LinuxRouteRules, LinuxRoutes
    from plugins.system.system_linux_netfilter import SystemLinuxNetfilter

    routes = LinuxRoutes(TESTDATA_ROUTES).get()
    route_rules = LinuxRouteRules(TESTDATA_RULES).get()

    router = Router(routes=routes, route_rules=route_rules, system=SystemLinuxNetfilter)

    packet = PacketIP(src='192.168.0.10', dst='1.1.1.1')
    r = router.get_route(packet)
    assert r is not None
    assert r.net == ip_network('0.0.0.0/0')
    assert r.table == 'default'


def test_router_src_route():
    from simulator.routes import Router
    from simulator.packet import PacketIP
    from plugins.translate.linux import LinuxRouteRules, LinuxRoutes
    from plugins.system.system_linux_netfilter import SystemLinuxNetfilter

    routes = LinuxRoutes(TESTDATA_ROUTES).get()
    route_rules = LinuxRouteRules(TESTDATA_RULES).get()

    router = Router(routes=routes, route_rules=route_rules, system=SystemLinuxNetfilter)

    packet = PacketIP(src='192.168.0.10', dst='1.1.1.1')
    r = router.get_src_route(packet)
    assert r is not None
    assert r.net == ip_network('0.0.0.0/0')
    assert r.table == 'default'

    packet = PacketIP(src='10.255.255.20', dst='1.1.1.1')
    r = router.get_src_route(packet)
    assert r is not None
    assert r.net == ip_network('10.255.255.0/24')
    assert r.table == 'default'


# todo: test other routing-edge cases
# todo: test route-prioritization

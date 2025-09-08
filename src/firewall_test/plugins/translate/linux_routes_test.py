from ipaddress import ip_network

from testdata_test import TESTDATA_FILE_ROUTES, TESTDATA_FILE_ROUTE_RULES

from config import DEFAULT_ROUTE_IP4, DEFAULT_ROUTE_IP6, LINK_LOCAL_IP6

with open(TESTDATA_FILE_ROUTES, 'r', encoding='utf-8') as f:
    TESTDATA_ROUTES = f.read()

with open(TESTDATA_FILE_ROUTE_RULES, 'r', encoding='utf-8') as f:
    TESTDATA_RULES = f.read()


def test_linux_rules():
    from plugins.translate.linux import LinuxRouteRules

    r = LinuxRouteRules(TESTDATA_RULES).get()

    assert len(r) == 4

    for rule in r:
        rule.validate()

        if rule.table == 'test':
            assert rule.priority == 32765
            assert len(rule.src) == 1
            assert rule.src[0] == ip_network('172.18.0.0/16')


def test_linux_routes():
    from plugins.translate.linux import LinuxRoutes

    r = LinuxRoutes(TESTDATA_ROUTES).get()

    assert len(r) == 13

    for route in r:
        route.validate()

        if route.net == DEFAULT_ROUTE_IP4:
            assert str(route.gw) == '10.255.255.254'
            assert route.scope == 'global'

        elif route.net == DEFAULT_ROUTE_IP6:
            assert str(route.gw) == 'fe80::7474:ceff:feb1:5347'
            assert route.scope == 'global'

        elif str(route.net) == '10.255.255.0/24':
            assert route.gw is None
            assert route.scope == 'link'
            assert str(route.src_pref) == '10.255.255.48'

from ipaddress import ip_network

from testdata_test import TESTDATA_FILE_ROUTES, TESTDATA_FILE_ROUTE_RULES

with open(TESTDATA_FILE_ROUTES, 'r', encoding='utf-8') as f:
    TESTDATA_ROUTES = f.read()

with open(TESTDATA_FILE_ROUTE_RULES, 'r', encoding='utf-8') as f:
    TESTDATA_RULES = f.read()


def test_linux_rules():
    from plugins.translate.linux import LinuxRouteRules

    r = LinuxRouteRules(TESTDATA_RULES)
    o = r.get()

    for rule in o:
        rule.validate()

        if rule.table == 'test':
            assert rule.priority == 32765
            assert len(rule.src) == 1
            assert rule.src[0] == ip_network('172.18.0.0/16')


def test_linux_routes():
    from plugins.translate.linux import LinuxRoutes

    r = LinuxRoutes(TESTDATA_ROUTES)
    o = r.get()

    for route in o:
        route.validate()

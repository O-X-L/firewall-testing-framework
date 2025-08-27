from pathlib import Path
from ipaddress import ip_network

TESTDATA_DIR = Path(__file__).parent.parent.parent.parent.parent / 'testdata'
with open(TESTDATA_DIR / 'plugin_translate_linux_routes.json', 'r', encoding='utf-8') as f:
    TESTDATA_ROUTES = f.read()

with open(TESTDATA_DIR / 'plugin_translate_linux_route-rules.json', 'r', encoding='utf-8') as f:
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

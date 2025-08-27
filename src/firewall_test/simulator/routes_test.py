from pathlib import Path
from ipaddress import ip_network

TESTDATA_DIR = Path(__file__).parent.parent.parent.parent / 'testdata'
with open(TESTDATA_DIR / 'plugin_translate_linux_routes.json', 'r', encoding='utf-8') as f:
    TESTDATA_ROUTES = f.read()

with open(TESTDATA_DIR / 'plugin_translate_linux_route-rules.json', 'r', encoding='utf-8') as f:
    TESTDATA_RULES = f.read()


def test_router():
    from simulator.routes import Router
    from simulator.packet import PacketIP
    from plugins.translate.linux import LinuxRouteRules, LinuxRoutes

    routes = LinuxRoutes(TESTDATA_ROUTES).get()
    route_rules = LinuxRouteRules(TESTDATA_RULES).get()

    router = Router(routes=routes, route_rules=route_rules)

    packet = PacketIP(src='192.168.0.10', dst='1.1.1.1', l3_proto='ip4')
    r = router.process(packet)
    assert len(r) == 1
    r = r[0]
    assert r.dst == ip_network('0.0.0.0/0')
    assert r.table == 'default'

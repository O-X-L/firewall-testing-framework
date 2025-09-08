from testdata_test import TESTDATA_FILE_OPN_NETWORK

from config import DEFAULT_ROUTE_IP4, DEFAULT_ROUTE_IP6, LINK_LOCAL_IP6

with open(TESTDATA_FILE_OPN_NETWORK, 'r', encoding='utf-8') as f:
    TESTDATA_OPN_NET = f.read()


def test_opnsense_routes():
    from plugins.translate.opnsense.routes import OPNsenseRoutes

    r = OPNsenseRoutes(TESTDATA_OPN_NET).get()

    assert len(r) == 19

    for route in r:
        route.validate()

        if route.ni == 'lan':
            if str(route.net) == '10.34.28.0/24':
                assert route.gw is None
                assert route.scope == 'link'

            elif route.net == LINK_LOCAL_IP6:
                assert route.gw is None
                assert route.scope == 'link'

        elif route.ni == 'opt5':
            if route.net == DEFAULT_ROUTE_IP4:
                assert str(route.gw) == '169.169.169.1'
                assert route.scope == 'global'
                assert str(route.src_pref) == '169.169.169.4'

            elif route.net == DEFAULT_ROUTE_IP6:
                assert str(route.gw) == '2a01:beef:beef:f5::1'
                assert route.scope == 'global'
                assert str(route.src_pref) == '2a01:beef:beef:f5::1:1'

            elif str(route.net) == '169.169.169.0/28':
                assert route.gw is None
                assert route.scope == 'link'

            elif str(route.net) == '2a01:beef:beef:f5::/64':
                assert route.gw is None
                assert route.scope == 'link'

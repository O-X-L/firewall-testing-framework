from testdata_test import TESTDATA_FILE_ROUTES, TESTDATA_FILE_ROUTE_RULES, TESTDATA_FILE_NIS, TESTDATA_FILE_NF_RULESET


def test_loader():
    from simulator.loader import load
    from plugins.translate.abstract import NetworkInterface, StaticRoute, StaticRouteRule, Ruleset
    from plugins.system.system_linux_netfilter import SystemLinuxNetfilter

    loaded = load(
        system='linux_netfilter',
        file_interfaces=TESTDATA_FILE_NIS,
        file_routes=TESTDATA_FILE_ROUTES,
        file_route_rules=TESTDATA_FILE_ROUTE_RULES,
        file_ruleset=TESTDATA_FILE_NF_RULESET,
    )
    assert 'system' in loaded
    assert 'nis' in loaded
    assert 'routes' in loaded
    assert 'route_rules' in loaded
    assert 'ruleset' in loaded

    assert loaded['system'] == SystemLinuxNetfilter

    assert len(loaded['nis']) > 0
    assert isinstance(loaded['nis'][0], NetworkInterface)

    assert len(loaded['routes']) > 0
    assert isinstance(loaded['routes'][0], StaticRoute)

    assert len(loaded['route_rules']) > 0
    assert isinstance(loaded['route_rules'][0], StaticRouteRule)

    assert isinstance(loaded['ruleset'], Ruleset)

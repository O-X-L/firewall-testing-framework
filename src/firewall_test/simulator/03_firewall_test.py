from testdata_test import TESTDATA_FILE_ROUTES, TESTDATA_FILE_ROUTE_RULES, TESTDATA_FILE_NIS, TESTDATA_FILE_NF_RULESET

with open(TESTDATA_FILE_NF_RULESET, 'r', encoding='utf-8') as f:
    TESTDATA_RULESET = f.read()


def test_firewall():
    from plugins.system.linux_netfilter import SystemLinuxNetfilter
    from plugins.translate.netfilter.ruleset import NetfilterRuleset, Ruleset
    from simulator.firewall import Firewall

    ruleset = NetfilterRuleset(TESTDATA_RULESET).get()
    fw = Firewall(
        system=SystemLinuxNetfilter,
        ruleset=ruleset,
    )

import pytest

from testdata_test import TESTDATA_FILE_NF_RULESET, TEST_DST_IP6_DROP, TEST_DST_IP4_ACCEPT, TEST_DST_IP6_ACCEPT, \
    TEST_DST_IP4_REJECT, TEST_DST_IP6_REJECT, TEST_DST_IP4_DROP
from config import RuleActionAccept, RuleActionDrop, RuleActionReject, RuleActionSNAT

with open(TESTDATA_FILE_NF_RULESET, 'r', encoding='utf-8') as f:
    TESTDATA_RULESET = f.read()


@pytest.mark.parametrize(
    'src,dst,ni_in,ni_out,result_pre,result_dnat,result_main,result_snat,result_eg',
    [
        # default policy drop of forward chain
        ('192.168.0.10', '1.1.1.1', 'wan', 'wan', RuleActionAccept, None, RuleActionDrop, None, RuleActionAccept),
        # explicit drop in forward chain
        ('192.168.0.10', TEST_DST_IP4_DROP, 'wan', 'wan', RuleActionAccept, None, RuleActionDrop, None, RuleActionAccept),
        # explicit reject in forward chain
        ('192.168.0.10', TEST_DST_IP4_REJECT, 'wan', 'wan', RuleActionAccept, None, RuleActionReject, None, RuleActionAccept),
        # explicit accept in forward chain
        ('192.168.0.10', TEST_DST_IP4_ACCEPT, 'wan', 'wan', RuleActionAccept, None, RuleActionAccept, None, RuleActionAccept),
        # DOCKER-FORWARD accept
        ('172.17.11.5', '1.1.1.1', 'docker0', 'wan', RuleActionAccept, None, RuleActionAccept, RuleActionSNAT, RuleActionAccept),
        # explicit drop in forward chain
        ('172.17.11.5', TEST_DST_IP4_DROP, 'docker0', 'wan', RuleActionAccept, None, RuleActionDrop, RuleActionSNAT, RuleActionAccept),
        # explicit accept in forward chain
        ('2003:1::1', TEST_DST_IP6_ACCEPT, 'wan', 'wan', RuleActionAccept, None, RuleActionAccept, None, RuleActionAccept),
        # explicit drop in forward chain
        ('2003:1::1', TEST_DST_IP6_DROP, 'wan', 'wan', RuleActionAccept, None, RuleActionDrop, None, RuleActionAccept),
        # explicit reject in forward chain
        ('2003:1::1', TEST_DST_IP6_REJECT, 'wan', 'wan', RuleActionAccept, None, RuleActionReject, None, RuleActionAccept),
    ]
)
def test_firewall_basic(src, dst, ni_in, ni_out, result_pre, result_dnat, result_main, result_snat, result_eg):
    from config import FlowForward
    from plugins.system.system_linux_netfilter import SystemLinuxNetfilter
    from plugins.translate.netfilter.ruleset import NetfilterRuleset
    from simulator.packet import PacketIP
    from simulator.firewall import Firewall

    ruleset = NetfilterRuleset(TESTDATA_RULESET).get()
    fw = Firewall(
        system=SystemLinuxNetfilter,
        ruleset=ruleset,
    )
    packet = PacketIP(src=src, dst=dst)
    # NOTE: network-interface discovery is done by main simulator.. will impact rule-matching
    packet.ni_in = ni_in
    packet.ni_out = ni_out

    passed, rule = fw.process_pre_routing(packet=packet, flow=FlowForward)
    assert passed == (result_pre == RuleActionAccept)
    if rule is not None:
        assert rule.action == result_pre

    has_nat, rule = fw.process_dnat(packet=packet, flow=FlowForward)
    if result_dnat is None:
        assert not has_nat
        assert rule is None

    else:
        assert has_nat
        assert rule.action == result_dnat

    passed, rule = fw.process_main(packet=packet, flow=FlowForward)
    if passed != (result_main == RuleActionAccept):
        raise ValueError(rule)

    assert passed == (result_main == RuleActionAccept)
    if rule is not None:
        assert rule.action == result_main

    has_nat, rule = fw.process_snat(packet=packet, flow=FlowForward)
    if result_snat is None:
        assert not has_nat
        assert rule is None

    else:
        assert has_nat
        if rule is not None:
            assert rule.action == result_snat

    passed, rule = fw.process_egress(packet=packet, flow=FlowForward)
    assert passed == (result_eg == RuleActionAccept)
    if rule is not None:
        assert rule.action == result_eg

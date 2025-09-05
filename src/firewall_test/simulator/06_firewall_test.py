from testdata_test import TESTDATA_FILE_NF_RULESET

with open(TESTDATA_FILE_NF_RULESET, 'r', encoding='utf-8') as f:
    TESTDATA_RULESET = f.read()


def test_firewall_basic():
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
    packet = PacketIP(src='192.168.0.10', dst='1.1.1.1')
    result, rule = fw.process_pre_routing(packet=packet, flow=FlowForward)
    assert result
    assert rule is None

    result, rule = fw.process_dnat(packet=packet, flow=FlowForward)
    assert not result
    assert rule is None

    result, rule = fw.process_main(packet=packet, flow=FlowForward)
    assert result
    assert rule is None

    result, rule = fw.process_snat(packet=packet, flow=FlowForward)
    assert not result
    assert rule is None

    result, rule = fw.process_egress(packet=packet, flow=FlowForward)
    assert result
    assert rule is None

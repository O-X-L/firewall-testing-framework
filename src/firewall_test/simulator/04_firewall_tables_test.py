import pytest

from testdata_test import TESTDATA_FILE_NF_RULESET
from config import ProtoL3IP4, ProtoL3IP4IP6, ProtoL3IP6, FlowInput, FlowOutput, FlowForward

with open(TESTDATA_FILE_NF_RULESET, 'r', encoding='utf-8') as f:
    TESTDATA_RULESET = f.read()


@pytest.mark.parametrize(
    'src,dst,ipp,matching',
    [
        ('127.0.0.1', '1.1.1.1', ProtoL3IP4, True),
        ('::1', '::1', ProtoL3IP6, True),
        ('2003::2', '2003::1', ProtoL3IP4, False),
        ('192.168.0.1', '10.255.255.49', ProtoL3IP6, False),
        ('192.168.0.1', '10.255.255.49', ProtoL3IP4IP6, True),
        ('2003::2', '2003::1', ProtoL3IP4IP6, True),
    ]
)
def test_firewall_packet_matching_table(src, dst, ipp, matching):
    from simulator.packet import PacketIP
    from simulator.firewall import Firewall
    from plugins.translate.abstract import Table
    from plugins.system.system_linux_netfilter import SystemLinuxNetfilter
    from plugins.translate.netfilter.ruleset import NetfilterRuleset

    ruleset = NetfilterRuleset(TESTDATA_RULESET).get()
    fw = Firewall(
        system=SystemLinuxNetfilter,
        ruleset=ruleset,
    )
    packet = PacketIP(src=src, dst=dst)
    table = Table(name='test', chains=[], family=ipp)
    assert fw._run_tables._is_matching_table(packet=packet, table=table) == matching


@pytest.mark.parametrize(
    'src,dst,ipp,matching',
    [
        ('127.0.0.1', '1.1.1.1', ProtoL3IP4, True),
        ('::1', '::1', ProtoL3IP6, True),
        ('2003::2', '2003::1', ProtoL3IP4, False),
        ('192.168.0.1', '10.255.255.49', ProtoL3IP6, False),
        ('192.168.0.1', '10.255.255.49', ProtoL3IP4IP6, True),
        ('2003::2', '2003::1', ProtoL3IP4IP6, True),
    ]
)
def test_firewall_packet_matching_chain(src, dst, ipp, matching):
    from simulator.packet import PacketIP
    from simulator.firewall import Firewall
    from plugins.system.system_linux_netfilter import SystemLinuxNetfilter
    from plugins.translate.netfilter.ruleset import NetfilterRuleset, NetfilterChainOutput as Chain

    ruleset = NetfilterRuleset(TESTDATA_RULESET).get()
    fw = Firewall(
        system=SystemLinuxNetfilter,
        ruleset=ruleset,
    )
    packet = PacketIP(src=src, dst=dst)
    chain = Chain(name='test', rules=[], family=ipp, policy=Chain.POLICY_ACCEPT, hook='input')
    assert fw._run_tables._is_matching_chain(packet=packet, chain=chain) == matching


def test_firewall_sort_tables_by_priority():
    from simulator.firewall import Firewall
    from plugins.translate.abstract import Table
    from plugins.system.system_linux_netfilter import SystemLinuxNetfilter
    from plugins.translate.netfilter.ruleset import NetfilterRuleset

    ruleset = NetfilterRuleset(TESTDATA_RULESET).get()
    fw = Firewall(
        system=SystemLinuxNetfilter,
        ruleset=ruleset,
    )
    tables = [
        Table(name='c', chains=[], family=ProtoL3IP4, priority=1),
        Table(name='e', chains=[], family=ProtoL3IP4, priority=100),
        Table(name='a', chains=[], family=ProtoL3IP4, priority=-10),
        Table(name='d', chains=[], family=ProtoL3IP4, priority=20),
        Table(name='b', chains=[], family=ProtoL3IP4),
    ]

    sorted_tables = fw._run_tables._sort_tables_by_priority(tables)

    assert tables != sorted_tables
    assert len(tables) == len(sorted_tables)
    assert [t.name for t in sorted_tables] == ['a', 'b', 'c', 'd', 'e']


def test_firewall_sort_chains_by_hook_and_priority():
    from simulator.firewall import Firewall
    from plugins.system.system_linux_netfilter import SystemLinuxNetfilter
    from plugins.translate.netfilter.ruleset import NetfilterRuleset, NetfilterChainOutput as Chain

    ruleset = NetfilterRuleset(TESTDATA_RULESET).get()
    fw = Firewall(
        system=SystemLinuxNetfilter,
        ruleset=ruleset,
    )
    chains = [
        Chain(name='0b', rules=[], family=ProtoL3IP4, policy=Chain.POLICY_ACCEPT, hook='prerouting'),
        Chain(name='0a', rules=[], family=ProtoL3IP4, priority=-100, policy=Chain.POLICY_ACCEPT, hook='prerouting'),
        Chain(name='1c', rules=[], family=ProtoL3IP4, priority=1, policy=Chain.POLICY_ACCEPT, hook='input'),
        Chain(name='1e', rules=[], family=ProtoL3IP4, priority=100, policy=Chain.POLICY_ACCEPT, hook='input'),
        Chain(name='1a', rules=[], family=ProtoL3IP4, priority=-10, policy=Chain.POLICY_ACCEPT, hook='input'),
        Chain(name='1d', rules=[], family=ProtoL3IP4, priority=20, policy=Chain.POLICY_ACCEPT, hook='input'),
        Chain(name='1b', rules=[], family=ProtoL3IP4, policy=Chain.POLICY_ACCEPT, hook='input'),
        Chain(name='2a', rules=[], family=ProtoL3IP4, policy=Chain.POLICY_ACCEPT, hook='postrouting'),
        Chain(name='2b', rules=[], family=ProtoL3IP4, priority=100, policy=Chain.POLICY_ACCEPT, hook='postrouting'),
    ]

    sorted_chains = fw._run_tables._sort_chains_by_hook_and_priority(chains)

    assert chains != sorted_chains
    assert len(chains) == len(sorted_chains)
    assert [t.name for t in sorted_chains] == [
        '0a', '0b',
        '1a', '1b', '1c', '1d', '1e',
        '2a', '2b',
    ]



@pytest.mark.parametrize(
    'compare_hook,compare_prio,chain_hook,chain_prio,result',
    [
        ('input', 0, 'ingress', 0, True),
        ('prerouting', -100, 'ingress', 0, True),
        ('input', 0, 'prerouting', 0, True),
        ('input', 0, 'input', -1, True),
        ('input', 0, 'input', 0, True),
        ('input', 0, 'output', 0, False),
        ('input', 0, 'postrouting', 0, False),
        ('input', 0, 'egress', 0, False),
        ('input', 0, None, 0, False),
    ]
)
def test_firewall_chain_before_eq_after(compare_hook, compare_prio, chain_hook, chain_prio, result):
    from simulator.firewall import Firewall
    from plugins.system.system_linux_netfilter import SystemLinuxNetfilter
    from plugins.translate.netfilter.ruleset import NetfilterRuleset, NetfilterChainOutput as Chain

    ruleset = NetfilterRuleset(TESTDATA_RULESET).get()
    fw = Firewall(
        system=SystemLinuxNetfilter,
        ruleset=ruleset,
    )
    chain = Chain(
        name='test', rules=[], family=ProtoL3IP4, policy=Chain.POLICY_ACCEPT,
        hook=chain_hook, priority=chain_prio,
    )
    is_before_eq = fw._run_tables._is_chain_before_eq(chain=chain, hook=compare_hook, priority=compare_prio)
    is_after = fw._run_tables._is_chain_after(chain=chain, hook=compare_hook, priority=compare_prio)

    if chain_hook is not None:
        assert is_before_eq == result
        assert is_after != result

    else:
        assert not is_before_eq
        assert not is_after


@pytest.mark.parametrize(
    'hook,flow,result',
    [
        ('input', FlowInput, True),
        ('prerouting', FlowInput, True),
        ('prerouting', FlowForward, True),
        ('prerouting', FlowOutput, False),
        ('output', FlowOutput, True),
        ('output', FlowForward, False),
        ('output', FlowInput, False),
        ('postrouting', FlowInput, False),
        ('postrouting', FlowForward, True),
        ('postrouting', FlowOutput, True),
    ]
)
def test_firewall_chain_in_flow(hook, flow, result):
    from simulator.firewall import Firewall
    from plugins.system.system_linux_netfilter import SystemLinuxNetfilter
    from plugins.translate.netfilter.ruleset import NetfilterRuleset, NetfilterChainOutput as Chain

    ruleset = NetfilterRuleset(TESTDATA_RULESET).get()
    fw = Firewall(
        system=SystemLinuxNetfilter,
        ruleset=ruleset,
    )
    chain = Chain(name='test', rules=[], family=ProtoL3IP4, policy=Chain.POLICY_ACCEPT, hook=hook)
    assert fw._run_tables._is_chain_in_flow(chain=chain, flow=flow) == result


@pytest.mark.parametrize(
    'prio_table,prio_chain,result',
    [
        (0, 0, 0),
        (None, None, None),
        (None, 0, 0),
        (0, 1, 1),
        (1, 10, 11),
        (-1, -1, -2),
    ]
)
def test_firewall_inherit_table_priority_chain(prio_table, prio_chain, result):
    from simulator.firewall import Firewall
    from plugins.translate.abstract import Table
    from plugins.system.system_linux_netfilter import SystemLinuxNetfilter
    from plugins.translate.netfilter.ruleset import NetfilterRuleset, NetfilterChainOutput as Chain

    ruleset = NetfilterRuleset(TESTDATA_RULESET).get()
    fw = Firewall(
        system=SystemLinuxNetfilter,
        ruleset=ruleset,
    )
    table = Table(name='test', chains=[], family=ProtoL3IP4, priority=prio_table)
    chain = Chain(name='test', rules=[], family=ProtoL3IP4, policy=Chain.POLICY_ACCEPT, hook='input', priority=prio_chain)

    fw._run_tables._inherit_table_priority_to_chain(table=table, chain=chain)
    assert chain.priority == result

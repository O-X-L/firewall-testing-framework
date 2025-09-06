import pytest

from testdata_test import TESTDATA_FILE_NF_RULESET
from config import ProtoL3IP4, ProtoL3IP6  # RuleActionAccept, RuleActionDrop, RuleActionReject, RuleActionSNAT
from simulator.firewall import Firewall

with open(TESTDATA_FILE_NF_RULESET, 'r', encoding='utf-8') as f:
    TESTDATA_RULESET = f.read()


def _init_test() -> Firewall:
    from plugins.system.system_linux_netfilter import SystemLinuxNetfilter
    from plugins.translate.netfilter.ruleset import NetfilterRuleset
    from simulator.firewall import Firewall

    ruleset = NetfilterRuleset(TESTDATA_RULESET).get()
    return Firewall(
        system=SystemLinuxNetfilter,
        ruleset=ruleset,
    )


@pytest.mark.parametrize(
    'src,dst,table_name,ipp,is_none',
    [
        ('192.168.0.10', '1.1.1.1', 'main', ProtoL3IP4, False),
        ('192.168.0.10', '1.1.1.1', 'main', ProtoL3IP6, True),
        ('192.168.0.10', '1.1.1.1', 'early', ProtoL3IP4, False),
        ('::1', '2003::2', 'main', ProtoL3IP6, False),
        ('::1', '2003::2', 'main', ProtoL3IP4, True),
    ]
)
def test_firewall_chain_by_name_and_family(src, dst, table_name, ipp, is_none):
    from simulator.packet import PacketIP
    from simulator.firewall import Firewall
    from plugins.translate.abstract import Table, Ruleset
    from plugins.system.system_linux_netfilter import SystemLinuxNetfilter
    from plugins.translate.netfilter.ruleset import NetfilterChainOutput as Chain

    table_early = Table(
        name='early',
        priority=-1,
        chains=[
            Chain(name='input', hook='input', policy=Chain.POLICY_ACCEPT, family=ProtoL3IP4, rules=[]),
            Chain(name='input', hook='input', policy=Chain.POLICY_ACCEPT, family=ProtoL3IP6, rules=[]),
        ],
    )
    table_main = Table(
        name='main',
        chains=[
            Chain(name='input', hook='input', policy=Chain.POLICY_DROP, family=ProtoL3IP4, rules=[]),
            Chain(name='input', hook='input', policy=Chain.POLICY_DROP, family=ProtoL3IP6, rules=[]),
            Chain(name='input', hook='input', policy=Chain.POLICY_DROP, rules=[]),
        ],
    )

    fw = Firewall(
        system=SystemLinuxNetfilter,
        ruleset=Ruleset(tables=[table_early, table_main]),
    )
    packet = PacketIP(src=src, dst=dst)
    table = None
    for t in fw.ruleset.tables:
        if t.name == table_name:
            table = t

        for c in t.chains:
            c.run_table = t

    c = fw._run_tables._run_chains._get_chain_by_name_and_family(
        packet=packet,
        name='input',
        family=ipp,
        table=table,
    )
    if is_none:
        assert c is None

    else:
        assert c is not None
        assert c.name == 'input'
        assert c.hook == 'input'
        assert c.family == ipp
        assert c.run_table.name == table_name


# todo: test multiple testdata-rulesets for edge-case handling (RunFirewallChain.process)
#   sub-chain (jump) terminal action should end hook
#   sub-chain (goto) should end parent chain
#   dnat
#   snat
#   masquerade
#   action return
#   action continue (?)
#   lazy action
#   lazy action mixed with 'quick' action
#   chain default-policy


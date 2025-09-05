import pytest

from testdata_test import TESTDATA_FILE_NF_RULESET
from config import ProtoL3IP4, ProtoL3IP4IP6, ProtoL3IP6, FlowInput, FlowOutput, FlowForward

with open(TESTDATA_FILE_NF_RULESET, 'r', encoding='utf-8') as f:
    TESTDATA_RULESET = f.read()



def test_firewall_chains_basic():
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
    # packet = PacketIP(src=src, dst=dst)
    # table = Table(name='test', chains=[], family=ipp)
    # assert fw._run_tables._is_matching_table(packet=packet, table=table) == matching

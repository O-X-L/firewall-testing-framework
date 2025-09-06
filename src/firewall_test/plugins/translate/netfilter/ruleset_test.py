from testdata_test import TESTDATA_FILE_NF_RULESET

with open(TESTDATA_FILE_NF_RULESET, 'r', encoding='utf-8') as f:
    TESTDATA_RULESET = f.read()


def test_nf_ruleset():
    from config import ProtoL3IP4, ProtoL3IP6, RuleActionReturn, RuleActionDrop
    from plugins.translate.netfilter.ruleset import NetfilterRuleset
    from plugins.translate.abstract import Ruleset
    from plugins.translate.netfilter.ruleset import NftRule

    nf = NetfilterRuleset(TESTDATA_RULESET)
    r = nf.get()

    assert isinstance(r, Ruleset)
    r.validate()
    assert len(r.tables) == 4
    r.tables[0].validate()
    assert r.tables[0].name == 'nat'
    assert r.tables[0].family == ProtoL3IP4
    assert r.tables[1].name == 'filter'
    assert r.tables[1].family == ProtoL3IP4
    assert r.tables[2].name == 'nat'
    assert r.tables[2].family == ProtoL3IP6
    assert r.tables[3].name == 'filter'
    assert r.tables[3].family == ProtoL3IP6

    assert len(r.tables[0].chains) == 4
    chain = r.tables[0].chains[0]
    chain.validate()

    assert len(r.tables[1].chains) == 8
    assert len(r.tables[2].chains) == 3
    assert len(r.tables[3].chains) == 9

    assert len(chain.rules) == 2
    rule = chain.rules[0]
    rule.validate()
    assert rule.seq == 0
    assert rule.action == RuleActionReturn
    assert isinstance(rule.raw, NftRule)

    rule = chain.rules[1]
    assert rule.seq == 1
    assert rule.action == RuleActionDrop
    assert isinstance(rule.raw, NftRule)

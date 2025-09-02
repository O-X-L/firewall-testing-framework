from testdata_test import TESTDATA_FILE_NF_RULESET

with open(TESTDATA_FILE_NF_RULESET, 'r', encoding='utf-8') as f:
    TESTDATA_RULESET = f.read()


def test_nf_ruleset():
    from plugins.translate.netfilter.ruleset import NetfilterRuleset
    from plugins.translate.abstract import Ruleset, Table, Chain, Rule

    nf = NetfilterRuleset(TESTDATA_RULESET)
    r = nf.get()

    assert isinstance(r, Ruleset)
    assert len(r.tables) == 4
    assert isinstance(r.tables[0], Table)
    assert r.tables[0].name == 'nat'
    assert r.tables[0].family == 'ip4'
    assert r.tables[1].name == 'filter'
    assert r.tables[1].family == 'ip4'
    assert r.tables[2].name == 'nat'
    assert r.tables[2].family == 'ip6'
    assert r.tables[3].name == 'filter'
    assert r.tables[3].family == 'ip6'

    assert len(r.tables[0].chains) == 4
    assert isinstance(r.tables[0].chains[0], Chain)

    assert len(r.tables[1].chains) == 8
    assert len(r.tables[2].chains) == 3
    assert len(r.tables[3].chains) == 8

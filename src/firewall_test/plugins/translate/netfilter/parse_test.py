from testdata_test import TESTDATA_FILE_NF_RULESET

with open(TESTDATA_FILE_NF_RULESET, 'r', encoding='utf-8') as f:
    TESTDATA_RULESET = f.read()


def test_nf_parse():
    from plugins.translate.netfilter.parse import NetfilterPreParse

    nf = NetfilterPreParse(TESTDATA_RULESET)

    assert len(nf.tables) == 4
    assert nf.tables[0].name == 'nat'
    assert nf.tables[0].family == 'ip'
    assert nf.tables[1].name == 'filter'
    assert nf.tables[1].family == 'ip'
    assert nf.tables[2].name == 'nat'
    assert nf.tables[2].family == 'ip6'
    assert nf.tables[3].name == 'filter'
    assert nf.tables[3].family == 'ip6'

    assert len(nf.chains) == 24

    assert nf.chains[0].name == 'DOCKER'
    assert nf.chains[0].table.name == 'nat'
    assert nf.chains[0].family == 'ip'
    assert nf.chains[0].family == nf.chains[0].table.family
    assert nf.chains[0].hook is None

    assert nf.chains[5].name == 'DOCKER-FORWARD'
    assert nf.chains[5].table.name == 'filter'
    assert nf.chains[5].family == 'ip' == nf.chains[5].table.family
    assert nf.chains[5].hook is None

    assert nf.chains[10].name == 'FORWARD'
    assert nf.chains[10].table.name == 'filter'
    assert nf.chains[10].family == 'ip' == nf.chains[10].table.family
    assert nf.chains[10].hook == 'forward'

    assert nf.chains[15].name == 'OUTPUT'
    assert nf.chains[15].table.name == 'nat'
    assert nf.chains[15].family == 'ip6' == nf.chains[15].table.family
    assert nf.chains[15].hook == 'output'

    assert nf.chains[20].name == 'DOCKER-ISOLATION-STAGE-1'
    assert nf.chains[20].table.name == 'filter'
    assert nf.chains[20].family == 'ip6' == nf.chains[20].table.family
    assert nf.chains[20].hook is None

    assert len(nf.rules) == 30

    assert nf.rules[0].table.name == 'nat'
    assert nf.rules[0].chain.name == 'DOCKER'
    assert nf.rules[0].chain.hook is None
    assert nf.rules[0].family == 'ip' == nf.rules[0].table.family == nf.rules[0].chain.family
    assert nf.rules[0].action == 'return'
    assert nf.rules[0].seq == 0
    assert len(nf.rules[0].matches) == 1
    assert nf.rules[0].matches[0].match_ni_in is True
    assert nf.rules[0].matches[0].operator == '=='
    assert nf.rules[0].matches[0].value == ['docker0']

    assert nf.rules[10].table.name == 'filter'
    assert nf.rules[10].chain.name == 'DOCKER-CT'
    assert nf.rules[10].chain.hook is None
    assert nf.rules[10].family == 'ip' == nf.rules[0].table.family == nf.rules[0].chain.family
    assert nf.rules[10].action == 'accept'
    assert nf.rules[10].seq == 0
    assert len(nf.rules[10].matches) == 1
    assert nf.rules[10].matches[0].match_ni_out is True
    assert nf.rules[10].matches[0].operator == '=='
    assert nf.rules[10].matches[0].value == ['docker0']

    fwd_rules = []
    for r in nf.rules:
        if r.chain.family == 'ip6' and r.chain.name == 'FORWARD':
            fwd_rules.append(r)

    assert len(fwd_rules) == 5
    assert fwd_rules[0].seq == 0
    assert fwd_rules[1].seq == 1


# todo: add tests for many possible real-life rule-expression-combinations to catch edge-cases

from testdata_test import TESTDATA_FILE_NF_RULESET

with open(TESTDATA_FILE_NF_RULESET, 'r', encoding='utf-8') as f:
    TESTDATA_RULESET = f.read()


def test_nf_parse():
    from plugins.translate.netfilter.parse import NFT

    nft = NFT(TESTDATA_RULESET)

    assert len(nft.tables) == 4
    assert nft.tables[0].name == 'nat'
    assert nft.tables[0].family == 'ip'
    assert nft.tables[1].name == 'filter'
    assert nft.tables[1].family == 'ip'
    assert nft.tables[2].name == 'nat'
    assert nft.tables[2].family == 'ip6'
    assert nft.tables[3].name == 'filter'
    assert nft.tables[3].family == 'ip6'

    assert len(nft.chains) == 23

    assert nft.chains[0].name == 'DOCKER'
    assert nft.chains[0].table.name == 'nat'
    assert nft.chains[0].family == 'ip'
    assert nft.chains[0].family == nft.chains[0].table.family
    assert nft.chains[0].hook is None

    assert nft.chains[5].name == 'DOCKER-FORWARD'
    assert nft.chains[5].table.name == 'filter'
    assert nft.chains[5].family == 'ip' == nft.chains[5].table.family
    assert nft.chains[5].hook is None

    assert nft.chains[10].name == 'FORWARD'
    assert nft.chains[10].table.name == 'filter'
    assert nft.chains[10].family == 'ip' == nft.chains[10].table.family
    assert nft.chains[10].hook == 'forward'

    assert nft.chains[15].name == 'DOCKER'
    assert nft.chains[15].table.name == 'filter'
    assert nft.chains[15].family == 'ip6' == nft.chains[15].table.family
    assert nft.chains[15].hook is None

    assert nft.chains[20].name == 'DOCKER-ISOLATION-STAGE-2'
    assert nft.chains[20].table.name == 'filter'
    assert nft.chains[20].family == 'ip6' == nft.chains[20].table.family
    assert nft.chains[20].hook is None

    assert len(nft.rules) == 24

    assert nft.rules[0].table.name == 'nat'
    assert nft.rules[0].chain.name == 'DOCKER'
    assert nft.rules[0].chain.hook is None
    assert nft.rules[0].family == 'ip' == nft.rules[0].table.family == nft.rules[0].chain.family
    assert nft.rules[0].action == 'return'
    assert len(nft.rules[0].matches) == 1
    assert nft.rules[0].matches[0].match == 'iifname'
    assert nft.rules[0].matches[0].operator == '=='
    assert nft.rules[0].matches[0].value == 'docker0'

    assert nft.rules[10].table.name == 'filter'
    assert nft.rules[10].chain.name == 'DOCKER-CT'
    assert nft.rules[10].chain.hook is None
    assert nft.rules[10].family == 'ip' == nft.rules[0].table.family == nft.rules[0].chain.family
    assert nft.rules[10].action == 'accept'
    assert len(nft.rules[10].matches) == 1
    assert nft.rules[10].matches[0].match == 'oifname'
    assert nft.rules[10].matches[0].operator == '=='
    assert nft.rules[10].matches[0].value == 'docker0'

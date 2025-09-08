from ipaddress import IPv4Network, IPv6Network, ip_network
from testdata_test import TESTDATA_FILE_OPN_CONFIG

from config import RuleActionDrop, RuleActionAccept

with open(TESTDATA_FILE_OPN_CONFIG, 'r', encoding='utf-8') as f:
    TESTDATA_OPN_CNF = f.read()


def test_opnsense_ruleset():
    from plugins.translate.opnsense.ruleset import OPNsenseRuleset

    r = OPNsenseRuleset(TESTDATA_OPN_CNF)
    o = r.get()

    o.validate()
    assert len(o.tables) == 1

    table = o.tables[0]
    table.validate()

    assert len(table.chains) == 5
    for c in table.chains:
        c.validate()

    assert len(r.aliases) == 73  # todo: find missing 1 alias!
    assert len(r.aliases['HOST_DNS_TRUSTED_REPOS']) > 0
    for e in r.aliases['HOST_DNS_TRUSTED_REPOS']:
        assert isinstance(e, (IPv4Network, IPv6Network))

    assert len(r.aliases['IPLIST_SpamHaus_DROP']) > 0
    for e in r.aliases['IPLIST_SpamHaus_DROP']:
        assert isinstance(e, (IPv4Network, IPv6Network))

    assert len(r.ni_grp) == 1
    assert 'GRP_MAIL' in r.ni_grp
    assert r.ni_grp['GRP_MAIL'] == ['lan']

    assert len(r.local_ips) == 15
    assert ip_network('10.34.28.254/32') in r.local_ips
    assert ip_network('169.169.169.5/32') in r.local_ips

    assert len(r.nis_nets) == 12
    assert r.nis_nets['lan'] == [ip_network('10.34.28.0/24')]
    assert r.nis_nets['opt5'] == [
        ip_network('169.169.169.0/28'),
        ip_network('2a01:beef:beef:f5::/64')
    ]

    assert len(r.nis_ips) == 12
    assert r.nis_ips['lan'] == [ip_network('10.34.28.251/32')]
    assert r.nis_ips['opt5'] == [
        ip_network('169.169.169.4/32'),
        ip_network('2a01:beef:beef:f5::1:1/128')
    ]

    assert len(r.chain_dnat.rules) == 0
    assert len(r.chain_floating.rules) == 17
    assert len(r.chain_ni_grp.rules) == 7
    assert len(r.chain_ni.rules) == 87
    assert len(r.chain_snat.rules) == 0

    # todo: validate that matches are correct..
    r1 = r.chain_floating.rules[1]
    assert r1.seq == 2
    assert r1.action == RuleActionDrop
    assert r1.raw.get_match_types() == ['proto_l3', 'ip_saddr']

    r2 = r.chain_ni_grp.rules[4]
    assert r2.seq == 5
    assert r2.action == RuleActionAccept
    assert r2.raw.get_match_types() == ['proto_l3', 'proto_l4', 'ip_saddr', 'ip_daddr', 'dst-port']

    r3 = r.chain_ni.rules[42]
    assert r3.seq == 43
    assert r3.action == RuleActionAccept
    assert r3.raw.get_match_types() == ['proto_l3', 'proto_l4', 'ip_saddr', 'ip_daddr', 'dst-port']

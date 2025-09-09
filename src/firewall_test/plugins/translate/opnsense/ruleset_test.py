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

    assert len(r.aliases) == 72  # todo: find missing 1 alias!
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
    assert len(r.chain_floating.rules) == 15
    assert len(r.chain_ni_grp.rules) == 8
    assert len(r.chain_ni.rules) == 82
    assert len(r.chain_snat.rules) == 0

    # todo: mock external responses (IPLists, DNS-resolution) for stable tests
    # todo: validate that matches are correct..

    # drop any traffic to blacklisted targets (dst = iplist/urltable)
    r1 = r.chain_floating.rules[1]
    assert r1.seq == 2
    assert r1.action == RuleActionDrop
    m = r1.raw.get_matches()
    assert 'ip_daddr' in m
    assert '==' in m['ip_daddr']
    assert len(m['ip_daddr']['==']) > 10  # IP-List content
    assert 'ip_saddr' in m
    assert '==' in m['ip_saddr'] and m['ip_saddr']['=='] == 'any'
    assert 'proto_l3' in m
    assert m['proto_l3'] == 'ip4'

    # allow some server to sync with external pop3s
    r2 = r.chain_ni_grp.rules[4]
    assert r2.seq == 5
    assert r2.action == RuleActionAccept
    m = r2.raw.get_matches()
    for e in ['dst_port', 'ip_daddr', 'ip_saddr', 'proto_l3', 'proto_l4']:
        assert e in m

    assert m['dst_port'] == [993]
    assert '!=' in m['ip_daddr']
    assert m['ip_daddr']['!='] == [
        '10.38.0.0/16',
        '10.0.0.0/8',
        '172.16.0.0/12',
    ]
    assert '==' in m['ip_saddr']
    assert m['ip_saddr']['=='] == ['10.34.28.206/32']
    assert m['proto_l3'] == 'ip4'
    assert m['proto_l4'] == ['tcp']

    # allow some internal hosts http+s to an external service via DNS
    r3 = r.chain_ni.rules[42]
    assert r3.seq == 44
    assert r3.action == RuleActionAccept
    m = r3.raw.get_matches()
    for e in ['dst_port', 'ip_daddr', 'ip_saddr', 'proto_l3', 'proto_l4']:
        assert e in m

    assert m['dst_port'] == [80, 443]
    assert '==' in m['ip_daddr']
    assert len(m['ip_daddr']['==']) > 10  # DNS-resolved alias
    assert '==' in m['ip_saddr']
    assert m['ip_saddr']['=='] == [
        '10.38.13.201/32',
        '10.34.28.101/32',
    ]
    assert m['proto_l3'] == 'ip4'
    assert m['proto_l4'] == ['tcp']


# todo: add tests for many possible real-life rule-expression-combinations to catch edge-cases

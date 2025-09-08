from testdata_test import TESTDATA_FILE_OPN_NETWORK

with open(TESTDATA_FILE_OPN_NETWORK, 'r', encoding='utf-8') as f:
    TESTDATA_OPN_NET = f.read()


def test_opnsense_nis():
    from plugins.translate.opnsense.interfaces import OPNsenseNetworkInterfaces

    nis = OPNsenseNetworkInterfaces(TESTDATA_OPN_NET).get()

    assert len(nis) == 9

    for ni in OPNsenseNetworkInterfaces(TESTDATA_OPN_NET).get():
        ni.validate()

        if ni.name == 'lo0':
            assert ni.up
            assert [str(ip) for ip in ni.ip4] == ['127.0.0.1']
            assert [str(ip) for ip in ni.ip6] == ['::1', 'fe80::1']
            assert [str(ip) for ip in ni.net4] == ['127.0.0.0/8']
            assert [str(ip) for ip in ni.net6] == ['fe80::/64']

        elif ni.name == 'lan':
            assert ni.up
            assert [str(ip) for ip in ni.ip4] == ['10.34.28.251', '10.34.28.254']
            assert [str(ip) for ip in ni.ip6] == ['fe80::fccb:e4ff:fea2:1b58']
            assert [str(ip) for ip in ni.net4] == ['10.34.28.0/24']
            assert [str(ip) for ip in ni.net6] == ['fe80::/64']

        elif ni.name == 'opt5':
            assert ni.up
            assert ni.desc == 'WAN2'
            is_ips = [str(ip) for ip in ni.ip4]
            is_ips.sort()
            want_ips = [
                '169.169.169.4', '169.169.169.5', '169.169.169.6', '169.169.169.7', '169.169.169.8'
            ]
            want_ips.sort()
            assert is_ips == want_ips

            is_ips = [str(ip) for ip in ni.ip6]
            is_ips.sort()
            want_ips = [
                '2a01:beef:beef:f5::1:1',
                '2a01:beef:beef:f5::10:1',
                '2a01:beef:beef:f5::10:115',
                'fe80::be24:11ff:feec:247c',
            ]
            want_ips.sort()
            assert is_ips == want_ips

            assert [str(ip) for ip in ni.net4] == ['169.169.169.0/28']
            assert [str(ip) for ip in ni.net6] == ['2a01:beef:beef:f5::/64', 'fe80::/64']

        elif ni.name == 'wan':
            assert not ni.up
            assert len(ni.ip4) == 0
            assert [str(ip) for ip in ni.ip6] == ['fe80::250:56ff:fe00:c384']
            assert len(ni.net4) == 0
            assert [str(ip) for ip in ni.net6] == ['fe80::/64']
            assert ni.mac == '00:50:56:00:c3:84'

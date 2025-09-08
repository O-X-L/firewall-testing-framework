from testdata_test import TESTDATA_FILE_NIS, TEST_WAN_IP4, TEST_WAN_IP6

with open(TESTDATA_FILE_NIS, 'r', encoding='utf-8') as f:
    TESTDATA_NICS = f.read()


def test_linux_nis():
    from plugins.translate.linux import LinuxNetworkInterfaces

    nis = LinuxNetworkInterfaces(TESTDATA_NICS).get()

    assert len(nis) == 4

    for ni in nis:
        ni.validate()

        if ni.name == 'lo':
            assert ni.up
            assert [str(ip) for ip in ni.ip4] == ['127.0.0.1']
            assert [str(ip) for ip in ni.ip6] == ['::1']
            assert [str(ip) for ip in ni.net4] == ['127.0.0.0/8']
            assert len(ni.net6) == 0

        elif ni.name == 'enp0s31f6':
            assert not ni.up
            assert len(ni.ip4) == 0
            assert len(ni.ip6) == 0
            assert len(ni.net4) == 0
            assert len(ni.net6) == 0

        elif ni.name == 'wan':
            assert ni.up
            assert [str(ip) for ip in ni.ip4] == [TEST_WAN_IP4]
            assert [str(ip) for ip in ni.ip6] == [TEST_WAN_IP6, 'fe80::a0d:5eeb:c78:aba7']
            assert [str(ip) for ip in ni.net4] == ['10.255.255.0/24']
            assert [str(ip) for ip in ni.net6] == ['fe80::/64']
            assert ni.mac == 'a0:59:aa:15:4e:0b'

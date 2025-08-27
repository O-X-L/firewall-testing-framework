import pytest


def test_packet_ip():
    from simulator.packet import PacketIP

    p = PacketIP(
        src='10.0.0.1',
        dst='10.0.0.2',
        l3_proto='ip4',
    )
    p.validate()


@pytest.mark.parametrize(
    'src,dst,ipp',
    [
        ('10.0.0.1', '2003::2', 'ip4'),
        ('2003::2', '10.0.0.1', 'ip4'),
        ('10.0.0.1', '2003::2', 'ip6'),
        ('2003::2', '10.0.0.1', 'ip6'),
        ('2003::2', '2001::2', 'ip4'),
        ('192.168.0.1', '10.0.0.1', 'ip6'),
    ]
)
def test_packet_invalid_ipp(src: str, dst: str, ipp: str):
    from simulator.packet import PacketIP

    with pytest.raises(AssertionError):
        PacketIP(src=src, dst=dst, l3_proto=ipp).validate()


def test_packet_tcp_udp():
    from simulator.packet import PacketTCPUDP

    p = PacketTCPUDP(
        src='10.0.0.1',
        dst='10.0.0.2',
        l3_proto='ip4',
        l4_proto='tcp',
    )
    p.validate()
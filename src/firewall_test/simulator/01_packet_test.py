import pytest


def test_packet_ip():
    from simulator.packet import PacketIP

    p = PacketIP(
        src='10.0.0.1',
        dst='10.0.0.2',
    )
    p.validate()


@pytest.mark.parametrize(
    'src,dst',
    [
        ('10.0.0.1', '2003::2'),
        ('2003::2', '10.0.0.1'),
        ('10.0.0.1', '2003::2'),
        ('2003::2', '10.0.0.1'),
    ]
)
def test_packet_invalid_ipp(src: str, dst: str):
    from simulator.packet import PacketIP

    with pytest.raises(AssertionError):
        PacketIP(src=src, dst=dst).validate()


def test_packet_tcp_udp():
    from simulator.packet import PacketTCPUDP

    p = PacketTCPUDP(
        src='10.0.0.1',
        dst='10.0.0.2',
        proto_l4='tcp',
    )
    p.validate()


def test_packet_icmp():
    from simulator.packet import PacketICMP

    p = PacketICMP(
        src='10.0.0.1',
        dst='10.0.0.2',
    )
    p.validate()

    p = PacketICMP(
        src='10.0.0.1',
        dst='10.0.0.2',
    )
    p.validate()

from ipaddress import ip_address, IPv4Address, IPv6Address

from config import PROTO_L3_IP4, PROTO_L3_IP6


class Packet:
    def __init__(self):
        self.ni_in = None
        self.ni_out = None

    def dump(self) -> dict:
        return {
            'ni_in': self.ni_in,
            'ni_out': self.ni_out,
        }


class PacketIP(Packet):
    def __init__(self, src: str, dst: str):
        super().__init__()
        self.src = ip_address(src)
        self.dst = ip_address(dst)
        self.pre_nat_src = ip_address(src)
        self.pre_nat_dst = ip_address(dst)

    @property
    def l3_proto(self) -> str:
        if isinstance(self.src, IPv6Address):
            return PROTO_L3_IP6

        return PROTO_L3_IP4

    def validate(self):
        assert self.l3_proto in [PROTO_L3_IP4, PROTO_L3_IP6]
        if self.l3_proto == PROTO_L3_IP4:
            assert isinstance(self.src, IPv4Address)
            assert isinstance(self.dst, IPv4Address)

        else:
            assert isinstance(self.src, IPv6Address)
            assert isinstance(self.dst, IPv6Address)

    def dump(self) -> dict:
        return {
            **super().dump(),
            'src': self.src,
            'dst': self.dst,
            'pre_nat_src': None if self.src == self.pre_nat_src else self.pre_nat_src,
            'pre_nat_dst': None if self.dst == self.pre_nat_dst else self.pre_nat_dst,
            'l3_proto': self.l3_proto,
        }


class PacketTCPUDP(PacketIP):
    def __init__(
            self, src: str, dst: str, l4_proto: str, l4_dport: int = None, l4_sport: int = None,
    ):
        super().__init__(src=src, dst=dst)
        self.l4_proto = l4_proto.lower()
        self.l4_dport = l4_dport
        self.l4_sport = l4_sport

        if l4_dport is None:
            if l4_proto == 'tcp':
                self.l4_dport = 443

            else:
                self.l4_dport = 53

        if l4_sport is None:
            self.l4_sport = 50_000

    def validate(self):
        super().validate()
        assert self.l4_proto in ['tcp', 'udp']
        assert isinstance(self.l4_dport, int)
        assert isinstance(self.l4_sport, int)
        assert 0 <= self.l4_dport <= 65535
        assert 0 <= self.l4_sport <= 65535

    def dump(self) -> dict:
        return {
            **super().dump(),
            'l4_proto': self.l4_proto,
            'l4_dport': self.l4_dport,
            'l4_sport': self.l4_sport,
        }


class PacketICMP(PacketIP):
    CODE_ECHO_REPLY = 0
    CODE_ECHO_REQUEST = 8

    CODE6_ECHO_REPLY = 0
    CODE6_ECHO_REQUEST = 128

    def __init__(
            self, src: str, dst: str, l4_proto: str, icmp_code: int = None,
    ):
        super().__init__(src=src, dst=dst)
        self.l4_proto = l4_proto.lower()
        self.icmp_code = icmp_code
        if icmp_code is None:
            if self.l4_proto == 'icmp':
                self.icmp_code = self.CODE_ECHO_REQUEST

            else:
                self.icmp_code = self.CODE6_ECHO_REQUEST

    def validate(self):
        super().validate()
        assert self.l4_proto in ['icmp', 'icmpv6']
        assert isinstance(self.icmp_code, int)
        assert -1 < self.icmp_code < 256

    def dump(self) -> dict:
        return {
            **super().dump(),
            'l4_proto': self.l4_proto,
            'icmp_code': self.icmp_code,
        }

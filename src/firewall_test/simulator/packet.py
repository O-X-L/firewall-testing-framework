from ipaddress import ip_address, IPv4Address, IPv6Address

from config import ProtoL3IP4, ProtoL3IP6, ProtoL3, PROTO_L4_MAPPING, ProtoL4ICMP


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
    def proto_l3(self) -> type[ProtoL3]:
        if isinstance(self.src, IPv6Address):
            return ProtoL3IP6

        return ProtoL3IP4

    def validate(self):
        assert self.proto_l3 in [ProtoL3IP4, ProtoL3IP6]
        if self.proto_l3 == ProtoL3IP4:
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
            'proto_l3': self.proto_l3.N,
        }

    def dnat_str(self) -> str:
        return f'{self.pre_nat_dst} => {self.dst}'

    def snat_str(self) -> str:
        return f'{self.pre_nat_src} => {self.src}'


class PacketTCPUDP(PacketIP):
    def __init__(
            self, src: str, dst: str, proto_l4: str, dport: int = None, sport: int = None, ct: str = 'new',
    ):
        super().__init__(src=src, dst=dst)
        self._proto_l4 = proto_l4.lower()
        self.sport = sport
        self.dport = dport
        self.ct = ct
        self.pre_nat_dst_port = dport

        if dport is None:
            if proto_l4 == 'tcp':
                self.dport = 443

            else:
                self.dport = 53

        if sport is None:
            self.sport = 50_000

    @property
    def proto_l4(self) -> type[ProtoL3]:
        return PROTO_L4_MAPPING[self._proto_l4]

    def validate(self):
        super().validate()
        assert self._proto_l4 in PROTO_L4_MAPPING
        assert isinstance(self.dport, int)
        assert isinstance(self.sport, int)
        assert 0 <= self.dport <= 65535
        assert 0 <= self.sport <= 65535

    def dump(self) -> dict:
        return {
            **super().dump(),
            'proto_l4': self.proto_l4.N,
            'dport': self.dport,
            'sport': self.sport,
        }

    def dnat_str(self) -> str:
        return f'{self.pre_nat_dst}:{self.pre_nat_dst_port} => {self.dst}:{self.dport}'


class PacketICMP(PacketIP):
    CODE_ECHO_REPLY = 0
    CODE_ECHO_REQUEST = 8

    CODE6_ECHO_REPLY = 0
    CODE6_ECHO_REQUEST = 128

    def __init__(self, src: str, dst: str, icmp_code: int = None):
        super().__init__(src=src, dst=dst)
        self.proto_l4 = ProtoL4ICMP
        self.icmp_code = icmp_code
        if icmp_code is None:
            if self.proto_l3 == ProtoL3IP4:
                self.icmp_code = self.CODE_ECHO_REQUEST

            else:
                self.icmp_code = self.CODE6_ECHO_REQUEST

    def validate(self):
        super().validate()
        assert self.proto_l4 == ProtoL4ICMP
        assert isinstance(self.icmp_code, int)
        assert -1 < self.icmp_code < 256

    def dump(self) -> dict:
        return {
            **super().dump(),
            'proto_l4': 'icmp' if self.proto_l3 == ProtoL3IP4 else 'icmpv6',
            'icmp_code': self.icmp_code,
        }


PACKET_KINDS = (PacketIP, PacketTCPUDP, PacketICMP)

from ipaddress import ip_address, IPv4Address, IPv6Address


class Packet:
    pass


class PacketIP(Packet):
    def __init__(self, src: str, dst: str, l3_proto: str):
        self.src = ip_address(src)
        self.dst = ip_address(dst)
        self.l3_proto = l3_proto.lower()

    def validate(self):
        assert self.l3_proto in ['ip4', 'ip6']
        if self.l3_proto == 'ip4':
            assert isinstance(self.src, IPv4Address)
            assert isinstance(self.dst, IPv4Address)

        else:
            assert isinstance(self.src, IPv6Address)
            assert isinstance(self.dst, IPv6Address)


class PacketTCPUDP(PacketIP):
    def __init__(
            self, src: str, dst: str, l3_proto: str, l4_proto: str, l4_dport: int = None, l4_sport: int = None,
    ):
        super().__init__(src=src, dst=dst, l3_proto=l3_proto)
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

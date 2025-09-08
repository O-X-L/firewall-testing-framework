from ipaddress import IPv4Network, IPv6Network

from config import ProtoL3IP4IP6, PROTOS_L3, PROTOS_L4

# pylint: disable=R0801

# pylint: disable=R0912,R0913,R0914,R0915,R0917
class OPNsenseRule:
    DIRECTION_IN = 'in'
    DIRECTION_OUT = 'out'
    DIRECTION_ANY = 'any'

    def __init__(
            self,
            nr: int,
            nis: list[str] = None,
            ni_direction: str = None,
            desc: str = None,
            quick: bool = True,
            ipprotocol: PROTOS_L3 = ProtoL3IP4IP6,
            protocol: PROTOS_L4 = None,
            source: list[(IPv4Network, IPv6Network)] = None,
            destination: list[(IPv4Network, IPv6Network)] = None,
            source_port: list[int] = None,
            destination_port: list[int] = None,
            source_invert: bool = False,
            destination_invert: bool = False,
            source_any: bool = False,
            destination_any: bool = False,
    ):
        self.nr = nr
        self.nis = nis
        self.ni_direction = ni_direction
        self.desc = desc
        self.quick = quick
        self.ipp = ipprotocol
        self.proto = protocol
        self.src = source
        self.dst = destination
        self.src_port = source_port
        self.dst_port = destination_port
        self.src_invert = source_invert
        self.dst_invert = destination_invert
        self.src_any = source_any
        self.dst_any = destination_any

    @property
    def match_ni_in(self) -> bool:
        if len(self.nis) == 0:
            return False

        if self.ni_direction in [self.DIRECTION_IN, self.DIRECTION_ANY]:
            return True

        return False

    @property
    def match_ni_out(self) -> bool:
        if len(self.nis) == 0:
            return False

        if self.ni_direction in [self.DIRECTION_OUT, self.DIRECTION_ANY]:
            return True

        return False

    @property
    def match_ip_saddr(self) -> bool:
        if self.src_any or (self.src is not None and len(self.src) > 0):
            return True

        return False

    @property
    def match_ip_daddr(self) -> bool:
        if self.dst_any or (self.src is not None and len(self.src) > 0):
            return True

        return False

    def get_match_types(self) -> (list[str], None):
        match = []
        if self.ipp is not None:
            match.append('proto_l3')

        if self.proto is not None:
            match.append('proto_l4')

        if self.match_ip_saddr:
            match.append('ip_saddr')

        if self.match_ip_daddr:
            match.append('ip_daddr')

        if self.match_ni_in:
            match.append('ni_in')

        if self.match_ni_out:
            match.append('ni_out')

        if self.src_port is not None and len(self.src_port) > 0:
            match.append('src-port')

        if self.dst_port is not None and len(self.dst_port) > 0:
            match.append('dst-port')

        if len(match) == 0:
            match = None

        return match

    def __repr__(self) -> str:
        desc = '' if self.desc is None else f' ({self.desc})'
        return f"Rule: #{self.nr}{desc} | Matches: {self.get_match_types()}"

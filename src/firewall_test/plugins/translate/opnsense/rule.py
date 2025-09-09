from ipaddress import IPv4Network, IPv6Network

from config import ProtoL3IP4IP6, PROTOS_L3, PROTOS_L4
from utils.logger import rule_repr

# pylint: disable=R0801

RULE_SEQUENCE_NEXT_CHAIN = 1_000_000


# pylint: disable=R0912,R0913,R0914,R0915,R0917
class OPNsenseRule:
    DIRECTION_IN = 'in'
    DIRECTION_OUT = 'out'
    DIRECTION_ANY = 'any'

    OP_EQ = '=='
    OP_NE = '!='

    def __init__(
            self,
            nr: int,
            uuid: str,
            nis: list[str] = None,
            ni_direction: str = None,
            desc: str = None,
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
        self.uuid = uuid
        self.nis = nis
        self.ni_direction = ni_direction
        self.desc = desc
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
        if self.dst_any or (self.dst is not None and len(self.dst) > 0):
            return True

        return False

    def get_matches(self) -> (dict, None):
        matches = {}
        if self.ipp is not None:
            matches['proto_l3'] = self.ipp.N

        if self.proto is not None:
            matches['proto_l4'] = [v.N for v in self.proto]

        if self.match_ip_saddr:
            op = self.OP_NE if self.src_invert else self.OP_EQ
            src = 'any' if self.src_any else [str(v) for v in self.src]
            matches['ip_saddr'] = {op: src}

        if self.match_ip_daddr:
            op = self.OP_NE if self.dst_invert else self.OP_EQ
            dst = 'any' if self.dst_any else [str(v) for v in self.dst]
            matches['ip_daddr'] = {op: dst}

        if self.match_ni_in:
            matches['ni_in'] = self.nis

        if self.match_ni_out:
            matches['ni_out'] = self.nis

        if self.src_port is not None and len(self.src_port) > 0:
            matches['src_port'] = self.src_port

        if self.dst_port is not None and len(self.dst_port) > 0:
            matches['dst_port'] = self.dst_port

        if len(matches) == 0:
            return None

        return matches

    def __repr__(self) -> str:
        cmt = '' if self.desc is None else f' "{self.desc}"'
        if self.uuid is not None:
            cmt += f' (UUID: {self.uuid})'

        return rule_repr(uid=self.nr, matches=self.get_matches(), cmt=cmt)

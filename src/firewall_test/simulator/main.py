from json import dumps as json_dumps
from ipaddress import IPv4Address, IPv6Address

from simulator.packet import PacketIP
from simulator.routes import Router

from plugins.translate.abstract import NetworkInterface, StaticRoute, StaticRouteRule
from plugins.system.abstract import FirewallSystem

FLOW_INPUT = 'input'
FLOW_OUTPUT = 'output'
FLOW_FORWARD = 'forward'
FLOW_INPUT_FORWARD = 'input_forward'  # before DNAT we might not yet know

MODE_INTERACTIVE = 1
MODE_CI = 2


class SimulatorRun:
    def __init__(self, packet: PacketIP, simulator):
        self.packet = packet
        self._s = simulator

        self._ipp = 4 if isinstance(self.packet.src, IPv4Address) else 6
        self._dnat_done = False
        self.dnat = None
        self.snat = None

        self.local_src, packet.ni_in = self._is_ip_local(packet.src)
        self.local_dst, packet.ni_out = self._is_ip_local(packet.dst)
        self.flow_type = self._get_flow_type()

        self.route_src = self._s.router.get_src_route(self.packet)
        self._update_packet_ni_in()

        if self.route_src is None:
            raise ConnectionError('No Source-Route found')

        # todo: DNAT
        self._dnat_done = True
        self.dnat = None

        self.local_dst, packet.ni_out = self._is_ip_local(packet.dst)
        self.flow_type = self._get_flow_type()
        self.route_dst = self._s.router.get_route(self.packet)
        self._update_packet_ni_out()

        if self.route_dst is None:
            raise ConnectionError('No Destination-Route found')

        # todo: SNAT
        self.snat = None

    def dump(self) -> dict:
        return {
            'packet': self.packet.dump(),
            'ipp': self._ipp,
            'src_is_local': self.local_src,
            'dst_is_local': self.local_dst,
            'flow_type': self.flow_type,
            'route_src': [route.dump() for route in self.route_src],
            'route_dst': [route.dump() for route in self.route_dst],
            'dnat': self.dnat,
            'snat': self.snat,
        }

    def to_json(self) -> str:
        return json_dumps(self.dump(), indent=2, default=str)

    def _is_ip_local(self, ip: (IPv4Address, IPv6Address)) -> (bool, (str, None)):
        for ni in self._s.nis:
            ni_ips = ni.ip4 if self._ipp == 4 else ni.ip6
            if ip in ni_ips:
                return True, ni.name

        return False, None

    def _get_flow_type(self) -> str:
        if self.local_src:
            return FLOW_OUTPUT

        if not self._dnat_done:
            return FLOW_INPUT_FORWARD

        if self.local_dst:
            return FLOW_INPUT

        return FLOW_FORWARD

    def _update_packet_ni_in(self):
        if self.packet.ni_in is not None:
            return

        if len(self.route_src) == 0:
            return

        self.packet.ni_in = self.route_src[0].ni

    def _update_packet_ni_out(self) -> (str, None):
        if self.packet.ni_out is not None:
            return

        if len(self.route_dst) == 0:
            return

        self.packet.ni_out = self.route_dst[0].ni


class Simulator:
    def __init__(
            self,
            system: type[FirewallSystem],
            nis: list[NetworkInterface],
            routes: list[StaticRoute],
            route_rules: list[StaticRouteRule] = None,
            mode: int = MODE_INTERACTIVE,
    ):
        self.mode = mode
        self.system = system
        self.nis = nis
        self.router = Router(
            system=system,
            routes=routes,
            route_rules=route_rules,
        )

    def run(self, packet: PacketIP) -> SimulatorRun:
        return SimulatorRun(
            packet=packet,
            simulator=self,
        )

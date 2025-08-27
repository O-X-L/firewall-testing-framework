from json import dumps as json_dumps
from ipaddress import IPv4Address, IPv6Address

from simulator.packet import PacketIP
from simulator.routes import Router
from simulator.logger import log_info, log_error, log_ok

from plugins.system.abstract import FirewallSystem
from plugins.translate.config import DEFAULT_ROUTES
from plugins.translate.abstract import NetworkInterface, StaticRoute, StaticRouteRule

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
        # log_info('Firewall', f'Flow-type: {self.flow_type}')

        self.route_src = self._s.router.get_src_route(self.packet)
        self._update_packet_ni_in()
        if packet.ni_in is not None:
            log_info('Firewall', f'Packet inbound-interface: {packet.ni_in}')

        if self.route_src is None:
            log_error('Router', 'No Source-Route found')
            return

        # todo: prerouting firewall-filters
        # todo: DNAT
        self._dnat_done = True
        self.dnat = None
        if self.dnat is not None:
            log_info('Firewall', f'Performed DNAT: {self.dnat}')

        self.local_dst, packet.ni_out = self._is_ip_local(packet.dst)
        self.flow_type = self._get_flow_type()

        self.route_dst = self._s.router.get_route(self.packet)
        self._update_packet_ni_out()
        if packet.ni_out is not None:
            log_info('Firewall', f'Packet outbound-interface: {packet.ni_out}')

        if self.route_dst is None:
            log_error('Router', 'No Destination-Route found')
            return

        log_info('Firewall', f'Flow-type: {self.flow_type}')

        if self._is_bogon_to_wan() and self._s.system.FIREWALL_WAN_DROP_BOGONS:
            log_error('Firewall', 'Dropping traffic to WAN targeting bogons')
            return

        # todo: main firewall-filters

        # todo: SNAT
        self.snat = None
        if self.snat is not None:
            log_info('Firewall', f'Performed SNAT: {self.snat}')

        # todo: egress firewall-filters

        log_ok('Firewall', 'Packet passed')

    def dump(self) -> dict:
        return {
            'packet': self.packet.dump(),
            'src_is_local': self.local_src,
            'dst_is_local': self.local_dst,
            'flow_type': self.flow_type,
            'route_src': self.route_src.dump() if self.route_src is not None else None,
            'route_dst': self.route_dst.dump() if self.route_dst is not None else None,
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

        if self.route_src is None:
            return

        self.packet.ni_in = self.route_src.ni

    def _update_packet_ni_out(self) -> (str, None):
        if self.packet.ni_out is not None:
            return

        if self.route_dst is None:
            return

        self.packet.ni_out = self.route_dst.ni

    def _is_bogon_to_wan(self) -> bool:
        if self.route_dst.net in DEFAULT_ROUTES and \
                not self.packet.dst.is_global:
            return True

        return False


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

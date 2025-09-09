from json import dumps as json_dumps
from ipaddress import IPv4Address, IPv6Address

from simulator.packet import PACKET_KINDS
from simulator.routes import Router
from simulator.firewall import Firewall
from utils.logger import log_info, log_error, log_ok, log_warn

from utils.net import ip_is_bogon
from config import DEFAULT_ROUTES, Flow, FlowForward, FlowInput, FlowInputForward, FlowOutput
from plugins.system.abstract import FirewallSystem
from plugins.translate.abstract import NetworkInterface, StaticRoute, StaticRouteRule, Ruleset, Rule


MODE_INTERACTIVE = 1
MODE_CI = 2


# pylint: disable=R0911,R0912,R0915
class SimulatorRun:
    def __init__(self, packet: PACKET_KINDS, simulator):
        self.packet = packet
        self.passed = False
        self._s = simulator

        self._ipp = 4 if isinstance(self.packet.src, IPv4Address) else 6
        self._dnat_done = False
        self.dnat = None
        self.snat = None

        ### CATEGORIZE TRAFFIC FLOW ###

        self.local_src, packet.ni_in = self._is_ip_local(packet.src)
        self.local_dst, packet.ni_out = self._is_ip_local(packet.dst)
        self.flow_type = self._get_flow_type()

        ### CHECK SOURCE-ROUTE AND UPDATE INBOUND-NETWORK-INTERFACE ###

        self.route_src = self._s.router.get_src_route(self.packet)
        self._update_packet_ni_in()
        if packet.ni_in is not None:
            self._log_ni(in_out='in', name=packet.ni_in)

        if self.route_src is None:
            log_error('Router', 'No Source-Route found', final=True)
            return

        self._log_route(out=False, route=self.route_src)

        ### PROCESSING FIREWALL-FILTERS UP TO DNAT ###

        passed, rule = self._s.fw.process_pre_routing(packet=packet, flow=self.flow_type)
        if not passed:
            self._log_block(rule)
            return

        ### PROCESSING DNAT ###

        _, self.dnat = self._s.fw.process_dnat(packet=packet, flow=self.flow_type)
        self._dnat_done = True
        if self.dnat is not None:
            log_info(label='Firewall', v1=f'Performed DNAT: {self.packet.dnat_str}')

        ### UPDATE TRAFFIC FLOW AND OUTBOUND-NETWORK-INTERFACE ###

        self.local_dst, packet.ni_out = self._is_ip_local(packet.dst)
        self.flow_type = self._get_flow_type()
        log_info('Firewall', v2=f'Flow-type: {self.flow_type.N}')

        ### CHECK DESTINATION-ROUTE ###

        self.route_dst = self._s.router.get_route(self.packet)
        self._update_packet_ni_out()
        if packet.ni_out is not None:
            self._log_ni(in_out='out', name=packet.ni_out)

        if self.flow_type != FlowInput:
            if self.route_dst is None:
                log_error('Router', 'No Destination-Route found', final=True)
                return

            self._log_route(out=True, route=self.route_dst)

        ### SYSTEM-SPECIFIC FILTERS OUTSIDE OF FIREWALL ####

        if self.flow_type != FlowInput:
            # DROP PACKET IF TRAFFIC TO BOGONS ON WAN
            if self._is_bogon_to_wan() and self._s.system.SYSTEM_DROP_WAN_BOGONS:
                log_error('System', 'Dropping traffic to WAN targeting bogons', final=True)
                return

        if self.flow_type == FlowForward and self._s.system.SYSTEM_DROP_FORWARD:
            # DROP PACKET IF TRAFFIC-FORWARDING IS NOT ALLOWED
            log_error('System', 'Dropping forward traffic', final=True)
            return

        ### PROCESSING MAIN FIREWALL-FILTERS ###

        passed, rule = self._s.fw.process_main(packet=packet, flow=self.flow_type)
        if not passed:
            self._log_block(rule)
            return

        ### PROCESSING SOURCE-NAT ###

        performed_snat, self.snat = self._s.fw.process_snat(packet=packet, flow=self.flow_type)
        if performed_snat:
            if self.snat is None:
                # generic masquerade
                snat_ip = self._get_snat_masquerade_ip()
                if snat_ip is None:
                    log_warn('Firewall', 'Unable to find usable IP for masquerade SNAT!')

                else:
                    self.packet.src = self._get_snat_masquerade_ip()

            log_info(label='Firewall', v1=f'Performed SNAT: {self.packet.snat_str()}')

        elif self.flow_type == FlowOutput:
            # use the correct outbound-IP if the traffic originated from this host itself
            self.packet.src = self._get_output_outbound_ip()

        elif self.flow_type == FlowForward and self._is_src_bogon_dst_wan_public():
            log_warn('Firewall', 'Source is bogon-network and heading to Public-WAN without SNAT!')

        ### PROCESSING FIREWALL-FILTERS AFTER SNAT ###

        passed, rule = self._s.fw.process_egress(packet=packet, flow=self.flow_type)
        if not passed:
            self._log_block(rule)
            return

        ### DONE ###

        log_ok('Firewall', 'Packet passed', final=True)
        self.passed = True

    def dump(self) -> dict:
        return {
            'packet': self.packet.dump(),
            'src_is_local': self.local_src,
            'dst_is_local': self.local_dst,
            'flow_type': self.flow_type.N,
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

    def _get_flow_type(self) -> type[Flow]:
        if self.local_src:
            return FlowOutput

        if not self._dnat_done:
            return FlowInputForward

        if self.local_dst:
            return FlowInput

        return FlowForward

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
        if self.flow_type == FlowInput or self.route_dst is None:
            return False

        if self.route_dst.net in DEFAULT_ROUTES and ip_is_bogon(self.packet.dst):
            return True

        return False

    def _is_src_bogon_dst_wan_public(self) -> bool:
        if self.flow_type == FlowInput or self.route_dst is None:
            return False

        if self.route_dst.net in DEFAULT_ROUTES and \
                ip_is_bogon(self.packet.src) and \
                not ip_is_bogon(self.packet.dst):
            return True

        return False

    def _get_output_outbound_ip(self) -> (IPv4Address, IPv6Address, None):
        if self.flow_type != FlowOutput:
            return None

        return self._get_snat_masquerade_ip()

    def _get_snat_masquerade_ip(self) -> (IPv4Address, IPv6Address, None):
        if ip_is_bogon(self.packet.dst):
            return None

        if self.route_dst.src_pref is not None:
            return self.route_dst.src_pref

        for ni in self._s.nis:
            if ni.name == self.packet.ni_out:
                ni_ips = ni.ip4 if self._ipp == 4 else ni.ip6
                return ni_ips[0]

        return None

    def _log_route(self, out: bool, route: StaticRoute):
        in_out = 'outbound'
        if not out:
            in_out = 'inbound'

        msg = f'Packet {in_out}-route: {route.net}'
        for field in ['gw', 'metric', 'scope']:
            value = getattr(route, field)
            if value is not None:
                msg += f', {field} {value}'

        if out and self.flow_type == FlowOutput and route.src_pref is not None:
            msg += f', preferred-source-IP {route.src_pref}'

        log_info('Router', msg)

    def _log_ni(self, in_out: str, name: str):
        desc = ''
        for ni in self._s.nis:
            if ni.name == name:
                if ni.desc is not None:
                    desc = f' ({ni.desc})'

                break

        log_info('Router', f'Packet {in_out}bound-interface: {name}{desc}')

    @staticmethod
    def _log_block(rule: (Rule, None)):
        if rule is None:
            log_error(label='Firewall', v1='Packet blocked by chain default-policy', final=True)

        else:
            log_error(label='Firewall', v1='Packet blocked by rule', v2=f': {rule.log()}', final=True)


class Simulator:
    def __init__(
            self,
            system: type[FirewallSystem],
            nis: list[NetworkInterface],
            ruleset: Ruleset,
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
        self.fw = Firewall(
            system=system,
            ruleset=ruleset,
        )

    def run(self, packet: PACKET_KINDS) -> SimulatorRun:
        # todo: implement multi-run handling
        #   for traffic that is flow-type 'output => input' (local to local)
        #   for multiple firewalls

        return SimulatorRun(
            packet=packet,
            simulator=self,
        )

from config import ProtoL3IP4IP6, RuleActionGoTo
from simulator.packet import PACKET_KINDS, PacketTCPUDP
from plugins.translate.abstract import Rule
from plugins.system.abstract_rule_match import RuleMatcher, RuleMatchResult
from plugins.translate.opnsense.rule import OPNsenseRule, RULE_SEQUENCE_NEXT_CHAIN
from utils.logger import log_warn, log_debug

# todo: add explicit match-tests


# pylint: disable=R0912
class RuleMatcherOPNsense(RuleMatcher):
    def matches(self, packet: PACKET_KINDS, rule: Rule) -> RuleMatchResult:
        """
        :param packet: Packet to match
        :param rule: Rule to check
        :return: RuleMatchResult
        """

        if rule.action == RuleActionGoTo and rule.seq == RULE_SEQUENCE_NEXT_CHAIN:
            return RuleMatchResult(
                matched=True,
                action=rule.action,
                target_chain_name=rule.raw,  # will only contain chain-name in that case
                target_nat_ip=None,
                target_nat_port=None,
            )

        opn_rule: OPNsenseRule = rule.raw
        results = []
        ### NETWORK INTERFACES ###
        if opn_rule.match_ni_in:
            results.append(packet.ni_in in opn_rule.nis)

        if opn_rule.match_ni_out:
            results.append(packet.ni_out in opn_rule.nis)

        ### PROTOCOLS ###
        if opn_rule.ipp is not None:
            if opn_rule.ipp == ProtoL3IP4IP6:
                results.append(True)

            else:
                results.append(opn_rule.ipp == packet.proto_l3)

        if opn_rule.proto is not None:
            if not hasattr(packet, 'proto_l4'):
                results.append(False)

            else:
                results.append(packet.proto_l4 in opn_rule.proto)

        ### SOURCE / DESTINATION ###
        if opn_rule.match_ip_saddr:
            if opn_rule.src_any:
                match = True

            else:
                match = any(packet.src in net for net in opn_rule.src)

            if opn_rule.src_invert:
                results.append(not match)

            else:
                results.append(match)

        if opn_rule.match_ip_daddr:
            if opn_rule.dst_any:
                match = True

            else:
                match = any(packet.dst in net for net in opn_rule.dst)

            if opn_rule.dst_invert:
                results.append(not match)

            else:
                results.append(match)

        ### PORTS ###
        if opn_rule.src_port is not None and len(opn_rule.src_port) > 0:
            if not isinstance(packet, PacketTCPUDP):
                results.append(False)

            else:
                results.append(packet.sport in opn_rule.src_port)

        if opn_rule.dst_port is not None and len(opn_rule.dst_port) > 0:
            if not isinstance(packet, PacketTCPUDP):
                results.append(False)

            else:
                results.append(packet.dport in opn_rule.dst_port)

        if len(results) == 0:
            log_warn('Firewall Plugin', ' > Matches: Found not matches we could process - skipping rule')

        else:
            log_debug('Firewall Plugin', f' > Match Results: {opn_rule.get_matches()} => {results}')

            return RuleMatchResult(
                matched=all(results),
                action=rule.action,
                target_chain_name=None,
                target_nat_ip=None,
                target_nat_port=None,
            )

        # todo: SNAT / DNAT

        return RuleMatchResult(False, None, None, None, None)

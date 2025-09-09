from config import RuleActionKindTerminal, RuleActionKindToChain, RuleActionKindNAT
from plugins.system.abstract_rule_match import RuleMatcher, RuleMatchResult
from plugins.translate.abstract import Rule
from plugins.translate.netfilter.parse import NftRule
from simulator.packet import PacketIP, PacketTCPUDP, PacketICMP
from utils.logger import log_debug, log_warn

# todo: add explicit match-tests


# pylint: disable=R0912
class RuleMatcherNetfilter(RuleMatcher):
    def matches(self, packet: (PacketIP, PacketTCPUDP, PacketICMP), rule: Rule) -> RuleMatchResult:
        """
        :param packet: Packet to match
        :param rule: Rule to check
        :return: RuleMatchResult
        """
        nf_rule: NftRule = rule.raw

        if rule.action is None or \
                not issubclass(rule.action, (RuleActionKindTerminal, RuleActionKindToChain, RuleActionKindNAT)):
            return RuleMatchResult(False, None, None, None, None)

        results = []

        if len(nf_rule.matches) == 0:
            return RuleMatchResult(
                matched=True,
                action=rule.action,
                target_chain_name=nf_rule.target_chain,
                target_nat_ip=nf_rule.target_nat_ip,
                target_nat_port=nf_rule.target_nat_port,
            )

        for match in nf_rule.matches:
            single_l3_result = True  # 'ip6 daddr != XXX' would drop any IPv4 traffic
            single_results = []
            # NETWORK INTERFACES
            if match.match_ni_in:
                single_results.append(packet.ni_in in match.value)

            if match.match_ni_out:
                single_results.append(packet.ni_out in match.value)

            # IP PROTOCOL
            if match.match_proto_l3:
                if match.value_proto_l3:
                    single_l3_result = packet.proto_l3 == match.value_proto_l3

                else:
                    single_l3_result = packet.proto_l3 in match.value

            # IP SOURCE AND DESTINATION
            if match.match_ip_saddr:
                single_results.append(any(
                    packet.src in ip_net for ip_net in match.value
                ))

            if match.match_ip_daddr:
                single_results.append(any(
                    packet.dst in ip_net for ip_net in match.value
                ))

            # TRANSPORT PROTOCOL
            if match.match_proto_l4:
                if match.value_proto_l4:
                    single_results.append(packet.proto_l4 == match.value_proto_l4)

                else:
                    single_results.append(packet.proto_l4 in match.value)

            if isinstance(packet, PacketTCPUDP):
                # PORTS
                if match.match_sport:
                    single_results.append(packet.sport in match.value)

                if match.match_dport:
                    single_results.append(packet.dport in match.value)

                # CONNECTION TRACKING STATE
                if match.match_ct:
                    single_results.append(packet.ct in match.value)

            # if we need to separate the L3-result from the actual condition as it can impact the match
            results.append(single_l3_result)

            if len(single_results) > 0:
                if match.operator in [match.OP_EQ, match.OP_IN]:
                    results.append(all(single_results))

                elif match.operator in [match.OP_NE, match.OP_NOT]:
                    results.append(not all(single_results))

                else:
                    log_warn('Firewall Plugin', f' > Unable to get results for operator "{match.operator}"')

        if len(results) == 0:
            log_warn('Firewall Plugin', ' > Matches: Found not matches we could process - skipping rule')

        else:
            log_debug('Firewall Plugin', f' > Match Results: {nf_rule.get_matches()} => {results}')

            return RuleMatchResult(
                matched=all(results),
                action=rule.action,
                target_chain_name=nf_rule.target_chain,
                target_nat_ip=nf_rule.target_nat_ip,
                target_nat_port=nf_rule.target_nat_port,
            )

        return RuleMatchResult(False, None, None, None, None)

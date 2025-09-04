from plugins.system.abstract_rule_match import RuleMatcher
from plugins.translate.config import RuleAction, RuleActionKindTerminal, RuleActionKindToChain
from plugins.translate.abstract import Rule, Chain  # Table
from plugins.translate.netfilter.parse import NftRule
from simulator.packet import PacketIP, PacketTCPUDP, PacketICMP
from simulator.logger import log_debug, log_warn


# pylint: disable=R0912
class RuleMatcherNetfilter(RuleMatcher):
    def matches(self, packet: (PacketIP, PacketTCPUDP, PacketICMP), rule: Rule) -> tuple[bool, (type[RuleAction], None), (Chain, None)]:
        """
        :param packet: Packet to match
        :param rule: Rule to check
        :return:
          - bool: If the packet matches the rule
          - (RuleAction, None): The action that should be performed - None if not matched
          - (Chain, None): The target-chain related to the action - None if not applicable
        """
        nf_rule: NftRule = rule.raw

        if rule.action is None:
            return False, None, None

        if issubclass(rule.action, RuleActionKindToChain):
            return False, rule.action, nf_rule.target_chain

        if issubclass(rule.action, RuleActionKindTerminal):
            all_results = []
            results = []
            for match in nf_rule.matches:
                single_results = []
                # NETWORK INTERFACES
                if match.match_ni_in:
                    single_results.append(packet.ni_in in match.value)

                if match.match_ni_out:
                    single_results.append(packet.ni_out in match.value)

                # IP PROTOCOL
                if match.match_proto_l3:
                    if match.value_proto_l3:
                        single_results.append(packet.proto_l3 == match.value_proto_l3)

                    else:
                        single_results.append(packet.proto_l3 in match.value)

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
                        single_results.append(packet.l4_sport in match.value)

                    if match.match_dport:
                        single_results.append(packet.l4_dport in match.value)

                    # CONNECTION TRACKING STATE
                    if match.match_ct:
                        single_results.append(packet.ct in match.value)

                all_results.append(single_results)

                if match.operator == match.OP_EQ:
                    results.append(all(single_results))

                elif match.operator == match.OP_NE:
                    results.append(not all(single_results))

                else:
                    log_warn('Firewall', f' > Unable to get results for operator {match.operator}')

            log_debug('Firewall', f' > Matches: {nf_rule.get_match_types()} | Result: {results}')
            return all(results), rule.action, None

        return True, rule.action, None

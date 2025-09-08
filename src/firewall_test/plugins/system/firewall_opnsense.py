from simulator.packet import PacketIP
from plugins.translate.abstract import Rule
from plugins.system.abstract_rule_match import RuleMatcher, RuleMatchResult
from plugins.translate.opnsense.rule import OPNsenseRule


class RuleMatcherOPNsense(RuleMatcher):
    def matches(self, packet: PacketIP, rule: Rule) -> RuleMatchResult:
        """
        :param packet: Packet to match
        :param rule: Rule to check
        :return: RuleMatchResult
        """
        opn_rule: OPNsenseRule = rule.raw
        del opn_rule
        return RuleMatchResult(False, None, None, None, None)

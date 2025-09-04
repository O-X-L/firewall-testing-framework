from plugins.system.abstract_rule_match import RuleMatcher
from plugins.translate.config import RuleAction
from plugins.translate.abstract import Rule, Chain  # Table
from plugins.translate.netfilter.parse import NftRule
from simulator.packet import PacketIP


class RuleMatcherNetfilter(RuleMatcher):
    def matches(self, packet: PacketIP, rule: Rule) -> tuple[bool, (type[RuleAction], None), (Chain, None)]:
        """
        :param packet: Packet to match
        :param rule: Rule to check
        :return:
          - bool: If the packet matches the rule
          - (RuleAction, None): The action that should be performed - None if not matched
          - (Chain, None): The target-chain related to the action - None if not applicable
        """
        nf_rule: NftRule = rule.raw
        del nf_rule
        return False, rule.action, None

from abc import abstractmethod

from plugins.system.abstract import BaseRuleMatcher
from plugins.translate.config import RuleAction
from plugins.translate.abstract import Table, Rule, Chain
from simulator.packet import PacketIP


class RuleMatcher(BaseRuleMatcher):
    def __init__(self, table: Table):
        self.table = table

    @abstractmethod
    def matches(self, packet: PacketIP, rule: Rule) -> tuple[bool, (RuleAction, None), (Chain, None)]:
        """
        :param packet: Packet to match
        :param rule: Rule to check
        :return:
          - bool: If the packet matches the rule
          - (RuleAction, None): The action that should be performed - None if not matched
          - (Chain, None): The target-chain related to the action - None if not applicable
        """
        return False, None, None

from abc import abstractmethod
from ipaddress import IPv4Address, IPv6Address

from config import RuleAction
from plugins.system.abstract import BaseRuleMatcher
from plugins.translate.abstract import Table, Rule
from simulator.packet import PacketIP


class RuleMatchResult:
    def __init__(
            self,
            matched: bool,
            action: (type[RuleAction], None),
            target_chain_name: (str, None),
            target_nat_ip: ((IPv4Address, IPv6Address), None),
            target_nat_port: (int, None),
    ):
        self.matched = matched
        self.action = action
        self.target_chain_name = target_chain_name
        self.target_nat_ip = target_nat_ip
        self.target_nat_port = target_nat_port

        self.validate()

    def validate(self):
        assert isinstance(self.matched, bool)

        if self.action is not None:
            assert issubclass(self.action, RuleAction)

        if self.target_chain_name is not None:
            assert isinstance(self.target_chain_name, str)

        if self.target_nat_ip is not None:
            assert isinstance(self.target_nat_ip, (IPv4Address, IPv6Address))

        if self.target_nat_port is not None:
            assert isinstance(self.target_nat_port, int) and 0 <= self.target_nat_port <= 65535


class RuleMatcher(BaseRuleMatcher):
    def __init__(self, table: Table):
        self.table = table

    @abstractmethod
    def matches(self, packet: PacketIP, rule: Rule) -> RuleMatchResult:
        """
        :param packet: Packet to match
        :param rule: Rule to check
        :return: RuleMatchResult
        """
        return RuleMatchResult(False, None, None, None, None)

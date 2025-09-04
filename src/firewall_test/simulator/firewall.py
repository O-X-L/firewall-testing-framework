from typing import Callable

from config import Flow, FlowInputForward, FlowInput, ProtoL3IP4, ProtoL3IP6, ProtoL3IP4IP6
from plugins.system.abstract import FirewallSystem
from plugins.translate.abstract import Ruleset, Table, Chain, Rule
from plugins.translate.config import RuleAction, RuleActionKindTerminal, RuleActionKindToChain, RuleActionContinue, \
    RuleActionKindTerminalKill
from simulator.packet import PacketIP
from simulator.logger import log_debug, log_info, log_warn


class RunFirewallChain:
    def __init__(self, fw):
        self._fw = fw

    @staticmethod
    def _log_rule_match(matches: bool, action: (None, RuleAction), debug: bool = False):
        msg = f' > Match: {matches}'

        if action is not None:
            msg += f' | Action: {action.N}'

        if debug:
            log_debug('Firewall', msg)

        else:
            log_info('Firewall', msg)

    def process(self, chain: Chain, packet: PacketIP) -> (bool, (Rule, None)):
        """
        :param chain: Firewall chain to process; if any rule has an action that targets another chain - it will also be processed
        :param packet: Packet to match
        :return:
          - bool: If the packet passed the chain
          - (Rule, None): If that packet did not pass - the rule that denied it
        """

        rule_matcher = self._fw.system.get_rule_matcher()(chain.run_table)
        chain.rules.sort(key=lambda r: r.seq, reverse=False)
        lazy_action: (None, RuleAction) = None
        lazy_rule: (None, Rule) = None

        for rule in chain.rules:
            log_info(
                'Firewall',
                f'Processing Rule: {rule.dump()}'
            )

            matches, action, target_chain = rule_matcher.matches(packet=packet, rule=rule)
            requires_action = matches and action is not None

            if requires_action:
                self._log_rule_match(matches=matches, action=action)

                if action == RuleActionContinue:
                    continue

                if issubclass(action, RuleActionKindTerminal):
                    if self._fw.system.FIREWALL_ACTION_LAZY and rule.action_lazy:
                        lazy_action = action
                        lazy_rule = rule
                        continue

                    return not issubclass(action, RuleActionKindTerminalKill), rule

                if issubclass(action, RuleActionKindToChain):
                    if target_chain is None:
                        log_warn('Firewall', f'Got to-chain action "{action.N}" but rule-matcher did not return target-chain!')
                        continue

                    # todo: jump to other chains if required (recurse)

            else:
                self._log_rule_match(matches=matches, action=action, debug=True)

        if self._fw.system.FIREWALL_ACTION_LAZY and lazy_rule is not None:
            action_str = '' if lazy_action is None else f' | Action: {lazy_action.N}'
            log_debug('Firewall', f'Applying lazy-action: {action_str}')
            return not issubclass(lazy_action, RuleActionKindTerminalKill), lazy_rule

        return True, None


class RunFirewallTables:
    def __init__(self, fw):
        self._fw = fw
        self._run_chains = RunFirewallChain(fw)

    @staticmethod
    def _is_matching_table(packet: PacketIP, table: Table, ignore_type: list[str] = None) -> bool:
        if ignore_type is not None and table.type in ignore_type:
            return False

        if table.family == ProtoL3IP4IP6:
            return True

        if table.family == ProtoL3IP4 == packet.proto_l3:
            return True

        if table.family == ProtoL3IP6 == packet.proto_l3:
            return True

        return False

    def _get_tables(self, packet: PacketIP, ignore_type: list[str] = None) -> list[Table]:
        return [
            t for t in self._fw.ruleset.tables
            if self._is_matching_table(packet=packet, table=t, ignore_type=ignore_type)
        ]

    @staticmethod
    def _is_matching_chain(packet: PacketIP, chain: Chain, ignore_type: list[str] = None) -> bool:
        if ignore_type is not None and chain.type in ignore_type:
            return False

        if chain.family == ProtoL3IP4IP6:
            return True

        if chain.family == ProtoL3IP4 == packet.proto_l3:
            return True

        if chain.family == ProtoL3IP6 == packet.proto_l3:
            return True

        return False

    def _get_chains(self, packet: PacketIP, table: Table, ignore_type: list[str] = None):
        return [
            c for c in table.chains
            if self._is_matching_chain(packet=packet, chain=c, ignore_type=ignore_type)
        ]

    def _sort_tables_by_priority(self, tables: list[Table]) -> list[Table]:
        sorted_tables = []
        priorities = [t.priority for t in tables if isinstance(t.priority, int)]
        priorities.sort()
        if not self._fw.system.FIREWALL_PRIO_LOWER_BETTER:
            priorities.reverse()

        for p in priorities:
            for table in tables:
                if table.priority == p and table not in sorted_tables:
                    sorted_tables.append(table)

        for table in tables:
            if table not in sorted_tables:
                sorted_tables.append(table)

        return sorted_tables

    def __sort_chains_by_priority(self, chains: list[Chain]) -> list[Chain]:
        sorted_chains = []
        priorities = [c.priority for c in chains if isinstance(c.priority, int)]
        priorities.sort()
        if not self._fw.system.FIREWALL_PRIO_LOWER_BETTER:
            priorities.reverse()

        for p in priorities:
            for chain in chains:
                if chain.priority == p and chain not in sorted_chains:
                    sorted_chains.append(chain)

        for chain in chains:
            if chain not in sorted_chains:
                sorted_chains.append(chain)

        return sorted_chains

    def _sort_chains_by_hook_and_priority(self, chains: list[Chain]) -> list[Chain]:
        sorted_chains = []
        for hook in self._fw.system.FIREWALL_HOOKS['full']:
            chains_filtered = [chain for chain in chains if chain.hook == hook]
            sorted_chains.extend(self.__sort_chains_by_priority(chains_filtered))

        return sorted_chains

    # todo: handle chains without hooks (jump/goto/...)
    def _is_chain_before_eq(self, chain: Chain, hook: str, priority: int) -> bool:
        if chain.hook is None:
            return False

        is_idx = self._fw.system.FIREWALL_HOOKS['full'].index(chain.hook)
        check_idx = self._fw.system.FIREWALL_HOOKS['full'].index(hook)
        if is_idx > check_idx:
            return False

        if is_idx == check_idx:
            return priority >= chain.priority

        return True

    def _is_chain_after(self, chain: Chain, hook: str, priority: int) -> bool:
        if chain.hook is None:
            return False

        return not self._is_chain_before_eq(chain=chain, hook=hook, priority=priority)

    def _is_chain_in_flow(self, chain: Chain, flow: type[Flow]) -> bool:
        return chain.hook in self._fw.system.FIREWALL_HOOKS[flow]

    @staticmethod
    def _inherit_table_priority_to_chain(table: Table, chain: Chain):
        if isinstance(chain.priority, int) and isinstance(table.priority, int):
            chain.priority += table.priority

        elif chain.priority is None and isinstance(table.priority, int):
            chain.priority = table.priority

    def _process_by_table_prio(
            self, tables: list[Table], callback_chain_filter: Callable[[Chain], bool], packet: PacketIP,
    ) -> (bool, (Rule, None)):
        for table in self._sort_tables_by_priority(tables):
            chains = [
                c for c in table.chains
                if callback_chain_filter(c)
            ]

            for chain in self._sort_chains_by_hook_and_priority(chains):
                chain.run_table = table
                result, rule = self._process_chain(chain=chain, packet=packet)
                if not result:
                    return False, rule

        return True, None

    def _process_by_chain_prio(
            self, tables: list[Table], callback_chain_filter: Callable[[Chain], bool], packet: PacketIP,
    ) -> (bool, (Rule, None)):
        chains: list[Chain] = []
        for table in tables:
            for chain in table.chains:
                if chain in chains:
                    continue

                if not callback_chain_filter(chain):
                    continue

                self._inherit_table_priority_to_chain(table, chain)

                chain.run_table = table
                chains.append(chain)

        for chain in self._sort_chains_by_hook_and_priority(chains):
            result, rule = self._process_chain(chain=chain, packet=packet)
            if not result:
                return False, rule

        return True, None

    def _process_chain(self, chain: Chain, packet: PacketIP) -> (bool, (Rule, None)):
        """
        see: RunFirewallChain.process
        """

        log_info(
            'Firewall',
            f'Processing Chain: '
            f'Table {chain.run_table.name} {chain.run_table.family.N} | '
            f'Chain {chain.name} {chain.family.N} {chain.type}'
        )
        return self._run_chains.process(chain=chain, packet=packet)

    def process_pre_routing(self, packet: PacketIP, flow: type[Flow]) -> (bool, (Rule, None)):
        """
        :param packet: Packet to process
        :param flow: traffic flow-type
        :return: see RunFirewallChain.process
        """

        def _chain_filter(chain: Chain) -> bool:
            if not self._is_chain_in_flow(chain, flow):
                return False

            before_dnat = self._is_chain_before_eq(chain=chain, **self._fw.system.FIREWALL_NAT[flow]['dnat'])
            return chain.type != chain.TYPE_NAT and before_dnat

        tables = self._get_tables(packet=packet, ignore_type=[Table.TYPE_NAT])
        if self._fw.system.FIREWALL_PRIO_TABLE_FULL:
            return self._process_by_table_prio(tables=tables, callback_chain_filter=_chain_filter, packet=packet)

        return self._process_by_chain_prio(tables=tables, callback_chain_filter=_chain_filter, packet=packet)

    def process_dnat(self, packet: PacketIP, flow: type[Flow]) -> (bool, (Rule, None)):
        """
        :param packet: Packet to process
        :param flow: traffic flow-type
        :return:
          - bool: If a NAT-operation was performed on the packet
          - (Rule, None): If NAT was performed - the rule that did so
        """

        def _chain_filter(chain: Chain) -> bool:
            if not self._is_chain_in_flow(chain, flow):
                return False

            chain_dnat = self._fw.system.FIREWALL_NAT[flow]['dnat']
            return chain.type == chain.TYPE_NAT and \
                chain.hook == chain_dnat['hook'] and \
                chain.priority == chain_dnat['priority']

        tables = self._get_tables(packet=packet)
        if self._fw.system.FIREWALL_PRIO_TABLE_FULL:
            result, rule = self._process_by_table_prio(tables=tables, callback_chain_filter=_chain_filter, packet=packet)

        else:
            result, rule = self._process_by_chain_prio(tables=tables, callback_chain_filter=_chain_filter, packet=packet)

        return not result, rule

    def process_main(self, packet: PacketIP, flow: type[Flow]) -> (bool, (Rule, None)):
        """
        :param packet: Packet to process
        :param flow: traffic flow-type
        :return: see RunFirewallChain.process
        """

        def _chain_filter(chain: Chain) -> bool:
            if not self._is_chain_in_flow(chain, flow):
                return False

            after_dnat = self._is_chain_after(chain=chain, **self._fw.system.FIREWALL_NAT[flow]['dnat'])
            before_snat = True
            if 'snat' in self._fw.system.FIREWALL_NAT[flow]:
                before_snat = self._is_chain_before_eq(chain=chain, **self._fw.system.FIREWALL_NAT[flow]['snat'])

            return chain.type != chain.TYPE_NAT and after_dnat and before_snat

        tables = self._get_tables(packet=packet, ignore_type=[Table.TYPE_NAT])
        if self._fw.system.FIREWALL_PRIO_TABLE_FULL:
            return self._process_by_table_prio(tables=tables, callback_chain_filter=_chain_filter, packet=packet)

        return self._process_by_chain_prio(tables=tables, callback_chain_filter=_chain_filter, packet=packet)

    def process_snat(self, packet: PacketIP, flow: type[Flow]) -> (bool, (Rule, None)):
        """
        :param packet: Packet to process
        :param flow: traffic flow-type
        :return: see RunFirewallTables.process_dnat
        """

        def _chain_filter(chain: Chain) -> bool:
            if not self._is_chain_in_flow(chain, flow):
                return False

            chain_snat = self._fw.system.FIREWALL_NAT[flow]['snat']
            return chain.type == chain.TYPE_NAT and \
                chain.hook == chain_snat['hook'] and \
                chain.priority == chain_snat['priority']

        tables = self._get_tables(packet=packet)
        if self._fw.system.FIREWALL_PRIO_TABLE_FULL:
            result, rule = self._process_by_table_prio(tables=tables, callback_chain_filter=_chain_filter, packet=packet)

        else:
            result, rule = self._process_by_chain_prio(tables=tables, callback_chain_filter=_chain_filter, packet=packet)

        return not result, rule

    def process_egress(self, packet: PacketIP, flow: type[Flow]) -> (bool, (Rule, None)):
        """
        :param packet: Packet to process
        :param flow: traffic flow-type
        :return: see RunFirewallChain.process
        """

        def _chain_filter(chain: Chain) -> bool:
            if not self._is_chain_in_flow(chain, flow):
                return False

            after_snat = self._is_chain_after(chain=chain, **self._fw.system.FIREWALL_NAT[flow]['snat'])
            return chain.type != chain.TYPE_NAT and after_snat

        tables = self._get_tables(packet=packet, ignore_type=[Table.TYPE_NAT])
        if self._fw.system.FIREWALL_PRIO_TABLE_FULL:
            return self._process_by_table_prio(tables=tables, callback_chain_filter=_chain_filter, packet=packet)

        return self._process_by_chain_prio(tables=tables, callback_chain_filter=_chain_filter, packet=packet)


class Firewall:
    def __init__(self, system: type[FirewallSystem], ruleset: Ruleset):
        self.system = system
        self.ruleset = ruleset

        self._run_tables = RunFirewallTables(self)

    def process_pre_routing(self, packet: PacketIP, flow: type[Flow]) -> (bool, (Rule, None)):
        log_info('Firewall', 'Processing Pre-Routing Filter-Hooks')
        if flow == FlowInputForward:
            # before DNAT we cannot know for sure
            flow = FlowInput

        return self._run_tables.process_pre_routing(packet=packet, flow=flow)

    def process_dnat(self, packet: PacketIP, flow: type[Flow]) -> (bool, (Rule, None)):
        if flow == FlowInputForward:
            # before DNAT we cannot know for sure
            flow = FlowInput

        if not self.system.FIREWALL_DNAT or 'dnat' not in self.system.FIREWALL_NAT[flow]:
            # system or flow has no DNAT capability
            return False, None

        log_info('Firewall', 'Processing DNAT')

        return self._run_tables.process_dnat(packet=packet, flow=flow)

    def process_main(self, packet: PacketIP, flow: type[Flow]) -> (bool, (Rule, None)):
        log_info('Firewall', 'Processing Main Filter-Hooks')

        return self._run_tables.process_main(packet=packet, flow=flow)

    def process_snat(self, packet: PacketIP, flow: type[Flow]) -> (bool, (Rule, None)):
        if not self.system.FIREWALL_SNAT or 'snat' not in self.system.FIREWALL_NAT[flow]:
            # system or flow has no SNAT capability
            return False, None

        log_info('Firewall', 'Processing SNAT')

        return self._run_tables.process_snat(packet=packet, flow=flow)

    def process_egress(self, packet: PacketIP, flow: type[Flow]) -> (bool, (Rule, None)):
        if 'snat' not in self.system.FIREWALL_NAT[flow]:
            # already processed all chains
            return True, None

        log_info('Firewall', 'Processing Egress Filter-Hooks')

        return self._run_tables.process_egress(packet=packet, flow=flow)

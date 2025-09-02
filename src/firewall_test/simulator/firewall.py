from typing import Callable

from config import FLOW_INPUT_FORWARD, FLOW_INPUT, PROTO_L3_IP4, PROTO_L3_IP6
from plugins.system.abstract import FirewallSystem
from plugins.translate.abstract import Ruleset, Table, Chain, Rule
from simulator.packet import PacketIP
from simulator.logger import log_debug, log_info


class Firewall:
    def __init__(self, system: type[FirewallSystem], ruleset: Ruleset):
        self.system = system
        self.ruleset = ruleset

    @staticmethod
    def _is_matching_table(packet: PacketIP, table: Table, ignore_type: list[str] = None) -> bool:
        if ignore_type is not None and table.type in ignore_type:
            return False

        if table.family == table.FAMILY_IP:
            return True

        if table.family == PROTO_L3_IP4 == packet.l3_proto:
            return True

        if table.family == PROTO_L3_IP6 == packet.l3_proto:
            return True

        return False

    def _get_tables(self, packet: PacketIP, ignore_type: list[str] = None) -> list[Table]:
        return [
            t for t in self.ruleset.tables
            if self._is_matching_table(packet=packet, table=t, ignore_type=ignore_type)
        ]

    @staticmethod
    def _is_matching_chain(packet: PacketIP, chain: Chain, ignore_type: list[str] = None) -> bool:
        if ignore_type is not None and chain.type in ignore_type:
            return False

        if chain.family == chain.FAMILY_IP:
            return True

        if chain.family == PROTO_L3_IP4 == packet.l3_proto:
            return True

        if chain.family == PROTO_L3_IP6 == packet.l3_proto:
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
        if not self.system.FIREWALL_PRIO_LOWER_BETTER:
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
        if not self.system.FIREWALL_PRIO_LOWER_BETTER:
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
        for hook in self.system.FIREWALL_HOOKS['full']:
            chains_filtered = [chain for chain in chains if chain.hook == hook]
            sorted_chains.extend(self.__sort_chains_by_priority(chains_filtered))

        return sorted_chains

    # todo: handle chains without hooks (jump/goto/...)
    def _is_chain_before_eq(self, chain: Chain, hook: str, priority: int) -> bool:
        if chain.hook is None:
            return False

        is_idx = self.system.FIREWALL_HOOKS['full'].index(chain.hook)
        check_idx = self.system.FIREWALL_HOOKS['full'].index(hook)
        if is_idx > check_idx:
            return False

        if is_idx == check_idx:
            return priority >= chain.priority

        return True

    def _is_chain_after(self, chain: Chain, hook: str, priority: int) -> bool:
        if chain.hook is None:
            return False

        return not self._is_chain_before_eq(chain=chain, hook=hook, priority=priority)

    @staticmethod
    def _inherit_table_priority_to_chain(table: Table, chain: Chain):
        if isinstance(chain.priority, int) and isinstance(table.priority, int):
            chain.priority += table.priority

        elif chain.priority is None and isinstance(table.priority, int):
            chain.priority = table.priority

    def _process_by_table_prio(self, tables: list[Table], callback_chain_filter: Callable[[Chain], bool]) -> (bool, (Rule, None)):
        for table in self._sort_tables_by_priority(tables):
            chains = [
                c for c in table.chains
                if callback_chain_filter(c)
            ]

            for chain in self._sort_chains_by_hook_and_priority(chains):
                log_debug(
                    'Firewall',
                    f'Processing Table {table.name}-{table.family} - Chain: {chain.name}-{chain.type}'
                )
                result, rule = self._process_chain(chain)
                if not result:
                    return False, rule

        return True, None

    def _process_by_chain_prio(self, tables: list[Table], callback_chain_filter: Callable[[Chain], bool]) -> (bool, (Rule, None)):
        chains: list[Chain] = []
        for table in tables:
            for chain in table.chains:
                if chain in chains:
                    continue

                if not callback_chain_filter(chain):
                    continue

                self._inherit_table_priority_to_chain(table, chain)

                chains.append(chain)

        for chain in self._sort_chains_by_hook_and_priority(chains):
            result, rule = self._process_chain(chain)
            if not result:
                return False, rule

        return True, None

    # todo: return rule that resulted in a negative outcome
    def _process_chain(self, chain: Chain) -> (bool, (dict, None)):
        log_debug('Firewall', f'Processing Chain: {chain.name}-{chain.type}')
        return True, None

    def process_pre_routing(self, packet: PacketIP, flow: str) -> (bool, (Rule, None)):
        log_info('Firewall', 'Processing Pre-Routing Filter-Hooks')
        if flow == FLOW_INPUT_FORWARD:
            # before DNAT we cannot know for sure
            flow = FLOW_INPUT

        def _chain_filter(chain: Chain) -> bool:
            before_dnat = self._is_chain_before_eq(chain=chain, **self.system.FIREWALL_NAT[flow]['dnat'])
            return chain.type != chain.TYPE_NAT and before_dnat

        tables = self._get_tables(packet=packet, ignore_type=[Table.TYPE_NAT])
        if self.system.FIREWALL_PRIO_TABLE_FULL:
            return self._process_by_table_prio(tables=tables, callback_chain_filter=_chain_filter)

        return self._process_by_chain_prio(tables=tables, callback_chain_filter=_chain_filter)

    def process_dnat(self, packet: PacketIP, flow: str) -> (bool, (Rule, None)):
        if flow == FLOW_INPUT_FORWARD:
            # before DNAT we cannot know for sure
            flow = FLOW_INPUT

        if 'dnat' not in self.system.FIREWALL_NAT[flow]:
            return False, None

        log_info('Firewall', 'Processing DNAT')

        def _chain_filter(chain: Chain) -> bool:
            chain_dnat = self.system.FIREWALL_NAT[flow]['dnat']
            return chain.type == chain.TYPE_NAT and \
                chain.hook == chain_dnat['hook'] and \
                chain.priority == chain_dnat['priority']

        tables = self._get_tables(packet=packet)
        if self.system.FIREWALL_PRIO_TABLE_FULL:
            result, rule = self._process_by_table_prio(tables=tables, callback_chain_filter=_chain_filter)

        else:
            result, rule = self._process_by_chain_prio(tables=tables, callback_chain_filter=_chain_filter)

        return not result, rule

    def process_main(self, packet: PacketIP, flow: str) -> (bool, (Rule, None)):
        log_info('Firewall', 'Processing Main Filter-Hooks')

        def _chain_filter(chain: Chain) -> bool:
            after_dnat = self._is_chain_after(chain=chain, **self.system.FIREWALL_NAT[flow]['dnat'])
            before_snat = True
            if 'snat' in self.system.FIREWALL_NAT[flow]:
                before_snat = self._is_chain_before_eq(chain=chain, **self.system.FIREWALL_NAT[flow]['snat'])

            return chain.type != chain.TYPE_NAT and after_dnat and before_snat

        tables = self._get_tables(packet=packet, ignore_type=[Table.TYPE_NAT])
        if self.system.FIREWALL_PRIO_TABLE_FULL:
            return self._process_by_table_prio(tables=tables, callback_chain_filter=_chain_filter)

        return self._process_by_chain_prio(tables=tables, callback_chain_filter=_chain_filter)

    def process_snat(self, packet: PacketIP, flow: str) -> (bool, (Rule, None)):
        if 'snat' not in self.system.FIREWALL_NAT[flow]:
            return False, None

        log_info('Firewall', 'Processing SNAT')

        def _chain_filter(chain: Chain) -> bool:
            chain_snat = self.system.FIREWALL_NAT[flow]['snat']
            return chain.type == chain.TYPE_NAT and \
                chain.hook == chain_snat['hook'] and \
                chain.priority == chain_snat['priority']

        tables = self._get_tables(packet=packet)
        if self.system.FIREWALL_PRIO_TABLE_FULL:
            result, rule = self._process_by_table_prio(tables=tables, callback_chain_filter=_chain_filter)

        else:
            result, rule = self._process_by_chain_prio(tables=tables, callback_chain_filter=_chain_filter)

        return not result, rule

    def process_egress(self, packet: PacketIP, flow: str) -> (bool, (Rule, None)):
        if 'snat' not in self.system.FIREWALL_NAT[flow]:
            # already processed all chains
            return True, None

        log_info('Firewall', 'Processing Egress Filter-Hooks')

        def _chain_filter(chain: Chain) -> bool:
            after_snat = self._is_chain_after(chain=chain, **self.system.FIREWALL_NAT[flow]['snat'])
            return chain.type != chain.TYPE_NAT and after_snat

        tables = self._get_tables(packet=packet, ignore_type=[Table.TYPE_NAT])
        if self.system.FIREWALL_PRIO_TABLE_FULL:
            return self._process_by_table_prio(tables=tables, callback_chain_filter=_chain_filter)

        return self._process_by_chain_prio(tables=tables, callback_chain_filter=_chain_filter)

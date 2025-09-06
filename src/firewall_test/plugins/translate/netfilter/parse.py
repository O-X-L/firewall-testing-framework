from json import loads as json_loads

from utils.logger import log_warn
from plugins.translate.netfilter.parts import VALID_ENTRIES
from plugins.translate.netfilter.elements import NftBase, NftTable, NftChain, NftRule, NftSet

# for schema see: https://www.mankier.com/5/libnftables-json

HANDLE_SEPARATOR = ' # handle '


class NetfilterPreParse:
    def __init__(self, raw: str):
        self.raw = json_loads(raw)['nftables']

        self.tables = []
        self.chains = []
        self.rules = []
        self.counters = []
        self.limits = []
        self.sets = []

        self._init()

    def _find_table(self, name: str, family: str) -> (NftTable|None):
        for table in self.tables:
            if table.name == name and table.family == family:
                return table

        return None

    def _find_chain(self, name: str, family: str) -> (NftChain|None):
        for chain in self.chains:
            if chain.name == name and chain.family == family:
                return chain

        return None

    def _parse_tables(self):
        for entry in self.raw:
            if isinstance(entry, dict) and 'table' in entry:
                entry = entry['table']

                self.tables.append(NftTable(raw=entry))

    def _parse_basic(self, key: str, entries: list, cls: type[NftBase]):
        for entry in self.raw:
            if isinstance(entry, dict) and key in entry:
                entry = entry[key]
                entries.append(cls(
                    raw=entry,
                    table=self._find_table(
                        name=entry['table'],
                        family=entry['family'],
                    ),
                ))

    def _parse_rules(self):
        chain_rule_seq = {}
        for entry in self.raw:
            if isinstance(entry, dict) and 'rule' in entry:
                entry = entry['rule']
                chain_unique = entry['chain'] + entry['family']
                if chain_unique not in chain_rule_seq:
                    seq = 0
                    chain_rule_seq[chain_unique] = seq

                else:
                    chain_rule_seq[chain_unique] += 1
                    seq = chain_rule_seq[chain_unique]

                rule = NftRule(
                    table=self._find_table(
                        name=entry['table'],
                        family=entry['family'],
                    ),
                    chain=self._find_chain(
                        name=entry['chain'],
                        family=entry['family'],
                    ),
                    raw=entry,
                    seq=seq,
                    sets=self.sets,
                )
                if rule.invalid_matches:
                    log_warn(
                        'Firewall Plugin',
                        v1=f'Unsupported rule: Table {rule.table.name}, Chain {rule.chain.name}, Rule {rule.seq}',
                        v4=f' | {rule.raw}'
                    )

                else:
                    self.rules.append(rule)

    def _init(self):
        for entry in self.raw:
            if not any(key in entry for key in VALID_ENTRIES):
                raise SystemExit(f"Got unexpected entry: '{entry}'")

        self._parse_tables()

        for key, cls, entries in [
            ('chain', NftChain, self.chains),
            ('set', NftSet, self.sets),
            ('map', NftSet, self.sets),
        ]:
            self._parse_basic(
                cls=cls,
                key=key,
                entries=entries,
            )

        self._parse_rules()

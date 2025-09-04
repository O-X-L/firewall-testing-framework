from abc import ABC

from plugins.translate.netfilter.parts import RULE_ACTIONS

# for schema see: https://www.mankier.com/5/libnftables-json


class NftBase(ABC):
    KEY = ''

    def __init__(self, raw: dict, table=None):
        self.handle = raw['handle']
        if table is not None:
            self.table = table


class NftTable(NftBase):
    def __init__(self, raw: dict):
        NftBase.__init__(self=self, raw=raw)
        self.family = raw.get('family', None)
        self.name = raw.get('name', None)
        self.prio = raw.get('prio', None)

    def __repr__(self) -> str:
        return f"Table: '{self.name}' {self.family} | ID {self.handle}"


class NftChain(NftBase):
    def __init__(self, raw: dict, table: NftTable):
        NftBase.__init__(self=self, raw=raw, table=table)
        self.name = raw.get('name', None)
        self.type = raw.get('type', None)
        self.family = raw.get('family', None)
        self.hook = raw.get('hook', None)
        self.prio = raw.get('prio', None)
        self.dev = raw.get('dev', None)
        self.policy = raw.get('policy', None)

    def __repr__(self) -> str:
        return f"Chain: '{self.name}' {self.family} {self.type} {self.hook} {self.prio} | ID {self.handle}"


class NftMatch:
    def __init__(self, operator: str, left: str, right: str):
        self.operator = operator
        self.match = left
        self.value = right

    def __repr__(self) -> str:
        return f"Match: {self.match} {self.operator} {self.value}"


class NftSet(NftBase):
    def __init__(self, raw: dict, table: NftTable):
        NftBase.__init__(self=self, raw=raw, table=table)
        self.family = raw.get('family', None)
        self.name = raw.get('name', None)
        self.type = raw.get('type', None)
        self.policy = raw.get('policy', None)
        self.flags = raw.get('flags', None)
        self.elem = raw.get('elem', None)
        self.timeout = raw.get('timeout', None)
        self.gc_interval = raw.get('gc-interval', None)
        self.size = raw.get('size', None)

    def __repr__(self) -> str:
        return f"Set: {self.name} {self.family} | ID {self.handle}"


class NftJump:
    def __init__(self, chain: NftChain):
        self.chain = chain

    def __repr__(self) -> str:
        return f"Jump: chain {self.chain.name}"


class NftGoTo:
    def __init__(self, chain: NftChain):
        self.chain = chain

    def __repr__(self) -> str:
        return f"Go-to: chain {self.chain.name}"


class NftRule(NftBase):
    def __init__(self, table: NftTable, chain: NftChain, raw: dict, seq: int):
        NftBase.__init__(self=self, raw=raw, table=table)
        self.chain = chain
        self.seq = seq

        self.comment = raw.get('comment', None)
        self.index = raw.get('index', None)
        self.family = raw.get('family', None)

        self.matches = []
        self.jump = None
        self.goto = None
        self.action = None

        for expression in raw['expr']:
            for a in RULE_ACTIONS:
                if a in expression:
                    self.action = a

            self._init_match(expression)
            self._init_jump(expression)
            self._init_goto(expression)

    def _init_goto(self, e: dict):
        if 'goto' in e:
            self.goto = NftGoTo(e['goto']['target'])

    def _init_jump(self, e: dict):
        if 'jump' in e:
            self.jump = NftJump(e['jump']['target'])

    def _init_match(self, e: dict):
        if 'match' in e:
            self.matches.append(
                NftMatch(
                    operator=e['match']['op'],
                    left=self._parse_rule_match(
                        expression=e, side='left'
                    ),
                    right=self._parse_rule_match(
                        expression=e, side='right'
                    ),
                )
            )

    @staticmethod
    def _parse_rule_match(expression: dict, side: str) -> str:
        parts = []
        side = expression['match'][side]

        if isinstance(side, dict):
            for v in side.values():
                if isinstance(v, dict):
                    for v2 in v.values():
                        parts.append(v2)

                else:
                    parts.append(v)

        else:
            parts.append(side)

        return ' '.join(map(str, parts))

    def __repr__(self) -> str:
        cmt = ''
        if self.comment is not None:
            cmt = f' "{self.comment}"'

        return f"Rule: #{self.handle}{cmt}"

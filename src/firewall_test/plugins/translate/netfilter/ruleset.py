from config import ProtoL3IP4, ProtoL3IP4IP6, ProtoL3IP6
from plugins.system.linux_netfilter import SystemLinuxNetfilter
from plugins.translate.abstract import TranslatePluginRuleset, TranslatePluginTable, TranslatePluginChain, \
    TranslatePluginRule, Ruleset, Table, Chain, Rule
from plugins.translate.netfilter.parse import NetfilterPreParse, NftTable, NftChain, NftRule


class NetfilterRule(TranslatePluginRule):
    def __init__(self, raw: NftRule):
        super().__init__(raw)

    def get(self) -> Rule:
        return Rule(**self.raw)


class NetfilterChainOutput(Chain):
    def _validate_hooks(self):
        assert self.hook is None or self.hook in SystemLinuxNetfilter.FIREWALL_HOOKS


class NetfilterChain(TranslatePluginChain):
    def __init__(self, raw: NftChain):
        super().__init__(raw)
        self.rules: list[NetfilterRule] = []

    def get(self) -> Chain:
        family = self.raw.family
        if family == 'ip':
            family = ProtoL3IP4

        elif family == 'inet':
            family = ProtoL3IP4IP6

        else:
            family = ProtoL3IP6

        if isinstance(self.raw.prio, int) or (isinstance(self.raw.prio, str) and self.raw.prio.isnumeric()):
            prio = int(self.raw.prio)

        else:
            prio = 0

        if self.raw.policy is None:
            policy = Chain.POLICY_ACCEPT

        else:
            policy = self.raw.policy

        if self.raw.type is None:
            chain_type = Chain.TYPE_FILTER

        else:
            chain_type = self.raw.type

        return NetfilterChainOutput(
            name=self.raw.name,
            type=chain_type,
            family=family,
            hook=self.raw.hook,
            priority=prio,
            policy=policy,
            rules=[r.get() for r in self.rules]
        )


class NetfilterTable(TranslatePluginTable):
    def __init__(self, raw: NftTable):
        super().__init__(raw)
        self.chains: list[NetfilterChain] = []

    def get(self) -> Table:
        family = self.raw.family
        if family == 'ip':
            family = ProtoL3IP4

        elif family == 'inet':
            family = ProtoL3IP4IP6

        else:
            family = ProtoL3IP6

        if isinstance(self.raw.prio, int) or (isinstance(self.raw.prio, str) and self.raw.prio.isnumeric()):
            prio = int(self.raw.prio)

        else:
            prio = 0

        return Table(
            name=self.raw.name,
            family=family,
            priority=prio,
            chains=[c.get() for c in self.chains],
        )


class NetfilterRuleset(TranslatePluginRuleset):
    def __init__(self, raw: str):
        self._pre_parse = NetfilterPreParse(raw)
        super().__init__(self._pre_parse)

    def get(self) -> Ruleset:
        tables: list[NetfilterTable] = [NetfilterTable(t) for t in self.raw.tables]
        for c in self.raw.chains:
            for t in tables:
                if c.table.name == t.raw.name and c.table.family == t.raw.family:
                    t.chains.append(NetfilterChain(c))

        return Ruleset([t.get() for t in tables])

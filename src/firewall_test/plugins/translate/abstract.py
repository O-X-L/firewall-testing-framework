from abc import ABC, abstractmethod
from ipaddress import ip_network, ip_address, IPv4Network, IPv6Network, IPv4Address, IPv6Address


class TranslatePlugin(ABC):
    def __init__(self, raw: (str, dict, list[dict])):
        self.raw = raw

    @abstractmethod
    def get(self) -> (dict, list[dict]):
        pass


class TranslateOutput(ABC):
    @abstractmethod
    def dump(self) -> (dict, list[dict]):
        pass

    @abstractmethod
    def validate(self):
        pass


# ROUTES: static route
class TranslateOutputStaticRoute(TranslateOutput):
    # pylint: disable=W0622
    def __init__(
        self, table: str, dst: str, scope: str, type: str, gw: str = None, src_pref: str = None,
        dev: str = None, metric: int = None,
    ):
        self.table = table
        self.dst = dst
        self.scope = scope
        self.type = type
        self.gw = gw
        self.src_pref = src_pref
        self.dev = dev
        self.metric = metric

    def __repr__(self) -> str:
        return f'ROUTE: Destination {self.dst} in Table {self.table} via {self.dev} {self.gw} metric {self.metric}'

    def dump(self) -> dict:
        src_pref, gw, dst = None, None, None
        if self.src_pref is not None:
            src_pref = ip_address(self.src_pref)

        if self.gw is not None:
            gw = ip_address(self.gw)

        if self.dst is not None:
            dst = ip_network(self.dst)

        metric = None
        if self.metric is not None:
            metric = int(self.metric)

        return {
            'table': self.table,
            'dst': dst,
            'scope': self.scope,
            'type': self.type,
            'gw': gw,
            'src_pref': src_pref,
            'dev': self.dev,
            'metric': metric,
        }

    def validate(self):
        r = self.dump()
        assert isinstance(r['dst'], (IPv4Network, IPv6Network))

        if r['gw'] is not None:
            assert isinstance(r['gw'], (IPv4Address, IPv6Address))

        if r['src_pref'] is not None:
            assert isinstance(r['src_pref'], (IPv4Address, IPv6Address))

        assert r['table'] in ['default', 'main', 'local', 'test']
        assert r['type'] in ['default', 'local', 'broadcast', 'multicast']


class TranslatePluginStaticRoutes(TranslatePlugin):
    def __init__(self, raw: list[dict]):
        super().__init__(raw)

    @abstractmethod
    def get(self) -> list[TranslateOutputStaticRoute]:
        routes = []
        for route in self.raw:
            routes.append(
                TranslateOutputStaticRoute(**route)
            )

        return routes


# ROUTE-RULES: for source-based routing
class TranslateOutputStaticRouteRule(TranslateOutput):
    def __init__(
        self, table: str, src: list[str], priority: int,
    ):
        self.table = table
        self.src = src
        self.priority = priority

    def __repr__(self) -> str:
        return f'ROUTE-RULE: Source {self.src} => Table {self.table} with priority {self.priority}'

    def dump(self) -> dict:
        src = []
        if isinstance(self.src, list) and len(self.src) > 0:
            for s in self.src:
                src.append(ip_network(s))

        prio = None
        if self.priority is not None:
            prio = int(self.priority)

        return {
            'table': self.table,
            'src': src,
            'priority': prio,
        }

    def validate(self):
        r = self.dump()
        assert isinstance(r['priority'], int)
        assert isinstance(r['src'], list)
        assert len(r['src']) > 0

        for net in r['src']:
            assert isinstance(net, (IPv4Network, IPv6Network))


class TranslatePluginStaticRouteRules(TranslatePlugin):
    def __init__(self, raw: list[dict]):
        super().__init__(raw)

    @abstractmethod
    def get(self) -> list[TranslateOutputStaticRouteRule]:
        return [
            TranslateOutputStaticRouteRule(**rule) for rule in self.raw
        ]


# RULE: a firewall-rule
class TranslateOutputRule(TranslateOutput):
    def __init__(
        self, action: str,
    ):
        self.action = action
        # todo: extend

    def dump(self) -> dict:
        return {
            'action': self.action,
        }

    def validate(self):
        # r = self.dump()
        pass


class TranslatePluginRule(TranslatePlugin):
    def __init__(self, raw: dict):
        super().__init__(raw)

    def get(self) -> TranslateOutputRule:
        # action: accept/drop/reject/jump/goto/...
        # action_delayed: pf-like lazy-matching (bsd)
        # l3_proto & invert
        # saddr & invert
        # daddr & invert
        # l4_proto & invert
        # l4_sport & invert
        # l4_dport & invert
        # icmp_type & invert
        # icmp_code & invert
        # icmp6_type & invert
        # icmp6_code & invert
        # ...
        return TranslateOutputRule(**self.raw)


# CHAIN: contains the actual rules
class TranslateOutputChain(TranslateOutput):
    def __init__(
        self, name: str, hook: str, policy: str, rules: list[TranslateOutputRule], priority: int = 0,
    ):
        self.name = name
        self.hook = hook
        self.policy = policy  # (accept/drop/reject)
        self.priority = priority
        self.rules = rules

    def dump(self) -> dict:
        return {
            "name": self.name,
            "hook": self.hook,
            "policy": self.policy,
            "priority": self.priority,
            "rules": [r.dump() for r in self.rules],
        }

    def validate(self):
        # r = self.dump()
        pass


class TranslatePluginChain(TranslatePlugin):
    def __init__(self, raw: dict):
        super().__init__(raw)

    def get(self) -> TranslateOutputChain:
        rules = self.raw.pop('rules')
        return TranslateOutputChain(
            **self.raw,
            rules=[
                TranslateOutputRule(**rule) for rule in rules
            ]
        )


# TABLE: contains chains that contain the actual rules
class TranslateOutputTable(TranslateOutput):
    def __init__(
        self, name: str, chains: list[TranslateOutputChain], priority: int = 0,
    ):
        self.name = name
        self.priority = priority
        self.chains = chains

    def dump(self) -> dict:
        return {
            "name": self.name,
            "priority": self.priority,
            "chains": [r.dump() for r in self.chains],
        }

    def validate(self):
        # r = self.dump()
        pass


class TranslatePluginTable(TranslatePlugin):
    def __init__(self, raw: dict):
        super().__init__(raw)

    def get(self) -> TranslateOutputTable:
        chains = self.raw.pop('chains')
        return TranslateOutputTable(
            **self.raw,
            chains=[
                TranslateOutputChain(**chain) for chain in chains
            ]
        )


# RULESET: list of tables that contain chains that contain the actual rules
class TranslateOutputRuleset(TranslateOutput):
    def __init__(self, tables: list[TranslateOutputTable]):
        self.tables = tables

    def dump(self) -> dict:
        return {
            "tables": [t.dump() for t in self.tables],
        }

    def validate(self):
        # r = self.dump()
        pass


class TranslatePluginRuleset(TranslatePlugin):
    def __init__(self, raw: list[dict]):
        super().__init__(raw)

    @abstractmethod
    def get(self) -> list[TranslateOutputTable]:
        return [
            TranslateOutputTable(**table) for table in self.raw['tables']
        ]

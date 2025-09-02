from abc import ABC, abstractmethod
from ipaddress import ip_network, ip_address, IPv4Network, IPv6Network, IPv4Address, IPv6Address
from re import compile as regex_compile

REGEX_MAC_ADDRESS = regex_compile(r'^[\da-f]{2}:[\da-f]{2}:[\da-f]{2}:[\da-f]{2}:[\da-f]{2}:[\da-f]{2}$')


class TranslatePlugin(ABC):
    def __init__(self, raw: any):
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
class StaticRoute(TranslateOutput):
    # pylint: disable=W0622
    def __init__(
        self, table: str, net: str, scope: str, type: str, gw: str = None, src_pref: str = None,
        ni: str = None, metric: int = None,
    ):
        self.table = table
        self.net = net
        self.scope = scope
        self.type = type
        self.gw = gw
        self.src_pref = src_pref
        self.ni = ni
        self.metric = metric

    def __repr__(self) -> str:
        return f'ROUTE: Network {self.net} in Table {self.table} via {self.ni} {self.gw} metric {self.metric} type {self.type}'

    def dump(self) -> dict:
        src_pref, gw, net = None, None, None
        if self.src_pref is not None:
            src_pref = ip_address(self.src_pref)

        if self.gw is not None:
            gw = ip_address(self.gw)

        if self.net is not None:
            net = ip_network(self.net)

        metric = None
        if self.metric is not None:
            metric = int(self.metric)

        return {
            'table': self.table,
            'net': net,
            'scope': self.scope,
            'type': self.type,
            'gw': gw,
            'src_pref': src_pref,
            'ni': self.ni,
            'metric': metric,
        }

    def validate(self):
        r = self.dump()
        assert isinstance(r['net'], (IPv4Network, IPv6Network))

        if r['gw'] is not None:
            assert isinstance(r['gw'], (IPv4Address, IPv6Address))

        if r['src_pref'] is not None:
            assert isinstance(r['src_pref'], (IPv4Address, IPv6Address))

        assert r['table'] in ['default', 'main', 'local', 'test']
        assert r['type'] in ['default', 'local', 'broadcast', 'multicast']
        assert r['scope'] in ['link', 'host', 'global', 'remote']

    def ip_count(self) -> int:
        cidr = int(str(self.net).split('/')[1])
        if str(self.net).find(':') == -1:
            return 2 ** (32 - cidr)

        return 2 ** (128 - cidr)

class TranslatePluginStaticRoutes(TranslatePlugin):
    def __init__(self, raw: list[dict]):
        super().__init__(raw)

    @abstractmethod
    def get(self) -> list[StaticRoute]:
        routes = []
        for route in self.raw:
            routes.append(
                StaticRoute(**route)
            )

        return routes


# ROUTE-RULES: for source-based routing
class StaticRouteRule(TranslateOutput):
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
    def get(self) -> list[StaticRouteRule]:
        return [
            StaticRouteRule(**rule) for rule in self.raw
        ]


# INTERFACES
class NetworkInterface(TranslateOutput):
    # pylint: disable=W0622
    def __init__(
            self,
            name: str, up: bool, ip4: list[str], ip6: list[str],
            net4: list[str], net6: list[str], mac: str = None,
    ):
        self.name = name
        self.up = up
        self.ip4 = ip4
        self.ip6 = ip6
        self.net4 = net4
        self.net6 = net6
        self.mac = mac

    def __repr__(self) -> str:
        return f'NETWORK-INTERFACE: {self.name} with IPv4 {self.ip4} and IPv6 {self.ip6}'

    def dump(self) -> dict:
        ip4, ip6, net4, net6 = [], [], [], []
        for ip in self.ip4:
            ip4.append(ip_address(ip))

        for ip in self.ip6:
            ip6.append(ip_address(ip))

        for net in self.net4:
            net4.append(ip_network(net))

        for net in self.net6:
            net6.append(ip_network(net))

        return {
            'name': self.name,
            'up': self.up,
            'ip4': ip4,
            'ip6': ip6,
            'net4': net4,
            'net6': net6,
            'mac': self.mac,
        }

    def validate(self):
        r = self.dump()
        assert isinstance(r['up'], bool)
        if r['mac'] is not None:
            assert REGEX_MAC_ADDRESS.match(r['mac']) is not None

        for ip in r['ip4']:
            assert isinstance(ip, IPv4Address)

        for ip in r['ip6']:
            assert isinstance(ip, IPv6Address)

        for net in r['net4']:
            assert isinstance(net, IPv4Network)

        for net in r['net6']:
            assert isinstance(net, IPv6Network)


class TranslatePluginNetworkInterfaces(TranslatePlugin):
    def __init__(self, raw: list[dict]):
        super().__init__(raw)

    @abstractmethod
    def get(self) -> list[NetworkInterface]:
        return [
            NetworkInterface(**ni) for ni in self.raw
        ]


# RULE: a firewall-rule
class Rule(TranslateOutput):
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
    def __init__(self, raw: any):
        super().__init__(raw)

    @abstractmethod
    def get(self) -> Rule:
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
        return Rule(**self.raw)


# CHAIN: contains the actual rules
class Chain(TranslateOutput):
    def __init__(
        self, name: str, hook: str, policy: str, rules: list[Rule], priority: int = 0,
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
    def __init__(self, raw: any):
        super().__init__(raw)

    @abstractmethod
    def get(self) -> Chain:
        rules = self.raw.pop('rules')
        return Chain(
            **self.raw,
            rules=[
                Rule(**rule) for rule in rules
            ]
        )


# TABLE: contains chains that contain the actual rules
class Table(TranslateOutput):
    def __init__(
        self, name: str, chains: list[Chain], priority: int = 0,
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
    def __init__(self, raw: any):
        super().__init__(raw)

    @abstractmethod
    def get(self) -> Table:
        chains = self.raw.pop('chains')
        return Table(
            **self.raw,
            chains=[
                Chain(**chain) for chain in chains
            ]
        )


# RULESET: list of tables that contain chains that contain the actual rules
class Ruleset(TranslateOutput):
    def __init__(self, tables: list[Table]):
        self.tables = tables

    def dump(self) -> dict:
        return {
            "tables": [t.dump() for t in self.tables],
        }

    def validate(self):
        # r = self.dump()
        pass


class TranslatePluginRuleset(TranslatePlugin):
    def __init__(self, raw: any):
        super().__init__(raw)

    @abstractmethod
    def get(self) -> list[Table]:
        return [
            Table(**table) for table in self.raw['tables']
        ]

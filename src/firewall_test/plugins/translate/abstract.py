from abc import ABC, abstractmethod
from ipaddress import ip_network, ip_address, IPv4Network, IPv6Network, IPv4Address, IPv6Address
from re import compile as regex_compile

from config import ProtoL3, ProtoL3IP4, ProtoL3IP6, PROTOS_L3, ProtoL3IP4IP6, \
    RuleAction, RuleActionAccept, RuleActionReject, RuleActionDrop, \
    RuleActionJump, RuleActionGoTo, RuleActionContinue, RULE_ACTIONS, RuleActionReturn, RULE_ACTION_MAPPING

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
        self, table: str, net: str, scope: str, gw: str = None, src_pref: str = None,
        ni: str = None, metric: int = None,
    ):
        self.table = table
        self.net = net
        self.scope = scope
        self.gw = gw
        self.src_pref = src_pref
        self.ni = ni
        self.metric = metric

        if self.src_pref is not None:
            self.src_pref = ip_address(self.src_pref)

    def __repr__(self) -> str:
        return f'ROUTE: Network {self.net} in Table {self.table} via {self.ni} {self.gw} metric {self.metric}'

    def dump(self) -> dict:
        gw, net = None, None
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
            'gw': gw,
            'src_pref': self.src_pref,
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
        assert r['scope'] in ['link', 'local', 'global']

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
            net4: list[str], net6: list[str], mac: str = None, desc: str = None,
    ):
        self.name = name
        self.up = up
        self.ip4 = ip4
        self.ip6 = ip6
        self.net4 = net4
        self.net6 = net6
        self.mac = mac
        self.desc = desc

    def __repr__(self) -> str:
        desc = '' if self.desc is None else f' description {self.desc}'
        return f'NETWORK-INTERFACE: {self.name} with IPv4 {self.ip4} and IPv6 {self.ip6}{desc}'

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
            ProtoL3IP4: ip4,
            ProtoL3IP6: ip6,
            'net4': net4,
            'net6': net6,
            'mac': self.mac,
            'desc': self.desc,
        }

    def validate(self):
        r = self.dump()
        assert isinstance(r['up'], bool)
        if r['mac'] is not None:
            assert REGEX_MAC_ADDRESS.match(r['mac']) is not None

        for ip in r[ProtoL3IP4]:
            assert isinstance(ip, IPv4Address)

        for ip in r[ProtoL3IP6]:
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
    ACTION_ACCEPT = RuleActionAccept.N
    ACTION_DROP = RuleActionDrop.N
    ACTION_REJECT = RuleActionReject.N
    ACTION_JUMP = RuleActionJump.N
    ACTION_GOTO = RuleActionGoTo.N
    ACTION_CONTINUE = RuleActionContinue.N
    ACTION_RETURN = RuleActionReturn.N
    ACTIONS = [ACTION_ACCEPT, ACTION_DROP, ACTION_REJECT, ACTION_JUMP, ACTION_GOTO, ACTION_CONTINUE, ACTION_RETURN, None]

    def __init__(self, action: type[RuleAction], seq: int, raw: any, action_lazy: bool = False):
        self.action: type[RuleAction] = action
        self.seq = seq  # sequence inside chain
        self.raw = raw  # interpreted in system-specific RuleMatcher
        self.action_lazy = action_lazy

    def __repr__(self) -> str:
        raw = self.raw
        if hasattr(self.raw, 'dump'):
            raw = self.raw.dump()

        return f'RULE: Sequence {self.seq} action {self.action.N} raw: "{raw}"'

    def dump(self) -> dict:
        action = self.action
        if action is not None:
            action = action.N

        return {
            'action': action,
            'seq': self.seq,
            'raw': self.raw,
        }

    def log(self) -> str:
        return f'Seq {self.seq}, Action: {self.action.N}, {self.raw}'

    def validate(self):
        r = self.dump()
        if self.action is not None:
            assert self.action in RULE_ACTIONS

        assert r['action'] in self.ACTIONS

        assert isinstance(r['seq'], int)
        assert self.raw is not None


class TranslatePluginRule(TranslatePlugin):
    @abstractmethod
    def get(self) -> Rule:
        return Rule(**self.raw)


# CHAIN: contains the actual rules
class Chain(TranslateOutput):
    TYPE_FILTER = 'filter'
    TYPE_NAT = 'nat'
    TYPE_ROUTE = 'route'
    TYPES = [TYPE_FILTER, TYPE_NAT, TYPE_ROUTE]

    FAMILY_IP = ProtoL3IP4IP6.N
    FAMILY_IP4 = ProtoL3IP4.N
    FAMILY_IP6 = ProtoL3IP6.N
    FAMILIES = [FAMILY_IP, FAMILY_IP4, FAMILY_IP6]

    POLICY_ACCEPT = RuleActionAccept
    POLICY_DROP = RuleActionDrop
    POLICY_REJECT = RuleActionReject

    # pylint: disable=W0622
    def __init__(
        self, name: str, hook: (str, None), policy: (None, RuleActionAccept, RuleActionDrop, RuleActionReject),
            rules: list[Rule], priority: int = 0, type: str = 'filter', family: type[ProtoL3] = ProtoL3IP4IP6,
    ):
        self.name = name
        self.type = type
        self.family: type[ProtoL3] = family
        self.hook = hook
        self.priority = priority
        self.policy = policy
        self.rules = rules

        if self.policy is None:
            self.policy = RuleActionAccept

        # runtime infos
        self.run_table = None

    def dump(self) -> dict:
        return {
            "name": self.name,
            "type": self.type,
            "hook": self.hook,
            "policy": self.policy.N,
            "priority": self.priority,
            "family": self.family.N,
            "rules": [r.dump() for r in self.rules],
        }

    @abstractmethod
    def _validate_hooks(self):
        # system-specific hooks => validation needs to be implemented at that level
        pass

    def validate(self):
        r = self.dump()
        assert isinstance(r['name'], str)
        assert len(r['name']) > 0
        assert r['policy'] in RULE_ACTION_MAPPING
        assert isinstance(r['priority'], int)
        assert r['type'] in self.TYPES
        if len(r['rules']) > 0:
            for r2 in self.rules:
                assert isinstance(r2, Rule)

            for r2 in r['rules']:
                assert isinstance(r2, dict)

        assert self.family in PROTOS_L3
        assert r['family'] in self.FAMILIES
        self._validate_hooks()


class TranslatePluginChain(TranslatePlugin):
    @abstractmethod
    def get(self) -> Chain:
        rules = self.raw.pop('rules')
        # pylint: disable=E0110
        return Chain(
            **self.raw,
            rules=[
                Rule(**rule) for rule in rules
            ]
        )


# TABLE: contains chains that contain the actual rules
class Table(TranslateOutput):
    TYPE_FILTER = 'filter'
    TYPE_NAT = 'nat'
    TYPES = [TYPE_FILTER, TYPE_NAT]

    FAMILY_IP = ProtoL3IP4IP6.N
    FAMILY_IP4 = ProtoL3IP4.N
    FAMILY_IP6 = ProtoL3IP6.N
    FAMILIES = [FAMILY_IP, FAMILY_IP4, FAMILY_IP6]

    # pylint: disable=W0622
    def __init__(
        self, name: str, chains: list[Chain], priority: int = 0, family: type[ProtoL3] = ProtoL3IP4IP6, type: str = 'filter',
    ):
        self.name = name
        self.type = type
        self.priority = priority
        self.chains = chains
        self.family: type[ProtoL3] = family

    def dump(self) -> dict:
        return {
            "name": self.name,
            "type": self.type,
            "priority": self.priority,
            "family": self.family.N,
            "chains": [r.dump() for r in self.chains],
        }

    def validate(self):
        r = self.dump()
        assert isinstance(r['name'], str)
        assert len(r['name']) > 0
        assert isinstance(r['priority'], int)
        assert r['type'] in self.TYPES
        if len(r['chains']) > 0:
            for c in self.chains:
                assert isinstance(c, Chain)

            for c in r['chains']:
                assert isinstance(c, dict)

        assert self.family in PROTOS_L3
        assert r['family'] in self.FAMILIES


class TranslatePluginTable(TranslatePlugin):
    @abstractmethod
    def get(self) -> Table:
        chains = self.raw.pop('chains')
        # pylint: disable=E0110
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
        r = self.dump()
        if len(r['tables']) > 0:
            for t in self.tables:
                assert isinstance(t, Table)

            for t in r['tables']:
                assert isinstance(t, dict)


class TranslatePluginRuleset(TranslatePlugin):
    @abstractmethod
    def get(self) -> list[Table]:
        return [
            Table(**table) for table in self.raw['tables']
        ]

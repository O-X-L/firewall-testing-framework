from abc import ABC, abstractmethod
from ipaddress import ip_network, ip_address, IPv4Network, IPv6Network, IPv4Address, IPv6Address
from re import compile as regex_compile

from config import ProtoL3, ProtoL3IP4, ProtoL3IP6, ProtoL4, PROTOS_L4, PROTOS_L3, ProtoL3IP4IP6
from simulator.logger import log_warn

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
            ProtoL3IP4: ip4,
            ProtoL3IP6: ip6,
            'net4': net4,
            'net6': net6,
            'mac': self.mac,
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


# RULE-MATCH
class RuleMatch(TranslateOutput):
    MATCH_NI = 'ni'
    MATCH_IP_NET = 'ip'
    MATCH_PROTO_L3 = 'proto_l3'
    MATCH_PROTO_L4 = 'proto_l4'
    MATCH_ICMP_CODE = 'icmp_code'
    MATCH_PORT = 'port'

    OP_EQ = '='
    OP_NE = '!='
    OP_GT = '>'
    OP_LT = '<'

    FIELD_IP_SRC = 'saddr'
    FIELD_IP_DST = 'daddr'
    FIELD_PORT_SRC = 'sport'
    FIELD_PORT_DST = 'dport'

    PORT_RANGE_SEP = ['-', ':']

    # pylint: disable=W0622
    def __init__(self, type: str, operator: str, compare: list, field: str = None):
        self.match_type = type
        self.operator = operator
        self.compare = compare
        self.field = field

    def _prepare_ports(self) -> list[int]:
        compare = []
        for c in self.compare:
            if isinstance(c, int):
                compare.append(c)
                continue

            if c.isnumeric():
                compare.append(int(c))
                continue

            # explode port-ranges
            port_range = False
            for range_char in self.PORT_RANGE_SEP:
                if port_range:
                    break

                port_range = True
                if c.find(range_char) != -1:
                    p1, p2 = c.split(range_char, 1)
                    if p1.isnumeric() and p2.isnumeric():
                        compare.extend(p for p in range(int(p1), int(p2) + 1))

            if not port_range:
                log_warn('Firewall', f"Unable to parse port-match: '{c}'")

        return compare

    def dump(self) -> dict:
        compare = self.compare
        if self.match_type == self.MATCH_IP_NET:
            compare = []
            for c in self.compare:
                compare.append(ip_network(c))

        elif self.match_type == self.MATCH_PORT:
            compare = self._prepare_ports()

        return {
            'type': self.match_type,
            'operator': self.operator,
            'field': self.field,
            'compare': compare,
        }

    def validate(self):
        r = self.dump()
        assert r['type'] in [
            self.MATCH_IP_NET, self.MATCH_ICMP_CODE, self.MATCH_NI,
            self.MATCH_PROTO_L3, self.MATCH_PROTO_L4, self.MATCH_PORT,
        ]
        if r['type'] == self.MATCH_PORT and len(r['compare']) == 1:
            assert r['operator'] in [self.OP_EQ, self.OP_NE, self.OP_LT, self.OP_GT]

        else:
            assert r['operator'] in [self.OP_EQ, self.OP_NE]

        assert r['field'] in [
            None,
            self.FIELD_IP_SRC,
            self.FIELD_IP_DST,
            self.FIELD_PORT_SRC,
            self.FIELD_PORT_DST,
        ]

        assert r['compare'] is not None
        assert len(r['compare']) > 0
        if r['type'] == self.MATCH_IP_NET:
            assert r['field'] in [self.FIELD_IP_SRC, self.FIELD_IP_DST]
            for ip_net in r['compare']:
                assert isinstance(ip_net, (IPv4Network, IPv6Network))

        if r['type'] == self.MATCH_PORT:
            assert r['field'] in [self.FIELD_PORT_SRC, self.FIELD_PORT_DST]
            for port in r['compare']:
                assert isinstance(port, int)
                assert 0 < port < 65536

        if r['type'] == self.MATCH_PROTO_L3:
            for proto_l3 in r['compare']:
                assert proto_l3 in PROTOS_L3

        if r['type'] == self.MATCH_PROTO_L4:
            for proto_l4 in r['compare']:
                assert proto_l4 in PROTOS_L4


# RULE: a firewall-rule
class Rule(TranslateOutput):
    def __init__(
            self, action: str, seq: int, matches: list[RuleMatch],
            comment: str,
    ):
        self.action = action
        self.seq = seq  # sequence inside chain
        self.matches: list[RuleMatch] = matches
        self.comment = comment  # comment or log-msg

    def dump(self) -> dict:
        return {
            'action': self.action,
            'seq': self.seq,
            'comment': self.comment,
            'matches': [match.dump() for match in self.matches],
        }

    def validate(self):
        r = self.dump()
        assert r['action'] in ['accept', 'drop', 'reject', 'jump', 'goto']
        assert isinstance(r['seq'], int)
        assert isinstance(r['matches'], list)
        assert len(r['matches']) > 0
        assert isinstance(r['matches'][0], list)


class TranslatePluginRule(TranslatePlugin):
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
    TYPE_FILTER = 'filter'
    TYPE_NAT = 'nat'
    TYPE_ROUTE = 'route'

    FAMILY_IP = ProtoL3IP4IP6.N
    FAMILY_IP4 = ProtoL3IP4.N
    FAMILY_IP6 = ProtoL3IP6.N

    POLICY_ACCEPT = 'accept'
    POLICY_DROP = 'drop'
    POLICY_REJECT = 'reject'

    # pylint: disable=W0622
    def __init__(
        self, name: str, hook: str, policy: str, rules: list[Rule], priority: int = 0,
            type: str = 'filter', family: type[ProtoL3] = ProtoL3IP4IP6,
    ):
        self.name = name
        self.type = type
        self.family: type[ProtoL3] = family
        self.hook = hook
        self.priority = priority
        self.policy = policy
        self.rules = rules

        # runtime infos
        self.log_table = None

    def dump(self) -> dict:
        return {
            "name": self.name,
            "type": self.type,
            "hook": self.hook,
            "policy": self.policy,
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
        assert r['policy'] in [self.POLICY_ACCEPT, self.POLICY_DROP, self.POLICY_REJECT]
        assert isinstance(r['priority'], int)
        assert r['type'] in [self.TYPE_FILTER, self.TYPE_NAT, self.TYPE_ROUTE]
        if len(r['rules']) > 0:
            for r in r['rules']:
                assert isinstance(r, dict)

        assert self.family in PROTOS_L3
        assert r['family'] in [self.FAMILY_IP, self.FAMILY_IP4, self.FAMILY_IP6]
        self._validate_hooks()


class TranslatePluginChain(TranslatePlugin):
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
    TYPE_FILTER = 'filter'
    TYPE_NAT = 'nat'

    FAMILY_IP = ProtoL3IP4IP6.N
    FAMILY_IP4 = ProtoL3IP4.N
    FAMILY_IP6 = ProtoL3IP6.N

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
        assert r['type'] in [self.TYPE_FILTER, self.TYPE_NAT]
        if len(r['chains']) > 0:
            for c in r['chains']:
                assert isinstance(c, dict)

        assert self.family in PROTOS_L3
        assert r['family'] in [self.FAMILY_IP, self.FAMILY_IP4, self.FAMILY_IP6]


class TranslatePluginTable(TranslatePlugin):
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
        r = self.dump()
        if len(r['tables']) > 0:
            for t in r['tables']:
                assert isinstance(t, dict)


class TranslatePluginRuleset(TranslatePlugin):
    @abstractmethod
    def get(self) -> list[Table]:
        return [
            Table(**table) for table in self.raw['tables']
        ]

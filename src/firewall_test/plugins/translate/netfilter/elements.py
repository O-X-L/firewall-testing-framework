from abc import ABC
from ipaddress import ip_network, summarize_address_range, ip_address

from config import ProtoL3, ProtoL3IP4, ProtoL3IP6, MatchPort, ProtoL4ICMP, ProtoL4TCP, ProtoL4UDP, ProtoL3IP4IP6, \
    PROTO_L4_MAPPING, PROTO_L3_MAPPING
from plugins.translate.netfilter.parts import RULE_ACTIONS, IGNORE_RULE_EXPRESSIONS, IGNORE_LEFT
from utils.logger import log_warn, rule_repr

# pylint: disable=R0801

# for schema see: https://www.mankier.com/5/libnftables-json

def translate_family(family: str) -> type[ProtoL3]:
    if family == 'ip':
        return ProtoL3IP4

    if family == 'inet':
        return ProtoL3IP4IP6

    # todo: add support for other table-families

    return ProtoL3IP6


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


class NftSet(NftBase):
    # dynamic sets
    def __init__(self, raw: dict, table: NftTable):
        NftBase.__init__(self=self, raw=raw, table=table)
        self.name = f"@{raw['name']}"
        self.family = translate_family(raw.get('family', None))

        set_type = raw.get('type', None)
        if set_type == 'ipv4_addr':
            self.type = ProtoL3IP4

        elif set_type == 'ipv6_addr':
            self.type = ProtoL3IP6

        else:
            self.type = MatchPort

        content = raw.get('elem', [])
        self.content = []
        if isinstance(content, list) and len(content) > 0:
            if isinstance(content[0], dict):
                for e in content:
                    self.content.append(e['elem']['val'])

            else:
                self.content = content


# pylint: disable=R0912,R1702
class NftMatch:
    OP_EQ = '=='
    OP_IN = 'in'
    OP_NE = '!='
    OP_NOT = '!'
    OP_GT = '>'
    OP_LT = '<'

    def __init__(self, operator: str, left: (str, dict), right: (str, dict, list)):
        self.operator = operator
        self._left = left

        self._right = right
        self.value = None
        self.value_is_set = False

        self.value_proto_l3 = None
        self.value_proto_l4 = None

        self.match_proto_l3 = False
        self.match_proto_l4 = False
        self.match_ip_saddr = False
        self.match_ip_daddr = False
        self.match_ni_in = False
        self.match_ni_out = False
        self.match_sport = False
        self.match_dport = False
        self.match_ct = False

        self._parse_left()
        self.parse_right()
        if self.value is None:
            self.value = right

        self.update_value_type()

    def _parse_left(self):
        left = self._left
        for e in IGNORE_LEFT:
            if left == e or e in left:
                self._left = None
                return

        if 'payload' in self._left:
            pl = self._left['payload']

            if 'protocol' in pl:
                if pl['protocol'] == 'ip':
                    self.match_proto_l3 = True
                    self.value_proto_l3 = ProtoL3IP4

                elif pl['protocol'] == 'ip6':
                    self.match_proto_l3 = True
                    self.value_proto_l3 = ProtoL3IP6

                elif pl['protocol'] == 'tcp':
                    self.match_proto_l4 = True
                    self.value_proto_l4 = ProtoL4TCP

                elif pl['protocol'] == 'udp':
                    self.match_proto_l4 = True
                    self.value_proto_l4 = ProtoL4UDP

                elif pl['protocol'] == 'icmp':
                    self.match_proto_l4 = True
                    self.value_proto_l4 = ProtoL4ICMP

            if 'field' in pl:
                if pl['field'] == 'saddr':
                    self.match_ip_saddr = True

                elif pl['field'] == 'daddr':
                    self.match_ip_daddr = True

                elif pl['field'] == 'sport':
                    self.match_sport = True

                elif pl['field'] == 'dport':
                    self.match_dport = True

        if 'meta' in left and 'key' in left['meta']:
            meta = left['meta']['key']
            if meta == 'oifname':
                self.match_ni_out = True

            elif meta == 'iifname':
                self.match_ni_in = True

            elif meta == 'l4proto':
                self.match_proto_l4 = True

        if 'ct' in left:
            self.match_ct = True

    def parse_right(self):
        if isinstance(self._right, str) and self._right.startswith('@'):
            self.value_is_set = True
            return

        if isinstance(self._right, dict):
            if 'set' in self._right:
                self.value = self._right['set']
                return

            if 'prefix' in self._right:
                # parsed in 'update_value_type'
                self.value = [self._right]

            if 'range' in self._right:
                # parsed in 'update_value_type'
                self.value = [self._right]

        if isinstance(self._right, (str, int)):
            self.value = [self._right]

        if self.value is None:
            if 'range' not in self._right and 'fin' not in self._right:
                log_warn('Firewall Plugin', f'Unable to parse match (right): "{self._right}"')
                return

            self.value = self._right

    def update_value_type(self):
        if self.value_is_set and isinstance(self.value, str):
            return

        if self.value is None:
            return

        values = []
        if self.match_ip_saddr or self.match_ip_daddr:
            for v in self.value:
                if isinstance(v, int):
                    values.append(v)

                elif isinstance(v, dict):
                    if 'prefix' in v:
                        v = v['prefix']
                        values.append(ip_network(f"{v['addr']}/{v['len']}"))

                    elif 'range' in v:
                        if str(v['range'][0]).isnumeric():
                            range_ports = range(v['range'][0], v['range'][1])
                            values.extend(range_ports)

                        else:
                            range_nets = list(summarize_address_range(
                                ip_address(v['range'][0]),
                                ip_address(v['range'][1]),
                            ))
                            values.extend(range_nets)

                    else:
                        raise ValueError(self.value)

                else:
                    try:
                        values.append(ip_network(v))

                    except ValueError as e:
                        raise ValueError(self.value) from e

        elif self.match_proto_l4 and not self.value_proto_l4:
            for v in self.value:
                values.append(PROTO_L4_MAPPING[v])

        elif self.match_proto_l3 and not self.value_proto_l3:
            for v in self.value:
                values.append(PROTO_L3_MAPPING[v])

        elif self.match_sport or self.match_dport:
            for v in self.value:
                if isinstance(v, int):
                    values.append(v)

                elif isinstance(v, dict):
                    range_ports = list(range(v['range'][0], v['range'][1]))
                    values.extend(range_ports)

        else:
            values = self.value

        self.value = values

    def get_matches(self) -> (dict, None):
        matches = {}
        if self.match_proto_l3:
            if self.value_proto_l3:
                matches['proto_l3'] = {self.OP_EQ: self.value_proto_l3.N}

            else:
                matches['proto_l3'] = {self.operator: [v.N for v in self.value]}

        if self.match_proto_l4:
            if self.value_proto_l4:
                matches['proto_l4'] = {self.OP_EQ: self.value_proto_l4.N}

            else:
                matches['proto_l4'] = {self.operator: [v.N for v in self.value]}

        if self.match_ip_saddr:
            matches['ip_saddr'] = { self.operator: [str(v) for v in self.value]}

        if self.match_ip_daddr:
            matches['ip_daddr'] = {self.operator: [str(v) for v in self.value]}

        if self.match_ni_in:
            matches['ni_in'] = {self.operator: self.value}

        if self.match_ni_out:
            matches['ni_out'] = {self.operator: self.value}

        if self.match_sport:
            matches['src_port'] = {self.operator: self.value}

        if self.match_dport:
            matches['dst_port'] = {self.operator: self.value}

        if self.match_ct:
            matches['ct'] = {self.operator: self.value}

        if len(matches) == 0:
            return None

        return matches

    def __repr__(self) -> str:
        matches = self.get_matches()
        if matches is None:
            return 'None (unsupported)'

        return f"{self.operator} {matches}"


class NftRule(NftBase):
    def __init__(self, table: NftTable, chain: NftChain, raw: dict, seq: int, sets: list[NftSet]):
        NftBase.__init__(self=self, raw=raw, table=table)
        self.raw = raw
        self.chain = chain
        self.seq = seq

        self.comment = raw.get('comment', None)
        self.family = raw.get('family', None)
        self.handle = raw.get('handle', None)

        self.action = None
        self.matches: list[NftMatch] = []
        self.invalid_matches = False
        self.target_chain = None
        self.target_nat_ip = None
        self.target_nat_port = None

        for expression in raw['expr']:
            supported = False
            for a in RULE_ACTIONS:
                if a in expression:
                    self.action = a
                    supported = True

            supported = any([
                supported,
                self._init_match(expression),
                self._init_jump(expression),
                self._init_goto(expression),
                self._init_dnat(expression),
                self._init_snat(expression),
                self._init_nat_xt(expression),
            ])

            if not supported:
                ignored = any(
                    e in expression for e in IGNORE_RULE_EXPRESSIONS
                )
                if not ignored:
                    log_warn('Firewall Plugin', f'Unsupported rule-expression: "{expression}"')

        for match in self.matches:
            if match.value_is_set:
                for s in sets:
                    if s.name == match.value:
                        match.value = s.content

                match.parse_right()
                match.update_value_type()

    def _init_goto(self, e: dict) -> bool:
        if 'goto' in e:
            self.target_chain = e['goto']['target']
            return True

        return False

    def _init_jump(self, e: dict) -> bool:
        if 'jump' in e:
            self.target_chain = e['jump']['target']
            return True

        return False

    def _init_match(self, e: dict) -> bool:
        if 'match' in e:
            match = NftMatch(
                operator=e['match']['op'],
                left=e['match']['left'],
                right=e['match']['right'],
            )
            if match.get_matches() is None:
                self.invalid_matches = True

            else:
                self.matches.append(match)

            return True

        return False

    def _init_dnat(self, e: dict) -> bool:
        if 'dnat' not in e:
            return False

        self.target_nat_ip = ip_address(e['dnat']['addr'])
        if 'port' in e['dnat']:
            self.target_nat_port = e['dnat']['port']

        return True

    def _init_snat(self, e: dict) -> bool:
        if 'snat' not in e:
            return False

        self.target_nat_ip = ip_address(e['snat']['addr'])
        return True

    def _init_nat_xt(self, e: dict) -> bool:
        if 'xt' not in e:
            return False

        if 'name' in e['xt'] and e['xt']['name'] == 'MASQUERADE':
            self.action = 'masquerade'
            return True

        return False

    def get_matches(self) -> dict:
        matches = {}
        for m in self.matches:
            matches = {**matches, **m.get_matches()}

        return matches

    def __repr__(self) -> str:
        return rule_repr(uid=self.handle, matches=self.get_matches(), cmt=self.comment)

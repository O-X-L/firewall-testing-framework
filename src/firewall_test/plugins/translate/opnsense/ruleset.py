from threading import Lock
from ipaddress import ip_network
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import Element

from requests import get as http_get
from requests import Response as HttpResponse
from requests.exceptions import Timeout as HttpTimeout
from oxl_utils.net import resolve_dns
from oxl_utils.valid.dns import valid_domain
from oxl_utils.ps import process_list_in_threads

from config import ProtoL3IP4IP6, DNS_RESOLVE_TIMEOUT, DNS_RESOLVE_THREADS, IPLIST_DOWNLOAD_TIMEOUT, \
    IPLIST_COMMENT_CHARS, ProtoL4ICMP, ProtoL4TCP, ProtoL4UDP, ProtoL3IP4, ProtoL3IP6, BOGONS
from plugins.system.system_opnsense import SystemOPNsense
from plugins.translate.abstract import Ruleset, TranslatePluginRuleset, Table, Chain, Rule, \
    RuleActionAccept, RuleActionDrop, RuleActionGoTo
from plugins.translate.opnsense.rule import OPNsenseRule, RULE_SEQUENCE_NEXT_CHAIN
from utils.logger import log_warn

XML_ELEMENT_NIS = 'interfaces'
XML_ELEMENT_NI_GROUPS = 'ifgroups'
XML_ELEMENT_VIPS = 'virtualip'
XML_ELEMENT_RULESET_OLD = 'filter'
XML_ELEMENT_RULESET_NEW = 'OPNsense/Firewall/Filter/rules'
XML_ELEMENT_ALIASES = 'OPNsense/Firewall/Alias/aliases'
XML_ELEMENT_GEOIP_URL = 'OPNsense/Firewall/Alias/geoip'
XML_ELEMENT_NAT_SNAT_OLD = 'nat'
XML_ELEMENT_NAT_SNAT_NEW = 'OPNsense/Firewall/Filter/snatrules'
XML_ELEMENT_NAT_DNAT = 'nat/outbound'
XML_ELEMENT_NAT_O2O_NEW = 'OPNsense/Firewall/Filter/onetoone'
XML_ELEMENT_NAT_NPT_NEW = 'OPNsense/Firewall/Filter/npt'

MAX_ALIAS_NESTING_DEPTH = 10


class OPNsenseChainOutput(Chain):
    def _validate_hooks(self):
        assert self.hook is None or self.hook in SystemOPNsense.FIREWALL_HOOKS['full']


RULE_MAPPING = {
    'type': {
        'pass': RuleActionAccept,
        'block': RuleActionDrop,
        '_default': RuleActionAccept,
    },
    'protocol': {
        'icmp': [ProtoL4ICMP],
        'ipv6-icmp': [ProtoL4ICMP],
        'tcp': [ProtoL4TCP],
        'udp': [ProtoL4UDP],
        'tcp/udp': [ProtoL4TCP, ProtoL4UDP],
    },
    'ipprotocol': {
        'inet': ProtoL3IP4,
        'inet6': ProtoL3IP6,
        'inet46': ProtoL3IP4IP6,
        '_default': ProtoL3IP4IP6,
    },
    'quick': {
        '1': True,
        'yes': True,
        '0': False,
        'no': False,
        '_default': True,
    },
}

NI_IPP_MAPPING = {
    'ipaddr': 'subnet',
    'ipaddrv6': 'subnetv6',
}


def split_csv(value: str) -> list:
    return [v for v in value.split(',') if v.strip() != '']


def xml_to_dict(element: Element) -> dict:
    out = {}
    if hasattr(element, 'uuid'):
        out['uuid'] = element.uuid

    for c in element:
        if len(list(c)) > 0:
            out[c.tag] = xml_to_dict(c)

        else:
            out[c.tag] = c.text

    return out


class OPNsenseRuleset(TranslatePluginRuleset):
    def __init__(self, raw: str):
        super().__init__(ET.ElementTree(ET.fromstring(raw)))

        self.chain_dnat = OPNsenseChainOutput(
            name='dnat', hook='dnat', policy=RuleActionAccept, type='nat', rules=[],
        )
        self.chain_floating = OPNsenseChainOutput(
            name='floating', hook='filters', policy=RuleActionDrop, rules=[],
        )
        self.chain_ni_grp = OPNsenseChainOutput(
            name='interface_groups', hook=None, policy=RuleActionAccept, rules=[],
        )
        self.chain_ni = OPNsenseChainOutput(
            name='interfaces', hook=None, policy=RuleActionDrop, rules=[],
        )
        self.chain_snat = OPNsenseChainOutput(
            name='snat', hook='snat', policy=RuleActionAccept, type='nat', rules=[],
        )

        # mapping interface-groups to actual interface names
        self.ni_grp = {}
        # list of all firewall IPs to resolve the alias "(self)"
        self.local_ips = []
        # network-interface to ip/net mapping as this is used by the rules
        self.nis_ips = {}
        self.nis_nets = {}

        # aliases
        self._dns_cache = {}
        self._dns_lock = Lock()
        self.aliases = {}

    def get(self) -> Ruleset:
        self._parse_ni_grp()
        self._parse_local_ips()
        self._parse_aliases()
        self.aliases['(self)'] = self.local_ips
        self.aliases['bogons'] = BOGONS

        self._parse_rules_old()
        self.chain_floating.rules.append(Rule(
            action=RuleActionGoTo,
            seq=RULE_SEQUENCE_NEXT_CHAIN,
            raw='interface_groups',
        ))
        self.chain_ni_grp.rules.append(Rule(
            action=RuleActionGoTo,
            seq=RULE_SEQUENCE_NEXT_CHAIN,
            raw='interfaces',
        ))

        return Ruleset(tables=[
            Table(
                name='default',
                family=ProtoL3IP4IP6,
                chains=[self.chain_dnat, self.chain_floating, self.chain_ni_grp, self.chain_ni, self.chain_snat],
            ),
        ])

    ### RULES ###

    def _parse_rule_address(self, value: str) -> (list, None):
        values = split_csv(value)
        out = []

        for v in values:
            if v in self.aliases:
                out.extend(self.aliases[v])
                continue

            if f'{v}ip' in self.nis_ips:
                out.extend(self.nis_nets[v])
                continue

            try:
                out.append(ip_network(v))

            except ValueError:
                log_warn('Firewall Plugin', f'Unable to parse rule-address: "{value}"')
                return None

        return out

    def _parse_rule_network(self, value: str) -> (list, None):
        values = split_csv(value)
        out = []

        for v in values:
            if v in self.aliases:
                out.extend(self.aliases[v])
                continue

            if v in self.nis_nets:
                out.extend(self.nis_nets[v])
                continue

            try:
                out.append(ip_network(v))

            except ValueError:
                log_warn('Firewall Plugin', f'Unable to parse rule-network: "{value}"')
                return None

        return out

    def _parse_rule_port(self, value: str) -> (list, None):
        values = split_csv(value)
        out = []

        for v in values:
            if v in self.aliases:
                out.extend(self.aliases[v])
                continue

            if v.find('-') != -1:
                v1, v2 = v.split('-', 1)
                range_ports = list(range(int(v1), int(v2)))
                out.extend(range_ports)
                continue

            try:
                out.append(int(v))

            except TypeError:
                log_warn('Firewall Plugin', f'Unable to parse rule-port: "{value}"')
                return None

        return out

    @staticmethod
    def log_unsupported_rule(chain: Chain, rule_raw: dict, rule: dict, result: (any, None), invalid: bool) -> bool:
        if invalid:
            return invalid

        if result is None:
            desc = '' if rule['desc'] is None else f" ({rule['desc']})"
            log_warn(
                'Firewall Plugin',
                f'Unsupported rule: Chain {chain.name}, Rule {rule["seq"]}{desc}',
                v4=f' | {rule_raw}'
            )
            return True

        return False

    # pylint: disable=R0912,R0914,R0915
    def _parse_rules_old(self):
        rules_raw = self.raw.getroot().find(XML_ELEMENT_RULESET_OLD)
        seq_float, seq_grp, seq_ni, nr = 0, 0, 0, 0
        for rule_raw in rules_raw:
            invalid_matches = False
            rule = xml_to_dict(rule_raw)
            build = {}
            chain_floating = rule.get('floating', None) == 'yes'
            nis = split_csv(rule.get('interface', ''))
            chain_grp = len(nis) == 1 and nis[0] in self.ni_grp
            if chain_floating:
                chain = self.chain_floating

            elif chain_grp:
                chain = self.chain_ni_grp

            else:
                chain = self.chain_ni

            build['uuid'] = rule.get('uuid', None)
            build['desc'] = rule.get('descr', None)

            ### SEQUENCE ###
            nr += 1
            build['nr'] = nr
            if chain_floating:
                seq_float += 1
                build['seq'] = seq_float

            elif chain_grp:
                seq_grp += 1
                build['seq'] = seq_grp

            else:
                seq_ni += 1
                build['seq'] = seq_ni

            ### RESOLVE NETWORK-INTERFACE GROUPS ###
            build['nis'] = []
            for ni in nis:
                if ni in self.ni_grp:
                    build['nis'].extend(self.ni_grp[ni])

                else:
                    build['nis'].append(ni)

            ### SIMPLE VALUE-MAPPING ###
            for field, mapping in RULE_MAPPING.items():
                if field not in rule:
                    build[field] = mapping.get('_default', None)
                    continue

                if rule[field] not in mapping:
                    log_warn(
                        'Firewall Plugin',
                        f'Unable to parse rule-field value: "{field}" => "{rule[field]}"',
                    )
                    build[field] = None
                    invalid_matches = True

                else:
                    build[field] = mapping[rule[field]]

            ### SRC / DST ###
            for key in ['source', 'destination']:
                value = rule.get(key, {})
                build[f'{key}_invert'] = 'not' in value and value['not'] == '1'
                build[f'{key}_any'] = 'any' in value and value['any'] == '1'

                if 'address' in value:
                    build[key] = self._parse_rule_address(value['address'])
                    invalid_matches = self.log_unsupported_rule(
                        chain=chain, rule_raw=rule, rule=build, result=build[key], invalid=invalid_matches
                    )

                elif 'network' in value:
                    build[key] = self._parse_rule_network(value['network'])
                    invalid_matches = self.log_unsupported_rule(
                        chain=chain, rule_raw=rule, rule=build, result=build[key], invalid=invalid_matches
                    )

                else:
                    build[key] = None

                if 'port' in value:
                    build[f'{key}_port'] = self._parse_rule_port(value['port'])
                    invalid_matches = self.log_unsupported_rule(
                        chain=chain, rule_raw=rule, rule=build, result=build[f'{key}_port'], invalid=invalid_matches
                    )

            # weird DNAT overrides..
            if 'targetip' in rule:
                build['destination'] = self._parse_rule_address(rule['targetip'])
                invalid_matches = self.log_unsupported_rule(
                    chain=chain, rule_raw=rule, rule=build, result=build['destination'], invalid=invalid_matches
                )

            elif 'target' in rule:
                build['destination'] = self._parse_rule_address(rule['target'])
                invalid_matches = self.log_unsupported_rule(
                    chain=chain, rule_raw=rule, rule=build, result=build['destination'], invalid=invalid_matches
                )

            if 'local-port' in rule:
                build['destination_port'] = self._parse_rule_port(rule['local-port'])
                invalid_matches = self.log_unsupported_rule(
                    chain=chain, rule_raw=rule, rule=build, result=build['destination_port'], invalid=invalid_matches
                )

            if invalid_matches:
                continue

            ### CREATE RULE ###
            chain.rules.append(Rule(
                action=build.pop('type'),
                seq=build.pop('seq'),
                action_lazy=not build.pop('quick'),
                raw=OPNsenseRule(**build),
            ))

    ### NETWORK INTERFACES ###

    def _parse_ni_grp(self):
        ni_grp_raw = self.raw.getroot().find(XML_ELEMENT_NI_GROUPS)
        for ni_grp in ni_grp_raw:
            properties = xml_to_dict(ni_grp)
            self.ni_grp[properties['ifname']] = list(properties['members'].split(','))

    def _parse_local_ips(self):
        nis_raw = self.raw.getroot().find(XML_ELEMENT_NIS)
        for ni in nis_raw:
            p = xml_to_dict(ni)
            ips, nets = [], []
            for ipp, subnet in NI_IPP_MAPPING.items():
                ip = p.get(ipp, None)
                cidr = p.get(subnet, '32')
                if ip is not None and ip.strip() != '':
                    nets.append(ip_network(f'{ip}/{cidr}', strict=False))
                    ip = ip_network(ip)
                    self.local_ips.append(ip)
                    ips.append(ip)

            self.nis_ips[ni.tag] = ips
            self.nis_nets[ni.tag] = nets

        vips_raw = self.raw.getroot().find(XML_ELEMENT_VIPS)
        for vip in vips_raw:
            p = xml_to_dict(vip)
            self.local_ips.append(ip_network(f"{p['subnet']}/{p['subnet_bits']}"))

    ### ALIASES ###

    @staticmethod
    def _get_alias_content(content: str) -> list[str]:
        return [c for c in content.split('\n') if c.strip() != '']

    def _resolve_nested_aliases(self, possible_nested: dict) -> dict:
        possible_nested_new = {}
        for name, content in possible_nested.items():
            nets = []
            invalid = False
            for c in content:
                try:
                    nets.append(ip_network(c))

                except ValueError:
                    if c in self.aliases:
                        nets.extend(self.aliases[c])

                    else:
                        invalid = True
                        possible_nested_new[name] = content
                        break

            if not invalid:
                self.aliases[name] = nets

        return possible_nested_new

    def _resolve_alias(self, item: str):
        resolved = resolve_dns(v=item, t='A', timeout=DNS_RESOLVE_TIMEOUT)
        resolved.extend(resolve_dns(v=item, t='AAAA', timeout=DNS_RESOLVE_TIMEOUT))
        if len(resolved) == 0:
            log_warn('Firewall Plugin', f'Unable to resolve alias DNS: "{item}"')
            return

        with self._dns_lock:
            self._dns_cache[item] = resolved

    def _resolve_alias_dns(self, aliases: dict):
        dns_to_resolve = set()
        for p in aliases.values():
            t = p['type']
            if t != 'host':
                continue

            for c in p['content']:
                if valid_domain(c):
                    dns_to_resolve.add(c)

        process_list_in_threads(
            to_process=list(dns_to_resolve),
            callback=self._resolve_alias,
            key='item',
            parallel=DNS_RESOLVE_THREADS,
        )

    def _parse_alias_iplist_plain(self, url: str) -> list[str]:
        content = []
        res = self._download_alias_iplist(url)
        if res is None:
            return []

        for l in res.text.split('\n'):
            l = l.strip()
            if l == '':
                continue

            # remove comments
            comment = False
            for c in IPLIST_COMMENT_CHARS:
                if l.startswith(c):
                    comment = True
                    break

            if comment:
                continue

            # remove any appended content
            if l.find(' ') != -1:
                l = l.split(' ', 1)[0]

            try:
                content.append(ip_network(l))

            except ValueError:
                log_warn('Firewall Plugin', f'Unable to parse alias-type "urltable" line: "{l}"')

        if len(content) == 0:
            log_warn('Firewall Plugin', f'Alias-type "urltable" resulted in empty list: "{url}"')

        return content

    @staticmethod
    def _download_alias_iplist(url: str) -> (HttpResponse, None):
        url = url.strip()
        if not url.startswith('http'):
            log_warn('Firewall Plugin', f'Unsupported alias-type "urltable" URL: {url}')
            return None

        try:
            return http_get(url.strip(), timeout=IPLIST_DOWNLOAD_TIMEOUT)

        except HttpTimeout:
            log_warn('Firewall Plugin', f'Unable to download IP-List from URL: "{url}"')
            return None

    def _parse_aliases(self):
        aliases_raw = self.raw.getroot().find(XML_ELEMENT_ALIASES)
        aliases = {}
        for a in aliases_raw:
            properties = xml_to_dict(a)
            name = properties.pop('name')
            aliases[name] = properties.copy()
            aliases[name]['content'] = self._get_alias_content(properties['content'])

        possible_nested = {}

        self._resolve_alias_dns(aliases)

        for name, p in aliases.items():
            t = p['type']
            if t == 'port':
                ports = []
                for c in p['content']:
                    if c.find(':') != -1:
                        c1, c2 = c.split(':', 1)
                        range_ports = list(range(int(c1), int(c2)))
                        ports.extend(range_ports)

                    else:
                        ports.append(int(c))

                self.aliases[name] = ports

            elif t == 'network':
                self.aliases[name] = [ip_network(n) for n in p['content']]

            elif t == 'host':
                content = []
                for c in p['content']:
                    if valid_domain(c):
                        if c in self._dns_cache:
                            content.extend(self._dns_cache[c])

                    else:
                        content.append(c)

                nets = []
                invalid = False
                for c in content:
                    try:
                        nets.append(ip_network(c))

                    except ValueError:
                        invalid = True
                        possible_nested[name] = p['content']
                        break

                if not invalid:
                    self.aliases[name] = nets

            elif t == 'urltable':
                self.aliases[name] = self._parse_alias_iplist_plain(p['content'][0].strip())

            else:
                # todo: geoip => download via link found in OPNsense config (XML_ELEMENT_GEOIP_URL)
                # todo: urltable JSON (https://docs.opnsense.org/manual/aliases.html#url-table-in-json-format-ips)
                log_warn('Firewall Plugin', f'Unsupported alias-type "{t}" will be skipped: "{name}"')

        # try to resolve nested aliases
        for _ in range(MAX_ALIAS_NESTING_DEPTH):
            possible_nested = self._resolve_nested_aliases(possible_nested)

        if len(possible_nested) > 0:
            log_warn('Firewall Plugin', f'Unable to parse aliases: {list(possible_nested.keys())}')

        self._dns_cache = {}

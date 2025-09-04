from ipaddress import ip_address, ip_network, IPv4Address
from json import loads as json_loads

from config import DEFAULT_ROUTE_IP4, DEFAULT_ROUTE_IP6, ProtoL3IP4, ProtoL3IP6
from plugins.translate.abstract import TranslatePluginStaticRoutes, TranslatePluginStaticRouteRules, \
    StaticRoute, StaticRouteRule, TranslatePluginNetworkInterfaces, NetworkInterface


class LinuxRouteRules(TranslatePluginStaticRouteRules):
    def __init__(self, raw: str):
        super().__init__(json_loads(raw))

    def get(self) -> list[StaticRouteRule]:
        return [
            StaticRouteRule(**self._parse_rule(r))
            for r in self.raw
        ]

    @staticmethod
    def _parse_rule(raw: dict) -> dict:
        r = {
            'priority': raw.get('priority', None),
            'table': raw.get('table', None),
        }

        src = raw.get('src', None)
        if src is None:
            r['src'] = []

        if src == 'all':
            r['src'] = [
                DEFAULT_ROUTE_IP4,
                DEFAULT_ROUTE_IP6,
            ]

        else:
            cidr = raw.get('srclen', 32 if src.find(':') == -1 else 128)
            r['src'] = [ip_network(f'{src}/{cidr}')]

        return r


class LinuxRoutes(TranslatePluginStaticRoutes):
    def __init__(self, raw: str):
        super().__init__(json_loads(raw))

    def get(self) -> list[StaticRoute]:
        return [
            StaticRoute(**self._parse_route(r))
            for r in self.raw
        ]

    @staticmethod
    def _parse_route(raw: dict) -> dict:
        r = {
            'scope': raw.get('scope', 'remote'),
            'ni': raw.get('dev', None),
            'metric': raw.get('metric', None),
            'src_pref': raw.get('prefsrc', None),
            'gw': raw.get('gateway', None),
            'table': raw.get('table', 'default'),
            'type': raw.get('type', 'default'),
        }

        if raw.get('dst') == 'default':
            if r['gw'] is None:
                r['net'] = DEFAULT_ROUTE_IP4

            elif r['gw'].find(':') == -1:
                r['net'] = DEFAULT_ROUTE_IP4

            else:
                r['net'] = DEFAULT_ROUTE_IP6

        else:
            r['net'] = ip_network(raw['dst'])

        return r


class LinuxNetworkInterfaces(TranslatePluginNetworkInterfaces):
    def __init__(self, raw: str):
        super().__init__(json_loads(raw))

    def get(self) -> list[NetworkInterface]:
        return [
            NetworkInterface(**self._parse_ni(r))
            for r in self.raw
            if 'linkdown' not in r.get('flags', [])
        ]

    @staticmethod
    def _parse_ni(raw: dict) -> dict:
        r = {
            'name': raw.get('ifname'),
            'mac': raw.get('address'),
            ProtoL3IP4.N: [],
            ProtoL3IP6.N: [],
            'net4': [],
            'net6': [],
        }
        r['up'] = raw.get('operstate') == 'UP' or r['name'] == 'lo'

        for info in raw.get('addr_info'):
            ip = ip_address(info['local'])
            cidr = info['prefixlen']
            if cidr in [32, 128]:
                net = None

            else:
                net = ip_network(f"{ip}/{info['prefixlen']}", strict=False)

            if isinstance(ip, IPv4Address):
                r[ProtoL3IP4.N].append(ip)
                if net is not None:
                    r['net4'].append(net)

            else:
                r[ProtoL3IP6.N].append(ip)
                if net is not None:
                    r['net6'].append(net)

        return r

from ipaddress import ip_network
from json import loads as json_loads

from plugins.translate.abstract import TranslatePluginStaticRoutes, TranslatePluginStaticRouteRules, \
    TranslateOutputStaticRoute, TranslateOutputStaticRouteRule


class LinuxRouteRules(TranslatePluginStaticRouteRules):
    def __init__(self, raw: str):
        super().__init__(json_loads(raw))

    def get(self) -> list[TranslateOutputStaticRouteRule]:
        return [
            TranslateOutputStaticRouteRule(**self._parse_rule(r))
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
                ip_network('0.0.0.0/0'),
                ip_network('::/0'),
            ]

        else:
            cidr = raw.get('srclen', 32 if src.find(':') == -1 else 128)
            r['src'] = [ip_network(f'{src}/{cidr}')]

        return r


class LinuxRoutes(TranslatePluginStaticRoutes):
    def __init__(self, raw: str):
        super().__init__(json_loads(raw))

    def get(self) -> list[TranslateOutputStaticRoute]:
        return [
            TranslateOutputStaticRoute(**self._parse_route(r))
            for r in self.raw
        ]

    @staticmethod
    def _parse_route(raw: dict) -> dict:
        r = {
            'scope': raw.get('scope', None),
            'dev': raw.get('dev', None),
            'metric': raw.get('metric', None),
            'src_pref': raw.get('prefsrc', None),
            'gw': raw.get('gateway', None),
            'table': raw.get('table', 'default'),
            'type': raw.get('type', 'default'),
        }

        if raw.get('dst') == 'default':
            if r['gw'] is None:
                r['dst'] = ip_network('0.0.0.0/0')

            elif r['gw'].find(':') == -1:
                r['dst'] = ip_network('0.0.0.0/0')

            else:
                r['dst'] = ip_network('::/0')

        else:
            r['dst'] = ip_network(raw['dst'])

        return r

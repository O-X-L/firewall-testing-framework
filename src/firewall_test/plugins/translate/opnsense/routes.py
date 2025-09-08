from json import loads as json_loads
from ipaddress import ip_address, ip_network, IPv4Address

from config import DEFAULT_ROUTE_IP4, DEFAULT_ROUTE_IP6
from plugins.translate.abstract import StaticRoute, TranslatePluginStaticRoutes


class OPNsenseRoutes(TranslatePluginStaticRoutes):
    def __init__(self, raw: str):
        super().__init__(json_loads(raw))

    def get(self) -> list[StaticRoute]:
        routes = []
        for r in self.raw:
            routes.extend(self._parse_routes(r))

        return [
            StaticRoute(**r)
            for r in routes
        ]

    @staticmethod
    def _parse_routes(raw: dict) -> list[dict]:
        if raw.get('status', '') != 'up':
            return []

        local_nets = [
            ip_network(ip['ipaddr'], strict=False) for ip in raw.get('ipv4', [])
        ]
        local_nets.extend([
            ip_network(ip['ipaddr'], strict=False) for ip in raw.get('ipv6', [])
        ])
        ni = raw['identifier']
        gws = raw.get('gateways', [])
        routes = []
        src_pref_ip4, src_pref_ip6 = raw['config'].get('ipaddr', None), raw['config'].get('ipaddrv6', None)
        gw_ip4, gw_ip6 = None, None
        default_ip4 = False

        for gw in gws:
            gw = ip_address(gw)
            if isinstance(gw, IPv4Address):
                gw_ip4 = gw

            else:
                gw_ip6 = gw

        for net in raw.get('routes', []):
            ipp = 4 if net.find(':') == -1 else 6
            if net.find('%') != -1:
                net, _ = net.split('%', 1)
                scope = 'link'

            elif net in local_nets:
                scope = 'link'

            else:
                scope = 'local' if len(gws) == 0 else 'global'

            if net == 'default':
                if not default_ip4:
                    default_ip4 = True
                    net = DEFAULT_ROUTE_IP4
                    gw = gw_ip4

                else:
                    net = DEFAULT_ROUTE_IP6
                    gw = gw_ip6
                    ipp = 6

            else:
                if ni == 'lo0' and net.find('/') == -1:
                    # all system-ips are routed to loopback by opnsense - might cause issues (?)
                    continue

                net = ip_network(net, strict=False)
                if net in local_nets:
                    scope = 'link'
                    gw = None

                elif ipp == 4:
                    gw = gw_ip4

                else:
                    gw = gw_ip6

            routes.append({
                'scope': scope,
                'ni': ni,
                'gw': gw,
                'net': net,
                'table': 'default',
                'src_pref': src_pref_ip4 if ipp == 4 else src_pref_ip6,
                'metric': None,
            })

        return routes

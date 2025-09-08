from json import loads as json_loads
from ipaddress import ip_address, ip_network, IPv4Address

from config import ProtoL3IP4, ProtoL3IP6
from plugins.translate.abstract import NetworkInterface, TranslatePluginNetworkInterfaces

# pylint: disable=R0801


class OPNsenseNetworkInterfaces(TranslatePluginNetworkInterfaces):
    def __init__(self, raw: str):
        super().__init__(json_loads(raw))

    def get(self) -> list[NetworkInterface]:
        return [
            NetworkInterface(**self._parse_ni(r))
            for r in self.raw
            if r['status'] != 'down'
        ]

    @staticmethod
    def _parse_ni(raw: dict) -> dict:
        r = {
            'name': raw.get('identifier'),
            'mac': raw.get('macaddr'),
            ProtoL3IP4.N: [],
            ProtoL3IP6.N: [],
            'net4': [],
            'net6': [],
            'up': raw['status'] == 'up',
            'desc': raw.get('description', None),
        }

        ips = raw.get('ipv4', [])
        ips.extend(raw.get('ipv6', []))
        for ip_cnf in ips:
            ip_cidr = ip_cnf['ipaddr']
            ip, cidr = ip_cidr.split('/', 1)
            ip = ip_address(ip)
            if cidr in ['32', '128']:
                net = None

            else:
                net = ip_network(ip_cidr, strict=False)

            if isinstance(ip, IPv4Address):
                r[ProtoL3IP4.N].append(ip)
                if net is not None:
                    r['net4'].append(net)

            else:
                r[ProtoL3IP6.N].append(ip)
                if net is not None:
                    r['net6'].append(net)

        return r

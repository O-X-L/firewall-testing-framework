# pylint: disable=R0801

from config import FlowInput, FlowOutput, FlowForward
from plugins.system.abstract import FirewallSystem


class SystemLinuxNetfilter(FirewallSystem):
    ROUTE_STATIC = True
    ROUTE_STATIC_RULES = True

    FIREWALL_LAZY_MATCHING = False
    FIREWALL_CT = True
    FIREWALL_PRIO_LOWER_BETTER = True
    FIREWALL_PRIO_TABLE_FULL = False
    FIREWALL_DNAT = True
    FIREWALL_SNAT = True

    # see: https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks & https://people.netfilter.org/pablo/nf-hooks.png
    FIREWALL_HOOKS = {
        FlowInput: ['ingress', 'prerouting', 'input'],
        FlowForward: ['ingress', 'prerouting', 'forward', 'postrouting', 'egress'],
        FlowOutput: ['output', 'postrouting', 'egress'],
        'full': ['ingress', 'prerouting', 'input', 'forward', 'output', 'postrouting', 'egress'],
    }
    FIREWALL_INGRESS = {
        FlowInput: {'hook': 'prerouting', 'priority': 1000},
        FlowForward: {'hook': 'prerouting', 'priority': 1000},
        FlowOutput: {'hook': 'output', 'priority': -100},
    }
    FIREWALL_NAT = {
        FlowInput: {
            'dnat': {'hook': 'prerouting', 'priority': -100},
        },
        FlowForward: {
            'dnat': {'hook': 'prerouting', 'priority': -100},
            'snat': {'hook': 'postrouting', 'priority': 100},
        },
        FlowOutput: {
            'dnat': FIREWALL_INGRESS[FlowOutput],
            'snat': {'hook': 'postrouting', 'priority': 100},
        },
    }

    # sudo nft describe icmp type
    ICMP_TYPE_TO_CODE_MAPPING = {
        'echo-reply': 0,
        'destination-unreachable': 3,
        'source-quench': 4,
        'redirect': 5,
        'echo-request': 8,
        'router-advertisement': 9,
        'router-solicitation': 10,
        'time-exceeded': 11,
        'parameter-problem': 12,
        'timestamp-request ': 13,
        'timestamp-reply': 14,
        'info-request': 15,
        'info-reply': 16,
        'address-mask-request': 17,
        'address-mask-reply': 18,
    }

    # sudo nft describe icmpv6 type
    ICMP6_TYPE_TO_CODE_MAPPING = {
        'destination-unreachable': 1,
        'packet-too-big': 2,
        'time-exceeded': 3,
        'parameter-problem': 4,
        'echo-request': 128,
        'echo-reply': 129,
        'mld-listener-query': 130,
        'mld-listener-report': 131,
        'mld-listener-done': 132,
        'mld-listener-reduction': 132,
        'nd-router-solicit': 133,
        'nd-router-advert': 134,
        'nd-neighbor-solicit': 135,
        'nd-neighbor-advert': 136,
        'nd-redirect': 137,
        'router-renumbering': 138,
        'ind-neighbor-solicit': 141,
        'ind-neighbor-advert': 142,
        'mld2-listener-report': 143,
    }

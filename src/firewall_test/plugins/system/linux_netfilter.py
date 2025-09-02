# pylint: disable=R0801

from config import FLOW_INPUT, FLOW_OUTPUT, FLOW_FORWARD
from plugins.system.abstract import FirewallSystem


class SystemLinuxNetfilter(FirewallSystem):
    ROUTE_STATIC = True
    ROUTE_STATIC_RULES = True

    FIREWALL_LAZY_MATCHING = False
    FIREWALL_CT = True
    FIREWALL_PRIO_LOWER_BETTER = True
    FIREWALL_PRIO_TABLE_FULL = False

    # see: https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks & https://people.netfilter.org/pablo/nf-hooks.png
    FIREWALL_HOOKS = {
        FLOW_INPUT: ['ingress', 'prerouting', 'input'],
        FLOW_FORWARD: ['ingress', 'prerouting', 'forward', 'postrouting', 'egress'],
        FLOW_OUTPUT: ['output', 'postrouting', 'egress'],
        'full': ['ingress', 'prerouting', 'input', 'forward', 'output', 'postrouting', 'egress'],
    }
    FIREWALL_PRE_ROUTING = {
        FLOW_INPUT: {'hook': 'prerouting', 'priority': -100},
        FLOW_FORWARD: {'hook': 'prerouting', 'priority': -100},
        FLOW_OUTPUT: {'hook': 'output', 'priority': -100},
    }
    FIREWALL_NAT = {
        FLOW_INPUT: {
            'dnat': {'type': 'nat', **FIREWALL_PRE_ROUTING[FLOW_INPUT]},
        },
        FLOW_FORWARD: {
            'dnat': {'type': 'nat', **FIREWALL_PRE_ROUTING[FLOW_FORWARD]},
            'snat': {'hook': 'postrouting', 'type': 'nat', 'priority': 100},
        },
        FLOW_OUTPUT: {
            'dnat': {'type': 'nat', **FIREWALL_PRE_ROUTING[FLOW_OUTPUT]},
            'snat': {'hook': 'postrouting', 'type': 'nat', 'priority': 100},
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

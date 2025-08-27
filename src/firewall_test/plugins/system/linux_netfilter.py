from plugins.system.abstract import FirewallSystem


class SystemLinuxNetfilter(FirewallSystem):
    ROUTE_STATIC = True
    ROUTE_STATIC_RULES = True

    FIREWALL_LAZY_MATCHING = False
    FIREWALL_CT = True

    # see: https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks & https://people.netfilter.org/pablo/nf-hooks.png
    FIREWALL_HOOKS = {
        'input': ['ingress', 'prerouting', 'input'],
        'forward': ['ingress', 'prerouting', 'forward', 'postrouting', 'egress'],
        'output': ['output', 'postrouting', 'egress'],
    }
    FIREWALL_PRE_ROUTING = {
        'input': {'hook': 'prerouting', 'type': 'nat', 'priority': -100},
        'forward': {'hook': 'prerouting', 'type': 'nat', 'priority': -100},
        'output': {'hook': 'output', 'type': 'nat', 'priority': -100},
    }
    FIREWALL_NAT = {
        'input': {
            'dnat': FIREWALL_PRE_ROUTING['input'],
        },
        'forward': {
            'dnat': FIREWALL_PRE_ROUTING['forward'],
            'snat': {'hook': 'postrouting', 'type': 'nat', 'priority': 100},
        },
        'output': {
            'dnat': FIREWALL_PRE_ROUTING['output'],
            'snat': {'hook': 'postrouting', 'type': 'nat', 'priority': 100},
        },
    }

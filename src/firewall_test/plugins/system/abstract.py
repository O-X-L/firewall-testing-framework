from abc import ABC


class FirewallSystem(ABC):
    # the system has static routes
    ROUTE_STATIC = True

    # the system has routing-rules for static routing (source-based routing)
    ROUTE_STATIC_RULES = False

    # if the system allows traffic to bogon-networks to be sent to wan/default-route
    FIREWALL_WAN_DROP_BOGONS = True

    # the firewall supports bsd-pf-style quick/lazy matching
    FIREWALL_LAZY_MATCHING = False

    # the firewall supports connection-tracking (ct-state)
    FIREWALL_CT = True

    # input = src is remote & dst is local
    # output = src is local
    # forward = src is remote & dst is remote
    FIREWALL_HOOKS = {
        'input': [],
        'output': [],
        'forward': [],
    }

    # last chain before we need to perform the routing-lookup
    FIREWALL_PRE_ROUTING = {
        'input': {},
        'output': {},
        'forward': {},
    }

    # chains where NAT-operations are performed
    FIREWALL_NAT = {
        'input': {
            'dnat': {},
            'snat': {},
        },
        'output': {
            'dnat': {},
            'snat': {},
        },
        'forward': {
            'dnat': {},
            'snat': {},
        },
    }

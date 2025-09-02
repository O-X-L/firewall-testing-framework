# pylint: disable=R0801
from abc import ABC

from config import FLOW_INPUT, FLOW_OUTPUT, FLOW_FORWARD


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

    # if lower table/chain/... priorities are rated better than larger ones
    FIREWALL_PRIO_LOWER_BETTER = True

    # if a table has a better priority => process all of its chains before any other table
    #   else all chain-priorities of all tables will be evaluated simultaneously; while the table-priority will impact the chain-priority
    FIREWALL_PRIO_TABLE_FULL = False

    # input = src is remote & dst is local
    # output = src is local
    # forward = src is remote & dst is remote
    # full = all chains combined in theoretical sequence
    FIREWALL_HOOKS = {
        FLOW_INPUT: [],
        FLOW_OUTPUT: [],
        FLOW_FORWARD: [],
        'full': [],
    }

    # last chain before we need to perform the routing-lookup and DNAT
    FIREWALL_INGRESS = {
        FLOW_INPUT: {},
        FLOW_OUTPUT: {},
        FLOW_FORWARD: {},
    }

    # chains after we performed SNAT
    FIREWALL_EGRESS = {
        FLOW_OUTPUT: {},
        FLOW_FORWARD: {},
    }

    # chains where NAT-operations are performed
    FIREWALL_NAT = {
        FLOW_INPUT: {
            'dnat': {},
            'snat': {},
        },
        FLOW_OUTPUT: {
            'dnat': {},
            'snat': {},
        },
        FLOW_FORWARD: {
            'dnat': {},
            'snat': {},
        },
    }

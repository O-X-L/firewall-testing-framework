# pylint: disable=R0801
from abc import ABC, abstractmethod

from config import FlowInput, FlowOutput, FlowForward


class BaseRuleMatcher(ABC):
    pass


class FirewallSystem(ABC):
    # the system has static routes
    ROUTE_STATIC = True

    # the system has routing-rules for static routing (source-based routing)
    ROUTE_STATIC_RULES = False

    # if the system allows traffic to bogon-networks to be sent to wan/default-route
    SYSTEM_DROP_WAN_BOGONS = True

    # if the system allows traffic to be forwarded; todo: should be instance-specific
    SYSTEM_DROP_FORWARD = False

    # the firewall supports bsd-pf-style quick/lazy matching
    FIREWALL_ACTION_LAZY = False

    # the firewall supports connection-tracking (ct-state)
    FIREWALL_CT = True

    # if lower table/chain/... priorities are rated better than larger ones
    FIREWALL_PRIO_LOWER_BETTER = True

    # if a table has a better priority => process all of its chains before any other table
    #   else all chain-priorities of all tables will be evaluated simultaneously; while the table-priority will impact the chain-priority
    FIREWALL_PRIO_TABLE_FULL = False

    # if it supports DNAT
    FIREWALL_DNAT = True

    # if it supports SNAT
    FIREWALL_SNAT = True

    # input = src is remote & dst is local
    # output = src is local
    # forward = src is remote & dst is remote
    # full = all chains combined in theoretical sequence
    FIREWALL_HOOKS = {
        FlowInput: [],
        FlowOutput: [],
        FlowForward: [],
        'full': [],
    }

    # last chain before we need to perform the routing-lookup and DNAT
    FIREWALL_INGRESS = {
        FlowInput: {'hook': '', 'priority': 1000},
        FlowOutput: {'hook': '', 'priority': 1000},
        FlowForward: {'hook': '', 'priority': 1000},
    }

    # chains where NAT-operations are performed
    FIREWALL_NAT = {
        FlowInput: {
            'dnat': {'hook': '', 'priority': 0},
            'snat': {'hook': '', 'priority': 0},
        },
        FlowOutput: {
            'dnat': {'hook': '', 'priority': 0},
            'snat': {'hook': '', 'priority': 0},
        },
        FlowForward: {
            'dnat': {'hook': '', 'priority': 0},
            'snat': {'hook': '', 'priority': 0},
        },
    }

    @classmethod
    @abstractmethod
    def get_rule_matcher(cls) -> type[BaseRuleMatcher]:
        """
        Return the system-specific rule-matcher (plugins.system.abstract_rule_match.RuleMatcher)

        :return: RuleMatcher
        """

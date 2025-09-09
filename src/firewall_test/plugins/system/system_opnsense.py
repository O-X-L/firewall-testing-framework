# pylint: disable=R0801

from config import FlowInput, FlowOutput, FlowForward
from plugins.system.abstract import FirewallSystem
from plugins.system.firewall_opnsense import RuleMatcher, RuleMatcherOPNsense


class SystemOPNsense(FirewallSystem):
    ROUTE_STATIC = True
    ROUTE_STATIC_RULES = False

    SYSTEM_DROP_WAN_BOGONS = True  # todo: instance-specific => read from config (interfaces-wan-blockbogons)
    SYSTEM_DROP_FORWARD = False

    FIREWALL_ACTION_LAZY = True
    FIREWALL_CT = True
    FIREWALL_PRIO_LOWER_BETTER = True
    FIREWALL_PRIO_TABLE_FULL = False
    FIREWALL_DNAT = True
    FIREWALL_SNAT = True

    # see: https://docs.opnsense.org/manual/firewall.html#processing-order
    FIREWALL_HOOKS = {
        FlowInput: ['dnat', 'filters'],
        FlowForward: ['dnat', 'filters', 'snat'],
        FlowOutput: ['dnat', 'filters', 'snat'],
        'full': ['dnat', 'filters', 'snat'],
    }
    FIREWALL_INGRESS = {
        FlowInput: {'hook': 'prerouting', 'priority': 1000},
        FlowForward: {'hook': 'prerouting', 'priority': 1000},
        FlowOutput: {'hook': 'output', 'priority': -100},
    }
    _chain_dnat = {'hook': 'dnat', 'priority': 0}
    _chain_snat = {'hook': 'snat', 'priority': 0}
    FIREWALL_NAT = {
        FlowInput: {
            'dnat': _chain_dnat,
        },
        FlowForward: {
            'dnat': _chain_dnat,
            'snat': _chain_snat,
        },
        FlowOutput: {
            'dnat': _chain_dnat,
            'snat': _chain_snat,
        },
    }

    @classmethod
    def get_rule_matcher(cls) -> type[RuleMatcher]:
        """
        Property to return the system-specific rule-matcher (plugins.system.abstract_rule_match.RuleMatcher)

        :return: RuleMatcher
        """
        return RuleMatcherOPNsense

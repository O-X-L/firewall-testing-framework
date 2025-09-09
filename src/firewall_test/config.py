from abc import ABC
from ipaddress import ip_network

ENV_VERBOSITY = 'VERB'
ENV_DEBUG = 'DEBUG'
ENV_LOG_COLOR = 'LOG_COLOR'
VERBOSITY_DEBUG = '4'
VERBOSITY_DEFAULT = '1'

DEFAULT_ROUTE_IP4 = ip_network('0.0.0.0/0')
DEFAULT_ROUTE_IP6 = ip_network('::/0')
DEFAULT_ROUTES = [DEFAULT_ROUTE_IP4, DEFAULT_ROUTE_IP6]
LINK_LOCAL_IP6 = ip_network('fe80::/64')
BOGONS_IP4 = [
    ip_network('0.0.0.0/8'),
    ip_network('10.0.0.0/8'),
    ip_network('100.64.0.0/10'),
    ip_network('127.0.0.0/8'),
    ip_network('127.0.53.53'),
    ip_network('169.254.0.0/16'),
    ip_network('172.16.0.0/12'),
    ip_network('192.0.0.0/24'),
    ip_network('192.0.2.0/24'),
    ip_network('192.168.0.0/16'),
    ip_network('198.18.0.0/15'),
    ip_network('198.51.100.0/24'),
    ip_network('203.0.113.0/24'),
    ip_network('224.0.0.0/4'),
    ip_network('240.0.0.0/4'),
    ip_network('255.255.255.255/32'),
]
BOGONS_IP6 = [
    ip_network('::/128'),
    ip_network('::1/128'),
    ip_network('::ffff:0:0/96'),
    ip_network('::/96'),
    ip_network('100::/64'),
    ip_network('2001:10::/28'),
    ip_network('2001:db8::/32'),
    ip_network('3fff::/20'),
    ip_network('fc00::/7'),
    ip_network('fe80::/10'),
    ip_network('fec0::/10'),
    ip_network('ff00::/8'),
]
BOGONS = BOGONS_IP4.copy()
BOGONS.extend(BOGONS_IP6)

# dns-resolving firewall-rule content
DNS_RESOLVE_TIMEOUT = 1
DNS_RESOLVE_THREADS = 50

IPLIST_DOWNLOAD_TIMEOUT = 3
IPLIST_COMMENT_CHARS = ['#', ';']


class Proto(ABC):
    N = 'Abstract Protocol'


class ProtoL3(Proto):
    N = 'Abstract L3 Protocol'


class ProtoL3IP4(ProtoL3):
    N = 'ip4'


class ProtoL3IP6(ProtoL3):
    N = 'ip6'


class ProtoL3IP4IP6(ProtoL3):
    N = 'ip'


PROTOS_L3 = (ProtoL3IP4, ProtoL3IP6, ProtoL3IP4IP6)
PROTO_L3_MAPPING = {
    ProtoL3IP4.N: ProtoL3IP4,
    ProtoL3IP6.N: ProtoL3IP6,
    ProtoL3IP4IP6.N: ProtoL3IP4IP6,
}

class ProtoL4(Proto):
    N = 'Abstract L4 Protocol'


class ProtoL4TCP(ProtoL4):
    N = 'tcp'


class ProtoL4UDP(ProtoL4):
    N = 'udp'


class ProtoL4ICMP(ProtoL4):
    N = 'icmp'


PROTOS_L4 = (ProtoL4TCP, ProtoL4UDP, ProtoL4ICMP)
PROTO_L4_MAPPING = {
    ProtoL4TCP.N: ProtoL4TCP,
    ProtoL4UDP.N: ProtoL4UDP,
    ProtoL4ICMP.N: ProtoL4ICMP,
}


class Flow(ABC):
    N = 'Abstract Flow'


class FlowInput(Flow):
    N = 'input'


class FlowOutput(Flow):
    N = 'output'


class FlowForward(Flow):
    N = 'forward'


class FlowInputForward(FlowInput):
    # before DNAT we might not yet know
    N = 'input_forward'


class Match(ABC):
    N = 'Abstract Match'


class MatchPort(Match):
    N = 'port'


class RuleAction(ABC):
    N = 'Abstract Rule-Action'


class RuleActionKindTerminal(RuleAction):
    N = 'Abstract Rule-Action Terminal'


class RuleActionKindTerminalKill(RuleActionKindTerminal):
    N = 'Abstract Rule-Action Terminal'


class RuleActionAccept(RuleActionKindTerminal):
    N = 'accept'


class RuleActionDrop(RuleActionKindTerminalKill):
    N = 'drop'


class RuleActionReject(RuleActionKindTerminalKill):
    N = 'reject'


class RuleActionKindToChain(RuleAction):
    N = 'Abstract Rule-Action To-Chain'


class RuleActionJump(RuleActionKindToChain):
    N = 'jump'


class RuleActionGoTo(RuleActionKindToChain):
    N = 'goto'


class RuleActionReturn(RuleActionKindTerminal):
    N = 'return'


class RuleActionContinue(RuleAction):
    N = 'continue'


class RuleActionKindNAT(RuleAction):
    N = 'Abstract Rule-Action NAT'


class RuleActionDNAT(RuleActionKindNAT):
    N = 'dnat'


class RuleActionSNAT(RuleActionKindNAT):
    N = 'snat'


RULE_ACTIONS = (
    RuleActionAccept, RuleActionDrop, RuleActionReject,
    RuleActionJump, RuleActionGoTo, RuleActionContinue, RuleActionReturn,
    RuleActionDNAT, RuleActionSNAT,
)
RULE_ACTION_MAPPING = {
    RuleActionAccept.N: RuleActionAccept,
    RuleActionDrop.N: RuleActionDrop,
    RuleActionReject.N: RuleActionReject,
    RuleActionJump.N: RuleActionJump,
    RuleActionGoTo.N: RuleActionGoTo,
    RuleActionContinue.N: RuleActionContinue,
    RuleActionReturn.N: RuleActionReturn,
    RuleActionDNAT.N: RuleActionDNAT,
    RuleActionSNAT.N: RuleActionSNAT,
}

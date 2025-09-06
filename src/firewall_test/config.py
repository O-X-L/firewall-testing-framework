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


PROTOS_L3 = [ProtoL3IP4, ProtoL3IP6]
PROTO_L3_MAPPING = {
    ProtoL3IP4.N: ProtoL3IP4,
    ProtoL3IP6.N: ProtoL3IP6,
}

class ProtoL4(Proto):
    N = 'Abstract L4 Protocol'


class ProtoL4TCP(ProtoL4):
    N = 'tcp'


class ProtoL4UDP(ProtoL4):
    N = 'udp'


class ProtoL4ICMP(ProtoL4):
    N = 'icmp'


PROTOS_L4 = [ProtoL4TCP, ProtoL4UDP, ProtoL4ICMP]
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

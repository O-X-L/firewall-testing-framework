from ipaddress import ip_network

DEFAULT_ROUTE_IP4 = ip_network('0.0.0.0/0')
DEFAULT_ROUTE_IP6 = ip_network('::/0')
DEFAULT_ROUTES = [DEFAULT_ROUTE_IP4, DEFAULT_ROUTE_IP6]

PROTO_L3_IP4 = 'ip4'
PROTO_L3_IP6 = 'ip6'
PROTO_L3_IP4_IP6 = 'ip'
PROTOS_L3 = [PROTO_L3_IP4, PROTO_L3_IP6]

PROTO_L4_TCP = 'tcp'
PROTO_L4_UDP = 'udp'
PROTO_L4_ICMP = 'icmp'
PROTOS_L4 = [PROTO_L4_TCP, PROTO_L4_UDP, PROTO_L4_ICMP]

FLOW_INPUT = 'input'
FLOW_OUTPUT = 'output'
FLOW_FORWARD = 'forward'
FLOW_INPUT_FORWARD = 'input_forward'  # before DNAT we might not yet know

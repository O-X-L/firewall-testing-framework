from ipaddress import ip_network

DEFAULT_ROUTE_IP4 = ip_network('0.0.0.0/0')
DEFAULT_ROUTE_IP6 = ip_network('::/0')
DEFAULT_ROUTES = [DEFAULT_ROUTE_IP4, DEFAULT_ROUTE_IP6]

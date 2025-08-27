from abc import ABC


class FirewallSystem(ABC):
    # the system has static routes
    ROUTE_STATIC = True

    # the system has routing-rules for static routing (source-based routing)
    ROUTE_STATIC_RULES = False

    # the system has additional dynamic routes that are queried
    ROUTE_RUNTIME = False

    # the firewall supports bsd-pf-style quick/lazy matching
    FIREWALL_LAZY_MATCHING = False

    # the firewall supports connection-tracking (ct-state)
    FIREWALL_CT = True

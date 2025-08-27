from plugins.system.abstract import FirewallSystem


class SystemLinuxNetfilter(FirewallSystem):
    ROUTE_STATIC = True
    ROUTE_STATIC_RULES = True

    # the runtime routes are already included in the 'static'
    ROUTE_RUNTIME = False

    FIREWALL_LAZY_MATCHING = False
    FIREWALL_CT = True

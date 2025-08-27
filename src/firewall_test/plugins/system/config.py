from plugins.system.linux_netfilter import SystemLinuxNetfilter
from plugins.translate.linux import LinuxRoutes, LinuxRouteRules, LinuxNetworkInterfaces
from plugins.translate.netfilter import NetfilterRuleset

SYSTEM_MAPPING = {
    'linux_netfilter': SystemLinuxNetfilter,
}

COMPONENT_MAPPING = {
    SystemLinuxNetfilter: {
        'nis': LinuxNetworkInterfaces,
        'routes': LinuxRoutes,
        'route_rules': LinuxRouteRules,
        'ruleset': NetfilterRuleset,
    }
}

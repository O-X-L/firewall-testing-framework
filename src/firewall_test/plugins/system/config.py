from plugins.system.system_linux_netfilter import SystemLinuxNetfilter
from plugins.translate.netfilter.ruleset import NetfilterRuleset
from plugins.translate.linux import LinuxRoutes, LinuxRouteRules, LinuxNetworkInterfaces

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

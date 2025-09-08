from plugins.system.system_linux_netfilter import SystemLinuxNetfilter
from plugins.translate.netfilter.ruleset import NetfilterRuleset
from plugins.translate.linux import LinuxRoutes, LinuxRouteRules, LinuxNetworkInterfaces
from plugins.system.system_opnsense import SystemOPNsense
from plugins.translate.opnsense.interfaces import OPNsenseNetworkInterfaces
from plugins.translate.opnsense.routes import OPNsenseRoutes
from plugins.translate.opnsense.ruleset import OPNsenseRuleset

SYSTEM_MAPPING = {
    'linux_netfilter': SystemLinuxNetfilter,
    'opnsense': SystemOPNsense,
}

COMPONENT_MAPPING = {
    SystemLinuxNetfilter: {
        'nis': LinuxNetworkInterfaces,
        'routes': LinuxRoutes,
        'route_rules': LinuxRouteRules,
        'ruleset': NetfilterRuleset,
    },
    SystemOPNsense: {
        'nis': OPNsenseNetworkInterfaces,
        'routes': OPNsenseRoutes,
        'ruleset': OPNsenseRuleset,
    },
}

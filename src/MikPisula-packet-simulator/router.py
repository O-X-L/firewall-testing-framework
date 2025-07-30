import subprocess
import json
import ipaddress
from .packet import Packet

# class _RoutingResult:
#     def __init__(self, direction, route):
#         self.direction = direction  # in out forward? yeah that seems reasonable
#         self.route = route

#     def __repr__(self):
#         return (
#             f"{self.__class__.__name__}(direction={self.direction}, route={self.route})"
#         )

#     def __iter__(self):
#         yield self.direction
#         yield self.route


# http://linux-ip.net/html/part-concepts.html
class Router:
    def __init__(
        self, interfaces: dict = None, routes: dict = None, rules: dict = None
    ):
        if routes is None:
            routes = self.get_system_routes()

        if interfaces is None:
            interfaces = self.get_system_interfaces()

        if rules is None:
            rules = self.get_system_rules()

        self.interfaces = self.parse_interfaces(interfaces)
        self.tables = self.parse_routes(routes)
        self.rules = self.parse_rules(rules)

    def get_system_routes(self):
        ip_route = subprocess.run(
            ["ip", "-j", "route", "show", "table", "all"],
            capture_output=True,
            text=True,
            check=True,
        )

        parsed_routes = json.loads(ip_route.stdout)
        return parsed_routes

    def parse_routes(self, raw_routes: dict):
        routes = {}

        for raw_route in raw_routes:
            # TODO: refactor this to use a Route class
            # TODO: support blackhole routes

            if "table" in raw_route:
                table = raw_route["table"]
            else:
                table = "main"

            if table not in routes:
                routes[table] = []

            route = {}

            route["destination"] = (
                ipaddress.ip_network("0.0.0.0/0")
                if raw_route["dst"] == "default"
                else ipaddress.ip_network(raw_route["dst"])
            )

            if "type" in raw_route and raw_route["type"] == "blackhole":
                route["type"] = "blackhole"
            else:
                route["iface"] = raw_route["dev"]

            route["metric"] = raw_route["metric"] if "metric" in raw_route else None
            route["flags"] = raw_route["flags"]
            route["destination"] = (
                ipaddress.ip_network("0.0.0.0/0")
                if raw_route["dst"] == "default"
                else ipaddress.ip_network(raw_route["dst"])
            )
            route["gateway"] = (
                ipaddress.ip_address(raw_route["gateway"])
                if "gateway" in raw_route
                else None
            )
            route["prefsrc"] = (
                ipaddress.ip_address(raw_route["prefsrc"])
                if "prefsrc" in raw_route
                else None
            )
            route["scope"] = raw_route["scope"] if "scope" in raw_route else "global"

            routes[table].append(route)

        return routes

    def get_system_rules(self):
        ip_route = subprocess.run(
            ["ip", "-j", "rule", "list"],
            capture_output=True,
            text=True,
            check=True,
        )

        parsed_rules = json.loads(ip_route.stdout)
        return parsed_rules

    def parse_rules(self, raw_rules: dict):
        rules = []

        for raw_rule in raw_rules:
            rule = {}
            rule["src"] = (
                ipaddress.ip_network("0.0.0.0/0")
                if raw_rule["src"] == "all"
                else ipaddress.ip_network(raw_rule["src"])
            )
            rule["fwmark"] = raw_rule["fwmark"] if "fwmark" in rule else None
            rule["table"] = raw_rule["table"]

            rules.append(rule)

        return rules

    def get_system_interfaces(self):
        ip_address = subprocess.run(
            ["ip", "-j", "address"], capture_output=True, text=True, check=True
        )

        parsed_interfaces = json.loads(ip_address.stdout)
        return parsed_interfaces

    def parse_interfaces(self, raw_interfaces: dict):
        interfaces = []

        for parsed_interface in raw_interfaces:
            interfaces.append(
                {
                    "iface": parsed_interface["ifname"],
                    "mtu": parsed_interface["mtu"],
                    "qdisc": parsed_interface["qdisc"],
                    "addresses": [
                        {
                            "family": address["family"],
                            "address": (
                                ipaddress.IPv4Address(address["local"])
                                if address["family"] == "inet"
                                else ipaddress.IPv6Address(address["local"])
                            ),
                            "network": (
                                ipaddress.IPv4Network(
                                    (address["local"], address["prefixlen"]),
                                    strict=False,
                                )
                                if address["family"] == "inet"
                                else ipaddress.IPv6Network(
                                    (address["local"], address["prefixlen"]),
                                    strict=False,
                                )
                            ),
                        }
                        for address in parsed_interface["addr_info"]
                    ],
                }
            )

        return interfaces

    def route(self, packet: Packet) -> dict:
        packet.route = None

        # http://linux-ip.net/html/routing-selection.html
        # TODO: support multiple routing tables

        table = None

        # TODO: suppress_prefixlength NUMBER - reject routing decisions that have a prefix length of NUMBER or less.
        #    Each policy routing rule consists of a selector and an action predicate.  The RPDB is scanned in order of decreasing priority (note that a lower number means higher priority, see the description of PREFERENCE below). The se‐
        #    lector of each rule is applied to {source address, destination address, incoming interface, tos, fwmark} and, if the selector matches the packet, the action is performed. The action predicate may return with success.  In this
        #    case, it will either give a route or failure indication and the RPDB lookup is terminated. Otherwise, the RPDB program continues with the next rule.
        for rule in self.rules:
            if packet.route is not None:
                break

            # TODO: this ignores packets originating from the host
            if packet.source is not None and packet.source not in rule["src"]:
                continue

            # if 'fwmark' in rule and rule['fwmark'] and not packet.fwmark == rule["fwmark"]:
            #     rule["fwmark"]
            #     continue

            for route in self.tables[rule["table"]]:
                if packet.destination in route["destination"]:

                    # TODO: implement metrics
                    if packet.route == None:
                        packet.route = route
                    elif (
                        packet.route["destination"].prefixlen
                        < route["destination"].prefixlen
                    ):
                        packet.route = route
                    elif (
                        packet.route["destination"].prefixlen
                        == route["destination"].prefixlen
                    ):
                        raise Exception("How did this happen.")

        packet.oiface = packet.route["iface"]

        print(
            f"[router] Using route: {packet.route['destination']} via {packet.route['iface']}"
        )

        if packet.route == None:
            raise Exception(f"No route to {packet.destination} could be found.")

        # TODO: refactor to use Route class
        return packet.route

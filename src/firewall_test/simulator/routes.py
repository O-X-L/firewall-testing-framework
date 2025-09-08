from os import environ

from plugins.system.abstract import FirewallSystem
from plugins.translate.abstract import StaticRouteRule, StaticRoute

from simulator.packet import PACKET_KINDS
from utils.logger import log_debug


class Router:
    def __init__(
            self,
            system: type[FirewallSystem],
            routes: list[StaticRoute],
            route_rules: list[StaticRouteRule] = None,
    ):
        self.system: type[FirewallSystem] = system
        self.routes: list[StaticRoute] = routes
        self.route_rules: list[StaticRouteRule]|None = route_rules

        self.rule_route_mapping = self._build_rule_route_mapping()
        self.table_priority = self._build_table_priority()

    def _build_rule_route_mapping(self) -> dict:
        m = {}
        if not self.system.ROUTE_STATIC_RULES:
            return m

        for rule in self.route_rules:
            m[rule]: list[StaticRoute] = []
            for route in self.routes:
                if rule.table == route.table:
                    m[rule].append(route)

        return m

    def _build_table_priority(self) -> list[str]:
        if self.system.ROUTE_STATIC_RULES:
            return self._build_table_priority_by_rules()

        all_tables = [route.table for route in self.routes]

        tables = []
        for table in list(set(all_tables)):
            if table != 'default':
                tables.append(table)

        tables.append('default')
        return tables

    def _build_table_priority_by_rules(self):
        priorities = [rule.priority for rule in self.route_rules]
        priorities.sort()
        tables = []
        for p in priorities:
            for rule in self.route_rules:
                if rule.priority == p:
                    tables.append(rule.table)

        return tables

    def _get_matching_rules(self, packet: PACKET_KINDS) -> list[StaticRouteRule]:
        if not self.system.ROUTE_STATIC_RULES:
            return []

        rules = []
        for rule in self.route_rules:
            for src_net in rule.src:
                if packet.src in src_net:
                    rules.append(rule)

        return rules

    def _get_matching_routes(self, packet: PACKET_KINDS, matching_rules: list[StaticRouteRule], src_route: bool = False) -> list[StaticRoute]:
        # todo: ignore routes of interfaces that are down

        route_for = packet.dst
        if src_route:
            route_for = packet.src

        routes = []
        if len(matching_rules) > 0:
            for rule in matching_rules:
                for route in self.rule_route_mapping[rule]:
                    if route_for in route.net:
                        routes.append(route)

        else:
            for route in self.routes:
                if route_for in route.net:
                    routes.append(route)

        return routes

    def _sort_routes(self, matching_routes: list[StaticRoute]) -> list[StaticRoute]:
        # prio by: table-prio, direct-attached, route-metric, route-subnet-size
        sorted_routes: list[StaticRoute] = []

        # todo: handle duplicate routes with scope=link (fe80)
        for table in self.table_priority:
            for route in matching_routes:
                if route.scope == 'link' and route not in sorted_routes:
                    sorted_routes.append(route)

            metrics: list[int] = []
            route_size: dict = {}

            for route in matching_routes:
                if route.table == table:
                    if route.metric is not None:
                        metrics.append(route.metric)

                    route_size[route.ip_count()] = route

            route_ip_count = list(route_size.keys())
            route_ip_count.sort()
            metrics.sort()
            for m in metrics:
                for n in route_ip_count:
                    route = route_size[n]
                    if route.metric == m and route not in sorted_routes:
                        sorted_routes.append(route)

            for n in route_ip_count:
                route = route_size[n]
                if route.metric is None and route not in sorted_routes:
                    sorted_routes.append(route)

        return sorted_routes

    def get_route(self, packet: PACKET_KINDS) -> (StaticRoute, None):
        rules = self._get_matching_rules(packet)
        routes = self._get_matching_routes(packet, rules)
        routes = self._sort_routes(routes)
        if 'DEBUG' in environ:
            log_debug('Router', f'Packet {packet.dump()} | Destination routes: {[r.dump() for r in routes]}')

        if len(routes) == 0:
            return None

        return routes[0]

    def get_src_route(self, packet: PACKET_KINDS) -> (StaticRoute, None):
        routes = self._get_matching_routes(packet, [], src_route=True)
        routes = self._sort_routes(routes)
        if 'DEBUG' in environ:
            log_debug('Router', f'Packet {packet.dump()} | Source routes: {[r.dump() for r in routes]}')

        if len(routes) == 0:
            return None

        return routes[0]

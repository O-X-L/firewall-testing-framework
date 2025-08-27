from plugins.translate.abstract import TranslateOutputStaticRouteRule, TranslateOutputStaticRoute
from simulator.packet import PacketIP


class Router:
    def __init__(self, routes: list[TranslateOutputStaticRoute], route_rules: list[TranslateOutputStaticRouteRule]):
        self.routes: list[TranslateOutputStaticRoute] = routes
        self.route_rules: list[TranslateOutputStaticRouteRule] = route_rules
        self.rule_route_mapping = self._build_rule_route_mapping()
        self.table_priority = self._build_rule_table_priority()

    def _build_rule_route_mapping(self) -> dict:
        m = {}
        for rule in self.route_rules:
            m[rule]: list[TranslateOutputStaticRoute] = []
            for route in self.routes:
                if rule.table == route.table:
                    m[rule].append(route)

        return m

    def _build_rule_table_priority(self) -> list:
        priorities = [rule.priority for rule in self.route_rules]
        priorities.sort()
        tables = []
        for p in priorities:
            for rule in self.route_rules:
                if rule.priority == p:
                    tables.append(rule.table)

        return tables

    def process(self, packet: PacketIP) -> list[TranslateOutputStaticRoute]:
        matching_rules = []
        for rule in self.route_rules:
            for src_net in rule.src:
                if packet.src in src_net:
                    matching_rules.append(rule)

        matching_routes = []
        if self.route_rules is None:
            for route in self.routes:
                if packet.dst in route.dst:
                    matching_routes.append(route)

        else:
            for rule in matching_rules:
                for route in self.rule_route_mapping[rule]:
                    if packet.dst in route.dst:
                        matching_routes.append(route)

        print(f"ROUTE RULES MATCHED: {matching_rules}")
        print(f"ROUTES MATCHED: {matching_routes}")

        sorted_routes: list[TranslateOutputStaticRoute] = []
        for table in self.table_priority:
            metrics: list[int] = []
            routes: list[TranslateOutputStaticRoute] = []
            for route in matching_routes:
                if route.table == table:
                    metrics.append(route.metric)
                    routes.append(route)

            metrics.sort()
            for m in metrics:
                for route in routes:
                    if route.metric == m and route not in sorted_routes:
                        sorted_routes.append(route)

        print(f"ROUTES SORTED: {sorted_routes}")
        return sorted_routes

import subprocess
import json
import ipaddress
from .packet import Packet


class _FirewallResult:
    def __init__(self):
        pass


class Firewall:
    def __init__(self, ruleset: dict = None):
        self.hooks = {}

        if ruleset is None:
            ruleset = self.get_system_ruleset()

        self.ruleset = self.parse_ruleset(ruleset)

    def get_system_ruleset(self):
        nft_list_ruleset = subprocess.run(
            ["nft", "-j", "list", "ruleset", "inet"],
            capture_output=True,
            text=True,
            check=True,
        )

        parsed_ruleset = json.loads(nft_list_ruleset.stdout)
        return parsed_ruleset

    def parse_ruleset(self, raw_ruleset: dict):
        ruleset = {}

        for raw_element in raw_ruleset["nftables"]:
            for element_type, element in raw_element.items():
                if element_type == "metainfo":
                    # TODO: print this in verbose mode
                    pass

                elif element_type == "table":
                    family = element["family"]

                    if family not in ruleset:
                        ruleset[family] = {}

                    ruleset[family][element["name"]] = {}

                elif element_type == "chain":
                    ruleset[element["family"]][element["table"]][element["name"]] = {
                        "name": element["name"],
                        "rules": [],
                        "hook": element["hook"] if "hook" in element else None,
                        "policy": element["policy"] if "policy" in element else None,
                        "priority": element["prio"] if "prio" in element else None,
                        "table": element["table"],
                        "family": element["family"],
                    }

                elif element_type == "rule":
                    ruleset[element["family"]][element["table"]][element["chain"]][
                        "rules"
                    ].append(
                        {
                            "expr": element["expr"],
                            "table": element["table"],
                            "family": element["family"],
                        }
                    )

                elif element_type == "ct helper":
                    continue

                else:
                    raise Exception(f"Unknown ruleset element_type: {element_type}")

        return ruleset

    # https://wiki.nftables.org/wiki-nftables/index.php/Matching_connection_tracking_stateful_metainformation#ct_status_-_conntrack_status
    # https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/netfilter/nf_conntrack_common.h#L65
    # TODO
    def _resolve_selector(self, raw_expression: dict, packet: Packet):
        if raw_expression == "dnat":
            return 1 << 5

        elif raw_expression == "invalid":
            return 1 << 0

        elif raw_expression == "established":
            return 1 << (0 + 1)

        elif raw_expression == "related":
            return 1 << (1 + 1)

        elif raw_expression == "new":
            return 1 << (2 + 1)

        else:
            raise Exception(f"Unknown selector: {raw_expression}")

    def _resolve_expression(self, raw_expression: dict, operator: str, packet: Packet):
        if isinstance(raw_expression, str):
            return (
                self._resolve_selector(raw_expression, packet)
                if operator == "in"
                else raw_expression
            )

        elif isinstance(raw_expression, int):
            return raw_expression

        ((expression_type, expression),) = raw_expression.items()

        # TODO: add conntrack tool support
        # TODO
        if expression_type == "ct":
            ct_key = expression["key"]

            if ct_key == "state":
                state = packet.ct["state"]
                return (
                    self._resolve_selector(state, packet) if operator == "in" else state
                )

            elif ct_key == "status":
                status = packet.ct["status"]
                return status

            else:
                raise Exception(f"Unknown ct_key: {ct_key}")

        # https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_metainformation
        # TODO
        elif expression_type == "meta":
            meta_key = expression["key"]

            if meta_key == "oifname":
                return packet.oiface

            elif meta_key == "iifname":
                return packet.iiface

            elif meta_key == "mark":
                return packet.fwmark

            elif meta_key == "nfproto":
                return (
                    "ipv4"
                    if isinstance(packet.source, ipaddress.IPv4Address)
                    else "ipv6"
                )

            elif meta_key == "l4proto":
                return packet.proto

            else:
                raise Exception(f"Unknown meta_key: {meta_key}")

        # TODO
        elif expression_type == "set":
            return [
                self._resolve_expression(set_expression, operator, packet)
                for set_expression in expression
            ]

        # TODO
        elif expression_type == "payload":
            if "protocol" in expression and "field" in expression:
                protocol = expression["protocol"]
                field = expression["field"]

                # TODO: refactor this so that not only daddr checks if packet is ipv6
                if protocol == "ip6":
                    if not isinstance(packet.source, ipaddress.IPv6Address):
                        return None

                    if field == "daddr":
                        return packet.destination

                    elif field == "saddr":
                        return packet.destination

                    elif field == "protocol":
                        return packet.proto

                    else:
                        raise Exception(f"Unknown field {expression}")

                if protocol == "ip":
                    if not isinstance(packet.destination, ipaddress.IPv4Address):
                        return None

                    if field == "daddr":
                        return packet.destination

                    elif field == "saddr":
                        return packet.destination

                    elif field == "protocol":
                        return packet.proto

                    else:
                        raise Exception(f"Unknown field {expression}")

                elif protocol == "icmpv6":
                    if packet.proto != "icmpv6":
                        return None

                    # TODO:
                    return None

                elif protocol == "tcp":
                    if packet.proto != "tcp":
                        return None

                    if field == "dport":
                        return packet.dport

                    elif field == "sport":
                        return packet.sport

                elif protocol == "udp":
                    if packet.proto != "udp":
                        return None

                    if field == "dport":
                        return packet.dport

                    elif field == "sport":
                        return packet.sport

                else:
                    raise Exception(f"Unknown protocol {protocol}")

            else:
                raise Exception(f'Unknown payload {expression["payload"]}')

        elif expression_type == "prefix":
            if isinstance(
                ipaddress.ip_address(expression["addr"]), ipaddress.IPv6Address
            ):
                return ipaddress.IPv6Network((expression["addr"], expression["len"]))
            else:
                return ipaddress.IPv4Network((expression["addr"], expression["len"]))

        elif expression_type == "range":
            return range(expression[0], expression[1] + 1)

        else:
            raise Exception(f"Unknown expression type {expression_type}")

    def _resolve_match(self, match: dict, packet: Packet):
        operator = match["op"]

        left = self._resolve_expression(match["left"], operator, packet)
        right = self._resolve_expression(match["right"], operator, packet)

        # print(f"[firewall] match {left} {operator} {right}")

        if isinstance(left, list):
            raise Exception(f"Unsupported expression on LHS {right}")

        elif (
            isinstance(right, list)
            or isinstance(right, range)
            or isinstance(right, ipaddress.IPv4Network)
            or isinstance(right, ipaddress.IPv6Network)
        ):
            if operator == "==":
                result = left is not None and left in right

            elif operator == "!=":
                result = left is None or not left in right

            else:
                raise Exception(f"Unknown operator {operator}")

        else:
            # TODO: interface globbing, i.e. wlan*
            # Like with iptables, wildcard matching on interface name prefixes is available for iifname and oifname matches
            # by appending an asterisk (*) character. Note however that unlike iptables, nftables does not accept interface
            # names consisting of the wildcard character only - users are supposed to just skip those always matching
            # expressions. In order to match on literal asterisk character, one may escape it using backslash (\).
            if operator == "==":
                result = right == left

            elif operator == "!=":
                result = right != left

            elif operator == "in":
                result = (right & left) == right

            else:
                raise Exception(f"Unknown operator: {operator}")

        print(f"[firewall] match {left} {operator} {right} -> {result}")
        return result

    def _resolve_rule(self, rule: dict, packet: Packet):
        for raw_expression in rule["expr"]:
            for expression_type, expression in raw_expression.items():
                if expression_type == "jump":
                    print(f"[firewall] jump to chain {expression['target']}")

                    return self._resolve_chain(
                        self.ruleset[rule["family"]][rule["table"]][
                            expression["target"]
                        ],
                        packet,
                    )

                elif expression_type == "match":
                    if self._resolve_match(expression, packet) == True:
                        continue
                    else:
                        return None

                elif expression_type in ["accept", "reject", "drop"]:
                    print(f"[firewall] {expression_type}")

                    return expression_type

                elif expression_type == "return":
                    print(f"[firewall] return")
                    return None

                elif expression_type == "xt":
                    print(f"[firewall] {expression_type}")

                    if expression["name"] in ("owner", "cgroup"):
                        print(
                            f"[firewall] Warning: Ignoring {expression['name']} extension"
                        )
                        return

                    else:
                        raise Exception(f"Unknown extension {expression['name']}")

                elif expression_type == "counter":
                    continue

                elif expression_type == "masquerade":
                    packet.source = packet.route["prefsrc"]

                else:
                    raise Exception(f"Unknown rule expression_type {expression_type}")

    def _resolve_chain(self, chain: dict, packet: Packet):
        print(f"[firewall] enter chain {chain['name']}")

        for rule in self.ruleset[chain["family"]][chain["table"]][chain["name"]][
            "rules"
        ]:
            value = self._resolve_rule(rule, packet)

            if value is not None:
                return value

    # https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks
    def resolve_hook(self, hook: str, packet: Packet):
        print(f"[firewall] hook {hook}")

        hooks = []

        for tables in self.ruleset.values():
            for chains in tables.values():
                for chain in chains.values():
                    if chain["hook"] == hook:
                        hooks.append(chain)

        hooks = sorted(hooks, key=lambda c: c["priority"])

        result = None

        for hook in hooks:
            if not hook["family"] == "inet" and not hook["family"] == (
                "ip6" if isinstance(packet.source, ipaddress.IPv6Address) else "ip"
            ):
                continue

            chain_result = self._resolve_chain(hook, packet)

            if chain_result is None:
                result = hook["policy"]
            else:
                result = chain_result

            print(f'[firewall] {hook["name"]} -> {result}')

            if result in ("reject", "drop"):
                return result

        return result

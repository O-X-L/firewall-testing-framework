#!/usr/bin/env python3

import argparse
import ipaddress
from pathlib import Path
import json

from . import Simulator, Packet, Firewall, Router


def main():
    parser = argparse.ArgumentParser(
        description="Packet simulator for testing routing and nf_tables firewall rules"
    )

    # TODO: add ipv6 support
    parser.add_argument(
        "-s",
        "--source",
        help="source IP address",
        type=ipaddress.IPv4Address,
        default=None,
    )
    parser.add_argument(
        "-d",
        "--destination",
        help="destination IP address",
        type=ipaddress.IPv4Address,
        required=True,
    )

    proto_group = parser.add_mutually_exclusive_group()

    proto_group.add_argument("-t", "--tcp", help="use TCP packet", action="store_true")
    proto_group.add_argument("-u", "--udp", help="use UDP packet", action="store_true")
    parser.add_argument(
        "-dport", "--destination-port", help="destination port", type=int, default=80
    )
    parser.add_argument(
        "-sport", "--source-port", help="source port", type=int, default=50000
    )

    proto_group.add_argument(
        "-i", "--icmp", help="use ICMP packet", action="store_true"
    )
    parser.add_argument("-p", "--type", help="ICMP type", type=int, default=0)
    parser.add_argument("-c", "--code", help="ICMP code", type=int, default=0)

    parser.add_argument("-v", "--verbose", action="store_true")

    parser.add_argument(
        "-r", "--ruleset", help="Ruleset file (`ntf -j list ruleset` output)"
    )

    parser.add_argument("-o", "--routes", help="Routing table (`ip -j route` output)")
    parser.add_argument(
        "-f", "--interfaces", help="Interface table (`ip -j address show` output)"
    )

    parser.add_argument(
        "-e",
        "--state",
        help="Packet conntrack state",
        type=str,
        choices=("new", "established", "related", "invalid"),
    )

    args = parser.parse_args()

    ruleset = None

    if args.ruleset:
        with Path(args.ruleset).open() as ruleset_fp:
            ruleset = json.load(ruleset_fp)

    firewall = Firewall(ruleset)

    routes = None
    interfaces = None

    if args.routes:
        with Path(args.routes).open() as routes_fp:
            routes = json.load(routes_fp)

    if args.interfaces:
        with Path(args.interfaces).open() as interfaces_fp:
            interfaces = json.load(interfaces_fp)

    router = Router(interfaces, routes)

    simulator = Simulator(firewall, router)
    packet = Packet(args.source, args.destination)

    if args.udp:
        packet.proto = "udp"
        packet.dport = args.dport
        packet.sport = args.dport

    elif args.tcp:
        packet.proto = "tcp"
        packet.dport = args.dport
        packet.sport = args.dport

    elif args.icmp:
        packet.proto = "icmp"
        packet.icmp["type"] = args.type
        packet.icmp["code"] = args.code

    if args.state:
        packet.ct["state"] = args.state

    simulator.simulate(packet)


if __name__ == "__main__":
    main()

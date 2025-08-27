from os import path as os_path
from sys import path as sys_path
from argparse import ArgumentParser

# pylint: disable=C0413
sys_path.append(os_path.dirname(os_path.abspath(__file__)))

from plugins.system.config import SYSTEM_MAPPING
from simulator.loader import load
from simulator.main import Simulator
from simulator.packet import PacketTCPUDP, PacketICMP


def main():
    parser = ArgumentParser(
        prog='Firewall-Testing-Framework (FTF)',
        description='Simulating traffic over network firewalls. License: MIT. (c) 2025 OXL IT Services'
    )

    parser.add_argument(
        '-s', '--src-ip', help='Packet source-IP',
        required=True,
    )
    parser.add_argument(
        '-d', '--dst-ip', help='Packet destination-IP',
        required=True,
    )
    parser.add_argument(
        '-3', '--proto-l3', help='Packet Layer-3 protocol',
        choices=['ip4', 'ip6'], default='ip4',
    )
    parser.add_argument(
        '-4', '--proto-l4', help='Packet Layer-4 protocol',
        choices=['tcp', 'udp', 'icmp', 'icmpv6'], default='tcp',
    )
    parser.add_argument(
        '-p', '--port', help='Packet destination-port (if L4-proto is tcp/udp)',
        type=int,
    )

    parser.add_argument(
        '-w', '--firewall-system', help='Kind of firewall system',
        choices=list(SYSTEM_MAPPING.keys()),
        required = True,
    )
    parser.add_argument(
        '-x', '--file-interfaces',
        help='Path to the file containing the network-interface information',
        required=True,
    )
    parser.add_argument(
        '-y', '--file-routes',
        help='Path to the file containing the network-route information',
        required=True,
    )
    parser.add_argument(
        '-z', '--file-route-rules',
        help='Path to the file containing the network-route-rule information',
    )

    args = parser.parse_args()

    if args.proto_l4 in ['tcp', 'udp']:
        packet = PacketTCPUDP(
            src=args.src_ip,
            dst=args.dst_ip,
            l3_proto=args.proto_l3,
            l4_proto=args.proto_l4,
        )

    else:
        packet = PacketICMP(
            src=args.src_ip,
            dst=args.dst_ip,
            l3_proto=args.proto_l3,
            l4_proto=args.proto_l4,
        )

    loaded = load(
        system=args.firewall_system,
        file_interfaces=args.file_interfaces,
        file_routes=args.file_routes,
        file_route_rules=args.file_route_rules,
    )
    s = Simulator(**loaded)
    r = s.run(packet)
    print('\n', r.to_json())


if __name__ == '__main__':
    main()

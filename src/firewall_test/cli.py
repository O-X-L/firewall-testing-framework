from os import environ
from os import path as os_path
from sys import path as sys_path
from sys import exit as sys_exit
from argparse import ArgumentParser

# pylint: disable=C0413
sys_path.append(os_path.dirname(os_path.abspath(__file__)))

from plugins.system.config import SYSTEM_MAPPING
from simulator.loader import load
from simulator.main import Simulator
from simulator.packet import PacketTCPUDP, PacketICMP
from config import ENV_DEBUG, ENV_VERBOSITY, VERBOSITY_DEBUG, VERBOSITY_DEFAULT, ENV_LOG_COLOR


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
        '-4', '--proto', help='Packet Layer-4 protocol',
        choices=['tcp', 'udp', 'icmp'], default='tcp',
    )
    parser.add_argument(
        '-p', '--port', help='Packet destination-port (if L4-proto is tcp/udp)',
        type=int,
    )

    parser.add_argument(
        '-n', '--no-color', help='Disable output colors',
        action='store_true',
    )
    parser.add_argument(
        '-v', '--verbosity', help='Output verbosity',
        choices=['0', '1', '2', '3', VERBOSITY_DEBUG, 'silent'], default=VERBOSITY_DEFAULT,
    )

    parser.add_argument(
        '-u', '--firewall-system', help='Kind of firewall system',
        choices=list(SYSTEM_MAPPING.keys()),
        required = True,
    )
    parser.add_argument(
        '-w', '--file-interfaces',
        help='Path to the file containing the network-interface information',
        required=True,
    )
    parser.add_argument(
        '-x', '--file-routes',
        help='Path to the file containing the network-route information',
        required=True,
    )
    parser.add_argument(
        '-y', '--file-route-rules',
        help='Path to the file containing the network-route-rule information',
    )
    parser.add_argument(
        '-z', '--file-ruleset',
        help='Path to the file containing the firewall-ruleset information',
        required=True,
    )

    args = parser.parse_args()

    environ.setdefault(ENV_VERBOSITY, args.verbosity)
    environ.setdefault(ENV_LOG_COLOR, '0' if args.no_color else '1')

    if args.proto in ['tcp', 'udp']:
        packet = PacketTCPUDP(
            src=args.src_ip,
            dst=args.dst_ip,
            proto_l4=args.proto,
            dport=args.port,
        )

    else:
        packet = PacketICMP(
            src=args.src_ip,
            dst=args.dst_ip,
        )

    print()
    loaded = load(
        system=args.firewall_system,
        file_interfaces=args.file_interfaces,
        file_routes=args.file_routes,
        file_route_rules=args.file_route_rules,
        file_ruleset=args.file_ruleset,
    )
    s = Simulator(**loaded)
    r = s.run(packet)

    if ENV_DEBUG in environ:
        print('\n', r.to_json())

    print()

    if not r.passed:
        sys_exit(1)


if __name__ == '__main__':
    main()

from ipaddress import IPv4Address, IPv6Address


def ip_is_bogon(ip: (IPv4Address, IPv6Address)) -> bool:
    return any([
        ip.is_multicast,
        ip.is_private,
        ip.is_unspecified,
        ip.is_reserved,
        ip.is_loopback,
        ip.is_link_local,
    ])

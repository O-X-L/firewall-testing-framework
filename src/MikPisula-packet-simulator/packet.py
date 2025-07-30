import ipaddress


class Packet:
    def __init__(self, source, destination):
        # TODO: ipv6
        if source is not None and not isinstance(source, ipaddress.IPv4Address):
            source = ipaddress.IPv4Address(source)

        # TODO: ipv6
        if not isinstance(destination, ipaddress.IPv4Address):
            destination = ipaddress.IPv4Address(destination)

        self.source = source
        self.destination = destination
        self.proto = "tcp"
        self.sport = 50000
        self.dport = 80
        self.iiface = None
        self.oiface = None

        self.ct = {"state": "new", "status": 0b0000000000000000}

        self.icmp = {"type": 0, "code": 0}

        self.fwmark = 0x0

        self.route = None

    def __repr__(self):
        return f"{self.__class__.__name__}(source={self.source}, destination={self.destination}, proto={self.proto}, sport={self.sport}, dport={self.dport}, iiface={self.iiface}, oiface={self.oiface}, ct={self.ct}, icmp={self.icmp})"

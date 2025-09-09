.. _usage_run:

.. include:: ../_include/head.rst

=======
3 - Run
=======

Install
#######

To install the **Firewall Testing Framework** you need to have `Python3 and the package-manager PIP <https://docs.python.org/3/installing/index.html>`_ installed!

Then just run:

.. code-block:: bash


    pip install firewall-test

`Module on pypi.org <https://pypi.org/project/firewall-test/>`_

----

Run Modes
#########

One-Shot CLI
============

For simulating single packets you can use the simple CLI.

This is also a good way to test your setup at first!

.. code-block:: bash

    ftf-cli --help
    > usage: Firewall-Testing-Framework (FTF) [-h] -s SRC_IP -d DST_IP [-4 {tcp,udp,icmp,icmpv6}] [-p PORT] [-n] [-v {0,1,2,3,4,silent}] -u {linux_netfilter} -w
    >                                         FILE_INTERFACES -x FILE_ROUTES [-y FILE_ROUTE_RULES] -z FILE_RULESET
    >
    > Simulating traffic over network firewalls. License: MIT. (c) 2025 OXL IT Services
    >
    > options:
    >   -h, --help            show this help message and exit
    >   -s SRC_IP, --src-ip SRC_IP
    >                         Packet source-IP
    >   -d DST_IP, --dst-ip DST_IP
    >                         Packet destination-IP
    >   -4 {tcp,udp,icmp}, --proto {tcp,udp,icmp}
    >                         Packet Layer-4 protocol
    >   -p PORT, --port PORT  Packet destination-port (if L4-proto is tcp/udp)
    >   -n, --no-color        Disable output colors
    >   -v {0,1,2,3,4,silent}, --verbosity {0,1,2,3,4,silent}
    >                         Output verbosity
    >   -u {linux_netfilter}, --firewall-system {linux_netfilter}
    >                         Kind of firewall system
    >   -w FILE_INTERFACES, --file-interfaces FILE_INTERFACES
    >                         Path to the file containing the network-interface information
    >   -x FILE_ROUTES, --file-routes FILE_ROUTES
    >                         Path to the file containing the network-route information
    >   -y FILE_ROUTE_RULES, --file-route-rules FILE_ROUTE_RULES
    >                         Path to the file containing the network-route-rule information
    >   -z FILE_RULESET, --file-ruleset FILE_RULESET
    >                         Path to the file containing the firewall-ruleset information

----

Pass Example
************

.. code-block:: bash

    ftf-cli --firewall-system 'linux_netfilter' \
            --file-interfaces 'testdata/plugin_translate_linux_interfaces.json' \
            --file-routes 'testdata/plugin_translate_linux_routes.json' \
            --file-route-rules 'testdata/plugin_translate_linux_route-rules.json' \
            --file-ruleset 'testdata/plugin_translate_netfilter_ruleset.json' \
            --src-ip 172.17.11.5 \
            --dst-ip 1.1.1.1

    > 🛈 ROUTER: Packet inbound-interface: docker0
    > 🛈 ROUTER: Packet inbound-route: 172.17.0.0/16, scope link
    > 🛈 FIREWALL: Processing Chain: Table nat ip4 | Chain PREROUTING ip4 nat
    > 🛈 FIREWALL: > Chain PREROUTING | Rule 0 | Match => jump
    > 🛈 FIREWALL: > Chain PREROUTING | Sub-Chain: DOCKER (2 rules)
    > 🛈 FIREWALL: > Chain DOCKER | Rule 0 | Match => return
    > 🛈 ROUTER: Packet outbound-interface: wan
    > 🛈 ROUTER: Packet outbound-route: 0.0.0.0/0, gw 10.255.255.254, metric 600, scope global
    > 🛈 FIREWALL: Processing Chain: Table filter ip4 | Chain FORWARD ip4 filter
    > 🛈 FIREWALL: > Chain FORWARD | Rule 0 | Match => jump
    > 🛈 FIREWALL: > Chain FORWARD | Sub-Chain: DOCKER-USER (1 rules)
    > 🛈 FIREWALL: > Chain DOCKER-USER | Rule 0 | Match => return
    > 🛈 FIREWALL: > Chain FORWARD | Rule 1
    > 🛈 FIREWALL: > Chain FORWARD | Rule 2
    > 🛈 FIREWALL: > Chain FORWARD | Rule 3
    > 🛈 FIREWALL: > Chain FORWARD | Rule 4 | Match => jump
    > 🛈 FIREWALL: > Chain FORWARD | Sub-Chain: DOCKER-FORWARD (4 rules)
    > 🛈 FIREWALL: > Chain DOCKER-FORWARD | Rule 0 | Match => jump
    > 🛈 FIREWALL: > Chain DOCKER-FORWARD | Sub-Chain: DOCKER-CT (1 rules)
    > 🛈 FIREWALL: > Chain DOCKER-CT | Rule 0
    > 🛈 FIREWALL: > Chain DOCKER-FORWARD | Rule 1 | Match => jump
    > 🛈 FIREWALL: > Chain DOCKER-FORWARD | Sub-Chain: DOCKER-ISOLATION-STAGE-1 (1 rules)
    > 🛈 FIREWALL: > Chain DOCKER-ISOLATION-STAGE-1 | Rule 0 | Match => jump
    > 🛈 FIREWALL: > Chain DOCKER-ISOLATION-STAGE-1 | Sub-Chain: DOCKER-ISOLATION-STAGE-2 (1 rules)
    > 🛈 FIREWALL: > Chain DOCKER-ISOLATION-STAGE-2 | Rule 0
    > 🛈 FIREWALL: > Chain DOCKER-FORWARD | Rule 2 | Match => jump
    > 🛈 FIREWALL: > Chain DOCKER-FORWARD | Sub-Chain: DOCKER-BRIDGE (1 rules)
    > 🛈 FIREWALL: > Chain DOCKER-BRIDGE | Rule 0
    > 🛈 FIREWALL: > Chain DOCKER-FORWARD | Rule 3 | Match => accept
    > 🛈 FIREWALL: Processing Chain: Table nat ip4 | Chain POSTROUTING ip4 nat
    > 🛈 FIREWALL: > Chain POSTROUTING | Rule 0 | Match => snat
    > 🛈 FIREWALL: Performed SNAT: 172.17.11.5 => 10.255.255.48
    > ✓ FIREWALL: Packet passed

----

Block Example
*************

.. code-block:: bash

    ftf-cli ... --src-ip 172.17.11.5 --dst-ip 2.2.2.2

    > 🛈 ROUTER: Packet inbound-interface: docker0
    > 🛈 ROUTER: Packet inbound-route: 172.17.0.0/16, scope link
    > 🛈 FIREWALL: Processing Chain: Table nat ip4 | Chain PREROUTING ip4 nat
    > 🛈 FIREWALL: > Chain PREROUTING | Rule 0 | Match => jump
    > 🛈 FIREWALL: > Chain PREROUTING | Sub-Chain: DOCKER (2 rules)
    > 🛈 FIREWALL: > Chain DOCKER | Rule 0 | Match => return
    > 🛈 ROUTER: Packet outbound-interface: wan
    > 🛈 ROUTER: Packet outbound-route: 0.0.0.0/0, gw 10.255.255.254, metric 600, scope global
    > 🛈 FIREWALL: Processing Chain: Table filter ip4 | Chain FORWARD ip4 filter
    > 🛈 FIREWALL: > Chain FORWARD | Rule 0 | Match => jump
    > 🛈 FIREWALL: > Chain FORWARD | Sub-Chain: DOCKER-USER (1 rules)
    > 🛈 FIREWALL: > Chain DOCKER-USER | Rule 0 | Match => return
    > 🛈 FIREWALL: > Chain FORWARD | Rule 1 | Match => drop
    > ✖ FIREWALL: Packet blocked by rule: Seq 1, Action: drop, Rule: #101 "TEST IP4-DADDR DROP"
    >              > Matches: {'proto_l3': {'==': 'ip4'}, 'ip_daddr': {'==': ['2.2.2.2/32']}}

----

Output Verbosity
****************

You can get more detailed output by increasing the verbosity:

.. code-block:: bash

    ftf-cli ... --src-ip 172.17.11.5 --dst-ip 2.2.2.2 --verbosity 2

    > 🛈 ROUTER: Packet inbound-interface: docker0
    > 🛈 ROUTER: Packet inbound-route: 172.17.0.0/16, scope link
    > 🛈 FIREWALL: Processing Chain: Table nat ip4 | Chain PREROUTING ip4 nat
    > 🛈 FIREWALL: > Chain PREROUTING | Rule 0 | Match => jump | Seq 0, Action: jump, Rule: #3
    >              > Matches: {}
    >
    > 🛈 FIREWALL: > Chain PREROUTING | Sub-Chain: DOCKER (2 rules)
    > 🛈 FIREWALL: > Chain DOCKER | Rule 0 | Match => return | Seq 0, Action: return, Rule: #10
    >              > Matches: {'ni_in': {'==': ['docker0']}}
    >
    > 🛈 FIREWALL: Flow-type: forward
    > 🛈 ROUTER: Packet outbound-interface: wan
    > 🛈 ROUTER: Packet outbound-route: 0.0.0.0/0, gw 10.255.255.254, metric 600, scope global
    > 🛈 FIREWALL: Processing Chain: Table filter ip4 | Chain FORWARD ip4 filter
    > 🛈 FIREWALL: > Chain FORWARD | Rule 0 | Match => jump | Seq 0, Action: jump, Rule: #20
    >              > Matches: {}
    >
    > 🛈 FIREWALL: > Chain FORWARD | Sub-Chain: DOCKER-USER (1 rules)
    > 🛈 FIREWALL: > Chain DOCKER-USER | Rule 0 | Match => return | Seq 0, Action: return, Rule: #19
    >              > Matches: {}
    >
    > 🛈 FIREWALL: > Chain FORWARD | Rule 1 | Match => drop | Seq 1, Action: drop, Rule: #101 "TEST IP4-DADDR DROP"
    >              > Matches: {'proto_l3': {'==': 'ip4'}, 'ip_daddr': {'==': ['2.2.2.2/32']}}
    >
    > ✖ FIREWALL: Packet blocked by rule: Seq 1, Action: drop, Rule: #101 "TEST IP4-DADDR DROP"
    >              > Matches: {'proto_l3': {'==': 'ip4'}, 'ip_daddr': {'==': ['2.2.2.2/32']}}

Or use the silent-mode:

.. code-block:: bash

    ftf-cli ... --src-ip 172.17.11.5 --dst-ip 2.2.2.2 --verbosity silent

    > ✖ FIREWALL: Packet blocked by rule: Seq 1, Action: drop, Rule: #101 "TEST IP4-DADDR DROP"
    >              > Matches: {'proto_l3': {'==': 'ip4'}, 'ip_daddr': {'==': ['2.2.2.2/32']}}

----

System-Config Example
*********************

Depending on the system-specific configuration traffic can be dropped by non-firewall conditions. (like Linux kernel networking)

.. code-block:: bash

    ftf-cli ... --src-ip 172.17.11.5 --dst-ip 10.100.1.1

    > 🛈 ROUTER: Packet inbound-interface: docker0
    > 🛈 ROUTER: Packet inbound-route: 172.17.0.0/16, scope link
    > 🛈 FIREWALL: Processing Chain: Table nat ip4 | Chain PREROUTING ip4 nat
    > 🛈 FIREWALL: > Chain PREROUTING | Rule 0 | Match => jump
    > 🛈 FIREWALL: > Chain PREROUTING | Sub-Chain: DOCKER (2 rules)
    > 🛈 FIREWALL: > Chain DOCKER | Rule 0 | Match => return
    > 🛈 ROUTER: Packet outbound-interface: wan
    > 🛈 ROUTER: Packet outbound-route: 0.0.0.0/0, gw 10.255.255.254, metric 600, scope remote
    > ✖ SYSTEM: Dropping traffic to WAN targeting bogons

----

Automated for CI
================

.. include:: ../_include/warn_develop.rst

----

Interactive Shell
=================

.. include:: ../_include/warn_develop.rst

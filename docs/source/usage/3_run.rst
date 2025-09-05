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

----

Run Modes
#########

One-Shot CLI
============

For simulating single packets you can use the simple CLI.

This is also a good way to test your setup at first!

.. code-block:: bash

    ftf-cli --help
    > usage: Firewall-Testing-Framework (FTF) [-h] -s SRC_IP -d DST_IP [-4 {tcp,udp,icmp,icmpv6}] [-p PORT] -v {linux_netfilter} -w FILE_INTERFACES -x
    >                                         FILE_ROUTES [-y FILE_ROUTE_RULES] -z FILE_RULESET
    >
    > Simulating traffic over network firewalls. License: MIT. (c) 2025 OXL IT Services
    >
    > options:
    >   -h, --help            show this help message and exit
    >   -s SRC_IP, --src-ip SRC_IP
    >                         Packet source-IP
    >   -d DST_IP, --dst-ip DST_IP
    >                         Packet destination-IP
    >   -4 {tcp,udp,icmp,icmpv6}, --proto-l4 {tcp,udp,icmp,icmpv6}
    >                         Packet Layer-4 protocol
    >   -p PORT, --port PORT  Packet destination-port (if L4-proto is tcp/udp)
    >   -v {linux_netfilter}, --firewall-system {linux_netfilter}
    >                         Kind of firewall system
    >   -w FILE_INTERFACES, --file-interfaces FILE_INTERFACES
    >                         Path to the file containing the network-interface information
    >   -x FILE_ROUTES, --file-routes FILE_ROUTES
    >                         Path to the file containing the network-route information
    >   -y FILE_ROUTE_RULES, --file-route-rules FILE_ROUTE_RULES
    >                         Path to the file containing the network-route-rule information
    >   -z FILE_RULESET, --file-ruleset FILE_RULESET
    >                         Path to the file containing the firewall-ruleset information


    # PASS EXAMPLE:
    ftf-cli --firewall-system 'linux_netfilter' \
            --file-interfaces 'testdata/plugin_translate_linux_interfaces.json' \
            --file-routes 'testdata/plugin_translate_linux_routes.json' \
            --file-route-rules 'testdata/plugin_translate_linux_route-rules.json' \
            --file-ruleset 'testdata/plugin_translate_netfilter_ruleset.json' \
            --src-ip 172.17.11.5 \
            --dst-ip 1.1.1.1

    > 🛈 ROUTER: Packet inbound-interface: docker0
    > 🛈 ROUTER: Packet inbound-route: 172.17.0.0/16, scope link
    > 🛈 FIREWALL: Processing Pre-Routing Filter-Hooks
    > 🛈 FIREWALL: Processing DNAT
    > 🛈 FIREWALL: Processing Chain: Table nat ip4 | Chain PREROUTING ip4 nat
    > 🛈 FIREWALL: PREROUTING | Processing Rule: {'action': 'jump', 'seq': 0, 'raw': Rule: #3 | Matches: []}
    > 🛈 FIREWALL:  > Match: True | Action: jump
    > 🛈 FIREWALL: PREROUTING | Processing Sub-Chain: Table nat ip4 | Chain DOCKER ip4 filter
    > 🛈 FIREWALL: DOCKER | Processing Rule: {'action': 'return', 'seq': 0, 'raw': Rule: #10 | Matches: [Match: ['ni_in'] == ['docker0']]}
    > 🛈 FIREWALL:  > Match: True | Action: return
    > 🛈 FIREWALL: Flow-type: forward
    > 🛈 ROUTER: Packet outbound-interface: wan
    > 🛈 ROUTER: Packet outbound-route: 0.0.0.0/0, gw 10.255.255.254, metric 600, scope remote
    > 🛈 FIREWALL: Processing Main Filter-Hooks
    > 🛈 FIREWALL: Processing Chain: Table filter ip4 | Chain FORWARD ip4 filter
    > 🛈 FIREWALL: FORWARD | Processing Rule: {'action': 'jump', 'seq': 0, 'raw': Rule: #20 | Matches: []}
    > 🛈 FIREWALL:  > Match: True | Action: jump
    > 🛈 FIREWALL: FORWARD | Processing Sub-Chain: Table filter ip4 | Chain DOCKER-USER ip4 filter
    > 🛈 FIREWALL: DOCKER-USER | Processing Rule: {'action': 'return', 'seq': 0, 'raw': Rule: #19 | Matches: []}
    > 🛈 FIREWALL:  > Match: True | Action: return
    > 🛈 FIREWALL: FORWARD | Processing Rule: {'action': 'jump', 'seq': 1, 'raw': Rule: #8 | Matches: []}
    > 🛈 FIREWALL:  > Match: True | Action: jump
    > 🛈 FIREWALL: FORWARD | Processing Sub-Chain: Table filter ip4 | Chain DOCKER-FORWARD ip4 filter
    > 🛈 FIREWALL: DOCKER-FORWARD | Processing Rule: {'action': 'jump', 'seq': 0, 'raw': Rule: #11 | Matches: []}
    > 🛈 FIREWALL:  > Match: True | Action: jump
    > 🛈 FIREWALL: DOCKER-FORWARD | Processing Sub-Chain: Table filter ip4 | Chain DOCKER-CT ip4 filter
    > 🛈 FIREWALL: DOCKER-CT | Processing Rule: {'action': 'accept', 'seq': 0, 'raw': Rule: #23 | Matches: [Match: ['ni_out'] == ['docker0']]}
    > 🛈 FIREWALL: DOCKER-FORWARD | Processing Rule: {'action': 'jump', 'seq': 1, 'raw': Rule: #10 | Matches: []}
    > 🛈 FIREWALL:  > Match: True | Action: jump
    > 🛈 FIREWALL: DOCKER-FORWARD | Processing Sub-Chain: Table filter ip4 | Chain DOCKER-ISOLATION-STAGE-1 ip4 filter
    > 🛈 FIREWALL: DOCKER-ISOLATION-STAGE-1 | Processing Rule: {'action': 'jump', 'seq': 0, 'raw': Rule: #25 | Matches: [Match: ['ni_in'] == ['docker0'], Match: ['ni_out'] != ['docker0']]}
    > 🛈 FIREWALL:  > Match: True | Action: jump
    > 🛈 FIREWALL: DOCKER-ISOLATION-STAGE-1 | Processing Sub-Chain: Table filter ip4 | Chain DOCKER-ISOLATION-STAGE-2 ip4 filter
    > 🛈 FIREWALL: DOCKER-ISOLATION-STAGE-2 | Processing Rule: {'action': 'drop', 'seq': 0, 'raw': Rule: #26 | Matches: [Match: ['ni_out'] == ['docker0']]}
    > 🛈 FIREWALL: DOCKER-FORWARD | Processing Rule: {'action': 'jump', 'seq': 2, 'raw': Rule: #9 | Matches: []}
    > 🛈 FIREWALL:  > Match: True | Action: jump
    > 🛈 FIREWALL: DOCKER-FORWARD | Processing Sub-Chain: Table filter ip4 | Chain DOCKER-BRIDGE ip4 filter
    > 🛈 FIREWALL: DOCKER-BRIDGE | Processing Rule: {'action': 'jump', 'seq': 0, 'raw': Rule: #24 | Matches: [Match: ['ni_out'] == ['docker0']]}
    > 🛈 FIREWALL: DOCKER-FORWARD | Processing Rule: {'action': 'accept', 'seq': 3, 'raw': Rule: #21 | Matches: [Match: ['ni_in'] == ['docker0']]}
    > 🛈 FIREWALL:  > Match: True | Action: accept
    > 🛈 FIREWALL: Processing SNAT
    > 🛈 FIREWALL: Processing Chain: Table nat ip4 | Chain POSTROUTING ip4 nat
    > 🛈 FIREWALL: POSTROUTING | Processing Rule: {'action': None, 'seq': 0, 'raw': Rule: #9 | Matches: [Match: ['ni_out'] != ['docker0'], Match: ['proto_l3', 'ip_saddr'] == ['172.17.0.0/16', 'ip4']]}
    > 🛈 FIREWALL: Performed SNAT: 172.17.11.5 => 10.255.255.48
    > 🛈 FIREWALL: Processing Egress Filter-Hooks
    > ✓ FIREWALL: Packet passed


    # BLOCK EXAMPLE:
    ftf-cli ... --src-ip 10.0.0.1 --dst-ip 172.17.10.6

    > 🛈 ROUTER: Packet inbound-interface: wan
    > 🛈 ROUTER: Packet inbound-route: 0.0.0.0/0, gw 10.255.255.254, metric 600, scope remote
    > 🛈 FIREWALL: Processing Pre-Routing Filter-Hooks
    > 🛈 FIREWALL: Processing DNAT
    > 🛈 FIREWALL: Processing Chain: Table nat ip4 | Chain PREROUTING ip4 nat
    > 🛈 FIREWALL: PREROUTING | Processing Rule: {'action': 'jump', 'seq': 0, 'raw': Rule: #3 | Matches: []}
    > 🛈 FIREWALL:  > Match: True | Action: jump
    > 🛈 FIREWALL: PREROUTING | Processing Sub-Chain: Table nat ip4 | Chain DOCKER ip4 filter
    > 🛈 FIREWALL: DOCKER | Processing Rule: {'action': 'return', 'seq': 0, 'raw': Rule: #10 | Matches: [Match: ['ni_in'] == ['docker0']]}
    > 🛈 FIREWALL: DOCKER | Processing Rule: {'action': 'drop', 'seq': 1, 'raw': Rule: #22 | Matches: [Match: ['ni_in'] != ['docker0'], Match: ['ni_out'] == ['docker0']]}
    > 🛈 FIREWALL: Flow-type: forward
    > 🛈 ROUTER: Packet outbound-interface: docker0
    > 🛈 ROUTER: Packet outbound-route: 172.17.0.0/16, scope link
    > 🛈 FIREWALL: Processing Main Filter-Hooks
    > 🛈 FIREWALL: Processing Chain: Table filter ip4 | Chain FORWARD ip4 filter
    > 🛈 FIREWALL: FORWARD | Processing Rule: {'action': 'jump', 'seq': 0, 'raw': Rule: #20 | Matches: []}
    > 🛈 FIREWALL:  > Match: True | Action: jump
    > 🛈 FIREWALL: FORWARD | Processing Sub-Chain: Table filter ip4 | Chain DOCKER-USER ip4 filter
    > 🛈 FIREWALL: DOCKER-USER | Processing Rule: {'action': 'return', 'seq': 0, 'raw': Rule: #19 | Matches: []}
    > 🛈 FIREWALL:  > Match: True | Action: return
    > 🛈 FIREWALL: FORWARD | Processing Rule: {'action': 'jump', 'seq': 1, 'raw': Rule: #8 | Matches: []}
    > 🛈 FIREWALL:  > Match: True | Action: jump
    > 🛈 FIREWALL: FORWARD | Processing Sub-Chain: Table filter ip4 | Chain DOCKER-FORWARD ip4 filter
    > 🛈 FIREWALL: DOCKER-FORWARD | Processing Rule: {'action': 'jump', 'seq': 0, 'raw': Rule: #11 | Matches: []}
    > 🛈 FIREWALL:  > Match: True | Action: jump
    > 🛈 FIREWALL: DOCKER-FORWARD | Processing Sub-Chain: Table filter ip4 | Chain DOCKER-CT ip4 filter
    > 🛈 FIREWALL: DOCKER-CT | Processing Rule: {'action': 'accept', 'seq': 0, 'raw': Rule: #23 | Matches: [Match: ['ni_out'] == ['docker0']]}
    > 🛈 FIREWALL:  > Match: True | Action: accept
    > 🛈 FIREWALL: DOCKER-FORWARD | Processing Rule: {'action': 'jump', 'seq': 1, 'raw': Rule: #10 | Matches: []}
    > 🛈 FIREWALL:  > Match: True | Action: jump
    > 🛈 FIREWALL: DOCKER-FORWARD | Processing Sub-Chain: Table filter ip4 | Chain DOCKER-ISOLATION-STAGE-1 ip4 filter
    > 🛈 FIREWALL: DOCKER-ISOLATION-STAGE-1 | Processing Rule: {'action': 'jump', 'seq': 0, 'raw': Rule: #25 | Matches: [Match: ['ni_in'] == ['docker0'], Match: ['ni_out'] != ['docker0']]}
    > 🛈 FIREWALL: DOCKER-FORWARD | Processing Rule: {'action': 'jump', 'seq': 2, 'raw': Rule: #9 | Matches: []}
    > 🛈 FIREWALL:  > Match: True | Action: jump
    > 🛈 FIREWALL: DOCKER-FORWARD | Processing Sub-Chain: Table filter ip4 | Chain DOCKER-BRIDGE ip4 filter
    > 🛈 FIREWALL: DOCKER-BRIDGE | Processing Rule: {'action': 'jump', 'seq': 0, 'raw': Rule: #24 | Matches: [Match: ['ni_out'] == ['docker0']]}
    > 🛈 FIREWALL:  > Match: True | Action: jump
    > 🛈 FIREWALL: DOCKER-BRIDGE | Processing Sub-Chain: Table filter ip4 | Chain DOCKER ip4 filter
    > 🛈 FIREWALL: DOCKER | Processing Rule: {'action': 'return', 'seq': 0, 'raw': Rule: #10 | Matches: [Match: ['ni_in'] == ['docker0']]}
    > 🛈 FIREWALL: DOCKER | Processing Rule: {'action': 'drop', 'seq': 1, 'raw': Rule: #22 | Matches: [Match: ['ni_in'] != ['docker0'], Match: ['ni_out'] == ['docker0']]}
    > 🛈 FIREWALL:  > Match: True | Action: drop
    > ✖ FIREWALL: Packet blocked by rule: {'action': 'drop', 'seq': 1, 'raw': Rule: #22 | Matches: [Match: ['ni_in'] != ['docker0'], Match: ['ni_out'] == ['docker0']]}


    # SYSTEM-CONFIG EXAMPLE:
    ftf-cli ... --src-ip 172.17.11.5 --dst-ip 10.100.1.1

    > 🛈 ROUTER: Packet inbound-interface: docker0
    > 🛈 ROUTER: Packet inbound-route: 172.17.0.0/16, scope link
    > 🛈 FIREWALL: Processing Pre-Routing Filter-Hooks
    > 🛈 FIREWALL: Processing DNAT
    > 🛈 FIREWALL: Processing Chain: Table nat ip4 | Chain PREROUTING ip4 nat
    > 🛈 FIREWALL: PREROUTING | Processing Rule: {'action': 'jump', 'seq': 0, 'raw': Rule: #3 | Matches: []}
    > 🛈 FIREWALL:  > Match: True | Action: jump
    > 🛈 FIREWALL: PREROUTING | Processing Sub-Chain: Table nat ip4 | Chain DOCKER ip4 filter
    > 🛈 FIREWALL: DOCKER | Processing Rule: {'action': 'return', 'seq': 0, 'raw': Rule: #10 | Matches: [Match: ['ni_in'] == ['docker0']]}
    > 🛈 FIREWALL:  > Match: True | Action: return
    > 🛈 FIREWALL: Flow-type: forward
    > 🛈 ROUTER: Packet outbound-interface: wan
    > 🛈 ROUTER: Packet outbound-route: 0.0.0.0/0, gw 10.255.255.254, metric 600, scope remote
    > ✖ FIREWALL: Dropping traffic to WAN targeting bogons

.. tip::

    You can export the environmental-variable :code:`export DEBUG=1` to enable more verbose output.

----

Automated for CI
================

.. warning::

    Still under development.

----

Interactive Shell
=================

.. warning::

    Still under development.
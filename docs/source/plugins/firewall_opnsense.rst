.. _plugins_fw_opnsense:

.. |export_backup| image:: ../_static/img/plugin-opnsense-backup.png
   :class: wiki-img-sm

.. |export_network| image:: ../_static/img/plugin-opnsense-export.png
   :class: wiki-img-sm

.. include:: ../_include/head.rst

===================
Firewall - OPNsense
===================

.. include:: ../_include/warn_develop.rst

Config Export
#############

1. `Download a Config-Backup <https://docs.opnsense.org/manual/backups.html>`_ (referenced as :code:`config.xml`)

    |export_backup|

2. Download the current network status via the WebUI: :code:`Interfaces - Overview - Download Buttom` (referenced as :code:`network.json`)

    |export_network|

----

Run
###

Here is an example on how to run it with the exported config:

.. code-block:: bash

    ftf-cli --firewall-system 'opnsense' \
            --file-ruleset 'config.xml' \
            --file-interfaces 'network.json' \
            --file-routes 'network.json' \
            --src-ip 10.57.65.44 \
            --dst-ip 1.1.1.1

Example
*******

**Note**: NAT is not yet implemented for this example.

.. code-block:: bash

    ftf-cli --firewall-system 'opnsense' \
            --file-ruleset 'testdata/plugin_translate_opnsense_config.xml' \
            --file-interfaces 'testdata/plugin_translate_opnsense_network.json' \
            --file-routes 'testdata/plugin_translate_opnsense_network.json' \
            --src-ip 10.34.28.206 \
            --dst-ip 1.1.1.1 \
            --port 993

    > ⚠ FIREWALL PLUGIN: Unable to resolve alias DNS: "test.some-invalid-domain.oxl.aaaa"
    > ⚠ FIREWALL PLUGIN: Unsupported alias-type "geoip" will be skipped: "GEOIP_NEARBY"
    > ⚠ FIREWALL PLUGIN: Unable to parse rule-address: "GEOIP_NEARBY"
    > ⚠ FIREWALL PLUGIN: Unsupported rule: Chain floating, Rule 15
    > ⚠ FIREWALL PLUGIN: Unable to parse rule-address: "GEOIP_NEARBY"
    > ⚠ FIREWALL PLUGIN: Unsupported rule: Chain interfaces, Rule 9 (GeoIP Block)
    > ⚠ FIREWALL PLUGIN: Unable to parse rule-address: "GEOIP_NEARBY"
    > ⚠ FIREWALL PLUGIN: Unsupported rule: Chain interfaces, Rule 80
    > ⚠ FIREWALL PLUGIN: Unable to parse rule-address: "GEOIP_NEARBY"
    > ⚠ FIREWALL PLUGIN: Unsupported rule: Chain interfaces, Rule 85 (SVC_1 Proxies)
    > 🛈 ROUTER: Packet inbound-interface: lan (LAN)
    > 🛈 ROUTER: Packet inbound-route: 10.34.28.0/24, scope link
    > 🛈 FIREWALL: Processing Chain: Table "default" ip | Chain "dnat" ip nat (0 rules)
    > 🛈 ROUTER: Packet outbound-interface: opt5 (WAN2)
    > 🛈 ROUTER: Packet outbound-route: 0.0.0.0/0, gw 169.169.169.1, scope global
    > 🛈 FIREWALL: Processing Chain: Table "default" ip | Chain "floating" ip filter (15 rules)
    > 🛈 FIREWALL: > Chain floating | Rule 1
    > 🛈 FIREWALL: > Chain floating | Rule 2
    > 🛈 FIREWALL: > Chain floating | Rule 3
    > 🛈 FIREWALL: > Chain floating | Rule 4
    > 🛈 FIREWALL: > Chain floating | Rule 5
    > 🛈 FIREWALL: > Chain floating | Rule 6
    > 🛈 FIREWALL: > Chain floating | Rule 7
    > 🛈 FIREWALL: > Chain floating | Rule 8
    > 🛈 FIREWALL: > Chain floating | Rule 9
    > 🛈 FIREWALL: > Chain floating | Rule 10
    > 🛈 FIREWALL: > Chain floating | Rule 11
    > 🛈 FIREWALL: > Chain floating | Rule 12
    > 🛈 FIREWALL: > Chain floating | Rule 13
    > 🛈 FIREWALL: > Chain floating | Rule 14
    > 🛈 FIREWALL: > Chain floating | Rule 1000000 | Match => goto
    > 🛈 FIREWALL: > Chain floating | Sub-Chain: interface_groups (8 rules)
    > 🛈 FIREWALL: > Chain interface_groups | Rule 1
    > 🛈 FIREWALL: > Chain interface_groups | Rule 2
    > 🛈 FIREWALL: > Chain interface_groups | Rule 3
    > 🛈 FIREWALL: > Chain interface_groups | Rule 4
    > 🛈 FIREWALL: > Chain interface_groups | Rule 5 | Match => accept
    > 🛈 FIREWALL: Processing Chain: Table "default" ip | Chain "snat" ip nat (0 rules)
    > ⚠ FIREWALL: Source is bogon-network and heading to Public-WAN without SNAT!
    > ✓ FIREWALL: Packet passed

**Block Example**:

.. code-block:: bash

    ftf-cli ... --src-ip 10.34.28.206 --dst-ip 1.10.16.4

    ...
    > 🛈 ROUTER: Packet inbound-interface: lan (LAN)
    > 🛈 ROUTER: Packet inbound-route: 10.34.28.0/24, scope link
    > 🛈 FIREWALL: Processing Chain: Table "default" ip | Chain "dnat" ip nat (0 rules)
    > 🛈 ROUTER: Packet outbound-interface: opt5 (WAN2)
    > 🛈 ROUTER: Packet outbound-route: 0.0.0.0/0, gw 169.169.169.1, scope global
    > 🛈 FIREWALL: Processing Chain: Table "default" ip | Chain "floating" ip filter (15 rules)
    > 🛈 FIREWALL: > Chain floating | Rule 1
    > 🛈 FIREWALL: > Chain floating | Rule 2 | Match => drop
    > ✖ FIREWALL: Packet blocked by rule: Seq 2, Action: drop, Rule: #2 "SpamHaus DROP Block Outbound"
    >              > Matches: {'proto_l3': 'ip4', 'ip_saddr': {'==': 'any'}, 'ip_daddr': {'==': ['1.10.16.0/20', '1.19.0.0/16', '1.32.128.0/18', '2.56.192.0/22', '2.57.122.0/24', '2.57.232.0/23', '2.57.234.0/23', '2.59.152.0/24', '2.59.154.0/24', '5.42.92.0/24', '5.105.220.0/24', '5.133.101.0/24', '5.134.128.0/19', '5.183.60.0/22', '5.183.129.0/24', '5.188.10.0/23', '5.188.11.0/24', '5.188.236.0/23', '14.128.32.0/20', '14.128.48.0/21', '14.152.94.0/24', '23.94.58.0/24', '23.129.252.0/23', '23.137.100.0/24', '23.146.240.0/24'...

**Increased Verbosity**:

Use the :code:`verbosity` flag to get more information about the rules and matching.

.. code-block:: bash

    ftf-cli ... --src-ip 10.34.28.206 --dst-ip 1.10.16.4 --verbosity 2

    ...
    > 🛈 ROUTER: Packet inbound-interface: lan (LAN)
    > 🛈 ROUTER: Packet inbound-route: 10.34.28.0/24, scope link
    > 🛈 FIREWALL: Processing Chain: Table "default" ip | Chain "dnat" ip nat (0 rules)
    > 🛈 FIREWALL: Flow-type: forward
    > 🛈 ROUTER: Packet outbound-interface: opt5 (WAN2)
    > 🛈 ROUTER: Packet outbound-route: 0.0.0.0/0, gw 169.169.169.1, scope global
    > 🛈 FIREWALL: Processing Chain: Table "default" ip | Chain "floating" ip filter (15 rules)
    > 🛈 FIREWALL: > Chain floating | Rule 1 | Seq 1, Action: accept, Rule: #1
    >              > Matches: {'proto_l3': 'ip4', 'ip_saddr': {'==': ['192.168.0.0/30']}, 'ip_daddr': {'==': ['192.168.0.0/30']}}
    >
    > 🛈 FIREWALL: > Chain floating | Rule 2 | Match => drop | Seq 2, Action: drop, Rule: #2 "SpamHaus DROP Block Outbound"
    >              > Matches: {'proto_l3': 'ip4', 'ip_saddr': {'==': 'any'}, 'ip_daddr': {'==': ['1.10.16.0/20', '1.19.0.0/16', '1.32.128.0/18', '2.56.192.0/22', '2.57.122.0/24', '2.57.232.0/23', '2.57.234.0/23', '2.59.152.0/24', '2.59.154.0/24', '5.42.92.0/24', '5.105.220.0/24', '5.133.101.0/24', '5.134.128.0/19', '5.183.60.0/22', '5.183.129.0/24', '5.188.10.0/23', '5.188.11.0/24', '5.188.236.0/23', '14.128.32.0/20', '14.128.48.0/21', '14.152.94.0/24', '23.94.58.0/24', '23.129.252.0/23', '23.137.100.0/24', '23.146.240.0/24'...
    >
    > ✖ FIREWALL: Packet blocked by rule: Seq 2, Action: drop, Rule: #2 "SpamHaus DROP Block Outbound"
    >              > Matches: {'proto_l3': 'ip4', 'ip_saddr': {'==': 'any'}, 'ip_daddr': {'==': ['1.10.16.0/20', '1.19.0.0/16', '1.32.128.0/18', '2.56.192.0/22', '2.57.122.0/24', '2.57.232.0/23', '2.57.234.0/23', '2.59.152.0/24', '2.59.154.0/24', '5.42.92.0/24', '5.105.220.0/24', '5.133.101.0/24', '5.134.128.0/19', '5.183.60.0/22', '5.183.129.0/24', '5.188.10.0/23', '5.188.11.0/24', '5.188.236.0/23', '14.128.32.0/20', '14.128.48.0/21', '14.152.94.0/24', '23.94.58.0/24', '23.129.252.0/23', '23.137.100.0/24', '23.146.240.0/24'...

----

Source Code
###########

* **System Config**: `system/system_opnsense.py <https://github.com/O-X-L/firewall-testing-framework/blob/latest/src/firewall_test/plugins/system/system_opnsense.py>`_

* **Config Parsing**: `translate/opnsense/ <https://github.com/O-X-L/firewall-testing-framework/tree/latest/src/firewall_test/plugins/translate/opnsense>`_

* **Traffic Matching**: `system/firewall_opnsense.py <https://github.com/O-X-L/firewall-testing-framework/blob/latest/src/firewall_test/plugins/system/firewall_opnsense.py>`_

----

Config-Parsing
##############

The current implementation focused on supporting the most widely used rule matches like:

* Layer 3 Protocol (IPv4/IPv6)
* Layer 4 Protocol (tcp/udp/icmp)
* Source- and Destination-IP filters
* Source- and Destination-Port filters
* Source- and Destination-NAT (including masquerade)
* Inbound- and Outbound-Network-Interfaces
* Aliases (including IPs/networks, ports, port-ranges, nested aliases, interface-groups, interface-IPs and -networks, :code:`This Firewall`, bogons, DNS-resolved hosts, URLTable/IPLists, ...)
* Quick/Lazy actions

The main match-parsing logic can be found here: `translate/opnsense/ruleset.py <https://github.com/O-X-L/firewall-testing-framework/tree/latest/src/firewall_test/plugins/translate/opnsense/ruleset.py>`_ & `translate/opnsense/rule.py <https://github.com/O-X-L/firewall-testing-framework/tree/latest/src/firewall_test/plugins/translate/opnsense/rule.py>`_

If we were not able to parse any match from the rule-config - the rule will be skipped.

If this happens you will see a warning at runtime! (:code:`Unsupported rule`)

.. warning::

    The plugin does not validate the syntax of the config-export you provide!

    You may encounter unexpected errors when manually modifying it!

Unsupported Expressions
=======================

Rules containing unsupported expressions will be skipped for now.

If this happens you will see a warning at runtime! (:code:`Unsupported rule-expression`)

These rule-expressions are unsupported for now:

* :code:`GeoIP aliases`
* :code:`URLTable JSON`
* :code:`ICMP Types`
* :code:`tagging`
* TCP flags
* Connection states

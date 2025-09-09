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

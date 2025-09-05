.. _usage_system_support:

.. include:: ../_include/head.rst

==================
2 - System Support
==================

Intro
#####

This **Firewall Testing Framework** can only process configuration of system that already have plugins implemented!

**Why do we need these plugins?**

* Firewall systems might behave differently
* There is no standardized firewall configuration across vendors and providers
* Thus we need to parse the vendor-specific configuration-format so we can interpret it correctly

----

Firewall System Support
#######################

For Firewall-Ruleset parsing.

.. list-table::
  :width: 100 %
  :widths: 10 10 10 45 25
  :header-rows: 1

  * - System

    - Description

    - Support

    - Config-Export Command

    - Source Code

  * - `Netfilter <https://www.netfilter.org/>`_ on Linux

    - `NFTables <https://www.netfilter.org/projects/nftables/index.html>`_ or `IPTables <https://www.netfilter.org/projects/iptables/index.html>`_

    - Experimental

    - :code:`sudo nft -j list ruleset > ruleset.json`

    - `system/firewall_netfilter.py <https://github.com/O-X-L/firewall-testing-framework/blob/latest/src/firewall_test/plugins/system/firewall_netfilter.py>`_,
      `translate/netfilter/ <https://github.com/O-X-L/firewall-testing-framework/tree/latest/src/firewall_test/plugins/translate/netfilter>`_

  * - `OPNsense <https://opnsense.org/>`_

    - \-

    - Development

    - `Download a Config-Backup <https://docs.opnsense.org/manual/backups.html>`_, `Querying runtime routes via API <https://docs.opnsense.org/development/api/core/diagnostics.html#id6>`_

    - `system/firewall_opnsense.py <https://github.com/O-X-L/firewall-testing-framework/blob/latest/src/firewall_test/plugins/system/firewall_opnsense.py>`_,
      `system/system_opnsense.py <https://github.com/O-X-L/firewall-testing-framework/blob/latest/src/firewall_test/plugins/system/system_opnsense.py>`_,
      `translate/opnsense/ <https://github.com/O-X-L/firewall-testing-framework/tree/latest/src/firewall_test/plugins/translate/opnsense>`_

----

Operating System Support
########################

For Routing- and Network-Interface parsing.

.. list-table::
  :width: 100 %
  :widths: 10 10 10 45 25
  :header-rows: 1

  * - OS

    - Description

    - Support

    - Config-Export Command

    - Source Code

  * - Linux

    - iproute2

    - Yes

    - :code:`ip -j address show > interfaces.json && ip -j route show table all > routes.json && ip -j rule show > route-rules.json`

    - `system/system_linux_netfilter.py <https://github.com/O-X-L/firewall-testing-framework/blob/latest/src/firewall_test/plugins/system/system_linux_netfilter.py>`_,
      `translate/linux.py <https://github.com/O-X-L/firewall-testing-framework/blob/latest/src/firewall_test/plugins/translate/linux.py>`_

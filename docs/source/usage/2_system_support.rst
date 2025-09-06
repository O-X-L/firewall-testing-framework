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
  :widths: 20 20 30 30
  :header-rows: 1

  * - System

    - Description

    - Support

    - Plugin Docs

  * - `Netfilter <https://www.netfilter.org/>`_ on Linux

    - `NFTables <https://www.netfilter.org/projects/nftables/index.html>`_ or `IPTables <https://www.netfilter.org/projects/iptables/index.html>`_

    - Experimental

    - :ref:`Plugins - Firewall Netfilter <plugins_fw_netfilter>`

  * - `OPNsense <https://opnsense.org/>`_

    - \-

    - Development

    - :ref:`Plugins - Firewall OPNsense <plugins_fw_opnsense>`


----

Networking System Support
#########################

For Routing- and Network-Interface parsing.

.. list-table::
  :width: 100 %
  :widths: 20 20 30 30
  :header-rows: 1

  * - System

    - Description

    - Support

    - Plugin Docs

  * - Linux

    - `iproute2 <https://wiki.linuxfoundation.org/networking/iproute2>`_

    - Yes

    - :ref:`Plugins - System Linux <plugins_sys_linux>`

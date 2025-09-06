.. _plugins_fw_netfilter:

.. include:: ../_include/head.rst

====================
Firewall - Netfilter
====================

Config Export
#############

You have to simply run this command:

.. code-block:: bash

    sudo nft -j list ruleset > ruleset.json

Optional: To get a more readable JSON-output, you can use the :code:`jq` tool to format it:

.. code-block:: bash

    sudo apt install jq  # json-query

    sudo nft -j list ruleset | jq > ruleset.json

----

Run
###

Here is an example on how to run supply the exported config:

.. code-block:: bash

    ftf-cli --firewall-system 'linux_netfilter' \
            --file-ruleset 'ruleset.json' \
            --file-interfaces 'interfaces.json' \
            --file-routes 'routes.json' \
            --file-route-rules 'route-rules.json' \
            --src-ip 172.17.11.5 \
            --dst-ip 1.1.1.1

It also requires the exported config of **interfaces**, **routes** and **route-rules** :ref:`for the Linux system <plugins_sys_linux>`!

----

Source Code
###########

* **System Config**: `system/system_linux_netfilter.py <https://github.com/O-X-L/firewall-testing-framework/blob/latest/src/firewall_test/plugins/system/system_linux_netfilter.py>`_

* **Config Parsing**: `translate/netfilter/ <https://github.com/O-X-L/firewall-testing-framework/tree/latest/src/firewall_test/plugins/translate/netfilter>`_

* **Traffic Matching**: `system/firewall_netfilter.py <https://github.com/O-X-L/firewall-testing-framework/blob/latest/src/firewall_test/plugins/system/firewall_netfilter.py>`_

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
* CT-State

The main match-parsing logic can be found here: `translate/netfilter/elements.py NftMatch & NftRule <https://github.com/O-X-L/firewall-testing-framework/tree/latest/src/firewall_test/plugins/translate/netfilter/elements.py>`_

If we were not able to parse any match from the rule-config - the rule will be skipped.

If this happens you will see a warning at runtime! (:code:`Unsupported rule`)

.. warning::

    The plugin does not validate the syntax of the config-export you provide!

    You may encounter unexpected errors when manually modifying it!

Unsupported Expressions
=======================

Rules only containing unsupported expressions will be skipped for now.

If this happens you will see a warning at runtime! (:code:`Unsupported rule-expression`)

These rule-expressions are unsupported for now:

* :code:`log`
* :code:`comment`
* :code:`limit`
* :code:`set` (*static sets are supported - but dynamic ones like meters are not!*)
* :code:`vmap`
* :code:`counter`
* :code:`xt` (*only SNAT-masquerade is currently supported*)
* :code:`ct helper`
* :code:`&`
* TCP flags

.. _plugins_sys_linux:

.. include:: ../_include/head.rst

==============
System - Linux
==============

Config Export
#############

This plugin only supports `iproute2 <https://wiki.linuxfoundation.org/networking/iproute2>`_!

You have to simply run these commands:

.. code-block:: bash

    ip -j address show > interfaces.json
    ip -j route show table all > routes.json
    ip -j rule show > route-rules.jso

Optional: To get a more readable JSON-output, you can use the :code:`jq` tool to format it:

.. code-block:: bash

    sudo apt install jq  # json-query

    ip -j address show | jq > interfaces.json
    ip -j route show table all | jq > routes.json
    ip -j rule show | jq > route-rules.jso

----

Run
###

Here is an example on how to run it with the exported config:

.. code-block:: bash

    ftf-cli --firewall-system 'linux_netfilter' \
            --file-interfaces 'interfaces.json' \
            --file-routes 'routes.json' \
            --file-route-rules 'route-rules.json' \
            --file-ruleset 'ruleset.json' \
            --src-ip 172.17.11.5 \
            --dst-ip 1.1.1.1

It also requires the exported **ruleset**-config :ref:`of the Netfilter firewall <plugins_fw_netfilter>`!

----

Source Code
###########

* **System Config**: `system/system_linux_netfilter.py <https://github.com/O-X-L/firewall-testing-framework/blob/latest/src/firewall_test/plugins/system/system_linux_netfilter.py>`_

* **Config Parsing**: `translate/linux.py <https://github.com/O-X-L/firewall-testing-framework/tree/latest/src/firewall_test/plugins/translate/linux.py>`_

----

Config-Parsing
##############

.. warning::

    The plugin does not validate the syntax of the config-export you provide!

    You may encounter unexpected errors when manually modifying it!

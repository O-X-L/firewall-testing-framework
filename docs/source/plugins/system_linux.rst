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

Source Code
###########

* **System Config**: `system/system_linux_netfilter.py <https://github.com/O-X-L/firewall-testing-framework/blob/latest/src/firewall_test/plugins/system/system_linux_netfilter.py>`_

* **Config Parsing**: `translate/linux.py <https://github.com/O-X-L/firewall-testing-framework/tree/latest/src/firewall_test/plugins/translate/linux.py>`_

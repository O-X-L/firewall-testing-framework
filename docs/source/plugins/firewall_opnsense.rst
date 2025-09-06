.. _plugins_fw_opnsense:

.. include:: ../_include/head.rst

===================
Firewall - OPNsense
===================

.. include:: ../_include/warn_develop.rst

Config Export
#############

1. `Download a Config-Backup <https://docs.opnsense.org/manual/backups.html>`_

2. `Supply the runtime routes manually <https://docs.opnsense.org/manual/routes.html#status>`_ or `query them via API <https://docs.opnsense.org/development/api/core/diagnostics.html#id6>`_

----

Run
###

.. include:: ../_include/warn_wip.rst

----

Source Code
###########

* **System Config**: `system/system_opnsense.py <https://github.com/O-X-L/firewall-testing-framework/blob/latest/src/firewall_test/plugins/system/system_opnsense.py>`_

* **Config Parsing**: `translate/opnsense/ <https://github.com/O-X-L/firewall-testing-framework/tree/latest/src/firewall_test/plugins/translate/opnsense>`_

* **Traffic Matching**: `system/firewall_opnsense.py <https://github.com/O-X-L/firewall-testing-framework/blob/latest/src/firewall_test/plugins/system/firewall_opnsense.py>`_


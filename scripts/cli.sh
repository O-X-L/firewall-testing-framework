#!/bin/bash

set -eo pipefail

if [ -z "$1" ]
then
  SRC='172.17.10.5'
else
  SRC="$1"
fi

if [ -z "$2" ]
then
  DST='1.1.1.1'
else
  DST="$2"
fi

cd "$(dirname "$0")/.."

python3 src/firewall_test/cli.py --firewall-system 'linux_netfilter' --file-interfaces 'testdata/plugin_translate_linux_interfaces.json' --file-routes 'testdata/plugin_translate_linux_routes.json' --file-route-rules 'testdata/plugin_translate_linux_route-rules.json' --file-ruleset 'testdata/plugin_translate_netfilter_ruleset.json' --src-ip "$SRC" --dst-ip "$DST"

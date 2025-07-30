#!/bin/bash

set -eo pipefail

if [ -z "$1" ]
then
  echo 'Supply a version!'
  exit 1
fi

set -u
VERSION="$1"

cd "$(dirname "$0")/.."
PATH_REPO="$(pwd)"
rm -r ./dist/

echo ''
echo '### TESTING PIP-INSTALL ###'
echo ''

PATH_VENV="/tmp/$(date +"%s")"
python3 -m virtualenv "$PATH_VENV" > /dev/null
cd /tmp
PYTHONPATH=''
source "${PATH_VENV}/bin/activate"
python3 -m pip install -e "$PATH_REPO" > /dev/null
firewall-test-ci --help >/dev/null
deactivate
echo ' => OK'

echo ''
echo "### BUILDING VERSION: ${VERSION} ###"
echo ''

cd "$PATH_REPO"
rm -rf ./dist/*

echo "$VERSION" > VERSION
python3 -m pip install -r ./requirements_build.txt >/dev/null
python3 -m build
if [ -f "./dist/firewall-test-${VERSION}.tar.gz" ]
then
  mv "./dist/firewall-test-${VERSION}.tar.gz" "./dist/dnsbl_check-${VERSION}.tar.gz"
fi
rm -rf ./src/dnsbl_check.egg-info/

# python3 -m twine upload --repository pypi dist/*

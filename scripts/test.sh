#!/bin/bash

set -e

cd "$(dirname "$0")/.."

PYTHONPATH=''

if ! python3 -m pytest --help >/dev/null 2>/dev/null
then
  python3 -m pip install -r requirements_test.txt
fi

echo ''
echo 'TESTING Python'
echo ''

python3 -m pytest --cov $@

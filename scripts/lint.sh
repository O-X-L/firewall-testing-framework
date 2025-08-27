#!/bin/bash

set -e

cd "$(dirname "$0")/.."

PYTHONPATH=''

if ! python3 -m pylint --help >/dev/null 2>/dev/null
then
  python3 -m pip install -r requirements_lint.txt
fi

echo ''
echo 'LINTING Python'
echo ''

python3 -m pylint --rcfile .pylintrc --recursive=y .

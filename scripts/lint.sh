#!/bin/bash

set -e

cd "$(dirname "$0")/.."

PYTHONPATH=''

echo ''
echo 'LINTING Python'
echo ''

python3 -m pylint --rcfile .pylintrc --recursive=y .

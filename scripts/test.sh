#!/bin/bash

set -e

cd "$(dirname "$0")/.."

PYTHONPATH=''

echo ''
echo 'TESTING Python'
echo ''

python3 -m pytest --cov

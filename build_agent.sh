#!/bin/bash
# Package agent/main.py with linux/arm64 Python 3.13 wheels for AgentCore Runtime code deploy.
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -d build/pkg ] || [ agent/requirements.txt -nt build/pkg ]; then
  rm -rf build/pkg
  .venv/bin/pip install -q --target build/pkg --platform manylinux2014_aarch64 --implementation cp \
    --python-version 3.13 --only-binary=:all: -r agent/requirements.txt
fi
rm -f build/agent.zip
(cd build/pkg && zip -qr ../agent.zip . -x '*__pycache__*')
(cd agent && zip -q ../build/agent.zip main.py)
ls -lh build/agent.zip

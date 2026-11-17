#!/bin/bash
# Package the event agent and the partner MCP server for AgentCore Runtime code deploy.
# Both reuse the linux/arm64 wheels that build_agent.sh installs into build/pkg.
set -euo pipefail
cd "$(dirname "$0")"
[ -d build/pkg ] || ./build_agent.sh
for pair in "event_agent:agent_event/main.py:main.py" "partner_mcp:mcp_partner/server.py:server.py"; do
  IFS=: read -r name src dst <<< "$pair"
  rm -f "build/$name.zip"
  (cd build/pkg && zip -qr "../$name.zip" . -x '*__pycache__*')
  tmp=$(mktemp -d); cp "$src" "$tmp/$dst"; (cd "$tmp" && zip -q "$OLDPWD/build/$name.zip" "$dst"); rm -rf "$tmp"
  ls -lh "build/$name.zip"
done

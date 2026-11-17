#!/usr/bin/env bash
# Start the demo console at http://localhost:8010 (Ctrl+C to stop).
#   ./run.sh            start it (creates .venv on first run)
#   ./run.sh --restart  stop a console already running on the port, then start
# The port is fixed: Okta's sign-in redirect URIs point at localhost:8010.
set -euo pipefail
cd "$(dirname "$0")"
PORT=8010

if [ ! -x .venv/bin/uvicorn ]; then
  echo "First run: creating .venv and installing requirements..."
  python3 -m venv .venv
  .venv/bin/pip install -q -r requirements.txt
fi
[ -f .env ] || { echo "Missing .env: copy .env.example to .env and fill it in."; exit 1; }

# The demo's AWS account is the profile in .env (ANYCO_AWS_PROFILE). Access keys exported in this
# terminal would otherwise override it for some SDK calls and mix two accounts, so drop them here.
if grep -qE '^ANYCO_AWS_PROFILE=.+' .env && [ -n "${AWS_ACCESS_KEY_ID:-}" ]; then
  echo "Ignoring AWS access keys in this shell; using the .env profile ($(grep -E '^ANYCO_AWS_PROFILE=' .env | cut -d= -f2))."
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_CREDENTIAL_EXPIRATION
fi

if lsof -ti :"$PORT" >/dev/null 2>&1; then
  if [ "${1:-}" = "--restart" ]; then
    echo "Stopping the console already on port $PORT..."
    lsof -ti :"$PORT" | xargs kill && sleep 1
  else
    echo "Port $PORT is in use (console already running?). Use ./run.sh --restart to restart it."
    exit 1
  fi
fi

echo "Console: http://localhost:$PORT"
exec .venv/bin/uvicorn server.app:app --host 127.0.0.1 --port "$PORT"

#!/bin/sh
# Start the full stack (server + dispatcher + worker containers) via Docker Compose.
#
# The only secret you must provide is your model API key:
#
#   export GLM_API_KEY=sk-...        # the key for the GLM-5.2 workers in dispatch.yaml
#   sh scripts/up.sh                 # add -d to run detached
#
# The three internal tokens below are localhost-only service tokens; this script
# generates fresh random ones if you have not exported them. The Web UI is at
# http://127.0.0.1:8765/ once the server becomes healthy.
set -e
cd "$(dirname "$0")/.."

# Load .env (holds GLM_API_KEY and the local service tokens) if present.
if [ -f .env ]; then
  set -a
  . ./.env
  set +a
fi

if [ -z "$GLM_API_KEY" ]; then
  echo "ERROR: GLM_API_KEY is not set." >&2
  echo "  export GLM_API_KEY=<your model api key>  then re-run this script." >&2
  exit 1
fi

gen() { openssl rand -hex 32; }
export CAIRN_INTERNAL_TOKEN="${CAIRN_INTERNAL_TOKEN:-$(gen)}"
export CAIRN_DISPATCHER_INTERNAL_TOKEN="${CAIRN_DISPATCHER_INTERNAL_TOKEN:-$(gen)}"
export CAIRN_MODEL_PROXY_TOKEN="${CAIRN_MODEL_PROXY_TOKEN:-$(gen)}"

echo "Starting Rabbit Code Audit (server :8765, dispatcher internal :8989)..."
echo "Make sure nothing else is already bound to port 8765 (e.g. a manual 'cairn serve')."
exec docker compose up --build "$@"

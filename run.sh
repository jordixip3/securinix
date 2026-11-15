#!/usr/bin/env bash
# ===================================================================
# Securinix - Next-Gen SIEM & Autonomous SOAR Platform Launcher
# ===================================================================

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

PORT="${PORT:-8085}"
HOST="${HOST:-0.0.0.0}"

# Activate virtual environment
if [ -d "$DIR/.venv" ]; then
    PYTHON="$DIR/.venv/bin/python"
    UVICORN="$DIR/.venv/bin/uvicorn"
elif [ -d "/Users/jordimaicas/Downloads/.venv" ]; then
    PYTHON="/Users/jordimaicas/Downloads/.venv/bin/python"
    UVICORN="/Users/jordimaicas/Downloads/.venv/bin/uvicorn"
else
    PYTHON="python3"
    UVICORN="uvicorn"
fi

echo "================================================================"
echo "🛡️  STARTING SECURINIX SIEM & SOAR PLATFORM"
echo "================================================================"
echo "• Host: $HOST"
echo "• Port: $PORT"
echo "• Web SOC URL: http://localhost:$PORT/"
echo "• API Docs:    http://localhost:$PORT/docs"
echo "• Python:      $PYTHON"
echo "================================================================"

exec "$UVICORN" app.main:app --host "$HOST" --port "$PORT" --reload

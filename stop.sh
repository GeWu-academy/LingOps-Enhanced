#!/bin/bash
# 停止 LingOps 主服务与扩展服务
set -u
cd "$(dirname "$0")" || exit 1

PORT=$(grep -E '^[[:space:]]*port:' configs/config.yaml 2>/dev/null | head -1 | awk '{print $2}')
PORT=${PORT:-12800}
EXT_PORT=12801

stop_port() {
  local p="$1" name="$2" pid
  pid=$(lsof -nP -iTCP:"$p" -sTCP:LISTEN -t 2>/dev/null | head -1)
  if [ -z "$pid" ]; then
    echo "[$name] 未运行 (端口 $p)"
    return
  fi
  kill "$pid" 2>/dev/null || true
  sleep 1
  if lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; then
    kill -9 "$pid" 2>/dev/null || true
  fi
  echo "[$name] 已停止 (PID $pid)"
}

stop_port "$PORT" "主服务"
stop_port "$EXT_PORT" "扩展服务"
stop_port 8787 "ARTEX"

# PostgreSQL 只停 ARTEX 专用的那一个（端口 5433）
PG_DATA="${ARTEX_PGDATA:-/opt/homebrew/var/postgresql@16}"
PG_BIN="${ARTEX_PGBIN:-/opt/homebrew/opt/postgresql@16/bin}"
if lsof -nP -iTCP:5433 -sTCP:LISTEN >/dev/null 2>&1; then
  if [ -x "$PG_BIN/pg_ctl" ] && [ -d "$PG_DATA" ]; then
    "$PG_BIN/pg_ctl" -D "$PG_DATA" stop -m fast >/dev/null 2>&1 \
      && echo "[PostgreSQL] 已停止 (:5433)" \
      || echo "[PostgreSQL] 停止失败，可手动 pg_ctl -D $PG_DATA stop"
  fi
fi

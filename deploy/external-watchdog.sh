#!/bin/sh
set -eu

CONTROL_PLANE_URL=${CONTROL_PLANE_URL:?CONTROL_PLANE_URL is required}
WATCHDOG_ID=${WATCHDOG_ID:?WATCHDOG_ID is required}
WATCHDOG_TOKEN=${WATCHDOG_TOKEN:?WATCHDOG_TOKEN is required}
CHECK_INTERVAL_SECONDS=${CHECK_INTERVAL_SECONDS:-30}
FAILURE_THRESHOLD=${FAILURE_THRESHOLD:-3}
TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN:-}
TELEGRAM_CHAT_ID=${TELEGRAM_CHAT_ID:-}
ALERT_WEBHOOK_URL=${ALERT_WEBHOOK_URL:-}
ALERT_WEBHOOK_TOKEN=${ALERT_WEBHOOK_TOKEN:-}

for value in "$CHECK_INTERVAL_SECONDS" "$FAILURE_THRESHOLD"; do
  case "$value" in
    ''|*[!0-9]*|0) echo "Watchdog interval settings must be positive integers" >&2; exit 1 ;;
  esac
done

CONTROL_PLANE_URL=${CONTROL_PLANE_URL%/}
node_name=$(hostname | tr -cd 'A-Za-z0-9._-')
display_url=$(printf '%s' "$CONTROL_PLANE_URL" | tr -cd 'A-Za-z0-9:/.?&=_-')
failures=0
state=healthy
outage_started=0

echo "Watchdog $WATCHDOG_ID started for $display_url"

send_message() {
  message=$1
  if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
    curl -fsS --max-time 8 \
      --data-urlencode "chat_id=$TELEGRAM_CHAT_ID" \
      --data-urlencode "text=$message" \
      "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" >/dev/null 2>&1 || true
  fi
  if [ -n "$ALERT_WEBHOOK_URL" ]; then
    if [ -n "$ALERT_WEBHOOK_TOKEN" ]; then
      curl -fsS --max-time 8 -H 'Content-Type: application/json' \
        -H "Authorization: Bearer $ALERT_WEBHOOK_TOKEN" \
        --data "{\"source\":\"linux-ai-external-watchdog\",\"message\":\"$message\"}" \
        "$ALERT_WEBHOOK_URL" >/dev/null 2>&1 || true
    else
      curl -fsS --max-time 8 -H 'Content-Type: application/json' \
        --data "{\"source\":\"linux-ai-external-watchdog\",\"message\":\"$message\"}" \
        "$ALERT_WEBHOOK_URL" >/dev/null 2>&1 || true
    fi
  fi
}

heartbeat() {
  report_status=$1
  outage_seconds=$2
  curl -fsS --max-time 8 \
    -H 'Content-Type: application/json' \
    -H "X-Watchdog-Token: $WATCHDOG_TOKEN" \
    --data "{\"watchdogId\":\"$WATCHDOG_ID\",\"nodeName\":\"$node_name\",\"status\":\"$report_status\",\"outageSeconds\":$outage_seconds,\"version\":\"2\"}" \
    "$CONTROL_PLANE_URL/api/watchdog/heartbeat" >/dev/null
}

while true; do
  body=$(mktemp)
  if curl -fsS --max-time 8 "$CONTROL_PLANE_URL/api/health" >"$body" \
      && grep -q '"status":"ok"' "$body" \
      && grep -q '"databaseReady":true' "$body"; then
    failures=0
    if [ "$state" = down ]; then
      now=$(date +%s)
      outage_seconds=$((now - outage_started))
      state=healthy
      echo "Control plane recovered after ${outage_seconds} seconds"
      send_message "✅ [Linux AI 中央已恢復] 節點：$node_name；中斷：${outage_seconds} 秒"
      heartbeat recovered "$outage_seconds" || true
    else
      heartbeat healthy 0 || true
    fi
  else
    failures=$((failures + 1))
    if [ "$failures" -eq 1 ]; then
      outage_started=$(date +%s)
    fi
    if [ "$failures" -ge "$FAILURE_THRESHOLD" ] && [ "$state" != down ]; then
      state=down
      echo "Control plane marked down after $failures consecutive failures"
      send_message "🚨 [Linux AI 中央無法連線] 監控節點：$node_name；網址：$display_url"
    fi
  fi
  rm -f "$body"
  sleep "$CHECK_INTERVAL_SECONDS"
done

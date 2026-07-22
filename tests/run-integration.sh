#!/bin/sh
set -eu

base_url=${CONTROL_PLANE_TEST_URL:-https://127.0.0.1:8443}
username=${CONTROL_PLANE_TEST_USER:-admin}
password=${CONTROL_PLANE_TEST_PASSWORD:?請設定 CONTROL_PLANE_TEST_PASSWORD}
otp=${CONTROL_PLANE_TEST_OTP:-}
cookie_file=$(mktemp)
trap 'rm -f "$cookie_file"' EXIT
request() {
  method=$1
  path=$2
  data=${3:-}
  if [ -n "$data" ]; then
    if [ -n "${CONTROL_PLANE_TEST_CACERT:-}" ]; then curl -fsS --cacert "$CONTROL_PLANE_TEST_CACERT" -b "$cookie_file" -c "$cookie_file" -X "$method" -H 'content-type: application/json' --data "$data" "$base_url$path"; else curl -kfsS -b "$cookie_file" -c "$cookie_file" -X "$method" -H 'content-type: application/json' --data "$data" "$base_url$path"; fi
  else
    if [ -n "${CONTROL_PLANE_TEST_CACERT:-}" ]; then curl -fsS --cacert "$CONTROL_PLANE_TEST_CACERT" -b "$cookie_file" -c "$cookie_file" -X "$method" "$base_url$path"; else curl -kfsS -b "$cookie_file" -c "$cookie_file" -X "$method" "$base_url$path"; fi
  fi
}

request GET /api/health | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["databaseReady"] and d["version"]'
login_json=$(python3 -c 'import json,sys; print(json.dumps({"username":sys.argv[1],"password":sys.argv[2],"otp":sys.argv[3]}))' "$username" "$password" "$otp")
request POST /api/auth/login "$login_json" | python3 -c 'import json,sys; assert json.load(sys.stdin)["user"]["id"]'
request GET /api/auth/me | python3 -c 'import json,sys; assert json.load(sys.stdin)["user"]["permissions"]'
request GET /api/security/posture | python3 -c 'import json,sys; d=json.load(sys.stdin); assert "mfa" in d'
request GET '/api/hosts?refresh=true' | python3 -c 'import json,sys; assert isinstance(json.load(sys.stdin)["hosts"],list)'
request GET /api/monitoring | python3 -c 'import json,sys; d=json.load(sys.stdin); assert "events" in d and "rules" in d'
request GET /api/tasks | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["arbitraryCommandsAllowed"] is False'
request GET /api/tasks/workers | python3 -c 'import json,sys; d=json.load(sys.stdin); assert "queue" in d and isinstance(d["workers"],list)'
request GET /api/backups | python3 -c 'import json,sys; d=json.load(sys.stdin); assert "jobs" in d'
request GET /api/system/version | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["compatible"] and not d["schema"]["pending"]'
request GET /api/system/limits | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["apiRateLimitPerMinute"] >= 30 and d["sshMaxConcurrency"] >= 1'
request GET /api/retention | python3 -c 'import json,sys; d=json.load(sys.stdin); assert any(p["dataset"]=="audit_events" and p["protected"] for p in d["policies"])'
request GET /api/observability | python3 -c 'import json,sys; d=json.load(sys.stdin); assert "services" in d and "forecasts" in d and "workers" in d'

if [ "${INTEGRATION_MUTATIONS:-0}" = 1 ]; then
  request POST /api/monitoring/collect | python3 -c 'import json,sys; assert json.load(sys.stdin)["status"]=="ok"'
  request POST /api/backups | python3 -c 'import json,sys; assert json.load(sys.stdin)["status"] in ("queued","running")'
  request POST /api/retention/preview | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["preview"] is True and "audit_events" in d["result"]'
  host_id=$(request GET /api/hosts | python3 -c 'import json,sys; print(json.load(sys.stdin)["hosts"][0]["id"])')
  create_payload=$(python3 -c 'import json,sys; print(json.dumps({"hostId":sys.argv[1],"runbookId":"system_overview","note":"v1.1 integration"}))' "$host_id")
  task_id=$(request POST /api/tasks "$create_payload" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
  request POST "/api/tasks/$task_id/approve" '{"note":"integration approval"}' >/dev/null
  request POST "/api/tasks/$task_id/execute" '{}' | python3 -c 'import json,sys; assert json.load(sys.stdin)["status"]=="queued"'
  tries=0
  while :; do
    task_status=$(request GET /api/tasks | python3 -c 'import json,sys; i=sys.argv[1]; print(next(x["status"] for x in json.load(sys.stdin)["tasks"] if x["id"]==i))' "$task_id")
    case "$task_status" in succeeded) break;; failed|timed_out|cancelled) echo "維運 Worker 任務失敗：$task_status"; exit 1;; esac
    tries=$((tries+1)); test "$tries" -lt 45 || { echo "維運 Worker 任務等待逾時"; exit 1; }; sleep 2
  done
fi

request POST /api/auth/logout >/dev/null
echo "整合測試通過：登入/MFA/主機採集/告警/獨立維運 Worker/備份/保存政策/Schema/登出"

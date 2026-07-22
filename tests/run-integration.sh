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
request GET /api/backups | python3 -c 'import json,sys; d=json.load(sys.stdin); assert "jobs" in d'
request GET /api/system/version | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["compatible"] and not d["schema"]["pending"]'

if [ "${INTEGRATION_MUTATIONS:-0}" = 1 ]; then
  request POST /api/monitoring/collect | python3 -c 'import json,sys; assert json.load(sys.stdin)["status"]=="ok"'
  request POST /api/backups | python3 -c 'import json,sys; assert json.load(sys.stdin)["status"] in ("queued","running")'
fi

request POST /api/auth/logout >/dev/null
echo "整合測試通過：登入/MFA 狀態/主機採集/告警/維運權限/備份還原狀態/Schema/登出"

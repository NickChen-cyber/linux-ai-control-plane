#!/bin/sh
set -eu

failures=0
check() {
  label=$1
  shift
  if "$@" >/dev/null 2>&1; then
    printf 'OK   %s\n' "$label"
  else
    printf 'FAIL %s\n' "$label"
    failures=$((failures + 1))
  fi
}

cpu=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 0)
mem_kib=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
disk_kib=$(df -Pk / | awk 'NR==2 {print $4}')

[ "${cpu:-0}" -ge 2 ] || failures=$((failures + 1))
[ "${mem_kib:-0}" -ge 2097152 ] || failures=$((failures + 1))
[ "${disk_kib:-0}" -ge 20971520 ] || failures=$((failures + 1))
printf '%s CPU: %s 核心\n' "$( [ "${cpu:-0}" -ge 2 ] && echo OK || echo FAIL )" "$cpu"
printf '%s RAM: %s MiB\n' "$( [ "${mem_kib:-0}" -ge 2097152 ] && echo OK || echo FAIL )" "$((mem_kib / 1024))"
printf '%s Disk free: %s GiB\n' "$( [ "${disk_kib:-0}" -ge 20971520 ] && echo OK || echo FAIL )" "$((disk_kib / 1024 / 1024))"
check "Docker Engine" docker version
check "Docker Compose" docker compose version
check "Git" git --version

if ss -ltn | awk '{print $4}' | grep -Eq '(:5432|:8080)$'; then
  echo 'FAIL 5432 或 8080 已被占用'
  failures=$((failures + 1))
else
  echo 'OK   5432 與 8080 可用'
fi

if [ "$failures" -gt 0 ]; then
  echo "冷備主機尚未就緒：$failures 項未通過" >&2
  exit 1
fi
echo '冷備主機準備完成。'

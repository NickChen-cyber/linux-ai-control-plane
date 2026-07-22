#!/bin/sh
set -eu

archive=${1:?用法：install-release.sh <release.tar.gz> <project-dir>}
project_dir=${2:?用法：install-release.sh <release.tar.gz> <project-dir>}
test -f "$archive" || { echo "找不到發布包：$archive"; exit 2; }
test -f "$project_dir/compose.yaml" || { echo "不是有效專案目錄：$project_dir"; exit 2; }

sh "$project_dir/deploy/check-installation.sh" "$project_dir"
stamp=$(date +%Y%m%d-%H%M%S)
snapshot_dir="$project_dir/release-snapshots"
mkdir -p "$snapshot_dir"
test -w "$snapshot_dir" || { echo "程式回復點目錄不可寫入：$snapshot_dir"; exit 2; }
snapshot="$snapshot_dir/linux-ai-agent-program-$stamp.tar.gz"
tar --exclude='./.env' --exclude='./secrets' --exclude='./node_modules' --exclude='./outputs' --exclude='./.git' -czf "$snapshot" -C "$project_dir" .
echo "已建立程式回復點：$snapshot"

if ! tar -tzf "$archive" | grep -q 'compose.yaml'; then
  echo "發布包缺少 compose.yaml，停止更新"
  exit 3
fi

tar -xzf "$archive" -C "$project_dir"
if docker compose -f "$project_dir/compose.yaml" -f "$project_dir/compose.https.yaml" up -d --build; then
  sleep 5
  if docker compose -f "$project_dir/compose.yaml" -f "$project_dir/compose.https.yaml" exec -T api python -c "import json,urllib.request; d=json.load(urllib.request.urlopen('http://127.0.0.1:8000/api/health')); assert d['databaseReady']"; then
    echo "更新成功；程式回復點保留於：$snapshot"
    exit 0
  fi
fi

echo "更新失敗，正在回復原程式"
tar -xzf "$snapshot" -C "$project_dir"
docker compose -f "$project_dir/compose.yaml" -f "$project_dir/compose.https.yaml" up -d --build
echo "已回復原程式；請檢查 docker compose ps 與 API 日誌"
exit 1

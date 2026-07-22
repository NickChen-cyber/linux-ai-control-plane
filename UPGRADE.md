# Linux AI Control Plane 升級與回復

1. 在「平台健檢」執行「更新前檢查＋備份」，等待備份狀態成功。
2. 在中央主機建立 VirtualBox Snapshot。
3. 將新版 `.tar.gz` 放到中央主機，執行：

```bash
sh deploy/install-release.sh /home/nickc/linux-ai-agent-v1.3.0.tar.gz /home/nickc
```

腳本會執行環境檢查、保存目前程式快照、重建容器、套用 checksum migration，並驗證 HTTPS/HTTP health。若建置或健康檢查失敗，會自動從快照覆蓋回原版本並重建。

資料庫回復應使用「備份管理」中已通過還原演練的 DB 備份；程式回復與資料庫回復是兩個獨立步驟。不得把舊版程式直接接到不相容的新 Schema。

## 1.1.0 升級後驗證

```bash
docker compose -f compose.yaml -f compose.https.yaml ps
docker compose -f compose.yaml -f compose.https.yaml logs --tail=80 maintenance-worker
curl -k https://192.168.0.151:8443/api/health
```

登入後到「備份管理」確認「資料保存與自動清理」已出現；到「維運任務」執行一個低風險唯讀 Runbook，狀態應依序由「已核准 → 排隊中 → 執行中 → 成功」。

Migration 003 的正向與反向測試只會使用可拋棄的測試容器，不碰正式資料庫：

```bash
sh tests/test-migrations.sh
```

## 1.2.0 升級後驗證

更新後等待約 20 秒，再登入「容量與服務」按「立即重新計算」。Schema 應為 `004`，並顯示三個中央服務狀態與受管主機容量資料。

## 1.3.0 升級後驗證

執行 `sh tests/test-migrations.sh` 應通過 Schema `005` 與 rollback；登入「可靠性報表」確認可用率、MTTA、MTTR 與 CSV 匯出可使用。

```bash
docker compose -f compose.yaml -f compose.https.yaml exec -T postgres \
  psql -U linux_ai -d linux_ai \
  -c "SELECT service,status,collected_at FROM service_health_samples ORDER BY collected_at DESC LIMIT 10;"
```

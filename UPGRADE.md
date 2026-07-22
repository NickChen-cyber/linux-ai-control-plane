# Linux AI Control Plane 升級與回復

1. 在「平台健檢」執行「更新前檢查＋備份」，等待備份狀態成功。
2. 在中央主機建立 VirtualBox Snapshot。
3. 將新版 `.tar.gz` 放到中央主機，執行：

```bash
sh deploy/install-release.sh /home/nickc/linux-ai-agent-postgresql-v2.1.0-notification-failure-center.tar.gz /home/nickc
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

## 1.4.0 升級後驗證

Schema 應為 `006`。登入「營運報表」手動產生一筆報表，確認歷史內容、高頻告警排行與 CSV 下載；自動通知預設停用。

## 1.5.0 升級後驗證

Schema 應為 `007`。設定 SMTP `.env` 後重建 API，在告警中心確認 Email 管道已啟用，再執行測試通知。

## 1.7.0 升級後驗證

Schema 應為 `009`。告警中心應顯示再次提醒政策與歷史；測試時可暫時將重大提醒間隔設為 1 分鐘。

## 1.8.0 升級後驗證

Schema 應為 `010`。等待約 5 分鐘或重新啟動 API 後，告警中心的 7／30／90 天範圍應可查詢彙總資料。

## 1.9.0 升級後驗證

Schema 應為 `011`。到「告警中心 → 通知與治理測試」，先以未勾選實際發送的模式執行，確認通知管道、靜音、安靜時段、升級與發送五個步驟都有結果；測試不會建立正式告警。

## 2.0.0 升級後驗證

Schema 應為 `012`。到告警中心建立一筆通知路由，再到通知測試實驗室選擇相同等級／主機／規則，確認「路由規則」顯示命中的名稱。

## 2.1.0 升級後驗證

Schema 應為 `013`。若目前沒有失敗通知，處理中心不會顯示操作；可在測試環境暫時提供錯誤目的地產生失敗，再確認人工重送、批次重送與忽略結案。

```bash
docker compose -f compose.yaml -f compose.https.yaml exec -T postgres \
  psql -U linux_ai -d linux_ai \
  -c "SELECT service,status,collected_at FROM service_health_samples ORDER BY collected_at DESC LIMIT 10;"
```

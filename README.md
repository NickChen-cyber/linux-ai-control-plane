# Linux/AI Control Plane

集中監控與管理 Linux 主機的 AI 維運學習平台。VirtualBox 本機版由 Web UI、FastAPI、PostgreSQL 18、Nginx 與 SSH 唯讀探測器組成。

## 目前完成

- 多主機營運總覽與健康狀態
- 主機清單、CPU、RAM、磁碟、Uptime 與失敗服務
- 唯讀主機資產盤點：OS、Kernel、網路介面、監聽連接埠、啟用服務、互動式帳號與套件數量
- 資產快照 SHA-256 與前後漂移比較，標示新增或移除的連接埠、服務、帳號及介面
- UI 新增主機：先驗證 SSH、主機身分與 known_hosts，再寫入 PostgreSQL
- UI 自動佈署：使用一次性 sudo 帳號建立 `linux-agent`、安裝中央公鑰與日誌群組權限
- 每台主機提供 Web SSH 終端，由中央 API 代理連線，不把私鑰交給瀏覽器
- PostgreSQL 平台帳號、群組權限與 8 小時 HttpOnly Session Cookie
- 登入頁、登出、使用者建立、自訂群組與權限配置
- 使用者修改、鎖定／解鎖、刪除與管理員密碼重設
- 群組修改與刪除；系統管理員群組固定受保護
- 可調整密碼最小長度及大小寫、數字、特殊符號要求
- 主機刪除採停用紀錄，不會更動遠端 Linux，也可透過重新註冊恢復
- UI 內依主機、等級與筆數查詢 `journalctl`
- 由真實主機狀態推導離線、失敗服務與資源告警
- 完整 UI 行為蒐集：頁面、點擊、焦點、表單、搜尋、捲動與 Session 狀態
- 稽核事件批次寫入 API
- PostgreSQL 真實稽核統計、搜尋、篩選與 SHA-256 雜湊鏈驗證
- PostgreSQL 18 稽核資料表、索引、`TIMESTAMPTZ` 與 `JSONB`
- PostgreSQL Named Volume，容器重建後資料仍會保留
- FastAPI 透過 SSH 即時探測 server-1 與 server-2
- FastAPI 常駐背景監控，不需要保持瀏覽器開啟
- CPU、記憶體、磁碟、可用性與失敗服務歷史樣本保存 30 天
- 告警規則、連續樣本判斷、告警確認與自動恢復生命週期
- 告警中心顯示 24 小時資源趨勢、事件與規則管理
- 告警發生與恢復可傳送 Telegram 或通用 Webhook，並保留傳送結果
- 告警中心顯示通知管道狀態、傳送紀錄與測試通知
- 隔離通知測試實驗室可模擬靜音、安靜時段、升級政策，並選擇是否實際發送；結果不污染正式告警與可靠性統計
- 告警通知可依等級、主機與規則套用優先路由、指定管道及自訂內容範本，未命中時使用安全備援路由
- 最終失敗通知可在處理中心人工或批次重送、忽略結案，並保存處理人、備註與完整歷史
- 通知交付 SLO 依管道統計成功率、失敗、抑制與補送成效，可調整觀察期間、目標及最低樣本數
- 計畫性維護時段仍持續採集告警證據，但可依主機／規則暫停通知與升級，結束後自動恢復
- 告警相依規則可用同主機的根因事件抑制子告警通知與升級，保留證據並降低通知風暴
- 根因關聯視圖永久保存實際命中的根因與子事件、時間線及解除狀態，支援事故回溯
- 告警風暴保護在同主機短時間大量事件時只送一則摘要，冷卻期間保留證據並抑制重複通知
- 值班排程將新告警自動指派給目前值班的可用平台使用者，保存班次與永久指派歷史
- PostgreSQL 每日自動備份、手動備份、保留期限與 SHA-256 校驗資訊
- 每份備份同步封存 Git 設定歷史與 SSH known_hosts，建立冷備復原檔及獨立 SHA-256
- 冷備候選主機可執行 SSH 唯讀就緒檢查，保存 CPU、記憶體、磁碟、Docker、Compose 與連接埠結果
- 每份備份自動還原至暫存資料庫，通過實際還原演練才標記成功
- 備份管理頁顯示工作狀態、檔案、容量、要求者與驗證結果
- 備份失敗會自動透過 Telegram／Webhook 發出嚴重通知
- 可在另一台 Linux 部署外部 Watchdog，中央完全離線時仍能通知並回報心跳
- Watchdog 永久保存每次中斷開始、恢復時間與持續秒數
- LINE Messaging API 與 Android SMS Gateway 通知管道
- 通知失敗自動於 1、5、15 分鐘重試，最多四次並保存結果
- AI 主機診斷：真實探測與 warning 日誌、敏感資料遮罩、證據引用及歷史結果
- AI 診斷只提供人工審查建議，不會自動執行模型產生的指令
- 安全維運任務：預設唯讀 Runbook、申請、人工核准／拒絕、執行及結果歷史
- 維運任務不接受瀏覽器傳入任意命令，SSH 只執行中央程式內建允許清單
- 維運任務具低／中／高風險政策；中高風險必須由非申請者獨立核准，高風險還需輸入確認字串
- 任務執行保存驗證結果、耗時與輸出 SHA-256，可檢查結果完整性
- 本機 Git 設定版控：主機、告警、群組、密碼規則與 Runbook 政策自動建立版本
- 設定快照排除密碼、私鑰與通知 Token，UI 可查看版本、異動區塊及完整 JSON
- 設定回滾採申請、獨立核准、輸入確認字串及執行前自動快照，結果永久保存
- 響應式桌面／平板／手機介面

目前已開放營運總覽、主機監控、AI 診斷、告警中心、通知、資料庫備份、日誌查詢、行為稽核、用戶與群組管理。遠端寫入只開放固定修復 Runbook，不能從 UI 或 API 傳入任意命令。

> `.openai/hosting.json` 中的 D1 只供 Sites 原型環境使用。你在 VirtualBox 上啟動的本機完整版會由 Nginx 將 `/api/*` 送到 FastAPI，實際資料庫是 PostgreSQL，不會寫入 D1 或 SQLite。

## 本機開發

需要 Node.js 22.13 以上版本。

```bash
pnpm install
pnpm run dev
```

開發網址為 `http://localhost:3000/`。

完整驗證：

```bash
pnpm run build
pnpm exec tsc --noEmit
node --test tests/rendered-html.test.mjs
```

## 在中央 Ubuntu 啟動本機完整版

中央機預設為 `192.168.0.151`。第一次啟動前建立環境設定：

```bash
cp .env.example .env
nano .env
```

至少修改 `POSTGRES_PASSWORD` 與 `ADMIN_PASSWORD`。`ADMIN_PASSWORD` 是第一次建立平台管理員時使用的密碼，不是 Ubuntu 的 `nickc` 密碼。接著啟動：

```bash
docker compose up -d --build
docker compose ps
```

瀏覽器開啟：

```text
http://192.168.0.151:8080/
```

PostgreSQL 只綁定中央機的 `127.0.0.1:5432`，不會直接開放給區網其他設備。Web UI 則綁定 `192.168.0.151:8080`。

常用檢查：

```bash
docker compose logs -f postgres api
curl http://192.168.0.151:8080/api/health
curl http://192.168.0.151:8080/api/hosts
```

健康檢查應顯示 `"database":"postgresql"` 與 `"databaseReady":true`。

### 平台健檢

登入後可從左側開啟「平台健檢」。頁面每 30 秒以唯讀方式檢查：

- PostgreSQL 連線與版本
- `backup` 背景服務心跳、最近備份時間與 DB＋DR 還原驗證
- 中央 SSH 私鑰是否存在、可讀且沒有群組或其他人權限
- `known_hosts` 已保存的主機指紋數量
- 本機 Git 設定版控是否存在有效 HEAD
- 外部 Watchdog 最近心跳
- 已啟用的 LINE、SMS、Telegram 或 Webhook 通知管道
- 目前是免費本機 AI 規則或 OpenAI 模式

健檢 API 不回傳 SSH 私鑰、密碼、Token 或 API Key。選用項目未設定只會顯示提醒，不會讓平台整體狀態變成異常；必要項目失敗才會顯示「需要處理」。

### Linux 更新盤點

「更新盤點」會透過既有 SSH 金鑰，在一台或全部受管 Ubuntu 執行唯讀查詢並將最新結果保存到 PostgreSQL：

- 目前運作中的 Kernel 版本
- 依現有 APT 索引列出的待更新套件與目前／候選版本
- `/var/run/reboot-required` 是否存在，以及觸發重啟的套件
- `unattended-upgrades.service` 是否啟用
- Ubuntu Pro／APT Security Pocket 所辨識的安全更新
- Canonical Ubuntu Security Notice（USN）及相關 CVE
- 高、中、一般三種平台維運優先級
- 盤點操作者、時間及 SSH 失敗原因

此功能不執行 `apt update`、`apt upgrade`、套件安裝或重新開機。因為它只讀取遠端主機現有的 APT Cache，如果主機很久沒有更新套件索引，結果也可能不是最新；後續若要更新索引或安裝套件，仍必須走維運任務、風險分級與審批流程。

API 會使用 Canonical 官方 `https://ubuntu.com/security/notices.json`，以主機版本代號、套件名稱及候選版本比對公告。結果會保存 USN 與 CVE ID，但不保存完整外部公告。中央無法連外時仍會保存 APT 結果，頁面則顯示「CVE 資料未完成」，不會把缺少的資料當成沒有漏洞。高／中／一般是平台用來安排維運順序的優先級，並非 Canonical Priority、CVSS 分數或可利用性判定。

### Linux 主機安全基準

「主機基準」會透過既有 SSH 金鑰執行唯讀檢查，並將每台主機的分數、證據、建議、操作者與時間保存到 PostgreSQL。第一版涵蓋：

- SSH Root 登入與密碼登入設定
- UFW 服務、AppArmor 與時間同步狀態
- `unattended-upgrades` 與 `auditd` 狀態
- `/etc/shadow` 及目前管理帳號 `authorized_keys` 的檔案權限
- 最近 12 次成功掃描的分數趨勢
- 與上一次成功掃描相比的分數、改善與退步項目

每項通過為 100、提醒為 50、未通過為 0，再取平均作為主機分數。分數是本地實驗室的快速基線，不代表完整 CIS 認證或正式弱點掃描，也不會自動變更遠端設定。UFW 目前刻意維持 inactive 時會顯示提醒，這是預期結果；是否啟用仍應依網路隔離設計決定。

SSH 設定結果是依 `/etc/ssh/sshd_config` 與 `sshd_config.d/*.conf` 的宣告內容估算，UFW 則讀取 systemd 啟用狀態，因此不能完全取代 `sshd -T`、實際防火牆規則及人工複核。頁面上的修正建議只供管理者評估，不會由中央自動執行。

所有歷史掃描都保留在 `host_security_scans`。主畫面顯示最近 12 次；需要取得較長紀錄時，可使用 `GET /api/security-baselines/{host_id}/history?limit=30`，上限 100 筆。

### 帳號與 Session 安全中心

系統管理員可從左側「安全中心」查看：

- 所有尚未到期的登入 Session、來源 IP、瀏覽器、建立時間、最後活動與到期時間
- 最近 100 筆登入成功、帳號或密碼錯誤、登入嘗試過多事件
- 最近 24 小時登入失敗次數
- 撤銷指定使用者或裝置的 Session
- 一次登出目前帳號在其他裝置上的 Session

目前使用中的 Session 不允許由撤銷按鈕刪除，必須使用左下角正常登出。鎖定使用者及重設其他使用者密碼時，原有 Session 仍會立即失效。登入事件只保存帳號、結果、來源 IP 與 User-Agent，不會保存輸入的密碼；Session 只保存 Token 的 SHA-256 雜湊。

「登入安全政策」可調整：

- 允許失敗次數：3–10 次，預設 5 次
- 暫時鎖定時間：1–1440 分鐘，預設 5 分鐘
- 登入紀錄保留：30–365 天，預設 90 天

失敗計數與政策保存在 PostgreSQL，因此重新建立 API 容器不會清除限制。計數以「正規化帳號＋實際來源 IP」為單位，成功登入後才重設該來源的失敗序列。Nginx 會傳遞用戶端 IP；API 只在直接來源是內部 Docker 私有位址時採用並驗證轉送標頭，避免任意偽造來源。

### 區網 HTTPS（選用）

HTTP `8080` 可以繼續用於初期實驗。準備消除瀏覽器「不安全」提示時，可在中央主機建立實驗室專用 Local CA 與包含 `192.168.0.151` SAN 的伺服器憑證：

```bash
cd /home/nickc
sh deploy/generate-local-tls.sh 192.168.0.151
```

腳本會在 `/home/nickc/secrets/tls` 建立憑證；此目錄已排除在 Git 與發布套件之外。以下私鑰只能留在中央主機：

- `local-ca.key`
- `server.key`

只將公開的 CA 憑證複製到 Mac：

```bash
scp nickc@192.168.0.151:/home/nickc/secrets/tls/local-ca.crt ~/Downloads/
```

在 macOS 開啟「鑰匙圈存取」，把 `local-ca.crt` 匯入「登入」鑰匙圈，打開該憑證的「信任」，將「使用此憑證時」改為「永遠信任」。這只適用自己的封閉實驗室；不要把 Local CA 私鑰分享給任何人。

接著在中央主機啟用 HTTPS Overlay：

```bash
docker compose -f compose.yaml -f compose.https.yaml \
  up -d --build --force-recreate api gateway
docker compose -f compose.yaml -f compose.https.yaml ps
```

瀏覽器改用：

```text
https://192.168.0.151:8443/
```

啟用 Overlay 後，`8080` 會轉址到 `8443`，Session Cookie 會強制 `Secure`。Nginx 同時加入 HSTS、CSP、禁止 iframe、禁止 MIME sniffing、Referrer 與裝置權限限制。若尚未在 Mac 信任 CA，請不要先啟用 Overlay，否則瀏覽器仍會顯示憑證警告。

需要暫時回到 HTTP 時，在中央主機執行：

```bash
docker compose up -d --build --force-recreate --no-deps api gateway
```

### PostgreSQL 串流複寫（選用）

預設仍是單一 PostgreSQL，`POSTGRES_BIND_IP=127.0.0.1`，不會對區網公開 5432。只有第二台中央備援主機準備完成後才啟用。先在兩台 VM 建立 Snapshot，並確認「備份管理」已有通過還原驗證的最新備份。

在 Primary 中央主機的 `.env` 設定：

```dotenv
POSTGRES_BIND_IP=192.168.0.151
POSTGRES_PRIMARY_HOST=192.168.0.151
POSTGRES_PRIMARY_PORT=5432
POSTGRES_REPLICATION_USER=linux_ai_replication
POSTGRES_REPLICATION_PASSWORD=請使用另一組至少16碼的隨機密碼
POSTGRES_REPLICATION_SLOT=linux_ai_standby
```

重新建立 Primary PostgreSQL，讓 WAL 與新的綁定位置生效，再用備援主機的固定 IP 設定最小範圍的 `pg_hba.conf` 規則：

```bash
docker compose up -d --force-recreate postgres
sh deploy/configure-postgres-primary.sh <備援主機IP>
```

腳本只允許該備援 IP 以複寫帳號連線，不會修改 UFW。若已啟用 UFW，應另外只允許備援主機連入 TCP 5432，不能對整個區網或 Internet 開放。

在 Standby 中央主機複製同一份專案及 `.env`，`POSTGRES_PRIMARY_HOST` 指向 Primary，且複寫密碼與 Slot 必須一致，然後啟動：

```bash
docker compose -f compose.standby.yaml up -d
docker compose -f compose.standby.yaml ps
docker compose -f compose.standby.yaml logs --tail=100 postgres-standby
```

完成後，「備份管理」→「資料庫串流複寫」會顯示 Slot 已連線、Standby IP 與 WAL 延遲。這一版只建立與監控非同步 Physical Streaming Replication；不會自動切換 Primary，避免網路分割時發生雙主寫入。故障切換仍需管理者確認後執行。

### AI 主機診斷

預設使用免費的本機規則診斷，不會呼叫外部 AI，也不會產生 API 費用。它會根據 CPU 90%、記憶體 85%、磁碟 80%、SSH 離線、失敗服務與 warning 日誌關鍵字產生附證據的結果：

```dotenv
AI_DIAGNOSTIC_MODE=local
```

若日後需要 OpenAI 深度分析，再改成 `openai` 並設定 API Key。請只在中央主機 `.env` 設定，不要把 Key 貼到聊天、UI 或程式碼：

```dotenv
OPENAI_API_KEY=請填入你的_OpenAI_API_Key
OPENAI_MODEL=gpt-5.6-luna
OPENAI_TIMEOUT_SECONDS=60
AI_DIAGNOSTIC_MODE=openai
```

本地學習環境預設採用成本敏感的 `gpt-5.6-luna`，可自行覆寫模型。平台使用 [OpenAI Responses API](https://developers.openai.com/api/reference/resources/responses/methods/create) 與 [Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs)，送出前會遮罩常見密碼、Token、私鑰與電子郵件，並設定 `store: false`。診斷輸出的命令只是人工審查建議，平台不會執行。

設定後重建 API：

```bash
docker compose up -d --build api ui
docker compose restart gateway
```

背景監控預設每 60 秒採集一次並保留 30 天，可在 `.env` 調整：

```dotenv
MONITOR_INTERVAL_SECONDS=60
METRIC_RETENTION_DAYS=30
```

登入後進入「告警中心」可查看歷史趨勢、立即採集、建立或修改規則，以及確認進行中的告警。預設規則包含主機離線、CPU、記憶體、磁碟與失敗 systemd 服務。

### 告警通知

通知管道由中央主機的 `.env` 設定。Telegram 與 Webhook 可以擇一或同時啟用；沒有設定時背景監控仍會正常運作，只是不向外傳送通知。

```dotenv
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
LINE_CHANNEL_ACCESS_TOKEN=
LINE_TARGET_ID=
SMS_GATEWAY_URL=
SMS_GATEWAY_TOKEN=
SMS_TO_NUMBER=
ALERT_WEBHOOK_URL=
ALERT_WEBHOOK_TOKEN=
NOTIFICATION_TIMEOUT_SECONDS=8
```

Telegram 需要 Bot Token 與 Chat ID。LINE 使用官方 Push Message API，需要 Channel Access Token 與 webhook event 取得的 `userId`、`groupId` 或 `roomId` 作為 `LINE_TARGET_ID`；LINE Official Account 必須符合可發送 Push Message 的條件，詳見 [LINE 官方文件](https://developers.line.biz/en/reference/messaging-api/#send-push-message)。

Android SMS Gateway 需提供接受 HTTP POST 的 URL，平台會傳送 `{ "to": "手機號碼", "message": "通知內容", "idempotencyKey": "固定重試識別碼" }`；若 Gateway 支援 Bearer Token，可設定 `SMS_GATEWAY_TOKEN`。通用 Webhook 則繼續傳送 `source`、`kind`、`severity`、`message`、`alertEventId` 與 `occurredAt`。

任何管道第一次傳送失敗後會建立 PostgreSQL 重試工作，依序於 1、5、15 分鐘補送，總嘗試次數最多四次。LINE 重試會沿用同一個官方 `X-Line-Retry-Key`，降低重複訊息風險。告警中心會顯示等待重試、已補送與最終失敗狀態。

修改 `.env` 後重建 API：

```bash
docker compose up -d --build api
```

登入後前往「告警中心」→「通知管道」，確認狀態為「已啟用」，再按「發送測試通知」。告警發生與恢復時會自動通知；每次結果都寫入 PostgreSQL，但 Token、完整 Webhook URL 與 Telegram Bot Token 不會寫入 UI、稽核紀錄或資料庫。

### PostgreSQL 自動備份

`backup` 背景容器預設每 24 小時建立一次 PostgreSQL custom archive，保存於 Docker Named Volume `backup-data`。每次建立後會自動建立臨時資料庫、完整還原、檢查 public schema 資料表，並同步封存 `config-history` Git 版本庫與 SSH `known_hosts`。兩份檔案都會計算 SHA-256，全部驗證成功才標示中央復原資料齊備。

可在 `.env` 調整：

```dotenv
BACKUP_INTERVAL_HOURS=24
BACKUP_RETENTION_DAYS=7
BACKUP_POLL_SECONDS=10
```

登入後前往「備份管理」可查看自動與手動備份、資料庫與復原封存 SHA-256、還原驗證結果及失敗原因。具有「執行備份」權限的帳號可以按「立即備份」。同一時間只允許一個工作，避免多份備份同時消耗中央主機資源。SSH 私鑰與 `.env` 不會自動放入封存，必須由管理者另外離機保管。

檢查背景服務：

```bash
docker compose ps backup
docker compose logs --tail=100 backup
docker volume ls | grep backup-data
```

備份檔案會在超過保留天數後自動刪除，但歷史工作仍保留在 PostgreSQL，方便稽核。`docker compose down` 不會刪除備份；只有執行 `docker compose down -v` 才會連同 PostgreSQL 與備份 Named Volume 一起移除。

具「執行備份」權限的管理者可在備份紀錄下載 `DB` 與 `DR` 兩份檔案。API 會在串流前重新驗證資料庫所記錄的 SHA-256。把兩份檔案、畫面顯示的完整校驗值、專案檔、另行保管的 `.env` 與 SSH 私鑰放到冷備中央後，可在專案目錄執行：

```bash
CONFIRM_RESTORE=RESTORE sh deploy/restore-cold-standby.sh \
  linux_ai_日期.dump 資料庫_SHA256 \
  linux_ai_recovery_日期.tar.gz 復原封存_SHA256
```

腳本會先校驗檔案，停止 API/UI/備份服務，還原 PostgreSQL、Git 設定歷史與 `known_hosts`，最後重新啟動服務。這是冷備還原工具，不是即時 PostgreSQL 複寫；正式執行前應先建立 VirtualBox Snapshot。

「備份管理」的冷備主機就緒檢查可選擇既有受管主機，透過 SSH 唯讀檢查至少 2 核 CPU、2 GB 記憶體、20 GB 可用空間、Docker Engine、Docker Compose，以及 5432/8080 連接埠是否可用。檢查結果會寫入 PostgreSQL，不會自動安裝套件或修改遠端主機。

若候選主機缺少 Docker，先關機調整 VirtualBox 資源並建立 Snapshot，再把專案放到候選主機。本地登入該主機後執行：

```bash
sudo sh deploy/prepare-cold-standby.sh nickc
sh deploy/verify-cold-standby.sh
```

準備腳本只支援 Ubuntu，會先檢查最低資源，再從 Docker 官方套件庫安裝 Engine、Compose 與 Git，將指定管理帳號加入 `docker` 群組並建立 `/opt/linux-ai-standby`。它不會開放防火牆、不會啟動資料庫複寫，也不會複製 `.env`、密碼或 SSH 私鑰。

### 外部存活監控

中央主機完全斷線時，中央本身無法發送告警，因此 Watchdog 必須安裝在另一台 Linux，例如 `server-1`。先在中央產生共享 Token：

```bash
openssl rand -hex 32
```

把輸出填入中央 `/home/nickc/.env`：

```dotenv
WATCHDOG_SHARED_TOKEN=請填入剛才產生的隨機值
WATCHDOG_STALE_SECONDS=120
```

重新建立 API：

```bash
docker compose up -d --force-recreate api
docker compose restart gateway
```

### 安全維運任務

「維運任務」提供受控的 SSH 檢查與修復流程。唯讀 Runbook 包含系統健康總覽、失敗服務、高資源程序、磁碟使用及可更新套件；受控寫入只包含重設 failed 狀態、更新 APT 索引與安裝安全更新。操作流程為「建立待核准任務 → 核准或拒絕 → 執行 → 前後驗證 → 保存證據」。

低風險 Runbook 採單一核准；中高風險 Runbook 必須由另一位具 `tasks.approve` 權限的使用者核准，申請者不能自行核准。高風險任務在執行時還必須輸入 `EXECUTE`。執行完成後會保存執行前證據、操作輸出、執行後驗證、耗時及輸出 SHA-256；失敗時也會保存已取得的部分證據。

瀏覽器只會傳送 Runbook ID，實際指令由 FastAPI 的允許清單決定，因此無法透過 API 插入任意 shell 命令。執行輸出會遮罩常見密碼、Token、私鑰與 Email，再保存至 PostgreSQL。群組可分別授予查看、申請、核准及執行權限。

自動佈署新主機時，平台會一併建立 `/etc/sudoers.d/linux-ai-agent`，只允許三條固定命令。既有主機需先把 `deploy/install-managed-host-sudoers.sh` 複製到主機，再由具 sudo 權限的既有管理帳號執行：

```bash
sudo sh install-managed-host-sudoers.sh
sudo visudo -cf /etc/sudoers.d/linux-ai-agent
```

安裝腳本在確認限制檔通過 `visudo` 後，會移除 `linux-agent` 原有的 `sudo` 群組資格。此設定不授予一般 root shell、任意 systemctl、任意 apt-get 參數或重新開機權限；日誌所需的 `adm` 與 `systemd-journal` 群組不受影響。

「安全維運任務」會從中央透過 SSH 執行 `sudo -n -l`，顯示每台主機的權限就緒狀態。所有受控寫入在真正執行前還會由後端重新檢查；只要缺少任一必要命令、SSH 不通、使用者不是 `linux-agent`，或偵測到 `ALL`、萬用字元及任何白名單外 sudo 命令，就會停止執行並寫入失敗稽核。

任務核准預設只在 60 分鐘內有效，可用 `MAINTENANCE_APPROVAL_TTL_MINUTES` 調整為 5～1,440 分鐘。資料庫使用部分唯一索引，保證同一台主機同時間最多只有一筆執行中的任務；另一筆會收到衝突而不會送出 SSH 指令。API 容器若在任務執行期間重新啟動，啟動遷移會把遺留的 `running` 任務標記失敗，避免畫面永久卡住或被誤認為仍在執行。

將以下四個檔案複製到 `server-1` 的同一個目錄：

- `deploy/external-watchdog.sh`
- `deploy/linux-ai-watchdog.service`
- `deploy/linux-ai-watchdog.env.example`
- `deploy/install-external-watchdog.sh`

在 `server-1` 執行：

```bash
sudo sh install-external-watchdog.sh
sudo nano /etc/linux-ai-watchdog.env
```

`WATCHDOG_TOKEN` 必須與中央的 `WATCHDOG_SHARED_TOKEN` 完全相同。若希望中央完全離線時仍能通知，還必須在這台外部主機設定 Telegram 或 Webhook 憑證。接著啟動：

```bash
sudo systemctl enable --now linux-ai-watchdog
sudo systemctl status linux-ai-watchdog --no-pager
sudo journalctl -u linux-ai-watchdog -n 50 --no-pager
```

約 30 秒後，「備份管理」→「外部存活監控」應顯示 `server-1` 心跳正常。預設連續 3 次、每次間隔 30 秒失敗才通知，避免短暫網路波動造成誤報。每次恢復會永久寫入 PostgreSQL 的 `watchdog_outages`，正常心跳不會再清除最後中斷秒數。Watchdog v2 也會把「判定離線」與「恢復」轉換寫入 systemd journal。

第一次開啟網站會顯示登入頁。預設帳號由 `.env` 的 `ADMIN_USERNAME` 與 `ADMIN_PASSWORD` 決定。登入後可分別到「用戶管理」及「群組管理」建立維運人員、唯讀檢視者或自訂權限群組。新增資料會在按下新增按鈕後才顯示輸入視窗；重設密碼會先產生至少 12 碼的臨時密碼，只有按下確認後才會寫入 PostgreSQL。

「密碼規則」位於用戶管理頁的新增使用者按鈕旁，點擊後才會開啟設定視窗。使用者清單會顯示每個帳號的所屬群組；群組管理清單則以橫向欄位呈現群組名稱、權限與操作。

密碼規則與群組新增／修改視窗的勾選項目採單欄排列，方便逐項閱讀。使用者名稱、所屬群組及群組權限使用固定欄位對齊；系統管理員群組固定顯示在群組清單第一筆。

用戶與群組清單包含表格式欄位標題，所有資料依欄位上下對齊。密碼規則及群組權限的文字固定顯示在勾選框右側。

> 管理員只在資料庫尚未存在該帳號時建立。日後修改 `.env` 不會自動覆蓋既有密碼，避免意外變更正式帳號。

## 從 UI 新增主機

「自動佈署」只需要目標主機已開啟 SSH，並提供一組能登入且可執行 `sudo` 的首次設定帳號。UI 會先顯示 SSH 主機指紋；請先在目標主機執行以下指令核對：

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

確認 UI 與目標主機顯示的 SHA256 指紋一致後，再按「確認指紋並佈署」。平台會建立 `linux-agent`、安裝中央公鑰、加入 `adm` 與 `systemd-journal` 群組，且不會把首次設定密碼寫入 PostgreSQL或稽核紀錄。

如果主機已經有 `linux-agent`，可切換至「已有 linux-agent」模式。這個模式需要先在中央機完成金鑰部署與首次指紋確認：

```bash
ssh-copy-id -i ~/.ssh/linux_ai_agent.pub linux-agent@192.168.0.154

ssh -o IdentitiesOnly=yes \
  -i ~/.ssh/linux_ai_agent \
  linux-agent@192.168.0.154 'hostname; id'
```

確認可以免密碼登入後，進入「主機監控」→「新增主機」，輸入名稱、IP、Port 與 SSH 帳號。API 會使用 `StrictHostKeyChecking=yes` 驗證；只有成功連線的主機才會存入 PostgreSQL。

## Web SSH 終端

在「主機監控」按每台主機後方的「SSH 終端」，瀏覽器會透過 Nginx WebSocket 連到中央 API，再由中央 API 使用既有金鑰登入該主機的 `linux-agent` 帳號。

- SSH 私鑰不會送到瀏覽器。
- 稽核會記錄連線開啟、成功、失敗與關閉。
- 終端按鍵與畫面不寫入 UI 稽核，避免意外保存密碼或 Token。
- 目前是本地實驗室功能；正式環境啟用前必須先完成平台登入、主機權限與閒置逾時。

## PostgreSQL 練習

進入 `psql`：

```bash
docker compose exec postgres psql -U linux_ai -d linux_ai
```

在 `psql` 內可以依序練習：

```sql
\l
\dt
\d+ audit_events

SELECT current_database(), current_user, version();

SELECT id, occurred_at, actor_name, event_type, action
FROM audit_events
ORDER BY occurred_at DESC
LIMIT 10;

SELECT event_type, COUNT(*) AS event_count
FROM audit_events
GROUP BY event_type
ORDER BY event_count DESC;
```

輸入 `\q` 離開。

備份資料庫：

```bash
docker compose exec -T postgres \
  pg_dump -U linux_ai -d linux_ai -Fc > linux_ai_backup.dump
```

Named Volume 名稱可用以下指令確認：

```bash
docker volume ls | grep linux-ai-agent
```

停止服務不會刪除資料：

```bash
docker compose down
```

只有在確定要清空 PostgreSQL 練習資料時，才使用：

```bash
docker compose down -v
```

## VirtualBox 測試環境

建議準備三台 Ubuntu VM：

| VM | 用途 | 建議規格 |
| --- | --- | --- |
| control-plane | 中央平台 | 4 vCPU / 4 GB RAM / 80 GB |
| ubuntu-node-01 | 正常受管主機 | 2 vCPU / 2 GB RAM / 30 GB |
| ubuntu-node-02 | 異常、審批與回滾測試 | 2 vCPU / 2 GB RAM / 30 GB |

網路使用 NAT 加 Host-only Adapter。請記錄每台 VM 的：

- Host-only IP
- 主機名稱
- Ubuntu 版本
- SSH Port
- 專用管理帳號名稱
- 所屬環境與主機群組

不要把密碼、SSH 私鑰、Token 或 MFA 驗證碼提交到 Git。正式串接會使用專用 SSH Key、限制過的 sudoers 與主機指紋驗證。

## 核心功能與身分安全整合版

本版把下列功能接到既有 PostgreSQL、RBAC、Session 與稽核流程：

- 固定且不可注入任意命令的修復 Runbook：重設 failed 狀態、更新 APT 索引、安裝安全更新。中高風險必須由另一位具權限使用者核准。
- APT／Canonical CVE 更新風險盤點，以及具本機規則編號與證據的 CIS-aligned 唯讀基準（不宣稱官方 CIS 認證）。
- systemd journal 集中採集至 PostgreSQL，預設每 5 分鐘採集、保留 30 天；日誌頁可切換「集中日誌」與「即時 SSH」。
- TOTP MFA 與一次性復原碼。復原碼只在設定時顯示，資料庫只保存不可逆雜湊。
- AES-256-GCM 祕密庫，API 永不回傳已保存的祕密值；每次覆寫都增加版本。
- OIDC／LDAP provider 的非敏感設定登錄；client secret 或 bind password 必須另存祕密庫。外部 Provider 未設定前，本機帳號登入保持可用。
- SSH Ed25519 金鑰採 staged → 逐台部署/驗證 → promote；切換時不自動刪除舊金鑰，避免失聯。

正式使用前請在 `.env` 產生固定主金鑰：

```bash
openssl rand -base64 32
```

把輸出填入 `PLATFORM_MASTER_KEY=`。此值一旦用來加密 MFA、祕密或 SSH 私鑰就不可任意更換，遺失後既有密文無法復原。未設定時平台會使用只適合本機學習的衍生金鑰並在安全中心提示。

遠端修復 Runbook 使用 `sudo -n`，因此不會在背景等待或保存 sudo 密碼。要執行哪一個操作，必須在受管主機以 `/etc/sudoers.d/linux-ai-agent` 精確允許對應命令；未授權時任務會安全失敗並留下錯誤證據。

### 身分安全收尾版操作順序

1. 先由每一位啟用中的管理員在「安全中心」完成 TOTP MFA，並離線保存一次性復原碼。
2. 再開啟「登入安全政策」中的「強制所有啟用中的系統管理員使用 MFA」。只要仍有管理員未設定，API 會拒絕開啟，避免誤鎖帳號。
3. 祕密庫支援新增、輪替與刪除；列表只顯示名稱、用途、版本與時間，不提供明文讀回 API。
4. SSH 金鑰依序執行「建立 staged 金鑰 → 部署並逐台驗證 → promote」。舊金鑰仍會保留。
5. 確認新金鑰持續可用後，建立舊金鑰退役申請。申請者不能自行核准，另一位具核准權限的管理員核准後才可逐台移除。

MFA 設定、復原碼輪替、MFA 停用、祕密新增／輪替／刪除、SSH 金鑰建立／部署／切換／退役都會由後端直接寫入雜湊鏈稽核，不依賴前端是否成功送出 UI 行為事件。

## 集中日誌強化版

集中日誌採集器透過既有 SSH 金鑰讀取 systemd journal JSON，不需在受管主機安裝額外 agent。除了訊息與等級，也會保存主機、systemd unit、syslog identifier、PID、transport、boot ID 與原始發生時間。

「日誌查詢」頁支援：

- 單一主機或全部主機
- 最低日誌等級
- systemd 服務
- 訊息或 identifier 關鍵字
- 開始／結束時間
- 最多 1,000 筆畫面結果
- 最多 10,000 筆 CSV 匯出
- 每台主機採集時間、保存筆數、連續失敗及最後錯誤
- 1～365 天保存期限、60～3,600 秒採集間隔與失敗告警門檻

集中日誌連續採集失敗會建立系統告警 `rule-log-collection`，並使用既有 Telegram、LINE、SMS 或 Webhook 通知與重試流程。這條系統規則可停用或調整門檻，但不可刪除或改成其他監控項目。政策變更與 CSV 匯出會由後端寫入稽核鏈。

資產盤點支援 1–168 小時的自動排程，透過唯讀 SSH 保存主機介面、監聽連接埠、啟用服務、互動式帳號、系統版本與套件數量快照。新快照出現差異時會建立內建 `rule-asset-drift` 告警，並可沿用既有 Telegram、LINE、SMS 或 Webhook 通知；此系統規則可調整或停用，但不可刪除或改成其他監控項目。

更新風險盤點也支援 1–168 小時的自動排程與每台主機安全更新數量門檻。中央只讀取 APT、Ubuntu Pro 與 Canonical 安全公告，不會自動安裝套件；達到門檻時建立內建 `rule-security-updates` 告警，數量降到門檻以下時自動恢復，並沿用既有手機與 Webhook 通知流程。

主機安全基準支援 1–168 小時的自動排程與最低分數政策。分數低於門檻或任一檢查項目相較前次退步時，會建立內建 `rule-security-baseline` 告警；分數與檢查結果回復後自動解除。檢查只讀取 SSH、防火牆、時間同步、AppArmor、帳號金鑰等狀態，不會自動修改遠端主機。

「巡檢排程」頁統一顯示資產漂移、更新風險與安全基準三種背景工作。每次系統排程或手動執行都會永久保存開始與完成時間、耗時、成功／失敗主機數、執行者及錯誤原因；API 意外重新啟動時，未完成紀錄會標記為失敗，不會永遠停留在執行中。

每筆巡檢紀錄可按「查看結果」開啟證據視窗：資產盤點顯示服務、連接埠、帳號、漂移摘要與快照 SHA-256；更新盤點顯示待更新、安全更新、CVE、重新開機狀態及安全套件；安全基準顯示分數、未通過與提醒項目。這些結果由該次執行時間範圍內的主機快照取得。

## 告警到受控維運

告警事件可直接建立維運任務，但平台不會提供任意指令輸入。每種告警只會列出它對應的固定 Runbook，例如磁碟告警只能使用磁碟分析與健康總覽，安全更新告警才可選更新檢查或經獨立核准的更新 Runbook。已恢復的告警不可建立新任務；同一告警、同一 Runbook 若已有待核准、已核准或執行中的任務，也不能重複建立。

建立後的任務仍完整套用既有風險分級、雙人核准、執行確認、輸出雜湊與驗證流程。任務會保存來源告警 ID 與告警摘要，並由後端雜湊鏈稽核「由告警建立受控維運任務」的行為。

在「告警中心」按「處理歷程」可查看該事件所建立的全部任務、申請與核准者、目前狀態、驗證結果、完成時間與輸出 SHA-256 摘要。這個畫面只讀取已保存的任務證據；執行輸出仍由「維運任務」頁的既有權限與流程管理。

## 目前實驗室主機

| 主機 | IP | 用途 |
| --- | --- | --- |
| AiAgnet | 192.168.0.151 | UI、API、PostgreSQL、SSH 探測 |
| server-1 | 192.168.0.152 | 受管 Linux 主機 |
| server-2 | 192.168.0.153 | 受管 Linux 主機 |

## 1.0 正式收尾功能

- 維運任務支援待核准、已核准及執行中取消；失敗、逾時或取消後可建立全新的待核准重試任務。背景回收器每 15 秒檢查失去心跳且超過 Runbook 期限的工作，管理者也可手動「回收卡住任務」。
- 告警事件支援負責人、人工調查筆記、確認與結案時間線、結案原因及處理結果。所有處理仍寫入後端稽核鏈。
- `backend/migrations` 使用不可變 SQL 與 SHA-256 checksum；`schema_migrations` 保存版本與套用時間。修改已套用 migration 會阻止 API 啟動。
- 「平台健檢」顯示 API 與 Schema 版本、相容性及更新準備紀錄。更新前檢查會先建立 PostgreSQL 備份並要求通過還原驗證。
- `deploy/install-release.sh` 在更新前保存程式回復點、重建服務並執行健康檢查；失敗時自動覆蓋回原程式版本。資料庫回復仍使用已驗證的 DB 備份，詳見 `UPGRADE.md`。
- `tests/run-integration.sh` 對已部署環境驗證登入、MFA 狀態、主機採集、告警、維運白名單、備份還原狀態、Schema 相容性與登出。設定 `INTEGRATION_MUTATIONS=1` 才會執行安全的採集與備份建立。
- 小螢幕介面支援橫向表格、底部 Modal、行動版導覽、任務篩選分頁及一致的載入／錯誤訊息。

## 1.1 第二階段：容量與生命週期

- API 只負責核准及排入 PostgreSQL 佇列；`maintenance-worker` 獨立領取任務，即使 API 重啟也不會直接把正常任務判定失敗。
- Worker 使用 `FOR UPDATE SKIP LOCKED` 安全領取工作、回報心跳，並維持同一台主機同時最多一個維運任務。UI 可取消排隊或執行中的工作。
- `API_RATE_LIMIT_PER_MINUTE` 與 `SSH_MAX_CONCURRENCY` 控制中央負載；Compose 另對 PostgreSQL、API、Worker、備份、UI 與 Gateway 設置 CPU、記憶體及 PID 上限。
- 「備份管理」可調整告警、維運、效能、巡檢、盤點、登入與中央日誌的保存期限，先預覽再清理。稽核鏈預設保留 3,650 天且標記為受保護，不接受 UI 清理。
- `tests/test-migrations.sh` 驗證正式 migration 與 rollback；`tests/run-integration.sh` 可在 AiAgnet 驗證真實登入、主機、Worker、備份、保存政策與 Schema。

## 1.2 第三階段：可觀測性與容量預測

- 「容量與服務」每 30 秒更新畫面，中央每 5 分鐘保存 PostgreSQL、備份 Worker、維運 Worker、任務佇列與資料庫容量狀態。
- 以最近 7 天 `host_metric_samples` 的線性趨勢估算 CPU、記憶體及磁碟每日變化，並顯示樣本數與低／中／高可信度。
- 預設資源可能在 14 天內達到 85% 時建立 `rule-capacity-forecast` 系統告警；可在告警中心調整預測天數與嚴重程度，但不可刪除或改成其他監控項目。
- Worker 容器重建後，舊登錄會先顯示離線並於 10 分鐘後清除；在線判斷仍使用 30 秒心跳門檻。
- 容量預測只提供提前規劃依據，不會自動擴容、刪除資料或修改遠端 Linux。

## 1.3 第四階段：可靠性目標與營運報表

- 「可靠性報表」依 7～90 天視窗彙整中央服務與受管主機可用率，預設 SLO 為 99.5%。
- 告警事件自動計算平均確認時間（MTTA）與平均修復時間（MTTR），並和可調整目標比較。
- 管理者可調整統計視窗、可用率、MTTA 與 MTTR 目標；修改行為會寫入後端稽核鏈。
- 報表可匯出 UTF-8 CSV，方便保留每台主機與中央服務的樣本數、可用率及達標狀態。
- 本功能只分析已保存的監控與事件資料，不會修改受管 Linux 主機或自動關閉事件。

## 1.4 第五階段：排程營運報表與趨勢

- 「營運報表」保存手動、週報與月報，包含 SLO、MTTA、MTTR、維運任務、高頻告警規則及主機排行。
- 排程可設定每週星期、每月日期及 UTC 產生時間；同一期間的週報／月報不會重複建立。
- 可選擇在產生後透過目前已啟用的 Telegram、LINE、SMS 或 Webhook 管道發送摘要，失敗沿用通知重試機制。
- 每筆歷史報表可在 UI 查看證據摘要並下載 UTF-8 CSV；產生及政策異動寫入後端稽核鏈。
- 報表是唯讀快照，不會自動修改 SLO、告警、維運任務或遠端 Linux。

## 1.5 第六階段：SMTP Email 通知

- 告警、恢復、備份失敗、測試通知與營運報表可透過 SMTP Email 發送，支援逗號分隔多位收件者。
- SMTP 密碼只由 `.env` 注入 API 容器；UI 與資料庫只顯示 SMTP 主機及收件者數量。
- Email 失敗沿用通知重試佇列與傳送歷史；可在告警中心使用「發送測試通知」驗證。

## 1.6 第七階段：通知治理

- 支援全域 UTC 安靜時段，以及指定主機、告警規則或全域範圍的定時靜音。
- 重大告警預設略過安靜時段；明確建立的靜音規則仍會抑制符合範圍的通知。
- 每次抑制會在通知歷史留下管道、原因與時間，不會進入失敗重試。

## 1.7 第八階段：告警升級與再次提醒

- 仍在 firing 且未確認的告警會依警告／重大間隔再次提醒；確認、恢復或達最大次數後停止。
- 重大告警超過指定時間會使用升級標題；每次提醒以事件與序號保證不重複。
- 再次提醒仍套用靜音與安靜時段，並保存成功、失敗、抑制或無通知管道狀態。

## 1.8 第九階段：長期監控彙總

- 每 5 分鐘更新每小時與每日 CPU、記憶體、磁碟、可用率及失敗服務彙總。
- 告警中心可切換 24 小時、7 天、30 天與 90 天；長期範圍使用小時／每日資料降低查詢量。
- 小時彙總保留 120 天，每日彙總保留 400 天；原始樣本仍依既有保存政策清理。

## 2.8 告警負責人工作佇列

- 集中列出作用中與未指派告警，並顯示各平台使用者目前負責數量。
- 管理者可指派、轉派或解除負責人；值班自動指派仍保留且不會覆蓋後續人工決策。
- 每次異動保存原負責人、新負責人、操作人、備註與時間，供事故責任鏈與稽核查詢。

## 2.9 告警責任 SLA

- 分別設定警告與重大告警的確認期限，以及未指派事件容許時間。
- 顯示作用中、即將逾期、已逾期及未指派逾時數量，協助值班人員排序處理優先級。
- 責任政策由具告警管理權限的人員調整，所有異動保存於稽核鏈。

## 3.0 責任 SLA 自動升級

- 背景 Worker 每分鐘偵測未指派或未確認逾期事件，透過既有路由、靜音、維護時段與通知管道派送。
- 同一事件只發送一次責任升級，防止逾期檢查本身形成通知風暴。
- 保存通知結果與恢復時間，供值班交接和事故回溯。

## 3.1 值班交接與代理

- 支援目前或未來班次因請假、換班或跨班支援正式轉交代理人。
- 交接完成後新告警立即依更新後班次自動指派，既有告警負責人不受影響。
- 永久保存原值班人、代理人、交接原因、操作人與時間。

## 3.2 值班覆蓋率與缺口

- 合併重疊班次，計算未來指定小時內的實際值班覆蓋率。
- 列出無人值班缺口的開始、結束與持續時間，方便補班。
- 可設定觀察範圍與覆蓋目標，未達標時以醒目狀態提示。

## 3.3 值班缺口自動通知

- 缺口進入設定的提前提醒範圍後，經由既有通知路由與治理機制發送一次提醒。
- 使用穩定指紋避免重複提醒；新增班次補齊缺口後保存恢復時間。
- UI 可啟停功能、調整提前提醒時數並查看完整歷史。

## 3.4 週期值班範本

- 支援每日、每週與每兩週重複班次，設定首次開始、班次長度與未來展開範圍。
- 建立時立即產生班次，背景 Worker 每小時補齊，唯一索引防止重複。
- 若與既有班次重疊則安全略過；刪除範本保留歷史班次，只移除未開始班次。

## 3.5 值班負載與公平性

- 統計每位啟用使用者的未來排班時數及相對平均值偏離比例。
- 結合目前告警、交接流入／流出與責任 SLA 逾期數，避免只看排班時數。
- 可調整觀察期間與不均衡門檻，明顯失衡者會醒目標示。

### 正式安裝檢查

```bash
sh deploy/check-installation.sh /home/nickc
```

### 已部署環境整合測試

```bash
export CONTROL_PLANE_TEST_URL=https://192.168.0.151:8443
export CONTROL_PLANE_TEST_USER=admin
export CONTROL_PLANE_TEST_PASSWORD='管理者密碼'
export CONTROL_PLANE_TEST_OTP='目前的六位數 MFA'
export CONTROL_PLANE_TEST_CACERT=/path/to/local-ca.crt
sh tests/run-integration.sh
```

### 設定版控

「設定版控」使用 API 容器內的本機 Git 儲存庫，資料保存在 Docker `config-history` Named Volume。新增或修改主機、告警規則、群組與密碼規則後會自動建立版本；管理者也可手動建立基準快照。快照刻意排除使用者密碼雜湊、SSH 私鑰、通知 Token 與其他 `.env` 敏感值。

回滾流程為「選擇版本 → 建立申請 → 另一位管理者核准或拒絕 → 輸入 `RESTORE` 執行」。申請者不能核准自己的回滾；執行前會強制建立目前設定快照，失敗時 PostgreSQL 交易會取消。回滾會恢復既有受管主機的啟用與連線設定、告警規則、自訂群組及密碼規則；不會還原密碼、Token、私鑰、系統管理員群組或遠端 Linux 內容。

## 安全原則

- AI 只負責理解、分析與提出計畫。
- 執行由確定性工具層完成，所有參數先驗證。
- 高風險操作不能由提出者自行批准。
- 所有具影響力的操作都要有驗證與回滾方案。
- 敏感值不寫入 UI 日誌、稽核日誌或 Git。

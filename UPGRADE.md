# Linux AI Control Plane 升級與回復

1. 在「平台健檢」執行「更新前檢查＋備份」，等待備份狀態成功。
2. 在中央主機建立 VirtualBox Snapshot。
3. 將新版 `.tar.gz` 放到中央主機，執行：

```bash
sh deploy/install-release.sh /home/nickc/linux-ai-agent-v1.0.0.tar.gz /home/nickc
```

腳本會執行環境檢查、保存目前程式快照、重建容器、套用 checksum migration，並驗證 HTTPS/HTTP health。若建置或健康檢查失敗，會自動從快照覆蓋回原版本並重建。

資料庫回復應使用「備份管理」中已通過還原演練的 DB 備份；程式回復與資料庫回復是兩個獨立步驟。不得把舊版程式直接接到不相容的新 Schema。

from __future__ import annotations

import asyncio
import base64
import csv
import hashlib
import hmac
import ipaddress
import io
import json
import os
import re
import secrets
import shlex
import shlex
import subprocess
import smtplib
import threading
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import asyncssh
import pyotp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, Response
import psycopg
from psycopg.rows import dict_row
from pydantic import BaseModel, Field

from app.audit import integrity_hash
from app.migrations import apply_migrations, migration_status

APP_VERSION = os.getenv("APP_VERSION", "2.0.0").strip() or "2.0.0"
MIN_COMPATIBLE_SCHEMA = "012"

INVENTORY_PATH = Path(os.getenv("INVENTORY_PATH", "/app/config/inventory.json"))
DATABASE_HOST = os.getenv("PGHOST", "postgres")
DATABASE_PORT = int(os.getenv("PGPORT", "5432"))
DATABASE_NAME = os.getenv("PGDATABASE", "linux_ai")
DATABASE_USER = os.getenv("PGUSER", "linux_ai")
DATABASE_PASSWORD = os.getenv("PGPASSWORD", "change-me")
DATABASE_CONNECT_TIMEOUT = int(os.getenv("PGCONNECT_TIMEOUT", "5"))
SSH_KEY_PATH = os.getenv("SSH_KEY_PATH", "/run/ssh/linux_ai_agent")
KNOWN_HOSTS_PATH = os.getenv("KNOWN_HOSTS_PATH", "/run/ssh/known_hosts")
PROBE_TTL_SECONDS = int(os.getenv("PROBE_TTL_SECONDS", "8"))
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin").strip()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
ADMIN_DISPLAY_NAME = os.getenv("ADMIN_DISPLAY_NAME", "平台管理員").strip()
SESSION_HOURS = int(os.getenv("SESSION_HOURS", "8"))
SESSION_COOKIE = "linux_ai_session"
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
MONITOR_INTERVAL_SECONDS = max(15, int(os.getenv("MONITOR_INTERVAL_SECONDS", "60")))
METRIC_RETENTION_DAYS = max(1, int(os.getenv("METRIC_RETENTION_DAYS", "30")))
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()
LINE_CHANNEL_ACCESS_TOKEN = os.getenv("LINE_CHANNEL_ACCESS_TOKEN", "").strip()
LINE_TARGET_ID = os.getenv("LINE_TARGET_ID", "").strip()
SMS_GATEWAY_URL = os.getenv("SMS_GATEWAY_URL", "").strip()
SMS_GATEWAY_TOKEN = os.getenv("SMS_GATEWAY_TOKEN", "").strip()
SMS_TO_NUMBER = os.getenv("SMS_TO_NUMBER", "").strip()
ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", "").strip()
ALERT_WEBHOOK_TOKEN = os.getenv("ALERT_WEBHOOK_TOKEN", "").strip()
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USERNAME).strip()
SMTP_TO = [item.strip() for item in os.getenv("SMTP_TO", "").split(",") if item.strip()]
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
NOTIFICATION_TIMEOUT_SECONDS = max(
    2, min(int(os.getenv("NOTIFICATION_TIMEOUT_SECONDS", "8")), 30)
)
BACKUP_INTERVAL_HOURS = max(1, int(os.getenv("BACKUP_INTERVAL_HOURS", "24")))
BACKUP_RETENTION_DAYS = max(1, int(os.getenv("BACKUP_RETENTION_DAYS", "7")))
WATCHDOG_SHARED_TOKEN = os.getenv("WATCHDOG_SHARED_TOKEN", "").strip()
WATCHDOG_STALE_SECONDS = max(60, int(os.getenv("WATCHDOG_STALE_SECONDS", "120")))
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5.6-luna").strip() or "gpt-5.6-luna"
OPENAI_TIMEOUT_SECONDS = max(10, min(int(os.getenv("OPENAI_TIMEOUT_SECONDS", "60")), 180))
AI_DIAGNOSTIC_MODE = os.getenv("AI_DIAGNOSTIC_MODE", "local").strip().lower()
if AI_DIAGNOSTIC_MODE not in {"local", "openai"}:
    AI_DIAGNOSTIC_MODE = "local"
LOCAL_DIAGNOSTIC_MODEL = "local-rules-v1"
CONFIG_REPO_PATH = Path(os.getenv("CONFIG_REPO_PATH", "/var/lib/linux-ai-config"))
BACKUP_STORAGE_PATH = Path(os.getenv("BACKUP_STORAGE_PATH", "/backups"))
UBUNTU_SECURITY_API_URL = os.getenv(
    "UBUNTU_SECURITY_API_URL", "https://ubuntu.com/security/notices.json"
).strip()
UBUNTU_SECURITY_CACHE_SECONDS = max(
    300, int(os.getenv("UBUNTU_SECURITY_CACHE_SECONDS", "3600"))
)
CENTRAL_LOG_INTERVAL_SECONDS = max(60, int(os.getenv("CENTRAL_LOG_INTERVAL_SECONDS", "300")))
CENTRAL_LOG_RETENTION_DAYS = max(1, int(os.getenv("CENTRAL_LOG_RETENTION_DAYS", "30")))
MAINTENANCE_APPROVAL_TTL_MINUTES = max(
    5, min(int(os.getenv("MAINTENANCE_APPROVAL_TTL_MINUTES", "60")), 1440)
)
PLATFORM_MASTER_KEY = os.getenv("PLATFORM_MASTER_KEY", "").strip()
API_RATE_LIMIT_PER_MINUTE = max(30, int(os.getenv("API_RATE_LIMIT_PER_MINUTE", "240")))
SSH_MAX_CONCURRENCY = max(1, min(int(os.getenv("SSH_MAX_CONCURRENCY", "8")), 64))

SAFE_RUNBOOKS: dict[str, dict[str, Any]] = {
    "system_overview": {
        "title": "系統健康總覽",
        "description": "查看 uptime、記憶體、根目錄磁碟與失敗服務。",
        "command": "uptime; free -h; df -h /; systemctl --failed --no-pager",
        "risk": "low",
        "approval_policy": "single",
        "verification": "SSH 指令成功結束並保存輸出雜湊。",
    },
    "failed_services": {
        "title": "失敗服務檢查",
        "description": "列出目前失敗的 systemd 服務與完整狀態。",
        "command": "systemctl --failed --no-pager --full",
        "risk": "low",
        "approval_policy": "single",
        "verification": "SSH 指令成功結束並保存輸出雜湊。",
    },
    "resource_processes": {
        "title": "高資源程序檢查",
        "description": "依 CPU 排序查看前 15 個程序，不終止任何程序。",
        "command": "ps -eo pid,user,comm,%cpu,%mem --sort=-%cpu | head -n 16",
        "risk": "medium",
        "approval_policy": "independent",
        "verification": "SSH 指令成功結束並保存輸出雜湊；申請者不得自行核准。",
    },
    "disk_usage": {
        "title": "磁碟使用分析",
        "description": "查看根目錄與 /var 第一層空間分布。",
        "command": "df -h /; findmnt /; du -x -d1 /var 2>/dev/null | sort -n | tail -n 15",
        "risk": "medium",
        "approval_policy": "independent",
        "verification": "SSH 指令成功結束並保存輸出雜湊；申請者不得自行核准。",
    },
    "available_updates": {
        "title": "可更新套件檢查",
        "description": "只讀取目前套件索引，不執行更新。",
        "command": "apt list --upgradable 2>/dev/null | head -n 80",
        "risk": "low",
        "approval_policy": "single",
        "verification": "SSH 指令成功結束並保存輸出雜湊。",
    },
    "reset_failed_services": {
        "title": "重設失敗服務狀態",
        "description": "清除 systemd 已修復服務的 failed 標記，不會啟停服務。",
        "precheck": "systemctl --failed --no-pager --full",
        "command": "sudo -n /usr/bin/systemctl reset-failed",
        "verify_command": "systemctl --failed --no-pager --full",
        "timeout": 30,
        "mutating": True,
        "risk": "medium", "approval_policy": "independent",
        "verification": "再次讀取 systemctl --failed，並保存前後輸出與雜湊。",
    },
    "refresh_package_index": {
        "title": "更新 APT 套件索引",
        "description": "執行 apt-get update，只更新套件索引，不安裝套件。",
        "precheck": "find /var/lib/apt/lists -maxdepth 1 -type f -printf '%TY-%Tm-%Td %TH:%TM %f\\n' 2>/dev/null | sort | tail -n 10",
        "command": "sudo -n /usr/bin/apt-get update",
        "verify_command": "apt list --upgradable 2>/dev/null | head -n 80",
        "timeout": 300,
        "mutating": True,
        "risk": "high", "approval_policy": "independent",
        "verification": "APT 成功結束後重新列出待更新套件並保存證據。",
    },
    "install_security_updates": {
        "title": "安裝可用安全更新",
        "description": "以 unattended-upgrade 僅安裝安全來源允許的更新。",
        "precheck": "apt list --upgradable 2>/dev/null | head -n 80",
        "command": "sudo -n /usr/bin/unattended-upgrade -d",
        "verify_command": "apt list --upgradable 2>/dev/null | head -n 80; if test -e /var/run/reboot-required; then echo REBOOT_REQUIRED; else echo REBOOT_NOT_REQUIRED; fi",
        "timeout": 1800,
        "mutating": True,
        "risk": "high", "approval_policy": "independent",
        "verification": "工具成功結束並檢查 reboot-required；輸出與雜湊永久保存。",
    },
}

# Alert-originated tasks remain constrained to the same fixed Runbook allowlist.
# The mapping narrows choices further according to the observed condition.
ALERT_RUNBOOKS: dict[str, tuple[str, ...]] = {
    "rule-host-offline": ("system_overview",),
    "rule-cpu-high": ("resource_processes", "system_overview"),
    "rule-ram-high": ("resource_processes", "system_overview"),
    "rule-disk-high": ("disk_usage", "system_overview"),
    "rule-service-failed": ("failed_services", "system_overview", "reset_failed_services"),
    "rule-log-collection": ("system_overview",),
    "rule-asset-drift": ("system_overview",),
    "rule-security-updates": ("available_updates", "refresh_package_index", "install_security_updates"),
    "rule-security-baseline": ("system_overview",),
}

MAINTENANCE_SUDO_COMMANDS = {
    "/usr/bin/systemctl reset-failed",
    "/usr/bin/apt-get update",
    "/usr/bin/unattended-upgrade -d",
}

REMOTE_PROBE = r'''
import json
import os
import shutil
import subprocess
import time

def cpu_sample():
    with open('/proc/stat', encoding='utf-8') as handle:
        values = [int(value) for value in handle.readline().split()[1:]]
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return sum(values), idle

total_a, idle_a = cpu_sample()
time.sleep(0.2)
total_b, idle_b = cpu_sample()
delta_total = max(total_b - total_a, 1)
cpu_percent = round(100 * (1 - ((idle_b - idle_a) / delta_total)), 1)

mem = {}
with open('/proc/meminfo', encoding='utf-8') as handle:
    for line in handle:
        key, value = line.split(':', 1)
        mem[key] = int(value.strip().split()[0]) * 1024
mem_total = mem.get('MemTotal', 0)
mem_available = mem.get('MemAvailable', 0)
ram_percent = round(100 * (mem_total - mem_available) / mem_total, 1) if mem_total else 0

disk = shutil.disk_usage('/')
disk_percent = round(100 * disk.used / disk.total, 1) if disk.total else 0

os_name = 'Linux'
try:
    with open('/etc/os-release', encoding='utf-8') as handle:
        values = dict(line.rstrip().split('=', 1) for line in handle if '=' in line)
    os_name = values.get('PRETTY_NAME', 'Linux').strip('"')
except OSError:
    pass

failed_output = subprocess.run(
    ['systemctl', '--failed', '--no-legend', '--plain', '--no-pager'],
    capture_output=True,
    text=True,
    timeout=4,
    check=False,
).stdout.strip()
failed_services = [line for line in failed_output.splitlines() if line.strip()]

print(json.dumps({
    'hostname': os.uname().nodename,
    'os': os_name,
    'cpu': cpu_percent,
    'ram': ram_percent,
    'disk': disk_percent,
    'load': list(os.getloadavg()),
    'uptime_seconds': float(open('/proc/uptime', encoding='utf-8').read().split()[0]),
    'memory_total': mem_total,
    'memory_available': mem_available,
    'disk_total': disk.total,
    'disk_free': disk.free,
    'failed_services': failed_services,
}, ensure_ascii=False))
'''

REMOTE_IDENTITY = r'''
import json
import os
import subprocess

fingerprint = subprocess.run(
    ['ssh-keygen', '-lf', '/etc/ssh/ssh_host_ed25519_key.pub'],
    capture_output=True,
    text=True,
    timeout=4,
    check=False,
).stdout.strip()

print(json.dumps({
    'hostname': os.uname().nodename,
    'machine_id': open('/etc/machine-id', encoding='utf-8').read().strip(),
    'host_key_fingerprint': fingerprint.split()[1] if len(fingerprint.split()) >= 2 else '',
}))
'''

REMOTE_STANDBY_PREFLIGHT = r'''
import json
import os
import shutil
import subprocess

def output(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=6, check=False)
    return result.stdout.strip() if result.returncode == 0 else ''

mem_kib = 0
with open('/proc/meminfo', encoding='utf-8') as stream:
    for line in stream:
        if line.startswith('MemTotal:'):
            mem_kib = int(line.split()[1])
            break
disk = shutil.disk_usage('/')
listeners = output(['ss', '-ltn'])
docker_version = output(['docker', '--version']) if shutil.which('docker') else ''
compose_version = output(['docker', 'compose', 'version']) if docker_version else ''
print(json.dumps({
    'hostname': os.uname().nodename,
    'cpuCount': os.cpu_count() or 0,
    'memoryBytes': mem_kib * 1024,
    'diskFreeBytes': disk.free,
    'dockerVersion': docker_version,
    'composeVersion': compose_version,
    'gitVersion': output(['git', '--version']) if shutil.which('git') else '',
    'port5432Free': ':5432 ' not in listeners and ':5432\n' not in listeners,
    'port8080Free': ':8080 ' not in listeners and ':8080\n' not in listeners,
}))
'''

REMOTE_PATCH_STATUS = r'''
import json
import os
import re
import shutil
import subprocess

def output(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
    return result.stdout.strip()

raw_updates = output(['apt', 'list', '--upgradable'])
packages = []
for line in raw_updates.splitlines():
    line = line.strip()
    if not line or line.lower().startswith('listing') or '/' not in line:
        continue
    parts = line.split()
    package_name = parts[0].split('/', 1)[0]
    candidate = parts[1] if len(parts) > 1 else ''
    architecture = parts[2] if len(parts) > 2 else ''
    match = re.search(r'upgradable from:\s*([^\]]+)', line)
    packages.append({
        'name': package_name,
        'candidateVersion': candidate,
        'architecture': architecture,
        'currentVersion': match.group(1).strip() if match else '',
        'securityHint': False,
        'securityProvider': '',
    })

pro_security = {}
if shutil.which('pro'):
    try:
        pro_payload = json.loads(output(['pro', 'api', 'u.pro.packages.updates.v1']))
        if isinstance(pro_payload, dict) and isinstance(pro_payload.get('data'), dict):
            pro_payload = pro_payload['data']
        for update in pro_payload.get('updates', []) if isinstance(pro_payload, dict) else []:
            provider = str(update.get('provided_by', '')).lower()
            status = str(update.get('status', '')).lower()
            if provider and ('security' in provider or provider.startswith('esm-') or 'security' in status):
                pro_security[str(update.get('package', ''))] = provider or status
    except (ValueError, TypeError):
        pass

for package in packages:
    provider = pro_security.get(package['name'], '')
    if not provider:
        policy = output(['apt-cache', 'policy', package['name']]).lower()
        if '-security' in policy or 'esm-infra' in policy or 'esm-apps' in policy:
            provider = 'apt-security-pocket'
    package['securityHint'] = bool(provider)
    package['securityProvider'] = provider

os_codename = ''
try:
    with open('/etc/os-release', encoding='utf-8') as stream:
        for line in stream:
            if line.startswith('VERSION_CODENAME='):
                os_codename = line.split('=', 1)[1].strip().strip('"')
                break
except OSError:
    pass

unattended = output(['systemctl', 'is-enabled', 'unattended-upgrades.service']) or 'unknown'
reboot_packages = []
try:
    with open('/var/run/reboot-required.pkgs', encoding='utf-8') as stream:
        reboot_packages = [line.strip() for line in stream if line.strip()]
except OSError:
    pass

print(json.dumps({
    'hostname': os.uname().nodename,
    'osCodename': os_codename,
    'kernelVersion': os.uname().release,
    'rebootRequired': os.path.exists('/var/run/reboot-required'),
    'rebootPackages': reboot_packages[:50],
    'unattendedUpgrades': unattended,
    'pendingCount': len(packages),
    'packages': packages[:200],
    'truncated': len(packages) > 200,
}, ensure_ascii=False))
'''

REMOTE_ASSET_INVENTORY = r'''
import json
import os
import subprocess

def output(command, timeout=15):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        return result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ''

def lines(command, limit=500):
    values = {' '.join(line.split()) for line in output(command).splitlines() if line.strip()}
    return sorted(values)[:limit]

os_name = 'Linux'
try:
    with open('/etc/os-release', encoding='utf-8') as stream:
        values = dict(line.rstrip().split('=', 1) for line in stream if '=' in line)
        os_name = values.get('PRETTY_NAME', 'Linux').strip('"')
except OSError:
    pass

interactive_users = []
try:
    with open('/etc/passwd', encoding='utf-8') as stream:
        for raw in stream:
            parts = raw.rstrip().split(':')
            if len(parts) < 7:
                continue
            name, uid, shell = parts[0], int(parts[2]), parts[6]
            if (uid == 0 or uid >= 1000) and shell not in {'/usr/sbin/nologin', '/sbin/nologin', '/bin/false', '/usr/bin/false'}:
                interactive_users.append('%s:%s:%s' % (name, uid, shell))
except (OSError, ValueError):
    pass

packages = output(['dpkg-query', '-W', '-f=${binary:Package}\\n'])
print(json.dumps({
    'hostname': os.uname().nodename,
    'osName': os_name,
    'kernelVersion': os.uname().release,
    'interfaces': lines(['ip', '-brief', 'address'], 100),
    'listeningPorts': lines(['ss', '-H', '-lntu'], 500),
    'enabledServices': lines(['systemctl', 'list-unit-files', '--type=service', '--state=enabled', '--no-legend', '--no-pager'], 500),
    'interactiveUsers': sorted(interactive_users)[:200],
    'installedPackageCount': len([line for line in packages.splitlines() if line.strip()]),
}, ensure_ascii=False))
'''

REMOTE_SECURITY_BASELINE = r'''
import glob
import json
import os
import stat
import subprocess

def command_output(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False)
        return result.stdout.strip(), result.returncode
    except (OSError, subprocess.TimeoutExpired):
        return '', 127

def check(key, label, status, evidence, recommendation=''):
    return {'key': key, 'label': label, 'status': status, 'evidence': evidence, 'recommendation': recommendation}

ssh_values = {}
for path in ['/etc/ssh/sshd_config'] + sorted(glob.glob('/etc/ssh/sshd_config.d/*.conf')):
    try:
        with open(path, encoding='utf-8', errors='replace') as stream:
            for raw in stream:
                line = raw.strip()
                if not line or line.startswith('#') or line.lower().startswith('match '):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    ssh_values[parts[0].lower()] = parts[1].split('#', 1)[0].strip().lower()
    except OSError:
        pass

checks = []
root_login = ssh_values.get('permitrootlogin')
checks.append(check(
    'ssh-root-login', 'SSH 禁止 Root 密碼登入',
    'pass' if root_login in {'no', 'prohibit-password', 'without-password', 'forced-commands-only'} else ('warn' if root_login is None else 'fail'),
    '未明確設定（使用 OpenSSH 預設）' if root_login is None else 'PermitRootLogin ' + root_login,
    '建議明確設定 PermitRootLogin no' if root_login is None else ('設定 PermitRootLogin no' if root_login == 'yes' else ''),
))
password_auth = ssh_values.get('passwordauthentication')
checks.append(check(
    'ssh-password-auth', 'SSH 使用金鑰而非密碼',
    'pass' if password_auth == 'no' else ('warn' if password_auth is None else 'fail'),
    '未明確設定（使用 OpenSSH 預設）' if password_auth is None else 'PasswordAuthentication ' + password_auth,
    '確認金鑰登入後，再明確設定 PasswordAuthentication no' if password_auth != 'no' else '',
))

ufw_enabled, _ = command_output(['systemctl', 'is-enabled', 'ufw.service'])
checks.append(check('ufw', '主機防火牆', 'pass' if ufw_enabled == 'enabled' else 'warn',
                    'ufw.service ' + (ufw_enabled or 'unknown'), '依網路設計評估啟用 UFW 並限制管理來源'))

apparmor = ''
try:
    apparmor = open('/sys/module/apparmor/parameters/enabled', encoding='utf-8').read().strip()
except OSError:
    pass
checks.append(check('apparmor', 'AppArmor', 'pass' if apparmor.upper().startswith('Y') else 'fail',
                    'kernel parameter: ' + (apparmor or 'not available'), '啟用 AppArmor 核心模組與 profiles'))

ntp, _ = command_output(['timedatectl', 'show', '-p', 'NTPSynchronized', '--value'])
checks.append(check('time-sync', '時間同步', 'pass' if ntp.lower() == 'yes' else 'fail',
                    'NTPSynchronized=' + (ntp or 'unknown'), '確認 systemd-timesyncd 或其他 NTP 服務正常'))

unattended, _ = command_output(['systemctl', 'is-enabled', 'unattended-upgrades.service'])
checks.append(check('unattended-upgrades', '自動安全更新', 'pass' if unattended == 'enabled' else 'warn',
                    'unattended-upgrades.service ' + (unattended or 'unknown'), '評估啟用 unattended-upgrades'))

auditd, _ = command_output(['systemctl', 'is-active', 'auditd.service'])
checks.append(check('auditd', 'Linux auditd', 'pass' if auditd == 'active' else 'warn',
                    'auditd.service ' + (auditd or 'not installed'), '需要主機層命令稽核時安裝並啟用 auditd'))

try:
    shadow = os.stat('/etc/shadow')
    shadow_mode = stat.S_IMODE(shadow.st_mode)
    shadow_ok = shadow.st_uid == 0 and shadow_mode & 0o007 == 0
    checks.append(check('shadow-permissions', '/etc/shadow 權限', 'pass' if shadow_ok else 'fail',
                        'owner uid=%s mode=%04o' % (shadow.st_uid, shadow_mode), '確保 root 擁有且 other 沒有權限'))
except OSError as error:
    checks.append(check('shadow-permissions', '/etc/shadow 權限', 'fail', str(error), '檢查檔案是否存在'))

authorized = os.path.expanduser('~/.ssh/authorized_keys')
try:
    auth_stat = os.stat(authorized)
    auth_mode = stat.S_IMODE(auth_stat.st_mode)
    auth_ok = auth_mode & 0o077 == 0
    checks.append(check('authorized-keys', '管理帳號 authorized_keys', 'pass' if auth_ok else 'fail',
                        '%s mode=%04o' % (authorized, auth_mode), '執行 chmod 600 ~/.ssh/authorized_keys'))
except OSError as error:
    checks.append(check('authorized-keys', '管理帳號 authorized_keys', 'fail', str(error), '確認中央公鑰已正確部署'))

# Traceable, read-only CIS-aligned laboratory controls. These identifiers are
# local mappings and intentionally do not claim official CIS certification.
sysctl_expectations = [
    ('LAB-CIS-3.1.1', 'net.ipv4.ip_forward', '0', '停用 IPv4 forwarding（非路由器主機）'),
    ('LAB-CIS-3.2.1', 'net.ipv4.conf.all.accept_redirects', '0', '拒絕 ICMP redirects'),
    ('LAB-CIS-3.2.2', 'net.ipv4.conf.all.send_redirects', '0', '不傳送 ICMP redirects'),
    ('LAB-CIS-3.3.1', 'net.ipv4.conf.all.accept_source_route', '0', '拒絕 source routed packets'),
    ('LAB-CIS-3.3.2', 'net.ipv4.conf.all.log_martians', '1', '記錄異常來源封包'),
]
for rule, key, expected, label in sysctl_expectations:
    value, rc = command_output(['sysctl', '-n', key])
    checks.append(check(rule, label, 'pass' if rc == 0 and value == expected else 'fail',
                        '%s=%s (expected %s)' % (key, value or 'unavailable', expected),
                        '在 /etc/sysctl.d/ 建立受版控設定並經核准套用'))

for rule, service, label in [
    ('LAB-CIS-2.1.1', 'avahi-daemon.service', '停用不必要的 Avahi'),
    ('LAB-CIS-2.1.2', 'cups.service', '停用不必要的列印服務'),
    ('LAB-CIS-2.1.3', 'ModemManager.service', '伺服器停用 ModemManager'),
]:
    state, _ = command_output(['systemctl', 'is-enabled', service])
    checks.append(check(rule, label, 'pass' if state in {'disabled', 'masked', 'not-found', ''} else 'warn',
                        '%s %s' % (service, state or 'not-found'), '確認無業務需求後停用或 mask'))

mounts, _ = command_output(['findmnt', '-rn', '-o', 'TARGET,OPTIONS'])
tmp_line = next((line for line in mounts.splitlines() if line.split(None, 1)[0] == '/tmp'), '')
tmp_ok = tmp_line and all(flag in tmp_line.split(None, 1)[-1].split(',') for flag in ('nodev', 'nosuid'))
checks.append(check('LAB-CIS-1.1.2', '/tmp 掛載限制', 'pass' if tmp_ok else 'warn', tmp_line or '/tmp 未獨立掛載',
                    '評估對 /tmp 設定 nodev,nosuid；變更前建立快照'))

pw_min, _ = command_output(['sh', '-c', "grep -E '^PASS_MIN_DAYS' /etc/login.defs | awk '{print $2}'"])
checks.append(check('LAB-CIS-5.4.1', '密碼最短使用天數', 'pass' if pw_min.isdigit() and int(pw_min) >= 1 else 'warn',
                    'PASS_MIN_DAYS=' + (pw_min or 'unset'), '依組織政策設定本機帳號密碼生命週期'))

points = {'pass': 100, 'warn': 50, 'fail': 0}
score = round(sum(points[item['status']] for item in checks) / len(checks)) if checks else 0
print(json.dumps({'hostname': os.uname().nodename, 'score': score, 'checks': checks}, ensure_ascii=False))
'''


class AuditEvent(BaseModel):
    id: str | None = None
    occurred_at: datetime | None = Field(default=None, alias="occurredAt")
    session_id: str = Field(default="unknown-session", alias="sessionId")
    actor_id: str = Field(default="anonymous", alias="actorId")
    actor_name: str = Field(default="未知使用者", alias="actorName")
    event_type: str = Field(default="ui.unknown", alias="eventType")
    page: str = "unknown"
    action: str = "unknown action"
    target: str | None = None
    result: str = "recorded"

    model_config = {"populate_by_name": True}


class AuditBatch(BaseModel):
    events: list[AuditEvent]


class HostCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    address: str = Field(min_length=3, max_length=64)
    port: int = Field(default=22, ge=1, le=65535)
    user: str = Field(default="linux-agent", min_length=1, max_length=32)
    group: str = Field(default="LAB / MANAGED", min_length=1, max_length=80)


class BootstrapInspect(BaseModel):
    address: str = Field(min_length=3, max_length=64)
    port: int = Field(default=22, ge=1, le=65535)
    admin_user: str = Field(alias="adminUser", min_length=1, max_length=32)
    password: str = Field(min_length=1, max_length=256)

    model_config = {"populate_by_name": True}


class BootstrapConfirm(BootstrapInspect):
    name: str = Field(min_length=1, max_length=80)
    group: str = Field(default="LAB / MANAGED", min_length=1, max_length=80)
    expected_fingerprint: str = Field(alias="expectedFingerprint", min_length=8, max_length=160)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    otp: str = Field(default="", max_length=16)


class MfaVerifyRequest(BaseModel):
    code: str = Field(min_length=6, max_length=16)


class SshRetirementDecision(BaseModel):
    note: str = Field(default="", max_length=500)


class SecretWriteRequest(BaseModel):
    name: str = Field(min_length=2, max_length=80, pattern=r"^[A-Za-z0-9._-]+$")
    value: str = Field(min_length=1, max_length=8192)
    purpose: str = Field(default="general", min_length=2, max_length=80)


class IdentityProviderUpdate(BaseModel):
    provider_type: str = Field(alias="providerType", pattern="^(oidc|ldap)$")
    enabled: bool = False
    display_name: str = Field(alias="displayName", min_length=2, max_length=80)
    configuration: dict[str, Any] = Field(default_factory=dict)

    model_config = {"populate_by_name": True}


class AuthSecurityPolicyUpdate(BaseModel):
    max_failed_attempts: int = Field(alias="maxFailedAttempts", ge=3, le=10)
    lockout_minutes: int = Field(alias="lockoutMinutes", ge=1, le=1440)
    event_retention_days: int = Field(alias="eventRetentionDays", ge=30, le=365)
    require_mfa_admins: bool = Field(alias="requireMfaAdmins", default=False)

    model_config = {"populate_by_name": True}


class PatchScanRequest(BaseModel):
    host_id: str | None = Field(default=None, alias="hostId", max_length=100)

    model_config = {"populate_by_name": True}


class SecurityBaselineScanRequest(PatchScanRequest):
    pass


class AssetInventoryPolicyUpdate(BaseModel):
    enabled: bool
    interval_hours: int = Field(alias="intervalHours", ge=1, le=168)
    notify_drift: bool = Field(alias="notifyDrift")

    model_config = {"populate_by_name": True}


class PatchInventoryPolicyUpdate(BaseModel):
    enabled: bool
    interval_hours: int = Field(alias="intervalHours", ge=1, le=168)
    security_threshold: int = Field(alias="securityThreshold", ge=1, le=1000)
    notify_security_updates: bool = Field(alias="notifySecurityUpdates")

    model_config = {"populate_by_name": True}


class SecurityBaselinePolicyUpdate(BaseModel):
    enabled: bool
    interval_hours: int = Field(alias="intervalHours", ge=1, le=168)
    minimum_score: int = Field(alias="minimumScore", ge=0, le=100)
    notify_regression: bool = Field(alias="notifyRegression")

    model_config = {"populate_by_name": True}


class CentralLogPolicyUpdate(BaseModel):
    retention_days: int = Field(alias="retentionDays", ge=1, le=365)
    interval_seconds: int = Field(alias="intervalSeconds", ge=60, le=3600)
    failure_threshold: int = Field(alias="failureThreshold", ge=1, le=20)

    model_config = {"populate_by_name": True}


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    display_name: str = Field(alias="displayName", min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)
    group_id: str = Field(alias="groupId", min_length=1, max_length=80)

    model_config = {"populate_by_name": True}


class GroupCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    permissions: list[str] = Field(min_length=1, max_length=20)


class UserUpdate(BaseModel):
    display_name: str = Field(alias="displayName", min_length=1, max_length=80)
    group_id: str = Field(alias="groupId", min_length=1, max_length=80)

    model_config = {"populate_by_name": True}


class PasswordReset(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class UserLock(BaseModel):
    locked: bool


class GroupUpdate(GroupCreate):
    pass


class PasswordPolicyUpdate(BaseModel):
    min_length: int = Field(alias="minLength", ge=8, le=128)
    require_upper: bool = Field(alias="requireUpper")
    require_lower: bool = Field(alias="requireLower")
    require_number: bool = Field(alias="requireNumber")
    require_special: bool = Field(alias="requireSpecial")

    model_config = {"populate_by_name": True}


class MaintenanceTaskCreate(BaseModel):
    host_id: str = Field(alias="hostId", min_length=1, max_length=100)
    runbook_id: str = Field(alias="runbookId", min_length=1, max_length=80)
    note: str = Field(default="", max_length=500)

    model_config = {"populate_by_name": True}


class AlertMaintenanceTaskCreate(BaseModel):
    runbook_id: str = Field(alias="runbookId", min_length=1, max_length=80)
    note: str = Field(default="", max_length=500)

    model_config = {"populate_by_name": True}


class MaintenanceTaskDecision(BaseModel):
    note: str = Field(default="", max_length=500)


class MaintenanceTaskExecute(BaseModel):
    confirmation: str = Field(default="", max_length=20)


class IncidentClose(BaseModel):
    summary: str = Field(min_length=3, max_length=2000)
    reason: str = Field(min_length=2, max_length=500)
    assignee_id: str | None = Field(default=None, alias="assigneeId", max_length=100)
    model_config = {"populate_by_name": True}


class IncidentTimelineNote(BaseModel):
    message: str = Field(min_length=2, max_length=2000)


class ReleasePreflight(BaseModel):
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$", max_length=50)


class RetentionPolicyItem(BaseModel):
    dataset: str = Field(pattern="^(alert_events|maintenance_tasks|host_metrics|automation_runs|inventory_scans|login_events|central_logs)$")
    retention_days: int = Field(alias="retentionDays", ge=1, le=3650)
    model_config = {"populate_by_name": True}


class RetentionPolicyUpdate(BaseModel):
    policies: list[RetentionPolicyItem] = Field(min_length=1, max_length=7)


class ReliabilityPolicyUpdate(BaseModel):
    window_days: int = Field(alias="windowDays", ge=7, le=90)
    availability_target: float = Field(alias="availabilityTarget", ge=90, le=100)
    mtta_target_minutes: int = Field(alias="mttaTargetMinutes", ge=1, le=1440)
    mttr_target_minutes: int = Field(alias="mttrTargetMinutes", ge=1, le=10080)

    model_config = {"populate_by_name": True}


class ReportPolicyUpdate(BaseModel):
    enabled: bool
    weekly_day: int = Field(alias="weeklyDay", ge=1, le=7)
    monthly_day: int = Field(alias="monthlyDay", ge=1, le=28)
    generate_hour_utc: int = Field(alias="generateHourUtc", ge=0, le=23)
    notify_enabled: bool = Field(alias="notifyEnabled")

    model_config = {"populate_by_name": True}

class NotificationGovernanceUpdate(BaseModel):
    quiet_enabled: bool = Field(alias="quietEnabled")
    quiet_start_hour: int = Field(alias="quietStartHour",ge=0,le=23)
    quiet_end_hour: int = Field(alias="quietEndHour",ge=0,le=23)
    critical_bypass: bool = Field(alias="criticalBypass")
    model_config={"populate_by_name":True}

class AlertSilenceCreate(BaseModel):
    name:str=Field(min_length=2,max_length=100); host_id:str|None=Field(default=None,alias="hostId",max_length=100); rule_id:str|None=Field(default=None,alias="ruleId",max_length=100)
    starts_at:datetime=Field(alias="startsAt"); ends_at:datetime=Field(alias="endsAt"); reason:str=Field(min_length=2,max_length=500)
    model_config={"populate_by_name":True}

class NotificationEscalationUpdate(BaseModel):
    enabled:bool; warning_interval_minutes:int=Field(alias="warningIntervalMinutes",ge=5,le=1440); critical_interval_minutes:int=Field(alias="criticalIntervalMinutes",ge=1,le=1440); max_reminders:int=Field(alias="maxReminders",ge=1,le=20); critical_escalate_after_minutes:int=Field(alias="criticalEscalateAfterMinutes",ge=1,le=10080)
    model_config={"populate_by_name":True}

class NotificationTestCreate(BaseModel):
    name:str=Field(min_length=2,max_length=100)
    severity:str=Field(pattern="^(warning|critical)$")
    host_id:str|None=Field(default=None,alias="hostId",max_length=100)
    rule_id:str|None=Field(default=None,alias="ruleId",max_length=100)
    delivery_requested:bool=Field(default=False,alias="deliveryRequested")
    model_config={"populate_by_name":True}

class NotificationRouteCreate(BaseModel):
    name:str=Field(min_length=2,max_length=100); enabled:bool=True; priority:int=Field(ge=1,le=9999)
    severity:str|None=Field(default=None,pattern="^(warning|critical)$"); host_id:str|None=Field(default=None,alias="hostId",max_length=100); rule_id:str|None=Field(default=None,alias="ruleId",max_length=100)
    channels:list[str]=Field(min_length=1,max_length=5); title_template:str=Field(alias="titleTemplate",min_length=2,max_length=200); body_template:str=Field(alias="bodyTemplate",min_length=2,max_length=2000)
    model_config={"populate_by_name":True}


class WatchdogHeartbeat(BaseModel):
    watchdog_id: str = Field(alias="watchdogId", min_length=3, max_length=80, pattern=r"^[A-Za-z0-9._-]+$")
    node_name: str = Field(alias="nodeName", min_length=1, max_length=120)
    status: str = Field(pattern="^(healthy|recovered)$")
    outage_seconds: int = Field(alias="outageSeconds", default=0, ge=0, le=31_536_000)
    version: str = Field(default="1", min_length=1, max_length=20)

    model_config = {"populate_by_name": True}


class AlertRuleCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    metric: str = Field(pattern="^(availability|cpu|ram|disk|failed_services|log_collection|asset_drift|security_updates|security_baseline|capacity_forecast)$")
    threshold: float = Field(default=1, ge=0, le=100000)
    consecutive_samples: int = Field(alias="consecutiveSamples", default=2, ge=1, le=60)
    severity: str = Field(pattern="^(warning|critical)$")

    model_config = {"populate_by_name": True}


class AlertRuleUpdate(AlertRuleCreate):
    enabled: bool = True


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_seed_inventory() -> list[dict[str, Any]]:
    with INVENTORY_PATH.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    hosts = payload.get("hosts", [])
    if not isinstance(hosts, list):
        raise RuntimeError("inventory hosts must be a list")
    return hosts


def load_inventory() -> list[dict[str, Any]]:
    with connect_db() as connection:
        rows = connection.execute(
            """
            SELECT id, name, address, port, ssh_user, group_name,
                   machine_id, host_key_fingerprint
            FROM managed_hosts
            WHERE enabled = TRUE
            ORDER BY created_at ASC, name ASC
            """
        ).fetchall()
    return [
        {
            "id": row["id"],
            "name": row["name"],
            "address": row["address"],
            "port": row["port"],
            "user": row["ssh_user"],
            "group": row["group_name"],
            "machine_id": row["machine_id"] or "",
            "host_key_fingerprint": row["host_key_fingerprint"] or "",
        }
        for row in rows
    ]


def connect_db() -> psycopg.Connection:
    return psycopg.connect(
        host=DATABASE_HOST,
        port=DATABASE_PORT,
        dbname=DATABASE_NAME,
        user=DATABASE_USER,
        password=DATABASE_PASSWORD,
        connect_timeout=DATABASE_CONNECT_TIMEOUT,
        row_factory=dict_row,
    )


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32
    )
    return f"scrypt$16384$8$1${salt.hex()}${derived.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, n, r, p, salt_hex, expected_hex = encoded.split("$", 5)
        if algorithm != "scrypt":
            return False
        actual = hashlib.scrypt(
            password.encode(),
            salt=bytes.fromhex(salt_hex),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(bytes.fromhex(expected_hex)),
        )
        return hmac.compare_digest(actual.hex(), expected_hex)
    except (ValueError, TypeError):
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def record_backend_audit(request: Request, event_type: str, action: str, target: str | None = None, result: str = "success") -> None:
    actor = request.state.user
    session_id = "backend-operation"
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        with connect_db() as connection:
            row = connection.execute("SELECT id FROM platform_sessions WHERE token_hash=%s", (token_hash(token),)).fetchone()
            if row:
                session_id = row["id"]
    save_audit_events([AuditEvent(
        id=f"evt-{uuid.uuid4().hex}", occurredAt=datetime.now(timezone.utc), sessionId=session_id,
        actorId=actor["id"], actorName=actor["displayName"], eventType=event_type,
        page="security", action=action, target=target, result=result,
    )])


def master_key() -> bytes:
    """Return a stable AES-256 key without ever persisting plaintext secrets."""
    material = PLATFORM_MASTER_KEY or f"{ADMIN_PASSWORD}\0{DATABASE_PASSWORD}\0linux-ai-local-v1"
    return hashlib.sha256(material.encode()).digest()


def encrypt_secret(value: str) -> str:
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(master_key()).encrypt(nonce, value.encode(), b"linux-ai-vault-v1")
    return base64.urlsafe_b64encode(nonce + ciphertext).decode()


def decrypt_secret(value: str) -> str:
    raw = base64.urlsafe_b64decode(value.encode())
    return AESGCM(master_key()).decrypt(raw[:12], raw[12:], b"linux-ai-vault-v1").decode()


def verify_mfa_code(user_id: str, code: str) -> bool:
    normalized = re.sub(r"\s+", "", code)
    with connect_db() as connection:
        row = connection.execute(
            "SELECT secret_encrypted, recovery_code_hashes FROM user_mfa WHERE user_id = %s AND enabled = TRUE",
            (user_id,),
        ).fetchone()
        if not row:
            return True
        if pyotp.TOTP(decrypt_secret(row["secret_encrypted"])).verify(normalized, valid_window=1):
            return True
        digest = token_hash(normalized.lower())
        recovery = list(row["recovery_code_hashes"] or [])
        if digest in recovery:
            recovery.remove(digest)
            connection.execute(
                "UPDATE user_mfa SET recovery_code_hashes = %s::jsonb, updated_at = NOW() WHERE user_id = %s",
                (json.dumps(recovery), user_id),
            )
            return True
    return False


def read_password_policy() -> dict[str, Any]:
    with connect_db() as connection:
        row = connection.execute(
            """
            SELECT min_length, require_upper, require_lower,
                   require_number, require_special, updated_at
            FROM password_policy WHERE id = 1
            """
        ).fetchone()
    return {
        "minLength": row["min_length"],
        "requireUpper": row["require_upper"],
        "requireLower": row["require_lower"],
        "requireNumber": row["require_number"],
        "requireSpecial": row["require_special"],
        "updatedAt": row["updated_at"].isoformat(),
    }


def validate_password_policy(password: str) -> None:
    policy = read_password_policy()
    missing: list[str] = []
    if len(password) < policy["minLength"]:
        missing.append(f"至少 {policy['minLength']} 個字元")
    if policy["requireUpper"] and not re.search(r"[A-Z]", password):
        missing.append("至少一個英文大寫")
    if policy["requireLower"] and not re.search(r"[a-z]", password):
        missing.append("至少一個英文小寫")
    if policy["requireNumber"] and not re.search(r"[0-9]", password):
        missing.append("至少一個數字")
    if policy["requireSpecial"] and not re.search(r"[^A-Za-z0-9]", password):
        missing.append("至少一個特殊符號")
    if missing:
        raise HTTPException(status_code=422, detail="密碼必須包含：" + "、".join(missing))


def configuration_snapshot() -> dict[str, Any]:
    """Return versionable control-plane settings without secrets or password hashes."""
    with connect_db() as connection:
        hosts = connection.execute(
            """SELECT id, name, address, port, ssh_user, group_name, enabled
               FROM managed_hosts ORDER BY id"""
        ).fetchall()
        rules = connection.execute(
            """SELECT id, name, metric, threshold, consecutive_samples, severity, enabled
               FROM alert_rules ORDER BY id"""
        ).fetchall()
        groups = connection.execute(
            """SELECT id, name, permissions, system_group
               FROM platform_groups ORDER BY id"""
        ).fetchall()
    return {
        "formatVersion": 1,
        "hosts": [
            {"id": row["id"], "name": row["name"], "address": row["address"],
             "port": row["port"], "sshUser": row["ssh_user"],
             "group": row["group_name"], "enabled": row["enabled"]}
            for row in hosts
        ],
        "alertRules": [
            {"id": row["id"], "name": row["name"], "metric": row["metric"],
             "threshold": float(row["threshold"]),
             "consecutiveSamples": row["consecutive_samples"],
             "severity": row["severity"], "enabled": row["enabled"]}
            for row in rules
        ],
        "groups": [
            {"id": row["id"], "name": row["name"],
             "permissions": sorted(list(row["permissions"])),
             "systemGroup": row["system_group"]}
            for row in groups
        ],
        "passwordPolicy": read_password_policy(),
        "runbookPolicy": [
            {"id": key, "risk": value["risk"], "approvalPolicy": value["approval_policy"]}
            for key, value in SAFE_RUNBOOKS.items()
        ],
    }


def git_config(*args: str, check: bool = True, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(CONFIG_REPO_PATH), *args], capture_output=True,
        text=True, timeout=15, check=check, env=env,
    )


def ensure_config_repository() -> None:
    CONFIG_REPO_PATH.mkdir(parents=True, exist_ok=True)
    if not (CONFIG_REPO_PATH / ".git").exists():
        subprocess.run(
            ["git", "init", "--initial-branch=main", str(CONFIG_REPO_PATH)],
            capture_output=True, text=True, timeout=15, check=True,
        )
        git_config("config", "user.name", "Linux AI Control Plane")
        git_config("config", "user.email", "control-plane@linux-ai.local")


def commit_configuration(actor: dict[str, Any] | None, reason: str, force: bool = False) -> dict[str, Any]:
    ensure_config_repository()
    content = json.dumps(configuration_snapshot(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    temporary = CONFIG_REPO_PATH / "config.json.tmp"
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(CONFIG_REPO_PATH / "config.json")
    git_config("add", "config.json")
    changed = git_config("diff", "--cached", "--quiet", check=False).returncode != 0
    if changed or force:
        actor_name = (actor or {}).get("displayName", "系統")[:80]
        actor_id = (actor or {}).get("username", "system")[:60]
        commit_env = os.environ.copy()
        commit_env.update({
            "GIT_AUTHOR_NAME": actor_name,
            "GIT_AUTHOR_EMAIL": f"{re.sub(r'[^A-Za-z0-9._-]', '-', actor_id)}@linux-ai.local",
        })
        command = ["commit"]
        if force and not changed:
            command.append("--allow-empty")
        git_config(*command, "-m", f"設定快照：{reason[:120]}", env=commit_env)
    return config_version_history(1)[0]


def config_version_history(limit: int = 50) -> list[dict[str, Any]]:
    ensure_config_repository()
    result = git_config(
        "log", f"--max-count={limit}", "--format=%H%x1f%h%x1f%an%x1f%aI%x1f%s",
        check=False,
    )
    if result.returncode != 0:
        return []
    versions = []
    for line in result.stdout.splitlines():
        parts = line.split("\x1f", 4)
        if len(parts) == 5:
            versions.append({"id": parts[0], "shortId": parts[1], "actor": parts[2],
                             "createdAt": parts[3], "message": parts[4]})
    return versions


def read_config_version(version_id: str) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{7,40}", version_id):
        raise HTTPException(status_code=422, detail="設定版本格式不正確")
    ensure_config_repository()
    result = git_config("show", f"{version_id}:config.json", check=False)
    if result.returncode != 0:
        raise HTTPException(status_code=404, detail="找不到設定版本")
    current = json.loads(result.stdout)
    parent_result = git_config("show", f"{version_id}^:config.json", check=False)
    parent = json.loads(parent_result.stdout) if parent_result.returncode == 0 else {}
    sections = [key for key in current if current.get(key) != parent.get(key)]
    return {"id": version_id, "changedSections": sections, "snapshot": current}


def restore_configuration_snapshot(snapshot: dict[str, Any], actor_id: str) -> dict[str, int]:
    if snapshot.get("formatVersion") != 1:
        raise HTTPException(status_code=422, detail="不支援的設定快照格式")
    hosts = snapshot.get("hosts", [])
    rules = snapshot.get("alertRules", [])
    groups = snapshot.get("groups", [])
    policy = snapshot.get("passwordPolicy", {})
    counts = {"hosts": 0, "alertRules": 0, "groups": 0, "passwordPolicy": 0}
    with connect_db() as connection:
        connection.execute("UPDATE managed_hosts SET enabled = FALSE")
        for item in hosts:
            row = connection.execute(
                """UPDATE managed_hosts SET name = %s, address = %s, port = %s,
                          ssh_user = %s, group_name = %s, enabled = %s
                   WHERE id = %s RETURNING id""",
                (item["name"], item["address"], int(item["port"]), item["sshUser"],
                 item["group"], bool(item["enabled"]), item["id"]),
            ).fetchone()
            if row:
                counts["hosts"] += 1
        connection.execute("UPDATE alert_rules SET enabled = FALSE, updated_at = NOW()")
        for item in rules:
            connection.execute(
                """INSERT INTO alert_rules (
                       id, name, metric, threshold, consecutive_samples, severity,
                       enabled, created_by
                   ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (id) DO UPDATE SET
                       name = EXCLUDED.name, metric = EXCLUDED.metric,
                       threshold = EXCLUDED.threshold,
                       consecutive_samples = EXCLUDED.consecutive_samples,
                       severity = EXCLUDED.severity, enabled = EXCLUDED.enabled,
                       updated_at = NOW()""",
                (item["id"], item["name"], item["metric"], float(item["threshold"]),
                 int(item["consecutiveSamples"]), item["severity"],
                 bool(item["enabled"]), actor_id),
            )
            counts["alertRules"] += 1
        for item in groups:
            if item.get("systemGroup") or item.get("id") == "administrators":
                continue
            connection.execute(
                """INSERT INTO platform_groups (id, name, permissions, system_group)
                   VALUES (%s, %s, %s::jsonb, FALSE)
                   ON CONFLICT (id) DO UPDATE SET
                       name = EXCLUDED.name, permissions = EXCLUDED.permissions""",
                (item["id"], item["name"], json.dumps(sorted(set(item["permissions"])))),
            )
            counts["groups"] += 1
        connection.execute(
            """UPDATE password_policy SET min_length = %s, require_upper = %s,
                      require_lower = %s, require_number = %s, require_special = %s,
                      updated_at = NOW(), updated_by = %s WHERE id = 1""",
            (int(policy["minLength"]), bool(policy["requireUpper"]),
             bool(policy["requireLower"]), bool(policy["requireNumber"]),
             bool(policy["requireSpecial"]), actor_id),
        )
        counts["passwordPolicy"] = 1
    return counts


def read_config_restore_requests(limit: int = 100) -> list[dict[str, Any]]:
    with connect_db() as connection:
        rows = connection.execute(
            """SELECT r.*, COALESCE(requester.display_name, '已刪除使用者') AS requester_name,
                      approver.display_name AS approver_name,
                      applier.display_name AS applier_name
               FROM config_restore_requests r
               LEFT JOIN platform_users requester ON requester.id = r.requested_by
               LEFT JOIN platform_users approver ON approver.id = r.approved_by
               LEFT JOIN platform_users applier ON applier.id = r.applied_by
               ORDER BY r.requested_at DESC LIMIT %s""",
            (limit,),
        ).fetchall()
    return [{
        "id": row["id"], "versionId": row["version_id"], "status": row["status"],
        "note": row["note"], "decisionNote": row["decision_note"],
        "requestedById": row["requested_by"], "requestedBy": row["requester_name"],
        "approvedBy": row["approver_name"], "appliedBy": row["applier_name"],
        "beforeVersionId": row["before_version_id"], "result": row["result"],
        "error": row["error"], "requestedAt": row["requested_at"].isoformat(),
        "completedAt": row["completed_at"].isoformat() if row["completed_at"] else None,
    } for row in rows]


def initialize_db() -> None:
    with connect_db() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                chain_seq BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
                occurred_at TIMESTAMPTZ NOT NULL,
                session_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                actor_name TEXT NOT NULL,
                event_type TEXT NOT NULL,
                page TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                result TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                integrity_hash TEXT NOT NULL,
                metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS audit_occurred_at_idx ON audit_events(occurred_at DESC)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS managed_hosts (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                address TEXT NOT NULL,
                port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
                ssh_user TEXT NOT NULL,
                group_name TEXT NOT NULL DEFAULT 'LAB / MANAGED',
                machine_id TEXT,
                host_key_fingerprint TEXT,
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE (address, port, ssh_user)
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS managed_hosts_enabled_idx ON managed_hosts(enabled, created_at)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS platform_groups (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
                system_group BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS platform_users (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS platform_user_groups (
                user_id TEXT NOT NULL REFERENCES platform_users(id) ON DELETE CASCADE,
                group_id TEXT NOT NULL REFERENCES platform_groups(id) ON DELETE CASCADE,
                PRIMARY KEY (user_id, group_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS platform_sessions (
                token_hash TEXT PRIMARY KEY,
                id TEXT UNIQUE,
                user_id TEXT NOT NULL REFERENCES platform_users(id) ON DELETE CASCADE,
                source_address TEXT,
                user_agent TEXT,
                expires_at TIMESTAMPTZ NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS platform_sessions_expires_idx ON platform_sessions(expires_at)"
        )
        connection.execute("ALTER TABLE platform_sessions ADD COLUMN IF NOT EXISTS id TEXT")
        connection.execute("ALTER TABLE platform_sessions ADD COLUMN IF NOT EXISTS source_address TEXT")
        connection.execute("ALTER TABLE platform_sessions ADD COLUMN IF NOT EXISTS user_agent TEXT")
        connection.execute(
            "UPDATE platform_sessions SET id = 'ses-' || substr(md5(token_hash), 1, 20) WHERE id IS NULL"
        )
        connection.execute("ALTER TABLE platform_sessions ALTER COLUMN id SET NOT NULL")
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS platform_sessions_id_idx ON platform_sessions(id)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_login_events (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                user_id TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
                success BOOLEAN NOT NULL,
                reason TEXT NOT NULL,
                source_address TEXT,
                user_agent TEXT,
                occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS auth_login_events_time_idx ON auth_login_events(occurred_at DESC)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS auth_login_events_user_time_idx ON auth_login_events(user_id, occurred_at DESC)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_security_policy (
                id SMALLINT PRIMARY KEY CHECK (id = 1),
                max_failed_attempts INTEGER NOT NULL CHECK (max_failed_attempts BETWEEN 3 AND 10),
                lockout_minutes INTEGER NOT NULL CHECK (lockout_minutes BETWEEN 1 AND 1440),
                event_retention_days INTEGER NOT NULL CHECK (event_retention_days BETWEEN 30 AND 365),
                require_mfa_admins BOOLEAN NOT NULL DEFAULT FALSE,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL
            )
            """
        )
        connection.execute(
            """INSERT INTO auth_security_policy (
                   id, max_failed_attempts, lockout_minutes, event_retention_days
               ) VALUES (1, 5, 5, 90) ON CONFLICT (id) DO NOTHING"""
        )
        connection.execute("ALTER TABLE auth_security_policy ADD COLUMN IF NOT EXISTS require_mfa_admins BOOLEAN NOT NULL DEFAULT FALSE")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS password_policy (
                id SMALLINT PRIMARY KEY CHECK (id = 1),
                min_length INTEGER NOT NULL CHECK (min_length BETWEEN 8 AND 128),
                require_upper BOOLEAN NOT NULL DEFAULT FALSE,
                require_lower BOOLEAN NOT NULL DEFAULT FALSE,
                require_number BOOLEAN NOT NULL DEFAULT FALSE,
                require_special BOOLEAN NOT NULL DEFAULT FALSE,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL
            )
            """
        )
        connection.execute(
            """
            INSERT INTO password_policy (
                id, min_length, require_upper, require_lower,
                require_number, require_special
            ) VALUES (1, 10, FALSE, FALSE, FALSE, FALSE)
            ON CONFLICT (id) DO NOTHING
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS host_metric_samples (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                host_id TEXT NOT NULL REFERENCES managed_hosts(id) ON DELETE CASCADE,
                collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                state TEXT NOT NULL CHECK (state IN ('healthy', 'warning', 'offline')),
                cpu_percent NUMERIC(5,1) NOT NULL DEFAULT 0,
                ram_percent NUMERIC(5,1) NOT NULL DEFAULT 0,
                disk_percent NUMERIC(5,1) NOT NULL DEFAULT 0,
                load_one NUMERIC(8,2),
                uptime_seconds BIGINT,
                failed_service_count INTEGER NOT NULL DEFAULT 0,
                error TEXT
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS host_metric_samples_host_time_idx ON host_metric_samples(host_id, collected_at DESC)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS host_patch_scans (
                id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL REFERENCES managed_hosts(id) ON DELETE CASCADE,
                status TEXT NOT NULL CHECK (status IN ('success', 'failed')),
                kernel_version TEXT,
                reboot_required BOOLEAN NOT NULL DEFAULT FALSE,
                reboot_packages JSONB NOT NULL DEFAULT '[]'::jsonb,
                unattended_upgrades TEXT,
                pending_count INTEGER NOT NULL DEFAULT 0,
                packages JSONB NOT NULL DEFAULT '[]'::jsonb,
                os_codename TEXT,
                security_count INTEGER NOT NULL DEFAULT 0,
                cve_count INTEGER NOT NULL DEFAULT 0,
                risk_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
                security_source_status TEXT,
                truncated BOOLEAN NOT NULL DEFAULT FALSE,
                error TEXT,
                checked_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
                checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS host_patch_scans_host_time_idx ON host_patch_scans(host_id, checked_at DESC)"
        )
        connection.execute("ALTER TABLE host_patch_scans ADD COLUMN IF NOT EXISTS os_codename TEXT")
        connection.execute("ALTER TABLE host_patch_scans ADD COLUMN IF NOT EXISTS security_count INTEGER NOT NULL DEFAULT 0")
        connection.execute("ALTER TABLE host_patch_scans ADD COLUMN IF NOT EXISTS cve_count INTEGER NOT NULL DEFAULT 0")
        connection.execute("ALTER TABLE host_patch_scans ADD COLUMN IF NOT EXISTS risk_summary JSONB NOT NULL DEFAULT '{}'::jsonb")
        connection.execute("ALTER TABLE host_patch_scans ADD COLUMN IF NOT EXISTS security_source_status TEXT")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS patch_inventory_policy (
                   id SMALLINT PRIMARY KEY CHECK(id=1), enabled BOOLEAN NOT NULL DEFAULT TRUE,
                   interval_hours INTEGER NOT NULL CHECK(interval_hours BETWEEN 1 AND 168),
                   security_threshold INTEGER NOT NULL CHECK(security_threshold BETWEEN 1 AND 1000),
                   notify_security_updates BOOLEAN NOT NULL DEFAULT TRUE,
                   last_started_at TIMESTAMPTZ, last_completed_at TIMESTAMPTZ,
                   updated_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
                   updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
               )"""
        )
        connection.execute(
            """INSERT INTO patch_inventory_policy(
                   id,enabled,interval_hours,security_threshold,notify_security_updates)
               VALUES(1,TRUE,24,1,TRUE) ON CONFLICT(id) DO NOTHING"""
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS host_asset_scans (
                id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL REFERENCES managed_hosts(id) ON DELETE CASCADE,
                status TEXT NOT NULL CHECK (status IN ('success', 'failed')),
                snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
                changes JSONB NOT NULL DEFAULT '{}'::jsonb,
                snapshot_sha256 TEXT,
                error TEXT,
                checked_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
                checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS host_asset_scans_host_time_idx ON host_asset_scans(host_id, checked_at DESC)"
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS asset_inventory_policy (
                   id SMALLINT PRIMARY KEY CHECK(id=1), enabled BOOLEAN NOT NULL DEFAULT TRUE,
                   interval_hours INTEGER NOT NULL CHECK(interval_hours BETWEEN 1 AND 168),
                   notify_drift BOOLEAN NOT NULL DEFAULT TRUE,
                   last_started_at TIMESTAMPTZ, last_completed_at TIMESTAMPTZ,
                   updated_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
                   updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
               )"""
        )
        connection.execute(
            """INSERT INTO asset_inventory_policy(id,enabled,interval_hours,notify_drift)
               VALUES(1,TRUE,24,TRUE) ON CONFLICT(id) DO NOTHING"""
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS host_security_scans (
                id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL REFERENCES managed_hosts(id) ON DELETE CASCADE,
                status TEXT NOT NULL CHECK (status IN ('success', 'failed')),
                score INTEGER NOT NULL DEFAULT 0 CHECK (score BETWEEN 0 AND 100),
                checks JSONB NOT NULL DEFAULT '[]'::jsonb,
                error TEXT,
                checked_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
                checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS host_security_scans_host_time_idx ON host_security_scans(host_id, checked_at DESC)"
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS security_baseline_policy (
                   id SMALLINT PRIMARY KEY CHECK(id=1), enabled BOOLEAN NOT NULL DEFAULT TRUE,
                   interval_hours INTEGER NOT NULL CHECK(interval_hours BETWEEN 1 AND 168),
                   minimum_score INTEGER NOT NULL CHECK(minimum_score BETWEEN 0 AND 100),
                   notify_regression BOOLEAN NOT NULL DEFAULT TRUE,
                   last_started_at TIMESTAMPTZ, last_completed_at TIMESTAMPTZ,
                   updated_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
                   updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
               )"""
        )
        connection.execute(
            """INSERT INTO security_baseline_policy(
                   id,enabled,interval_hours,minimum_score,notify_regression)
               VALUES(1,TRUE,24,80,TRUE) ON CONFLICT(id) DO NOTHING"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS automation_runs (
                   id TEXT PRIMARY KEY,
                   job_type TEXT NOT NULL CHECK(job_type IN ('asset_inventory','patch_inventory','security_baseline')),
                   trigger_type TEXT NOT NULL CHECK(trigger_type IN ('scheduled','manual')),
                   status TEXT NOT NULL CHECK(status IN ('running','success','partial','failed')),
                   requested_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
                   total_hosts INTEGER NOT NULL DEFAULT 0,
                   succeeded_hosts INTEGER NOT NULL DEFAULT 0,
                   failed_hosts INTEGER NOT NULL DEFAULT 0,
                   error TEXT,
                   started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                   completed_at TIMESTAMPTZ,
                   duration_ms INTEGER
               )"""
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS automation_runs_type_time_idx ON automation_runs(job_type,started_at DESC)"
        )
        connection.execute(
            """UPDATE automation_runs SET status='failed',error='API 重新啟動，前次巡檢未完成',
                      completed_at=NOW(),duration_ms=GREATEST(0,(EXTRACT(EPOCH FROM (NOW()-started_at))*1000)::int)
               WHERE status='running'"""
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS alert_rules (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                metric TEXT NOT NULL CHECK (metric IN ('availability', 'cpu', 'ram', 'disk', 'failed_services', 'log_collection', 'asset_drift', 'security_updates', 'security_baseline')),
                threshold NUMERIC(8,1) NOT NULL DEFAULT 1,
                consecutive_samples INTEGER NOT NULL DEFAULT 2 CHECK (consecutive_samples BETWEEN 1 AND 60),
                severity TEXT NOT NULL CHECK (severity IN ('warning', 'critical')),
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                created_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        connection.execute("ALTER TABLE alert_rules DROP CONSTRAINT IF EXISTS alert_rules_metric_check")
        connection.execute("ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_metric_check CHECK (metric IN ('availability','cpu','ram','disk','failed_services','log_collection','asset_drift','security_updates','security_baseline','capacity_forecast'))")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS alert_events (
                id TEXT PRIMARY KEY,
                rule_id TEXT NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
                host_id TEXT NOT NULL REFERENCES managed_hosts(id) ON DELETE CASCADE,
                status TEXT NOT NULL CHECK (status IN ('firing', 'acknowledged', 'resolved')),
                severity TEXT NOT NULL CHECK (severity IN ('warning', 'critical')),
                message TEXT NOT NULL,
                last_value NUMERIC(8,1),
                started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                acknowledged_at TIMESTAMPTZ,
                acknowledged_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
                resolved_at TIMESTAMPTZ
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS alert_events_recent_idx ON alert_events(started_at DESC)"
        )
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS alert_events_active_idx
            ON alert_events(rule_id, host_id)
            WHERE status IN ('firing', 'acknowledged')
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS notification_deliveries (
                id TEXT PRIMARY KEY,
                alert_event_id TEXT REFERENCES alert_events(id) ON DELETE SET NULL,
                channel TEXT NOT NULL CHECK (channel IN ('telegram', 'line', 'sms', 'webhook')),
                kind TEXT NOT NULL CHECK (kind IN ('firing', 'resolved', 'test', 'backup_failed', 'report')),
                status TEXT NOT NULL CHECK (status IN ('sent', 'failed')),
                destination_hint TEXT NOT NULL,
                message TEXT NOT NULL,
                response_detail TEXT,
                attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS notification_deliveries_time_idx ON notification_deliveries(attempted_at DESC)"
        )
        connection.execute(
            "ALTER TABLE notification_deliveries DROP CONSTRAINT IF EXISTS notification_deliveries_kind_check"
        )
        connection.execute(
            "ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_kind_check CHECK (kind IN ('firing', 'resolved', 'test', 'backup_failed', 'report'))"
        )
        connection.execute(
            "ALTER TABLE notification_deliveries DROP CONSTRAINT IF EXISTS notification_deliveries_channel_check"
        )
        connection.execute(
            "ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_channel_check CHECK (channel IN ('telegram', 'line', 'sms', 'webhook', 'email'))"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS notification_retry_jobs (
                id TEXT PRIMARY KEY,
                alert_event_id TEXT REFERENCES alert_events(id) ON DELETE SET NULL,
                channel TEXT NOT NULL CHECK (channel IN ('telegram', 'line', 'sms', 'webhook', 'email')),
                kind TEXT NOT NULL CHECK (kind IN ('firing', 'resolved', 'test', 'backup_failed', 'report')),
                severity TEXT NOT NULL CHECK (severity IN ('warning', 'critical')),
                message TEXT NOT NULL,
                retry_key TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('queued', 'sending', 'sent', 'failed')),
                attempt_count INTEGER NOT NULL DEFAULT 1,
                max_attempts INTEGER NOT NULL DEFAULT 4,
                next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_error TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE (channel, retry_key)
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS notification_retry_jobs_due_idx ON notification_retry_jobs(status, next_attempt_at)"
        )
        connection.execute(
            "UPDATE notification_retry_jobs SET status = 'queued', next_attempt_at = NOW() WHERE status = 'sending'"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS database_backup_jobs (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL CHECK (kind IN ('scheduled', 'manual')),
                status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'success', 'failed')),
                filename TEXT,
                size_bytes BIGINT,
                sha256 TEXT,
                restore_verified BOOLEAN NOT NULL DEFAULT FALSE,
                recovery_filename TEXT,
                recovery_size_bytes BIGINT,
                recovery_sha256 TEXT,
                recovery_verified BOOLEAN NOT NULL DEFAULT FALSE,
                detail TEXT,
                requested_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
                requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                started_at TIMESTAMPTZ,
                completed_at TIMESTAMPTZ
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS database_backup_jobs_time_idx ON database_backup_jobs(requested_at DESC)"
        )
        connection.execute(
            "ALTER TABLE database_backup_jobs ADD COLUMN IF NOT EXISTS notified_at TIMESTAMPTZ"
        )
        connection.execute("ALTER TABLE database_backup_jobs ADD COLUMN IF NOT EXISTS recovery_filename TEXT")
        connection.execute("ALTER TABLE database_backup_jobs ADD COLUMN IF NOT EXISTS recovery_size_bytes BIGINT")
        connection.execute("ALTER TABLE database_backup_jobs ADD COLUMN IF NOT EXISTS recovery_sha256 TEXT")
        connection.execute("ALTER TABLE database_backup_jobs ADD COLUMN IF NOT EXISTS recovery_verified BOOLEAN NOT NULL DEFAULT FALSE")
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS database_backup_jobs_active_idx ON database_backup_jobs((TRUE)) WHERE status IN ('queued', 'running')"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS external_watchdogs (
                id TEXT PRIMARY KEY,
                node_name TEXT NOT NULL,
                last_status TEXT NOT NULL CHECK (last_status IN ('healthy', 'recovered')),
                last_outage_seconds INTEGER NOT NULL DEFAULT 0,
                source_address TEXT,
                version TEXT NOT NULL DEFAULT '1',
                last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_recovered_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS external_watchdogs_seen_idx ON external_watchdogs(last_seen_at DESC)"
        )
        connection.execute(
            "ALTER TABLE external_watchdogs ADD COLUMN IF NOT EXISTS last_recovered_at TIMESTAMPTZ"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS watchdog_outages (
                id TEXT PRIMARY KEY,
                watchdog_id TEXT NOT NULL REFERENCES external_watchdogs(id) ON DELETE CASCADE,
                started_at TIMESTAMPTZ NOT NULL,
                recovered_at TIMESTAMPTZ NOT NULL,
                duration_seconds INTEGER NOT NULL CHECK (duration_seconds > 0),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE (watchdog_id, recovered_at)
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS watchdog_outages_time_idx ON watchdog_outages(recovered_at DESC)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS ai_diagnostics (
                id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL REFERENCES managed_hosts(id) ON DELETE CASCADE,
                status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
                model TEXT NOT NULL,
                evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
                result JSONB,
                redaction_count INTEGER NOT NULL DEFAULT 0,
                error TEXT,
                requested_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
                requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                completed_at TIMESTAMPTZ
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS ai_diagnostics_host_time_idx ON ai_diagnostics(host_id, requested_at DESC)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS maintenance_tasks (
                id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL REFERENCES managed_hosts(id) ON DELETE CASCADE,
                runbook_id TEXT NOT NULL,
                title TEXT NOT NULL,
                command_preview TEXT NOT NULL,
                risk_level TEXT NOT NULL DEFAULT 'low',
                approval_policy TEXT NOT NULL DEFAULT 'single',
                verification_method TEXT NOT NULL DEFAULT '',
                verification_status TEXT NOT NULL DEFAULT 'pending',
                output_sha256 TEXT,
                duration_ms INTEGER,
                source_alert_id TEXT,
                request_note TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'running', 'succeeded', 'failed')),
                output TEXT,
                error TEXT,
                requested_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
                approved_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
                decision_note TEXT NOT NULL DEFAULT '',
                requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                decided_at TIMESTAMPTZ,
                approval_expires_at TIMESTAMPTZ,
                started_at TIMESTAMPTZ,
                completed_at TIMESTAMPTZ
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS maintenance_tasks_time_idx ON maintenance_tasks(requested_at DESC)"
        )
        connection.execute("ALTER TABLE maintenance_tasks ADD COLUMN IF NOT EXISTS risk_level TEXT NOT NULL DEFAULT 'low'")
        connection.execute("ALTER TABLE maintenance_tasks ADD COLUMN IF NOT EXISTS approval_policy TEXT NOT NULL DEFAULT 'single'")
        connection.execute("ALTER TABLE maintenance_tasks ADD COLUMN IF NOT EXISTS verification_method TEXT NOT NULL DEFAULT ''")
        connection.execute("ALTER TABLE maintenance_tasks ADD COLUMN IF NOT EXISTS verification_status TEXT NOT NULL DEFAULT 'pending'")
        connection.execute("ALTER TABLE maintenance_tasks ADD COLUMN IF NOT EXISTS output_sha256 TEXT")
        connection.execute("ALTER TABLE maintenance_tasks ADD COLUMN IF NOT EXISTS duration_ms INTEGER")
        connection.execute("ALTER TABLE maintenance_tasks ADD COLUMN IF NOT EXISTS source_alert_id TEXT")
        connection.execute("ALTER TABLE maintenance_tasks ADD COLUMN IF NOT EXISTS approval_expires_at TIMESTAMPTZ")
        connection.execute(
            "CREATE INDEX IF NOT EXISTS maintenance_tasks_source_alert_idx "
            "ON maintenance_tasks(source_alert_id, requested_at DESC)"
        )
        # Running jobs belong to the independent worker. The heartbeat reaper,
        # rather than an API restart, decides whether an execution is stale.
        connection.execute(
            """UPDATE maintenance_tasks
               SET approval_expires_at=COALESCE(decided_at,NOW()) + make_interval(mins => %s)
               WHERE status='approved' AND approval_expires_at IS NULL""",
            (MAINTENANCE_APPROVAL_TTL_MINUTES,),
        )
        connection.execute(
            """CREATE UNIQUE INDEX IF NOT EXISTS maintenance_one_running_per_host_idx
               ON maintenance_tasks(host_id) WHERE status='running'"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS user_mfa (
                user_id TEXT PRIMARY KEY REFERENCES platform_users(id) ON DELETE CASCADE,
                secret_encrypted TEXT NOT NULL,
                recovery_code_hashes JSONB NOT NULL DEFAULT '[]'::jsonb,
                enabled BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS secret_vault (
                id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, purpose TEXT NOT NULL,
                value_encrypted TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1,
                updated_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS identity_providers (
                provider_type TEXT PRIMARY KEY CHECK (provider_type IN ('oidc','ldap')),
                display_name TEXT NOT NULL, enabled BOOLEAN NOT NULL DEFAULT FALSE,
                configuration JSONB NOT NULL DEFAULT '{}'::jsonb,
                updated_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS central_log_events (
                id BIGSERIAL PRIMARY KEY, host_id TEXT NOT NULL REFERENCES managed_hosts(id) ON DELETE CASCADE,
                cursor TEXT NOT NULL, occurred_at TIMESTAMPTZ, priority TEXT NOT NULL,
                systemd_unit TEXT, identifier TEXT, process_id TEXT, transport TEXT, boot_id TEXT,
                message TEXT NOT NULL, collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE(host_id, cursor)
            )"""
        )
        for column in ("systemd_unit", "identifier", "process_id", "transport", "boot_id"):
            connection.execute(f"ALTER TABLE central_log_events ADD COLUMN IF NOT EXISTS {column} TEXT")
        connection.execute("CREATE INDEX IF NOT EXISTS central_logs_search_idx ON central_log_events(host_id, occurred_at DESC)")
        connection.execute("CREATE INDEX IF NOT EXISTS central_logs_unit_time_idx ON central_log_events(systemd_unit, occurred_at DESC)")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS central_log_policy (
                id SMALLINT PRIMARY KEY CHECK(id=1), retention_days INTEGER NOT NULL,
                interval_seconds INTEGER NOT NULL, failure_threshold INTEGER NOT NULL,
                updated_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )"""
        )
        connection.execute("""INSERT INTO central_log_policy(id,retention_days,interval_seconds,failure_threshold)
            VALUES(1,%s,%s,2) ON CONFLICT(id) DO NOTHING""", (CENTRAL_LOG_RETENTION_DAYS,CENTRAL_LOG_INTERVAL_SECONDS))
        connection.execute(
            """CREATE TABLE IF NOT EXISTS central_log_collection_status (
                host_id TEXT PRIMARY KEY REFERENCES managed_hosts(id) ON DELETE CASCADE,
                last_attempt_at TIMESTAMPTZ, last_success_at TIMESTAMPTZ,
                last_event_at TIMESTAMPTZ, last_event_count INTEGER NOT NULL DEFAULT 0,
                consecutive_failures INTEGER NOT NULL DEFAULT 0, last_error TEXT,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS ssh_key_rotations (
                id TEXT PRIMARY KEY, status TEXT NOT NULL, old_fingerprint TEXT,
                new_fingerprint TEXT NOT NULL, public_key TEXT NOT NULL,
                private_key_encrypted TEXT NOT NULL, created_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), promoted_at TIMESTAMPTZ
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS ssh_key_rotation_hosts (
                rotation_id TEXT NOT NULL REFERENCES ssh_key_rotations(id) ON DELETE CASCADE,
                host_id TEXT NOT NULL REFERENCES managed_hosts(id) ON DELETE CASCADE,
                status TEXT NOT NULL, error TEXT, verified_at TIMESTAMPTZ,
                PRIMARY KEY(rotation_id,host_id)
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS ssh_key_retirement_requests (
                id TEXT PRIMARY KEY, rotation_id TEXT NOT NULL REFERENCES ssh_key_rotations(id) ON DELETE CASCADE,
                public_key_to_remove TEXT NOT NULL, status TEXT NOT NULL,
                requested_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
                approved_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
                request_note TEXT NOT NULL DEFAULT '', decision_note TEXT NOT NULL DEFAULT '',
                requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), decided_at TIMESTAMPTZ,
                completed_at TIMESTAMPTZ, result JSONB, error TEXT
            )"""
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS config_restore_requests (
                id TEXT PRIMARY KEY,
                version_id TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'applying', 'applied', 'failed')),
                note TEXT NOT NULL DEFAULT '',
                decision_note TEXT NOT NULL DEFAULT '',
                requested_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
                approved_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
                applied_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
                before_version_id TEXT,
                result JSONB,
                error TEXT,
                requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                decided_at TIMESTAMPTZ,
                completed_at TIMESTAMPTZ
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS config_restore_requests_time_idx ON config_restore_requests(requested_at DESC)"
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS standby_preflight_checks (
                   id TEXT PRIMARY KEY,
                   host_id TEXT NOT NULL REFERENCES managed_hosts(id) ON DELETE CASCADE,
                   ready BOOLEAN NOT NULL,
                   result JSONB NOT NULL,
                   checked_by TEXT REFERENCES platform_users(id) ON DELETE SET NULL,
                   checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
               )"""
        )
        connection.execute("CREATE INDEX IF NOT EXISTS standby_preflight_time_idx ON standby_preflight_checks(checked_at DESC)")
        connection.execute(
            """
            INSERT INTO watchdog_outages (
                id, watchdog_id, started_at, recovered_at, duration_seconds
            )
            SELECT 'wdo-legacy-' || substr(md5(id || last_seen_at::text), 1, 12),
                   id, last_seen_at - make_interval(secs => last_outage_seconds),
                   last_seen_at, last_outage_seconds
            FROM external_watchdogs
            WHERE last_status = 'recovered'
              AND last_outage_seconds > 0
              AND last_recovered_at IS NULL
            ON CONFLICT (watchdog_id, recovered_at) DO NOTHING
            """
        )
        connection.execute(
            """
            UPDATE external_watchdogs
            SET last_recovered_at = last_seen_at
            WHERE last_status = 'recovered'
              AND last_outage_seconds > 0
              AND last_recovered_at IS NULL
            """
        )
        default_rules = (
            ("rule-host-offline", "主機無法連線", "availability", 1, 2, "critical"),
            ("rule-cpu-high", "CPU 使用率過高", "cpu", 90, 3, "warning"),
            ("rule-ram-high", "記憶體使用率過高", "ram", 85, 3, "warning"),
            ("rule-disk-high", "磁碟使用率過高", "disk", 80, 2, "critical"),
            ("rule-service-failed", "systemd 服務失敗", "failed_services", 1, 1, "critical"),
            ("rule-log-collection", "集中日誌採集失敗", "log_collection", 1, 2, "warning"),
            ("rule-asset-drift", "主機資產設定漂移", "asset_drift", 1, 1, "warning"),
            ("rule-security-updates", "主機有安全更新待處理", "security_updates", 1, 1, "critical"),
            ("rule-security-baseline", "主機安全基準低於門檻", "security_baseline", 80, 1, "warning"),
        )
        for rule in default_rules:
            connection.execute(
                """
                INSERT INTO alert_rules (
                    id, name, metric, threshold, consecutive_samples, severity
                ) VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
                """,
                rule,
            )
        default_groups = (
            ("administrators", "系統管理員", ["*"]),
            ("operators", "維運人員", ["hosts.read", "hosts.manage", "logs.read", "terminal.open", "audit.read", "alerts.read", "alerts.manage", "backup.read", "backup.manage", "ai.read", "ai.manage", "tasks.read", "tasks.request", "tasks.approve", "tasks.execute"]),
            ("viewers", "唯讀檢視者", ["hosts.read", "logs.read", "audit.read", "alerts.read", "backup.read", "ai.read", "tasks.read"]),
        )
        for group_id, name, permissions in default_groups:
            connection.execute(
                """
                INSERT INTO platform_groups (id, name, permissions, system_group)
                VALUES (%s, %s, %s::jsonb, TRUE)
                ON CONFLICT (id) DO UPDATE SET permissions = EXCLUDED.permissions
                """,
                (group_id, name, json.dumps(permissions)),
            )
        admin = connection.execute(
            "SELECT id FROM platform_users WHERE username = %s",
            (ADMIN_USERNAME,),
        ).fetchone()
        if not admin:
            if len(ADMIN_PASSWORD) < 10:
                raise RuntimeError("ADMIN_PASSWORD must contain at least 10 characters")
            admin_id = f"usr-{uuid.uuid4().hex[:16]}"
            connection.execute(
                """
                INSERT INTO platform_users (id, username, display_name, password_hash)
                VALUES (%s, %s, %s, %s)
                """,
                (admin_id, ADMIN_USERNAME, ADMIN_DISPLAY_NAME, hash_password(ADMIN_PASSWORD)),
            )
            connection.execute(
                "INSERT INTO platform_user_groups (user_id, group_id) VALUES (%s, 'administrators')",
                (admin_id,),
            )
        connection.execute("DELETE FROM platform_sessions WHERE expires_at <= NOW()")
        for host in load_seed_inventory():
            connection.execute(
                """
                INSERT INTO managed_hosts (
                    id, name, address, port, ssh_user, group_name,
                    machine_id, host_key_fingerprint
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
                """,
                (
                    host["id"], host["name"], host["address"], host.get("port", 22),
                    host["user"], host["group"], host.get("machine_id"),
                    host.get("host_key_fingerprint"),
                ),
            )


@asynccontextmanager
async def lifespan(_: FastAPI):
    last_error: Exception | None = None
    for _ in range(20):
        try:
            await asyncio.to_thread(initialize_db)
            await asyncio.to_thread(apply_migrations, connect_db)
            last_error = None
            break
        except psycopg.OperationalError as error:
            last_error = error
            await asyncio.sleep(1)
    if last_error:
        raise RuntimeError("PostgreSQL did not become ready") from last_error
    await asyncio.to_thread(commit_configuration, None, "中央服務啟動同步")
    monitor_task = asyncio.create_task(monitor_loop(), name="host-monitor")
    backup_notification_task = asyncio.create_task(
        backup_notification_loop(), name="backup-notification-monitor"
    )
    notification_retry_task = asyncio.create_task(
        notification_retry_loop(), name="notification-retry-worker"
    )
    central_log_task = asyncio.create_task(central_log_collection_loop(), name="central-log-collector")
    asset_inventory_task = asyncio.create_task(asset_inventory_loop(), name="asset-inventory-monitor")
    patch_inventory_task = asyncio.create_task(patch_inventory_loop(), name="patch-inventory-monitor")
    security_baseline_task = asyncio.create_task(security_baseline_loop(), name="security-baseline-monitor")
    maintenance_reaper_task = asyncio.create_task(maintenance_reaper_loop(), name="maintenance-task-reaper")
    retention_task = asyncio.create_task(retention_cleanup_loop(), name="data-retention-worker")
    observability_task = asyncio.create_task(observability_loop(), name="service-observability-worker")
    report_task = asyncio.create_task(scheduled_report_loop(), name="scheduled-report-worker")
    escalation_task = asyncio.create_task(notification_escalation_loop(), name="notification-escalation-worker")
    rollup_task = asyncio.create_task(metric_rollup_loop(), name="metric-rollup-worker")
    try:
        yield
    finally:
        monitor_task.cancel()
        backup_notification_task.cancel()
        notification_retry_task.cancel()
        central_log_task.cancel()
        asset_inventory_task.cancel()
        patch_inventory_task.cancel()
        security_baseline_task.cancel()
        maintenance_reaper_task.cancel()
        retention_task.cancel()
        observability_task.cancel()
        report_task.cancel()
        escalation_task.cancel()
        rollup_task.cancel()
        try:
            await asyncio.gather(
                monitor_task, backup_notification_task, notification_retry_task, central_log_task,
                asset_inventory_task,
                patch_inventory_task,
                security_baseline_task,
                maintenance_reaper_task,
                retention_task,
                observability_task,
                report_task,
                escalation_task,
                rollup_task,
            )
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="Linux AI Control Plane API",
    version=APP_VERSION,
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

api_rate_buckets: dict[str, list[float]] = {}
api_rate_lock = threading.Lock()


@app.middleware("http")
async def bounded_api_requests(request: Request, call_next):
    if request.url.path.startswith("/api/") and request.url.path not in {"/api/health"}:
        now = time.monotonic()
        source = request.client.host if request.client else "unknown"
        with api_rate_lock:
            recent = [stamp for stamp in api_rate_buckets.get(source, []) if now - stamp < 60]
            if len(recent) >= API_RATE_LIMIT_PER_MINUTE:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "API 請求過於頻繁，請稍後再試"},
                    headers={"Retry-After": "60"},
                )
            recent.append(now)
            api_rate_buckets[source] = recent
    return await call_next(request)

probe_cache: dict[str, tuple[float, dict[str, Any]]] = {}
probe_lock = asyncio.Lock()
monitor_cycle_lock = asyncio.Lock()
known_hosts_lock = asyncio.Lock()
patch_scan_lock = asyncio.Lock()
asset_scan_lock = asyncio.Lock()
security_scan_lock = asyncio.Lock()
central_log_collection_lock = asyncio.Lock()
maintenance_execution_tasks: dict[str, asyncio.Task[Any]] = {}
ssh_semaphore = asyncio.Semaphore(SSH_MAX_CONCURRENCY)
ubuntu_security_notice_cache: dict[str, tuple[float, dict[str, list[dict[str, Any]]]]] = {}
ubuntu_security_notice_lock = threading.Lock()


def session_user(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None
    with connect_db() as connection:
        row = connection.execute(
            """
            SELECT u.id, u.username, u.display_name,
                   COALESCE(jsonb_agg(DISTINCT permission.value)
                       FILTER (WHERE permission.value IS NOT NULL), '[]'::jsonb) AS permissions
            FROM platform_sessions s
            JOIN platform_users u ON u.id = s.user_id AND u.enabled = TRUE
            LEFT JOIN platform_user_groups ug ON ug.user_id = u.id
            LEFT JOIN platform_groups g ON g.id = ug.group_id
            LEFT JOIN LATERAL jsonb_array_elements_text(g.permissions) permission(value) ON TRUE
            WHERE s.token_hash = %s AND s.expires_at > NOW()
            GROUP BY u.id, u.username, u.display_name
            """,
            (token_hash(token),),
        ).fetchone()
        if row:
            connection.execute(
                "UPDATE platform_sessions SET last_seen_at = NOW() WHERE token_hash = %s",
                (token_hash(token),),
            )
    if not row:
        return None
    return {
        "id": row["id"],
        "username": row["username"],
        "displayName": row["display_name"],
        "permissions": list(row["permissions"]),
    }


def has_permission(user: dict[str, Any], permission: str) -> bool:
    permissions = set(user.get("permissions", []))
    return "*" in permissions or permission in permissions


def require_permission(request: Request, permission: str) -> dict[str, Any]:
    user = request.state.user
    if not has_permission(user, permission):
        raise HTTPException(status_code=403, detail="你的帳號沒有執行這項操作的權限")
    return user


def request_source_address(request: Request) -> str:
    direct = request.client.host if request.client else "unknown"
    forwarded = request.headers.get("x-forwarded-for", "").split(",", 1)[0].strip()
    try:
        direct_ip = ipaddress.ip_address(direct)
        forwarded_ip = ipaddress.ip_address(forwarded) if forwarded else None
    except ValueError:
        return direct
    # API port is internal-only. Trust the gateway header only from a private
    # Docker peer, never from a directly exposed public client.
    if direct_ip.is_private and forwarded_ip:
        return str(forwarded_ip)
    return str(direct_ip)


@app.middleware("http")
async def authenticate_api(request: Request, call_next):
    if not request.url.path.startswith("/api/") or request.url.path in {
        "/api/health",
        "/api/auth/login",
        "/api/watchdog/heartbeat",
    }:
        return await call_next(request)
    user = await asyncio.to_thread(session_user, request.cookies.get(SESSION_COOKIE))
    if not user:
        return JSONResponse(status_code=401, content={"detail": "請先登入管理平台"})
    request.state.user = user
    return await call_next(request)


VERSIONED_CONFIG_ROUTE = re.compile(
    r"^/api/(?:hosts(?:/[^/]+)?|alert-rules(?:/[^/]+)?|groups(?:/[^/]+)?|password-policy)$"
)


@app.middleware("http")
async def version_control_changes(request: Request, call_next):
    response = await call_next(request)
    if (
        request.method in {"POST", "PUT", "DELETE"}
        and response.status_code < 300
        and VERSIONED_CONFIG_ROUTE.fullmatch(request.url.path)
    ):
        actor = getattr(request.state, "user", None)
        reason = f"{request.method} {request.url.path}"
        try:
            await asyncio.to_thread(commit_configuration, actor, reason)
        except Exception as error:
            print(f"configuration version commit failed: {error}", flush=True)
    return response


@app.get("/api/config-versions")
async def list_config_versions(request: Request) -> dict[str, Any]:
    require_permission(request, "audit.read")
    versions = await asyncio.to_thread(config_version_history)
    return {"versions": versions, "repository": "local-git", "secretsIncluded": False}


@app.post("/api/config-versions/snapshot")
async def create_config_version(request: Request) -> dict[str, Any]:
    actor = require_permission(request, "access.manage")
    version = await asyncio.to_thread(commit_configuration, actor, "手動建立快照", True)
    return {"version": version}


@app.get("/api/config-versions/{version_id}")
async def get_config_version(version_id: str, request: Request) -> dict[str, Any]:
    require_permission(request, "audit.read")
    return await asyncio.to_thread(read_config_version, version_id)


@app.get("/api/config-restore-requests")
async def list_config_restore_requests(request: Request) -> dict[str, Any]:
    require_permission(request, "audit.read")
    return {"requests": await asyncio.to_thread(read_config_restore_requests)}


@app.post("/api/config-versions/{version_id}/restore-requests", status_code=201)
async def create_config_restore_request(
    version_id: str, payload: MaintenanceTaskDecision, request: Request
) -> dict[str, Any]:
    actor = require_permission(request, "access.manage")
    await asyncio.to_thread(read_config_version, version_id)
    request_id = f"restore-{uuid.uuid4().hex[:18]}"
    with connect_db() as connection:
        connection.execute(
            """INSERT INTO config_restore_requests (
                   id, version_id, status, note, requested_by
               ) VALUES (%s, %s, 'pending', %s, %s)""",
            (request_id, version_id, payload.note.strip(), actor["id"]),
        )
    return next(item for item in await asyncio.to_thread(read_config_restore_requests) if item["id"] == request_id)


@app.post("/api/config-restore-requests/{restore_id}/approve")
async def approve_config_restore_request(
    restore_id: str, payload: MaintenanceTaskDecision, request: Request
) -> dict[str, Any]:
    actor = require_permission(request, "access.manage")
    with connect_db() as connection:
        current = connection.execute(
            "SELECT status, requested_by FROM config_restore_requests WHERE id = %s",
            (restore_id,),
        ).fetchone()
        if not current or current["status"] != "pending":
            raise HTTPException(status_code=409, detail="還原申請不存在或已完成審核")
        if current["requested_by"] == actor["id"]:
            raise HTTPException(status_code=403, detail="設定回滾必須由另一位管理者核准")
        connection.execute(
            """UPDATE config_restore_requests SET status = 'approved', approved_by = %s,
                      decision_note = %s, decided_at = NOW() WHERE id = %s AND status = 'pending'""",
            (actor["id"], payload.note.strip(), restore_id),
        )
    return {"id": restore_id, "status": "approved"}


@app.post("/api/config-restore-requests/{restore_id}/reject")
async def reject_config_restore_request(
    restore_id: str, payload: MaintenanceTaskDecision, request: Request
) -> dict[str, Any]:
    actor = require_permission(request, "access.manage")
    with connect_db() as connection:
        current = connection.execute(
            "SELECT status, requested_by FROM config_restore_requests WHERE id = %s",
            (restore_id,),
        ).fetchone()
        if not current or current["status"] != "pending":
            raise HTTPException(status_code=409, detail="還原申請不存在或已完成審核")
        if current["requested_by"] == actor["id"]:
            raise HTTPException(status_code=403, detail="設定回滾必須由另一位管理者審核")
        connection.execute(
            """UPDATE config_restore_requests SET status = 'rejected', approved_by = %s,
                      decision_note = %s, decided_at = NOW(), completed_at = NOW()
               WHERE id = %s AND status = 'pending'""",
            (actor["id"], payload.note.strip(), restore_id),
        )
    return {"id": restore_id, "status": "rejected"}


@app.post("/api/config-restore-requests/{restore_id}/apply")
async def apply_config_restore_request(restore_id: str, request: Request) -> dict[str, Any]:
    actor = require_permission(request, "access.manage")
    with connect_db() as connection:
        restore = connection.execute(
            """UPDATE config_restore_requests SET status = 'applying', applied_by = %s
               WHERE id = %s AND status = 'approved' RETURNING version_id""",
            (actor["id"], restore_id),
        ).fetchone()
    if not restore:
        raise HTTPException(status_code=409, detail="還原申請必須先由另一位管理者核准")
    try:
        before = await asyncio.to_thread(commit_configuration, actor, "設定回滾前自動快照", True)
        version = await asyncio.to_thread(read_config_version, restore["version_id"])
        counts = await asyncio.to_thread(restore_configuration_snapshot, version["snapshot"], actor["id"])
        probe_cache.clear()
        after = await asyncio.to_thread(commit_configuration, actor, f"套用回滾版本 {restore['version_id'][:12]}", True)
        result = {"restored": counts, "beforeVersionId": before["id"], "afterVersionId": after["id"]}
        with connect_db() as connection:
            connection.execute(
                """UPDATE config_restore_requests SET status = 'applied', before_version_id = %s,
                          result = %s::jsonb, completed_at = NOW() WHERE id = %s""",
                (before["id"], json.dumps(result), restore_id),
            )
    except Exception as error:
        safe_error = str(error)[:1000]
        with connect_db() as connection:
            connection.execute(
                """UPDATE config_restore_requests SET status = 'failed', error = %s,
                          completed_at = NOW() WHERE id = %s""",
                (safe_error, restore_id),
            )
        raise HTTPException(status_code=409, detail=f"設定回滾失敗，資料庫交易已取消：{safe_error[:300]}") from error
    return next(item for item in await asyncio.to_thread(read_config_restore_requests) if item["id"] == restore_id)


def authenticate_login(username: str, password: str) -> dict[str, Any] | None:
    with connect_db() as connection:
        row = connection.execute(
            """
            SELECT id, username, display_name, password_hash
            FROM platform_users
            WHERE lower(username) = lower(%s) AND enabled = TRUE
            """,
            (username.strip(),),
        ).fetchone()
    if not row or not verify_password(password, row["password_hash"]):
        return None
    return row


def record_login_event(
    username: str, user_id: str | None, success: bool, reason: str,
    source_address: str, user_agent: str,
) -> None:
    try:
        with connect_db() as connection:
            connection.execute(
                """INSERT INTO auth_login_events (
                       id, username, user_id, success, reason, source_address, user_agent
                   ) VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (
                    f"login-{uuid.uuid4().hex[:20]}", username.strip().lower()[:64],
                    user_id, success, reason[:80], source_address[:80], user_agent[:300],
                ),
            )
            connection.execute(
                """DELETE FROM auth_login_events
                   WHERE occurred_at < NOW() - make_interval(days => (
                       SELECT event_retention_days FROM auth_security_policy WHERE id = 1
                   ))"""
            )
    except psycopg.Error as error:
        print(f"login event write failed: {error}", flush=True)


def read_auth_security_policy() -> dict[str, Any]:
    with connect_db() as connection:
        row = connection.execute(
            """SELECT max_failed_attempts, lockout_minutes, event_retention_days, require_mfa_admins,
                      updated_at FROM auth_security_policy WHERE id = 1"""
        ).fetchone()
    return {
        "maxFailedAttempts": row["max_failed_attempts"],
        "lockoutMinutes": row["lockout_minutes"],
        "eventRetentionDays": row["event_retention_days"],
        "requireMfaAdmins": row["require_mfa_admins"],
        "updatedAt": row["updated_at"].isoformat(),
    }


def recent_failed_login_count(username: str, source_address: str, lockout_minutes: int) -> int:
    with connect_db() as connection:
        row = connection.execute(
            """
            SELECT COUNT(*) AS count FROM auth_login_events failed
            WHERE failed.username = %s AND failed.source_address = %s
              AND failed.success = FALSE AND failed.reason = 'invalid_credentials'
              AND failed.occurred_at >= NOW() - make_interval(mins => %s)
              AND failed.occurred_at > COALESCE((
                  SELECT MAX(success.occurred_at) FROM auth_login_events success
                  WHERE success.username = %s AND success.source_address = %s
                    AND success.success = TRUE
              ), '-infinity'::timestamptz)
            """,
            (username, source_address, lockout_minutes, username, source_address),
        ).fetchone()
    return int(row["count"])


def create_session(user_id: str, source_address: str, user_agent: str) -> str:
    token = secrets.token_urlsafe(32)
    with connect_db() as connection:
        connection.execute(
            """
            INSERT INTO platform_sessions (
                token_hash, id, user_id, source_address, user_agent, expires_at
            ) VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                token_hash(token), f"ses-{uuid.uuid4().hex[:20]}", user_id,
                source_address[:80], user_agent[:300],
                datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS),
            ),
        )
    return token


@app.post("/api/auth/login")
async def login(payload: LoginRequest, request: Request) -> JSONResponse:
    client_ip = request_source_address(request)
    user_agent = request.headers.get("user-agent", "unknown")
    normalized_username = payload.username.strip().lower()
    policy = await asyncio.to_thread(read_auth_security_policy)
    attempts = await asyncio.to_thread(
        recent_failed_login_count, normalized_username, client_ip, policy["lockoutMinutes"]
    )
    if attempts >= policy["maxFailedAttempts"]:
        await asyncio.to_thread(
            record_login_event, normalized_username, None, False, "rate_limited",
            client_ip, user_agent,
        )
        raise HTTPException(
            status_code=429,
            detail=f"登入嘗試過多，請 {policy['lockoutMinutes']} 分鐘後再試",
        )
    user = await asyncio.to_thread(authenticate_login, payload.username, payload.password)
    if not user:
        await asyncio.to_thread(
            record_login_event, normalized_username, None, False, "invalid_credentials",
            client_ip, user_agent,
        )
        raise HTTPException(status_code=401, detail="帳號或密碼不正確")
    with connect_db() as connection:
        mfa = connection.execute(
            "SELECT enabled FROM user_mfa WHERE user_id = %s", (user["id"],)
        ).fetchone()
        is_admin = connection.execute(
            "SELECT EXISTS(SELECT 1 FROM platform_user_groups WHERE user_id=%s AND group_id='administrators') AS value",
            (user["id"],),
        ).fetchone()["value"]
    if policy["requireMfaAdmins"] and is_admin and not (mfa and mfa["enabled"]):
        await asyncio.to_thread(record_login_event, normalized_username, user["id"], False, "mfa_enrollment_required", client_ip, user_agent)
        raise HTTPException(status_code=403, detail="管理員必須先啟用 MFA；請由另一位管理員暫時關閉強制政策以完成註冊")
    if mfa and mfa["enabled"] and not await asyncio.to_thread(verify_mfa_code, user["id"], payload.otp):
        await asyncio.to_thread(
            record_login_event, normalized_username, user["id"], False, "mfa_required",
            client_ip, user_agent,
        )
        raise HTTPException(status_code=401, detail="請輸入有效的 MFA 動態碼或復原碼")
    token = await asyncio.to_thread(create_session, user["id"], client_ip, user_agent)
    await asyncio.to_thread(
        record_login_event, normalized_username, user["id"], True, "authenticated",
        client_ip, user_agent,
    )
    response = JSONResponse({"user": await asyncio.to_thread(session_user, token)})
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_HOURS * 3600,
        httponly=True,
        samesite="strict",
        secure=COOKIE_SECURE,
        path="/",
    )
    return response


@app.get("/api/auth/me")
async def auth_me(request: Request) -> dict[str, Any]:
    return {"user": request.state.user}


@app.get("/api/security/posture")
async def security_posture(request: Request) -> dict[str, Any]:
    actor = require_permission(request, "access.manage")
    with connect_db() as connection:
        mfa = connection.execute(
            "SELECT enabled, updated_at FROM user_mfa WHERE user_id = %s", (actor["id"],)
        ).fetchone()
        providers = connection.execute(
            "SELECT provider_type, display_name, enabled, configuration, updated_at FROM identity_providers ORDER BY provider_type"
        ).fetchall()
        vault_count = connection.execute("SELECT COUNT(*) AS count FROM secret_vault").fetchone()["count"]
        rotation = connection.execute(
            "SELECT id, status, new_fingerprint, created_at, promoted_at FROM ssh_key_rotations ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
    return {
        "mfa": {"enabled": bool(mfa and mfa["enabled"]), "updatedAt": mfa["updated_at"].isoformat() if mfa else None},
        "providers": [{"providerType": row["provider_type"], "displayName": row["display_name"],
                       "enabled": row["enabled"], "configuration": row["configuration"],
                       "updatedAt": row["updated_at"].isoformat()} for row in providers],
        "vaultCount": vault_count,
        "masterKeySource": "environment" if PLATFORM_MASTER_KEY else "derived-lab-fallback",
        "sshRotation": ({"id": rotation["id"], "status": rotation["status"],
                         "fingerprint": rotation["new_fingerprint"],
                         "createdAt": rotation["created_at"].isoformat(),
                         "promotedAt": rotation["promoted_at"].isoformat() if rotation["promoted_at"] else None} if rotation else None),
    }


@app.post("/api/security/mfa/setup")
async def setup_mfa(request: Request) -> dict[str, Any]:
    actor = request.state.user
    secret = pyotp.random_base32()
    recovery = [secrets.token_hex(5) for _ in range(8)]
    with connect_db() as connection:
        current = connection.execute("SELECT enabled FROM user_mfa WHERE user_id=%s", (actor["id"],)).fetchone()
        if current and current["enabled"]:
            raise HTTPException(status_code=409, detail="MFA 已啟用；請使用復原碼重建功能")
        connection.execute(
            """INSERT INTO user_mfa(user_id, secret_encrypted, recovery_code_hashes, enabled)
               VALUES (%s, %s, %s::jsonb, FALSE)
               ON CONFLICT(user_id) DO UPDATE SET secret_encrypted=EXCLUDED.secret_encrypted,
                 recovery_code_hashes=EXCLUDED.recovery_code_hashes, enabled=FALSE, updated_at=NOW()""",
            (actor["id"], encrypt_secret(secret), json.dumps([token_hash(code) for code in recovery])),
        )
    uri = pyotp.TOTP(secret).provisioning_uri(name=actor["username"], issuer_name="Linux AI Control Plane")
    await asyncio.to_thread(record_backend_audit, request, "security.mfa.setup", "建立 MFA 待驗證設定", actor["username"])
    return {"secret": secret, "otpauthUri": uri, "recoveryCodes": recovery, "notice": "復原碼只顯示這一次"}


@app.post("/api/security/mfa/enable")
async def enable_mfa(payload: MfaVerifyRequest, request: Request) -> dict[str, Any]:
    actor = request.state.user
    with connect_db() as connection:
        row = connection.execute("SELECT secret_encrypted FROM user_mfa WHERE user_id=%s", (actor["id"],)).fetchone()
        if not row or not pyotp.TOTP(decrypt_secret(row["secret_encrypted"])).verify(payload.code, valid_window=1):
            raise HTTPException(status_code=422, detail="動態碼不正確，MFA 尚未啟用")
        connection.execute("UPDATE user_mfa SET enabled=TRUE, updated_at=NOW() WHERE user_id=%s", (actor["id"],))
    await asyncio.to_thread(record_backend_audit, request, "security.mfa.enable", "啟用 TOTP MFA", actor["username"])
    return {"enabled": True}


@app.post("/api/security/mfa/recovery-codes")
async def regenerate_mfa_recovery_codes(payload: MfaVerifyRequest, request: Request) -> dict[str, Any]:
    actor = request.state.user
    if not await asyncio.to_thread(verify_mfa_code, actor["id"], payload.code):
        raise HTTPException(status_code=422, detail="動態碼或復原碼不正確")
    recovery = [secrets.token_hex(5) for _ in range(8)]
    with connect_db() as connection:
        connection.execute("UPDATE user_mfa SET recovery_code_hashes=%s::jsonb,updated_at=NOW() WHERE user_id=%s AND enabled=TRUE",
                           (json.dumps([token_hash(code) for code in recovery]), actor["id"]))
    await asyncio.to_thread(record_backend_audit, request, "security.mfa.recovery.rotate", "重新產生 MFA 復原碼", actor["username"])
    return {"recoveryCodes": recovery, "notice": "舊復原碼已失效；新復原碼只顯示這一次"}


@app.delete("/api/security/mfa", status_code=204)
async def disable_mfa(payload: MfaVerifyRequest, request: Request) -> None:
    actor = request.state.user
    if not await asyncio.to_thread(verify_mfa_code, actor["id"], payload.code):
        raise HTTPException(status_code=422, detail="動態碼或復原碼不正確")
    with connect_db() as connection:
        connection.execute("DELETE FROM user_mfa WHERE user_id=%s", (actor["id"],))
    await asyncio.to_thread(record_backend_audit, request, "security.mfa.disable", "停用 TOTP MFA", actor["username"])


@app.get("/api/security/secrets")
async def list_secrets(request: Request) -> dict[str, Any]:
    require_permission(request, "access.manage")
    with connect_db() as connection:
        rows = connection.execute("SELECT id,name,purpose,version,created_at,updated_at FROM secret_vault ORDER BY name").fetchall()
    return {"secrets": [{"id": r["id"], "name": r["name"], "purpose": r["purpose"], "version": r["version"],
                         "createdAt": r["created_at"].isoformat(), "updatedAt": r["updated_at"].isoformat()} for r in rows]}


@app.put("/api/security/secrets/{name}")
async def put_secret(name: str, payload: SecretWriteRequest, request: Request) -> dict[str, Any]:
    actor = require_permission(request, "access.manage")
    if name != payload.name:
        raise HTTPException(status_code=422, detail="路徑與祕密名稱不一致")
    with connect_db() as connection:
        row = connection.execute(
            """INSERT INTO secret_vault(id,name,purpose,value_encrypted,updated_by)
               VALUES(%s,%s,%s,%s,%s) ON CONFLICT(name) DO UPDATE SET purpose=EXCLUDED.purpose,
               value_encrypted=EXCLUDED.value_encrypted,version=secret_vault.version+1,updated_by=EXCLUDED.updated_by,updated_at=NOW()
               RETURNING id,version,updated_at""",
            (f"sec-{uuid.uuid4().hex[:16]}", name, payload.purpose, encrypt_secret(payload.value), actor["id"]),
        ).fetchone()
    await asyncio.to_thread(record_backend_audit, request, "security.secret.write", "建立或輪替加密祕密", name)
    return {"id": row["id"], "name": name, "version": row["version"], "updatedAt": row["updated_at"].isoformat(), "valueReturned": False}


@app.delete("/api/security/secrets/{name}", status_code=204)
async def delete_secret(name: str, request: Request) -> None:
    require_permission(request, "access.manage")
    with connect_db() as connection:
        row = connection.execute("DELETE FROM secret_vault WHERE name=%s RETURNING id", (name,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="找不到這筆祕密")
    await asyncio.to_thread(record_backend_audit, request, "security.secret.delete", "刪除加密祕密", name)


@app.put("/api/security/identity-providers/{provider_type}")
async def put_identity_provider(provider_type: str, payload: IdentityProviderUpdate, request: Request) -> dict[str, Any]:
    actor = require_permission(request, "access.manage")
    if provider_type != payload.provider_type:
        raise HTTPException(status_code=422, detail="Provider 類型不一致")
    safe = {k: v for k, v in payload.configuration.items() if "secret" not in k.lower() and "password" not in k.lower()}
    with connect_db() as connection:
        connection.execute(
            """INSERT INTO identity_providers(provider_type,display_name,enabled,configuration,updated_by)
               VALUES(%s,%s,%s,%s::jsonb,%s) ON CONFLICT(provider_type) DO UPDATE SET
               display_name=EXCLUDED.display_name,enabled=EXCLUDED.enabled,configuration=EXCLUDED.configuration,
               updated_by=EXCLUDED.updated_by,updated_at=NOW()""",
            (provider_type, payload.display_name, payload.enabled, json.dumps(safe), actor["id"]),
        )
    await asyncio.to_thread(record_backend_audit, request, "security.identity-provider.update", "更新外部身分提供者設定", provider_type)
    return {"providerType": provider_type, "enabled": payload.enabled, "configuration": safe,
            "note": "連線密碼與 client secret 請存入加密祕密庫；啟用前仍需完成外部服務連線測試"}


@app.post("/api/security/ssh-keys/rotations", status_code=201)
async def create_ssh_rotation(request: Request) -> dict[str, Any]:
    actor = require_permission(request, "access.manage")
    key = ed25519.Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()).decode()
    public = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode() + " linux-ai-rotated"
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(public.split()[1])).digest()).decode().rstrip("=")
    rotation_id = f"keyrot-{uuid.uuid4().hex[:16]}"
    with connect_db() as connection:
        active = connection.execute("SELECT new_fingerprint FROM ssh_key_rotations WHERE status='active' ORDER BY promoted_at DESC LIMIT 1").fetchone()
        connection.execute("INSERT INTO ssh_key_rotations(id,status,old_fingerprint,new_fingerprint,public_key,private_key_encrypted,created_by) VALUES(%s,'staged',%s,%s,%s,%s,%s)",
                           (rotation_id, active["new_fingerprint"] if active else None, fingerprint, public, encrypt_secret(private), actor["id"]))
    await asyncio.to_thread(record_backend_audit, request, "security.ssh-key.stage", "建立 staged SSH 金鑰", fingerprint)
    return {"id": rotation_id, "status": "staged", "fingerprint": fingerprint, "publicKey": public,
            "nextStep": "透過已核准維運流程部署公鑰、逐台驗證後才可切換；舊金鑰尚未移除"}


@app.post("/api/security/ssh-keys/rotations/{rotation_id}/deploy")
async def deploy_ssh_rotation(rotation_id: str, request: Request) -> dict[str, Any]:
    require_permission(request, "tasks.execute")
    with connect_db() as database:
        rotation = database.execute("SELECT public_key,private_key_encrypted,status FROM ssh_key_rotations WHERE id=%s", (rotation_id,)).fetchone()
    if not rotation or rotation["status"] != "staged":
        raise HTTPException(status_code=409, detail="找不到待部署的金鑰輪替")
    hosts = await asyncio.to_thread(load_inventory)
    results = []
    for host in hosts:
        try:
            encoded = base64.b64encode(rotation["public_key"].encode()).decode()
            command = f"umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; key=$(printf %s {shlex.quote(encoded)} | base64 -d); grep -qxF \"$key\" ~/.ssh/authorized_keys || printf '%s\\n' \"$key\" >> ~/.ssh/authorized_keys"
            await run_ssh(host, command, timeout=15)
            key = asyncssh.import_private_key(decrypt_secret(rotation["private_key_encrypted"]))
            test = await asyncio.wait_for(asyncssh.connect(host["address"], port=host.get("port",22), username=host["user"], client_keys=[key], known_hosts=KNOWN_HOSTS_PATH), timeout=10)
            test.close(); await test.wait_closed()
            status, error = "verified", None
        except Exception as problem:
            status, error = "failed", str(problem)[:500]
        with connect_db() as database:
            database.execute("""INSERT INTO ssh_key_rotation_hosts(rotation_id,host_id,status,error,verified_at)
                VALUES(%s,%s,%s,%s,CASE WHEN %s='verified' THEN NOW() END)
                ON CONFLICT(rotation_id,host_id) DO UPDATE SET status=EXCLUDED.status,error=EXCLUDED.error,verified_at=EXCLUDED.verified_at""",
                (rotation_id,host["id"],status,error,status))
        results.append({"hostId":host["id"],"status":status,"error":error})
    await asyncio.to_thread(record_backend_audit, request, "security.ssh-key.deploy", "部署並逐台驗證 SSH 新金鑰", rotation_id,
                            "success" if results and all(item["status"]=="verified" for item in results) else "partial")
    return {"id":rotation_id,"hosts":results,"ready":bool(results) and all(item["status"]=="verified" for item in results)}


@app.post("/api/security/ssh-keys/rotations/{rotation_id}/promote")
async def promote_ssh_rotation(rotation_id: str, request: Request) -> dict[str, Any]:
    require_permission(request, "access.manage")
    with connect_db() as database:
        missing = database.execute("""SELECT COUNT(*) AS count FROM managed_hosts h WHERE h.enabled=TRUE AND NOT EXISTS
            (SELECT 1 FROM ssh_key_rotation_hosts r WHERE r.rotation_id=%s AND r.host_id=h.id AND r.status='verified')""", (rotation_id,)).fetchone()["count"]
        if missing:
            raise HTTPException(status_code=409, detail=f"仍有 {missing} 台主機尚未用新金鑰驗證")
        database.execute("UPDATE ssh_key_rotations SET status='superseded' WHERE status='active' AND id<>%s", (rotation_id,))
        row = database.execute("UPDATE ssh_key_rotations SET status='active',promoted_at=NOW() WHERE id=%s AND status='staged' RETURNING new_fingerprint", (rotation_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=409, detail="輪替不存在或已完成")
    await asyncio.to_thread(record_backend_audit, request, "security.ssh-key.promote", "切換中央作用中 SSH 金鑰", row["new_fingerprint"])
    return {"id":rotation_id,"status":"active","fingerprint":row["new_fingerprint"],"oldKeyRemoved":False}


def read_ssh_retirements() -> list[dict[str, Any]]:
    with connect_db() as connection:
        rows = connection.execute("""SELECT r.id,r.rotation_id,r.status,r.request_note,r.decision_note,r.requested_at,r.decided_at,r.completed_at,
            requester.display_name AS requester,approver.display_name AS approver,r.result,r.error
            FROM ssh_key_retirement_requests r LEFT JOIN platform_users requester ON requester.id=r.requested_by
            LEFT JOIN platform_users approver ON approver.id=r.approved_by ORDER BY r.requested_at DESC""").fetchall()
    return [{"id":r["id"],"rotationId":r["rotation_id"],"status":r["status"],"requestNote":r["request_note"],
             "decisionNote":r["decision_note"],"requestedBy":r["requester"],"approvedBy":r["approver"],
             "requestedAt":r["requested_at"].isoformat(),"decidedAt":r["decided_at"].isoformat() if r["decided_at"] else None,
             "completedAt":r["completed_at"].isoformat() if r["completed_at"] else None,"result":r["result"],"error":r["error"]} for r in rows]


@app.get("/api/security/ssh-keys/retirements")
async def list_ssh_retirements(request: Request) -> dict[str, Any]:
    require_permission(request, "access.manage")
    return {"requests": await asyncio.to_thread(read_ssh_retirements)}


@app.post("/api/security/ssh-keys/retirements", status_code=201)
async def request_ssh_key_retirement(payload: SshRetirementDecision, request: Request) -> dict[str, Any]:
    actor = require_permission(request, "access.manage")
    with connect_db() as connection:
        existing = connection.execute("SELECT id FROM ssh_key_retirement_requests WHERE status IN ('pending','approved','running') LIMIT 1").fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="已有尚未完成的舊金鑰退役申請")
        active = connection.execute("SELECT id,public_key FROM ssh_key_rotations WHERE status='active' ORDER BY promoted_at DESC LIMIT 1").fetchone()
        if not active:
            raise HTTPException(status_code=409, detail="尚未完成新金鑰 promote")
        old = connection.execute("SELECT public_key FROM ssh_key_rotations WHERE status='superseded' ORDER BY promoted_at DESC LIMIT 1").fetchone()
        public_key = old["public_key"] if old else control_plane_public_key()
        if public_key.split()[:2] == active["public_key"].split()[:2]:
            raise HTTPException(status_code=409, detail="找不到可安全退役的舊金鑰")
        request_id = f"keyret-{uuid.uuid4().hex[:16]}"
        connection.execute("INSERT INTO ssh_key_retirement_requests(id,rotation_id,public_key_to_remove,status,requested_by,request_note) VALUES(%s,%s,%s,'pending',%s,%s)",
                           (request_id,active["id"],public_key,actor["id"],payload.note))
    await asyncio.to_thread(record_backend_audit, request, "security.ssh-key.retire.request", "申請退役舊 SSH 金鑰", request_id)
    return next(item for item in await asyncio.to_thread(read_ssh_retirements) if item["id"]==request_id)


@app.post("/api/security/ssh-keys/retirements/{retirement_id}/approve")
async def approve_ssh_key_retirement(retirement_id: str, payload: SshRetirementDecision, request: Request) -> dict[str, Any]:
    actor = require_permission(request, "tasks.approve")
    with connect_db() as connection:
        current = connection.execute("SELECT requested_by,status FROM ssh_key_retirement_requests WHERE id=%s", (retirement_id,)).fetchone()
        if not current or current["status"] != "pending": raise HTTPException(status_code=409,detail="退役申請不存在或已審核")
        if current["requested_by"] == actor["id"]: raise HTTPException(status_code=403,detail="舊金鑰退役必須由另一位管理員核准")
        connection.execute("UPDATE ssh_key_retirement_requests SET status='approved',approved_by=%s,decision_note=%s,decided_at=NOW() WHERE id=%s",
                           (actor["id"],payload.note,retirement_id))
    await asyncio.to_thread(record_backend_audit, request, "security.ssh-key.retire.approve", "核准退役舊 SSH 金鑰", retirement_id)
    return {"id":retirement_id,"status":"approved"}


@app.post("/api/security/ssh-keys/retirements/{retirement_id}/reject")
async def reject_ssh_key_retirement(retirement_id: str, payload: SshRetirementDecision, request: Request) -> dict[str, Any]:
    actor = require_permission(request, "tasks.approve")
    with connect_db() as connection:
        current = connection.execute("SELECT requested_by,status FROM ssh_key_retirement_requests WHERE id=%s", (retirement_id,)).fetchone()
        if not current or current["status"] != "pending": raise HTTPException(status_code=409,detail="退役申請不存在或已審核")
        if current["requested_by"] == actor["id"]: raise HTTPException(status_code=403,detail="申請者不能自行審核舊金鑰退役")
        connection.execute("UPDATE ssh_key_retirement_requests SET status='rejected',approved_by=%s,decision_note=%s,decided_at=NOW(),completed_at=NOW() WHERE id=%s",
                           (actor["id"],payload.note,retirement_id))
    await asyncio.to_thread(record_backend_audit, request, "security.ssh-key.retire.reject", "拒絕退役舊 SSH 金鑰", retirement_id)
    return {"id":retirement_id,"status":"rejected"}


@app.post("/api/security/ssh-keys/retirements/{retirement_id}/execute")
async def execute_ssh_key_retirement(retirement_id: str, request: Request) -> dict[str, Any]:
    require_permission(request, "tasks.execute")
    with connect_db() as connection:
        item = connection.execute("UPDATE ssh_key_retirement_requests SET status='running' WHERE id=%s AND status='approved' RETURNING public_key_to_remove", (retirement_id,)).fetchone()
    if not item: raise HTTPException(status_code=409,detail="退役申請必須先由另一位管理員核准")
    encoded = base64.b64encode(item["public_key_to_remove"].encode()).decode()
    results=[]
    for host in await asyncio.to_thread(load_inventory):
        try:
            command=f"key=$(printf %s {shlex.quote(encoded)} | base64 -d); grep -vxF \"$key\" ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.linux-ai-tmp && chmod 600 ~/.ssh/authorized_keys.linux-ai-tmp && mv ~/.ssh/authorized_keys.linux-ai-tmp ~/.ssh/authorized_keys"
            await run_ssh(host,command,timeout=15); results.append({"hostId":host["id"],"status":"removed"})
        except Exception as problem: results.append({"hostId":host["id"],"status":"failed","error":str(problem)[:300]})
    success=all(row["status"]=="removed" for row in results)
    with connect_db() as connection:
        connection.execute("UPDATE ssh_key_retirement_requests SET status=%s,result=%s::jsonb,error=%s,completed_at=NOW() WHERE id=%s",
                           ("completed" if success else "failed",json.dumps(results),None if success else "部分主機移除失敗",retirement_id))
        if success:
            connection.execute("UPDATE ssh_key_rotations SET status='retired' WHERE status='superseded' AND public_key=%s", (item["public_key_to_remove"],))
    await asyncio.to_thread(record_backend_audit, request, "security.ssh-key.retire.execute", "執行舊 SSH 金鑰退役", retirement_id, "success" if success else "partial")
    return {"id":retirement_id,"status":"completed" if success else "failed","hosts":results}


@app.post("/api/auth/logout")
async def logout(request: Request) -> JSONResponse:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        with connect_db() as connection:
            connection.execute(
                "DELETE FROM platform_sessions WHERE token_hash = %s", (token_hash(token),)
            )
    response = JSONResponse({"status": "ok"})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


def read_security_sessions(current_token_hash: str) -> dict[str, Any]:
    with connect_db() as connection:
        session_rows = connection.execute(
            """
            SELECT s.id, s.user_id, u.username, u.display_name, s.source_address,
                   s.user_agent, s.created_at, s.last_seen_at, s.expires_at,
                   s.token_hash = %s AS is_current
            FROM platform_sessions s
            JOIN platform_users u ON u.id = s.user_id
            WHERE s.expires_at > NOW()
            ORDER BY s.last_seen_at DESC
            """,
            (current_token_hash,),
        ).fetchall()
        event_rows = connection.execute(
            """
            SELECT e.id, e.username, u.display_name, e.success, e.reason,
                   e.source_address, e.user_agent, e.occurred_at
            FROM auth_login_events e
            LEFT JOIN platform_users u ON u.id = e.user_id
            ORDER BY e.occurred_at DESC LIMIT 100
            """
        ).fetchall()
    return {
        "sessions": [
            {
                "id": row["id"], "userId": row["user_id"],
                "username": row["username"], "displayName": row["display_name"],
                "sourceAddress": row["source_address"] or "未知",
                "userAgent": row["user_agent"] or "舊版 Session（未記錄）",
                "createdAt": row["created_at"].isoformat(),
                "lastSeenAt": row["last_seen_at"].isoformat(),
                "expiresAt": row["expires_at"].isoformat(),
                "isCurrent": row["is_current"],
            }
            for row in session_rows
        ],
        "loginEvents": [
            {
                "id": row["id"], "username": row["username"],
                "displayName": row["display_name"], "success": row["success"],
                "reason": row["reason"], "sourceAddress": row["source_address"] or "未知",
                "userAgent": row["user_agent"] or "未知",
                "occurredAt": row["occurred_at"].isoformat(),
            }
            for row in event_rows
        ],
        "policy": read_auth_security_policy(),
    }


@app.get("/api/security/sessions")
async def list_security_sessions(request: Request) -> dict[str, Any]:
    require_permission(request, "access.manage")
    current_hash = token_hash(request.cookies.get(SESSION_COOKIE, ""))
    return await asyncio.to_thread(read_security_sessions, current_hash)


@app.put("/api/security/policy")
async def update_auth_security_policy(
    payload: AuthSecurityPolicyUpdate, request: Request
) -> dict[str, Any]:
    actor = require_permission(request, "access.manage")
    with connect_db() as connection:
        if payload.require_mfa_admins:
            missing = connection.execute("""SELECT COUNT(DISTINCT u.id) AS count FROM platform_users u
                JOIN platform_user_groups ug ON ug.user_id=u.id AND ug.group_id='administrators'
                LEFT JOIN user_mfa m ON m.user_id=u.id AND m.enabled=TRUE
                WHERE u.enabled=TRUE AND m.user_id IS NULL""").fetchone()["count"]
            if missing:
                raise HTTPException(status_code=409, detail=f"仍有 {missing} 位啟用中的管理員尚未設定 MFA")
        connection.execute(
            """UPDATE auth_security_policy
               SET max_failed_attempts = %s, lockout_minutes = %s,
                   event_retention_days = %s, require_mfa_admins = %s, updated_at = NOW(), updated_by = %s
               WHERE id = 1""",
            (
                payload.max_failed_attempts, payload.lockout_minutes,
                payload.event_retention_days, payload.require_mfa_admins, actor["id"],
            ),
        )
    await asyncio.to_thread(record_backend_audit, request, "security.policy.update", "更新登入安全政策", "auth-security-policy")
    return {"policy": await asyncio.to_thread(read_auth_security_policy)}


@app.delete("/api/security/sessions/{session_id}", status_code=204)
async def revoke_security_session(session_id: str, request: Request) -> None:
    actor = require_permission(request, "access.manage")
    current_hash = token_hash(request.cookies.get(SESSION_COOKIE, ""))
    with connect_db() as connection:
        target = connection.execute(
            "SELECT id, user_id, token_hash FROM platform_sessions WHERE id = %s",
            (session_id,),
        ).fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="Session 不存在或已到期")
        if hmac.compare_digest(target["token_hash"], current_hash):
            raise HTTPException(status_code=409, detail="目前 Session 請使用左下角登出")
        connection.execute("DELETE FROM platform_sessions WHERE id = %s", (session_id,))
    return None


@app.post("/api/security/sessions/revoke-others")
async def revoke_other_sessions(request: Request) -> dict[str, Any]:
    actor = require_permission(request, "access.manage")
    current_hash = token_hash(request.cookies.get(SESSION_COOKIE, ""))
    with connect_db() as connection:
        result = connection.execute(
            "DELETE FROM platform_sessions WHERE user_id = %s AND token_hash <> %s",
            (actor["id"], current_hash),
        )
    return {"status": "ok", "revoked": result.rowcount}


@app.get("/api/access")
async def list_access(request: Request) -> dict[str, Any]:
    require_permission(request, "access.manage")
    def read_access() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        with connect_db() as connection:
            users = connection.execute(
                """
                SELECT u.id, u.username, u.display_name, u.enabled, u.created_at,
                       COALESCE(jsonb_agg(jsonb_build_object('id', g.id, 'name', g.name))
                           FILTER (WHERE g.id IS NOT NULL), '[]'::jsonb) AS groups
                FROM platform_users u
                LEFT JOIN platform_user_groups ug ON ug.user_id = u.id
                LEFT JOIN platform_groups g ON g.id = ug.group_id
                GROUP BY u.id
                ORDER BY u.created_at ASC
                """
            ).fetchall()
            groups = connection.execute(
                "SELECT id, name, permissions, system_group FROM platform_groups ORDER BY system_group DESC, name"
            ).fetchall()
        return (
            [{"id": row["id"], "username": row["username"], "displayName": row["display_name"], "enabled": row["enabled"], "createdAt": row["created_at"].isoformat(), "groups": row["groups"]} for row in users],
            [{"id": row["id"], "name": row["name"], "permissions": row["permissions"], "systemGroup": row["system_group"]} for row in groups],
        )
    access_data, policy = await asyncio.gather(
        asyncio.to_thread(read_access), asyncio.to_thread(read_password_policy)
    )
    users, groups = access_data
    return {"users": users, "groups": groups, "passwordPolicy": policy}


@app.post("/api/users", status_code=201)
async def create_user(payload: UserCreate, request: Request) -> dict[str, Any]:
    require_permission(request, "access.manage")
    await asyncio.to_thread(validate_password_policy, payload.password)
    username = payload.username.strip().lower()
    if not re.fullmatch(r"[a-z][a-z0-9._-]{2,63}", username):
        raise HTTPException(status_code=422, detail="帳號格式不正確")
    user_id = f"usr-{uuid.uuid4().hex[:16]}"
    try:
        with connect_db() as connection:
            group = connection.execute(
                "SELECT id FROM platform_groups WHERE id = %s", (payload.group_id,)
            ).fetchone()
            if not group:
                raise HTTPException(status_code=422, detail="指定的群組不存在")
            connection.execute(
                """
                INSERT INTO platform_users (id, username, display_name, password_hash)
                VALUES (%s, %s, %s, %s)
                """,
                (user_id, username, payload.display_name.strip(), hash_password(payload.password)),
            )
            connection.execute(
                "INSERT INTO platform_user_groups (user_id, group_id) VALUES (%s, %s)",
                (user_id, payload.group_id),
            )
    except psycopg.errors.UniqueViolation as error:
        raise HTTPException(status_code=409, detail="這個登入帳號已經存在") from error
    return {"id": user_id, "username": username}


@app.put("/api/users/{user_id}")
async def update_user(user_id: str, payload: UserUpdate, request: Request) -> dict[str, Any]:
    require_permission(request, "access.manage")
    with connect_db() as connection:
        target = connection.execute(
            """
            SELECT u.id,
                   EXISTS (SELECT 1 FROM platform_user_groups ug WHERE ug.user_id = u.id AND ug.group_id = 'administrators') AS is_admin
            FROM platform_users u WHERE u.id = %s
            """,
            (user_id,),
        ).fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="找不到這個使用者")
        group = connection.execute("SELECT id FROM platform_groups WHERE id = %s", (payload.group_id,)).fetchone()
        if not group:
            raise HTTPException(status_code=422, detail="指定的群組不存在")
        if target["is_admin"] and payload.group_id != "administrators":
            admin_count = connection.execute(
                "SELECT COUNT(DISTINCT user_id) AS count FROM platform_user_groups WHERE group_id = 'administrators'"
            ).fetchone()["count"]
            if admin_count <= 1:
                raise HTTPException(status_code=409, detail="至少必須保留一位系統管理員")
        connection.execute(
            "UPDATE platform_users SET display_name = %s WHERE id = %s",
            (payload.display_name.strip(), user_id),
        )
        connection.execute("DELETE FROM platform_user_groups WHERE user_id = %s", (user_id,))
        connection.execute(
            "INSERT INTO platform_user_groups (user_id, group_id) VALUES (%s, %s)",
            (user_id, payload.group_id),
        )
    return {"status": "ok"}


@app.post("/api/users/{user_id}/lock")
async def lock_user(user_id: str, payload: UserLock, request: Request) -> dict[str, Any]:
    actor = require_permission(request, "access.manage")
    if user_id == actor["id"] and payload.locked:
        raise HTTPException(status_code=409, detail="不能鎖定目前登入中的自己")
    with connect_db() as connection:
        target = connection.execute(
            """
            SELECT u.id, EXISTS (
                SELECT 1 FROM platform_user_groups ug
                WHERE ug.user_id = u.id AND ug.group_id = 'administrators'
            ) AS is_admin
            FROM platform_users u WHERE u.id = %s
            """,
            (user_id,),
        ).fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="找不到這個使用者")
        if payload.locked and target["is_admin"]:
            enabled_admins = connection.execute(
                """
                SELECT COUNT(DISTINCT u.id) AS count
                FROM platform_users u JOIN platform_user_groups ug ON ug.user_id = u.id
                WHERE ug.group_id = 'administrators' AND u.enabled = TRUE
                """
            ).fetchone()["count"]
            if enabled_admins <= 1:
                raise HTTPException(status_code=409, detail="不能鎖定最後一位啟用中的系統管理員")
        connection.execute("UPDATE platform_users SET enabled = %s WHERE id = %s", (not payload.locked, user_id))
        if payload.locked:
            connection.execute("DELETE FROM platform_sessions WHERE user_id = %s", (user_id,))
    return {"status": "locked" if payload.locked else "unlocked"}


@app.post("/api/users/{user_id}/reset-password")
async def reset_user_password(user_id: str, payload: PasswordReset, request: Request) -> dict[str, Any]:
    actor = require_permission(request, "access.manage")
    await asyncio.to_thread(validate_password_policy, payload.password)
    with connect_db() as connection:
        row = connection.execute(
            "UPDATE platform_users SET password_hash = %s WHERE id = %s RETURNING id",
            (hash_password(payload.password), user_id),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="找不到這個使用者")
        if user_id == actor["id"]:
            current_token_hash = token_hash(request.cookies.get(SESSION_COOKIE, ""))
            connection.execute(
                "DELETE FROM platform_sessions WHERE user_id = %s AND token_hash <> %s",
                (user_id, current_token_hash),
            )
        else:
            connection.execute("DELETE FROM platform_sessions WHERE user_id = %s", (user_id,))
    return {"status": "ok"}


@app.delete("/api/users/{user_id}", status_code=204)
async def delete_user(user_id: str, request: Request) -> None:
    actor = require_permission(request, "access.manage")
    if user_id == actor["id"]:
        raise HTTPException(status_code=409, detail="不能刪除目前登入中的自己")
    with connect_db() as connection:
        target = connection.execute(
            """
            SELECT u.id, EXISTS (
                SELECT 1 FROM platform_user_groups ug
                WHERE ug.user_id = u.id AND ug.group_id = 'administrators'
            ) AS is_admin
            FROM platform_users u WHERE u.id = %s
            """,
            (user_id,),
        ).fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="找不到這個使用者")
        if target["is_admin"]:
            admin_count = connection.execute(
                "SELECT COUNT(DISTINCT user_id) AS count FROM platform_user_groups WHERE group_id = 'administrators'"
            ).fetchone()["count"]
            if admin_count <= 1:
                raise HTTPException(status_code=409, detail="不能刪除最後一位系統管理員")
        connection.execute("DELETE FROM platform_users WHERE id = %s", (user_id,))


@app.post("/api/groups", status_code=201)
async def create_group(payload: GroupCreate, request: Request) -> dict[str, Any]:
    require_permission(request, "access.manage")
    allowed = {"hosts.read", "hosts.manage", "logs.read", "terminal.open", "audit.read", "access.manage", "alerts.read", "alerts.manage", "backup.read", "backup.manage", "ai.read", "ai.manage", "tasks.read", "tasks.request", "tasks.approve", "tasks.execute"}
    permissions = sorted(set(payload.permissions))
    if any(permission not in allowed for permission in permissions):
        raise HTTPException(status_code=422, detail="群組包含不支援的權限")
    group_id = f"grp-{uuid.uuid4().hex[:12]}"
    try:
        with connect_db() as connection:
            connection.execute(
                "INSERT INTO platform_groups (id, name, permissions) VALUES (%s, %s, %s::jsonb)",
                (group_id, payload.name.strip(), json.dumps(permissions)),
            )
    except psycopg.errors.UniqueViolation as error:
        raise HTTPException(status_code=409, detail="這個群組名稱已經存在") from error
    return {"id": group_id, "name": payload.name.strip(), "permissions": permissions}


@app.put("/api/groups/{group_id}")
async def update_group(group_id: str, payload: GroupUpdate, request: Request) -> dict[str, Any]:
    require_permission(request, "access.manage")
    if group_id == "administrators":
        raise HTTPException(status_code=403, detail="系統管理員群組不可修改")
    allowed = {"hosts.read", "hosts.manage", "logs.read", "terminal.open", "audit.read", "access.manage", "alerts.read", "alerts.manage", "backup.read", "backup.manage", "ai.read", "ai.manage", "tasks.read", "tasks.request", "tasks.approve", "tasks.execute"}
    permissions = sorted(set(payload.permissions))
    if any(permission not in allowed for permission in permissions):
        raise HTTPException(status_code=422, detail="群組包含不支援的權限")
    try:
        with connect_db() as connection:
            row = connection.execute(
                "UPDATE platform_groups SET name = %s, permissions = %s::jsonb WHERE id = %s RETURNING id",
                (payload.name.strip(), json.dumps(permissions), group_id),
            ).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="找不到這個群組")
    except psycopg.errors.UniqueViolation as error:
        raise HTTPException(status_code=409, detail="這個群組名稱已經存在") from error
    return {"status": "ok"}


@app.delete("/api/groups/{group_id}", status_code=204)
async def delete_group(group_id: str, request: Request) -> None:
    require_permission(request, "access.manage")
    if group_id == "administrators":
        raise HTTPException(status_code=403, detail="系統管理員群組不可刪除")
    with connect_db() as connection:
        members = connection.execute(
            "SELECT COUNT(*) AS count FROM platform_user_groups WHERE group_id = %s", (group_id,)
        ).fetchone()["count"]
        if members:
            raise HTTPException(status_code=409, detail="群組仍有使用者，請先將使用者移至其他群組")
        row = connection.execute("DELETE FROM platform_groups WHERE id = %s RETURNING id", (group_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="找不到這個群組")


@app.put("/api/password-policy")
async def update_password_policy(payload: PasswordPolicyUpdate, request: Request) -> dict[str, Any]:
    actor = require_permission(request, "access.manage")
    with connect_db() as connection:
        connection.execute(
            """
            UPDATE password_policy
            SET min_length = %s, require_upper = %s, require_lower = %s,
                require_number = %s, require_special = %s,
                updated_at = NOW(), updated_by = %s
            WHERE id = 1
            """,
            (payload.min_length, payload.require_upper, payload.require_lower,
             payload.require_number, payload.require_special, actor["id"]),
        )
    return {"passwordPolicy": await asyncio.to_thread(read_password_policy)}


def ssh_command(host: dict[str, Any], remote_command: str) -> list[str]:
    return [
        "ssh",
        "-i",
        SSH_KEY_PATH,
        "-p",
        str(host.get("port", 22)),
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={KNOWN_HOSTS_PATH}",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "LogLevel=ERROR",
        f"{host['user']}@{host['address']}",
        remote_command,
    ]


async def run_ssh(host: dict[str, Any], remote_command: str, timeout: float = 8) -> str:
    async with ssh_semaphore:
        return await _run_ssh_unlimited(host, remote_command, timeout)


async def _run_ssh_unlimited(host: dict[str, Any], remote_command: str, timeout: float = 8) -> str:
    with connect_db() as database:
        active = database.execute(
            "SELECT private_key_encrypted FROM ssh_key_rotations WHERE status='active' ORDER BY promoted_at DESC LIMIT 1"
        ).fetchone()
    if active:
        try:
            ssh = await asyncio.wait_for(asyncssh.connect(
                host["address"], port=host.get("port", 22), username=host["user"],
                client_keys=[asyncssh.import_private_key(decrypt_secret(active["private_key_encrypted"]))],
                known_hosts=KNOWN_HOSTS_PATH,
            ), timeout=timeout)
            try:
                result = await asyncio.wait_for(ssh.run(remote_command, check=False), timeout=timeout)
            finally:
                ssh.close()
                await ssh.wait_closed()
            if result.exit_status != 0:
                raise RuntimeError((result.stderr or "").strip() or f"SSH exited with status {result.exit_status}")
            return result.stdout
        except (asyncssh.Error, OSError, TimeoutError) as error:
            raise RuntimeError(str(error)) from error
    process = await asyncio.create_subprocess_exec(
        *ssh_command(host, remote_command),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.CancelledError:
        process.kill()
        await process.wait()
        raise
    except TimeoutError:
        process.kill()
        await process.wait()
        raise RuntimeError("SSH probe timed out") from None
    if process.returncode != 0:
        detail = stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(detail or f"SSH exited with status {process.returncode}")
    return stdout.decode("utf-8", errors="replace")


def normalize_bootstrap_target(address: str, admin_user: str, password: str) -> tuple[str, str]:
    try:
        normalized_address = str(ipaddress.ip_address(address.strip()))
    except ValueError as error:
        raise HTTPException(status_code=422, detail="目前只接受有效的 IPv4 或 IPv6 位址") from error
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,31}", admin_user):
        raise HTTPException(status_code=422, detail="首次設定帳號格式不正確")
    if "\n" in password or "\r" in password:
        raise HTTPException(status_code=422, detail="首次設定密碼格式不正確")
    return normalized_address, admin_user


async def bootstrap_connection(
    address: str,
    port: int,
    admin_user: str,
    password: str,
) -> asyncssh.SSHClientConnection:
    try:
        return await asyncio.wait_for(
            asyncssh.connect(
                address,
                port=port,
                username=admin_user,
                password=password,
                known_hosts=None,
                client_keys=None,
                preferred_auth=["password", "keyboard-interactive"],
            ),
            timeout=10,
        )
    except (asyncssh.Error, OSError, TimeoutError) as error:
        raise HTTPException(
            status_code=422,
            detail=f"無法使用首次設定帳號登入 SSH：{str(error)[:180]}",
        ) from error


def server_identity(connection: asyncssh.SSHClientConnection) -> tuple[str, str]:
    key = connection.get_server_host_key()
    return key.get_fingerprint("sha256"), key.export_public_key().decode().strip()


def control_plane_public_key() -> str:
    try:
        command = subprocess.run(
            ["ssh-keygen", "-y", "-f", SSH_KEY_PATH],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        result = command.stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as error:
        raise HTTPException(status_code=500, detail="中央 SSH 私鑰無法讀取") from error
    if not result.startswith(("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-")):
        raise HTTPException(status_code=500, detail="無法從中央 SSH 私鑰取得公鑰")
    return f"{result} linux-ai-control-plane"


async def save_known_host(address: str, port: int, public_key: str) -> None:
    host_pattern = address if port == 22 else f"[{address}]:{port}"
    line = f"{host_pattern} {public_key}"
    async with known_hosts_lock:
        path = Path(KNOWN_HOSTS_PATH)
        current = path.read_text(encoding="utf-8") if path.exists() else ""
        if line in current.splitlines():
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            if current and not current.endswith("\n"):
                handle.write("\n")
            handle.write(f"{line}\n")


async def probe_host(host: dict[str, Any], force: bool = False) -> dict[str, Any]:
    cached = probe_cache.get(host["id"])
    if not force and cached and time.monotonic() - cached[0] < PROBE_TTL_SECONDS:
        return cached[1]

    encoded_probe = base64.b64encode(REMOTE_PROBE.encode()).decode()
    command = f"python3 -c \"import base64;exec(base64.b64decode('{encoded_probe}'))\""
    try:
        payload = json.loads(await run_ssh(host, command))
        warning = bool(payload["failed_services"]) or max(
            payload["cpu"], payload["ram"], payload["disk"]
        ) >= 80
        result = {
            "id": host["id"],
            "name": payload["hostname"],
            "ip": host["address"],
            "group": host["group"],
            "os": payload["os"],
            "cpu": payload["cpu"],
            "ram": payload["ram"],
            "disk": payload["disk"],
            "load": payload["load"],
            "uptimeSeconds": payload["uptime_seconds"],
            "memoryTotal": payload["memory_total"],
            "memoryAvailable": payload["memory_available"],
            "diskTotal": payload["disk_total"],
            "diskFree": payload["disk_free"],
            "failedServices": payload["failed_services"],
            "state": "warning" if warning else "healthy",
            "seen": "剛剛",
            "lastSeenAt": utc_now(),
            "machineId": host["machine_id"],
            "hostKeyFingerprint": host["host_key_fingerprint"],
        }
    except (RuntimeError, json.JSONDecodeError, KeyError) as error:
        result = {
            "id": host["id"],
            "name": host["name"],
            "ip": host["address"],
            "group": host["group"],
            "os": "Unknown",
            "cpu": 0,
            "ram": 0,
            "disk": 0,
            "failedServices": [],
            "state": "offline",
            "seen": "無法連線",
            "lastSeenAt": None,
            "error": str(error)[:240],
            "machineId": host["machine_id"],
            "hostKeyFingerprint": host["host_key_fingerprint"],
        }
    probe_cache[host["id"]] = (time.monotonic(), result)
    return result


def get_host(host_id: str) -> dict[str, Any]:
    for host in load_inventory():
        if host["id"] == host_id:
            return host
    raise HTTPException(status_code=404, detail="Host not found")


def redact_diagnostic_text(value: str) -> tuple[str, int]:
    """Remove common credentials and personal identifiers before AI/API storage."""
    patterns = (
        (r"-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----", "[REDACTED_PRIVATE_KEY]"),
        (r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED_TOKEN]"),
        (r"(?i)\b(password|passwd|token|secret|api[_-]?key|authorization)\b\s*[:=]\s*[^\s,;]+", r"\1=[REDACTED]"),
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[REDACTED_EMAIL]"),
    )
    redacted = value
    count = 0
    for pattern, replacement in patterns:
        redacted, matches = re.subn(pattern, replacement, redacted)
        count += matches
    return redacted[:16000], count


def diagnostic_schema() -> dict[str, Any]:
    finding = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "title": {"type": "string"},
            "explanation": {"type": "string"},
            "evidenceRefs": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["title", "explanation", "evidenceRefs"],
    }
    action = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "title": {"type": "string"},
            "rationale": {"type": "string"},
            "risk": {"type": "string", "enum": ["low", "medium", "high"]},
            "command": {"type": "string"},
        },
        "required": ["title", "rationale", "risk", "command"],
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "summary": {"type": "string"},
            "risk": {"type": "string", "enum": ["low", "medium", "high"]},
            "findings": {"type": "array", "items": finding},
            "actions": {"type": "array", "items": action},
            "limitations": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["summary", "risk", "findings", "actions", "limitations"],
    }


def extract_response_text(response: dict[str, Any]) -> str:
    for item in response.get("output", []):
        if item.get("type") != "message":
            continue
        for content in item.get("content", []):
            if content.get("type") == "refusal":
                raise RuntimeError(f"模型拒絕診斷：{content.get('refusal', '未提供原因')}")
            if content.get("type") == "output_text" and content.get("text"):
                return str(content["text"])
    raise RuntimeError("OpenAI 回應中沒有可用的診斷內容")


def local_rule_diagnosis(evidence: list[dict[str, str]]) -> dict[str, Any]:
    """Generate a deterministic, no-cost diagnosis from the collected snapshot."""
    try:
        probe = json.loads(next(item["content"] for item in evidence if item["id"] == "E1"))
    except (StopIteration, json.JSONDecodeError, KeyError, TypeError):
        probe = {}
    findings: list[dict[str, Any]] = []
    actions: list[dict[str, Any]] = []
    risks = {"low": 0, "medium": 1, "high": 2}
    overall_risk = "low"

    def add_finding(title: str, explanation: str, risk: str, command: str = "") -> None:
        nonlocal overall_risk
        findings.append({"title": title, "explanation": explanation, "evidenceRefs": ["E1"]})
        actions.append({
            "title": f"檢查：{title}",
            "rationale": "先由維運人員確認即時狀態與影響範圍，再決定是否變更。",
            "risk": risk,
            "command": command,
        })
        if risks[risk] > risks[overall_risk]:
            overall_risk = risk

    state = probe.get("state", "offline")
    if state == "offline":
        add_finding("SSH 探測失敗", f"中央目前無法取得主機即時資料：{probe.get('error', '未提供原因')}", "high", "systemctl status ssh --no-pager")
    else:
        cpu = float(probe.get("cpu", 0) or 0)
        ram = float(probe.get("ram", 0) or 0)
        disk = float(probe.get("disk", 0) or 0)
        failed_services = probe.get("failedServices", []) or []
        if cpu >= 90:
            add_finding("CPU 使用率過高", f"即時 CPU 使用率為 {cpu:.1f}%，已達 90% 規則門檻。", "medium", "ps -eo pid,comm,%cpu --sort=-%cpu | head")
        if ram >= 85:
            add_finding("記憶體使用率過高", f"即時記憶體使用率為 {ram:.1f}%，已達 85% 規則門檻。", "medium", "free -h; ps -eo pid,comm,%mem --sort=-%mem | head")
        if disk >= 80:
            add_finding("根目錄磁碟空間偏高", f"根目錄使用率為 {disk:.1f}%，已達 80% 規則門檻。", "high", "df -h /; du -xhd1 / 2>/dev/null | sort -h")
        if failed_services:
            add_finding("systemd 服務失敗", f"探測發現 {len(failed_services)} 個失敗服務。", "high", "systemctl --failed --no-pager")

    journal = next((item.get("content", "") for item in evidence if item.get("id") == "E2"), "")
    journal_lines = [line for line in journal.splitlines() if line.strip()]
    if journal_lines and not journal.startswith("-- No entries --"):
        severe = sum(1 for line in journal_lines if re.search(r"(?i)failed|error|denied|critical", line))
        if severe:
            findings.append({
                "title": "警告日誌含錯誤關鍵字",
                "explanation": f"最近 warning 以上日誌共 {len(journal_lines)} 行，其中 {severe} 行符合 failed/error/denied/critical 規則。",
                "evidenceRefs": ["E2"],
            })
            actions.append({
                "title": "人工檢視警告日誌",
                "rationale": "確認錯誤是否持續發生，以及是否與目前服務或資源異常相關。",
                "risk": "low",
                "command": "journalctl -b -p warning -n 50 --no-pager",
            })
            if overall_risk == "low":
                overall_risk = "medium"

    if not findings:
        findings.append({
            "title": "規則檢查未發現明顯異常",
            "explanation": "目前快照未超過 CPU、記憶體、磁碟、離線或失敗服務門檻。",
            "evidenceRefs": ["E1"],
        })
        actions.append({
            "title": "持續監控",
            "rationale": "單次快照正常不代表長期沒有問題，請持續觀察歷史趨勢與告警。",
            "risk": "low",
            "command": "",
        })

    return {
        "summary": {
            "low": "本機規則診斷未發現需要立即處理的異常。",
            "medium": "本機規則診斷發現需要人工確認的狀況。",
            "high": "本機規則診斷發現高優先度狀況，建議儘快人工確認。",
        }[overall_risk],
        "risk": overall_risk,
        "findings": findings,
        "actions": actions,
        "limitations": [
            "此結果由固定門檻與關鍵字規則產生，未呼叫付費 AI。",
            "只代表診斷當下的快照，所有建議指令都必須由維運人員審查。",
        ],
    }


def request_openai_diagnosis(evidence: list[dict[str, str]], actor_id: str) -> dict[str, Any]:
    payload = {
        "model": OPENAI_MODEL,
        "store": False,
        "reasoning": {"effort": "low"},
        "safety_identifier": hashlib.sha256(f"linux-ai:{actor_id}".encode()).hexdigest()[:32],
        "instructions": (
            "你是防禦性 Linux 維運分析助理。只能根據提供的證據用繁體中文診斷；"
            "每項發現必須引用存在的證據編號。不得假設未提供的狀態，不得聲稱已執行任何指令。"
            "建議指令只能是供人工審查的唯讀或低風險修復建議；不確定時將 command 留空字串。"
        ),
        "input": "請分析以下已遮罩的主機證據：\n" + json.dumps(evidence, ensure_ascii=False),
        "text": {
            "format": {
                "type": "json_schema",
                "name": "linux_host_diagnosis",
                "strict": True,
                "schema": diagnostic_schema(),
            }
        },
    }
    request = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=OPENAI_TIMEOUT_SECONDS) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"OpenAI API 回傳 HTTP {error.code}: {detail}") from error
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise RuntimeError(f"無法取得 OpenAI 診斷：{error}") from error
    try:
        return json.loads(extract_response_text(body))
    except json.JSONDecodeError as error:
        raise RuntimeError("OpenAI 診斷不是有效的結構化 JSON") from error


async def collect_diagnostic_evidence(host: dict[str, Any]) -> tuple[list[dict[str, str]], int]:
    probe = await probe_host(host, force=True)
    evidence_raw = [
        ("E1", "中央即時探測", json.dumps(probe, ensure_ascii=False, default=str)),
    ]
    if probe.get("state") != "offline":
        try:
            journal = await run_ssh(
                host,
                "journalctl -b -p warning -n 30 --no-pager --output=short-iso 2>&1",
                timeout=12,
            )
        except RuntimeError as error:
            journal = f"無法讀取警告日誌：{error}"
        evidence_raw.append(("E2", "本次開機的 warning 以上日誌（最多 30 筆）", journal))
    evidence: list[dict[str, str]] = []
    redaction_count = 0
    for evidence_id, title, content in evidence_raw:
        clean, count = redact_diagnostic_text(content)
        redaction_count += count
        evidence.append({"id": evidence_id, "title": title, "content": clean})
    return evidence, redaction_count


def metric_value(sample: dict[str, Any], metric: str) -> float:
    if metric == "availability":
        return 1.0 if sample.get("state") == "offline" else 0.0
    if metric == "failed_services":
        return float(sample.get("failed_service_count", 0))
    return float(sample.get(f"{metric}_percent", 0))


def rule_is_violated(sample: dict[str, Any], metric: str, threshold: float) -> bool:
    return metric_value(sample, metric) >= threshold


def alert_message(host_name: str, rule: dict[str, Any], value: float) -> str:
    metric = rule["metric"]
    if metric == "availability":
        detail = "SSH 無法連線"
    elif metric == "failed_services":
        detail = f"{int(value)} 個 systemd 服務失敗"
    else:
        labels = {"cpu": "CPU", "ram": "記憶體", "disk": "磁碟"}
        detail = f"{labels[metric]} 使用率 {value:.1f}%（門檻 {float(rule['threshold']):.1f}%）"
    return f"{host_name}：{detail}"


def notification_channels() -> list[dict[str, Any]]:
    webhook_host = urllib.parse.urlparse(ALERT_WEBHOOK_URL).hostname or ""
    sms_host = urllib.parse.urlparse(SMS_GATEWAY_URL).hostname or ""
    return [
        {
            "id": "telegram",
            "name": "Telegram",
            "enabled": bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID),
            "destination": f"Chat …{TELEGRAM_CHAT_ID[-4:]}" if TELEGRAM_CHAT_ID else "尚未設定",
        },
        {
            "id": "line",
            "name": "LINE Messaging API",
            "enabled": bool(LINE_CHANNEL_ACCESS_TOKEN and LINE_TARGET_ID),
            "destination": f"Target …{LINE_TARGET_ID[-4:]}" if LINE_TARGET_ID else "尚未設定",
        },
        {
            "id": "sms",
            "name": "Android SMS Gateway",
            "enabled": bool(SMS_GATEWAY_URL and SMS_TO_NUMBER),
            "destination": f"{sms_host} / …{SMS_TO_NUMBER[-4:]}" if SMS_TO_NUMBER else "尚未設定",
        },
        {
            "id": "webhook",
            "name": "通用 Webhook / SMS Gateway",
            "enabled": bool(ALERT_WEBHOOK_URL),
            "destination": webhook_host or "尚未設定",
        },
        {
            "id": "email", "name": "SMTP Email",
            "enabled": bool(SMTP_HOST and SMTP_FROM and SMTP_TO),
            "destination": f"{len(SMTP_TO)} 位收件者 / {SMTP_HOST}" if SMTP_TO else "尚未設定",
        },
    ]

def render_notification_template(template:str,context:dict[str,str])->str:
    result=template
    for key,value in context.items(): result=result.replace("{{"+key+"}}",value)
    return result

def resolve_notification_route(intent:dict[str,Any],enabled_channels:list[str])->tuple[list[str],dict[str,Any]|None,dict[str,str]]:
    if intent.get("kind") not in {"firing","resolved","test"}: return enabled_channels,None,{"title":"","message":intent["message"]}
    host_id=intent.get("hostId"); rule_id=intent.get("ruleId"); host_name=intent.get("hostName","全部主機"); rule_name=intent.get("ruleName","全部規則")
    with connect_db() as connection:
        if intent.get("eventId"):
            scope=connection.execute("SELECT e.host_id,e.rule_id,h.name AS host_name,r.name AS rule_name FROM alert_events e JOIN managed_hosts h ON h.id=e.host_id JOIN alert_rules r ON r.id=e.rule_id WHERE e.id=%s",(intent["eventId"],)).fetchone()
            if scope: host_id=scope["host_id"]; rule_id=scope["rule_id"]; host_name=scope["host_name"]; rule_name=scope["rule_name"]
        route=connection.execute("SELECT * FROM notification_routes WHERE enabled=TRUE AND (severity IS NULL OR severity=%s) AND (host_id IS NULL OR host_id=%s) AND (rule_id IS NULL OR rule_id=%s) ORDER BY priority LIMIT 1",(intent["severity"],host_id,rule_id)).fetchone()
    context={"severity":intent["severity"],"host":host_name,"rule":rule_name,"message":intent["message"],"kind":intent["kind"]}
    if not route: return enabled_channels,None,{"title":"","message":intent["message"]}
    selected=[channel for channel in route["channels"] if channel in enabled_channels]
    title=render_notification_template(route["title_template"],context); body=render_notification_template(route["body_template"],context)
    return selected,route,{"title":title,"message":f"{title}\n{body}"}


def write_notification_delivery(
    channel: str,
    intent: dict[str, Any],
    status: str,
    destination_hint: str,
    response_detail: str,
) -> dict[str, Any]:
    delivery_id = f"ntf-{uuid.uuid4().hex[:20]}"
    with connect_db() as connection:
        connection.execute(
            """
            INSERT INTO notification_deliveries (
                id, alert_event_id, channel, kind, status,
                destination_hint, message, response_detail
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                delivery_id, intent.get("eventId"), channel, intent["kind"], status,
                destination_hint, intent["message"], response_detail[:240],
            ),
        )
    return {"id": delivery_id, "channel": channel, "status": status, "responseDetail": response_detail[:240]}


def send_notification(channel: str, intent: dict[str, Any]) -> dict[str, Any]:
    headers = {"Content-Type": "application/json", "User-Agent": "linux-ai-control-plane/1"}
    if channel == "email":
        destination = f"{len(SMTP_TO)} 位收件者 / {SMTP_HOST}"
        message = EmailMessage(); message["Subject"] = "Linux AI Control Plane 通知"; message["From"] = SMTP_FROM
        message["To"] = ", ".join(SMTP_TO); message.set_content(intent["message"])
        try:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=NOTIFICATION_TIMEOUT_SECONDS) as client:
                if SMTP_USE_TLS: client.starttls()
                if SMTP_USERNAME: client.login(SMTP_USERNAME, SMTP_PASSWORD)
                client.send_message(message)
            return write_notification_delivery(channel,intent,"sent",destination,"SMTP accepted")
        except (smtplib.SMTPException,OSError,TimeoutError) as error:
            return write_notification_delivery(channel,intent,"failed",destination,type(error).__name__)
    if channel == "telegram":
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {"chat_id": TELEGRAM_CHAT_ID, "text": intent["message"]}
        destination = f"Chat …{TELEGRAM_CHAT_ID[-4:]}"
    elif channel == "line":
        url = "https://api.line.me/v2/bot/message/push"
        payload = {
            "to": LINE_TARGET_ID,
            "messages": [{"type": "text", "text": intent["message"][:5000]}],
        }
        destination = f"Target …{LINE_TARGET_ID[-4:]}"
        headers["Authorization"] = f"Bearer {LINE_CHANNEL_ACCESS_TOKEN}"
        headers["X-Line-Retry-Key"] = intent["retryKey"]
    elif channel == "sms":
        parsed = urllib.parse.urlparse(SMS_GATEWAY_URL)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return write_notification_delivery(
                channel, intent, "failed", "設定錯誤", "SMS Gateway URL 格式不正確"
            )
        url = SMS_GATEWAY_URL
        payload = {
            "to": SMS_TO_NUMBER,
            "message": intent["message"],
            "idempotencyKey": intent["retryKey"],
        }
        destination = f"{parsed.hostname} / …{SMS_TO_NUMBER[-4:]}"
        if SMS_GATEWAY_TOKEN:
            headers["Authorization"] = f"Bearer {SMS_GATEWAY_TOKEN}"
    elif channel == "webhook":
        parsed = urllib.parse.urlparse(ALERT_WEBHOOK_URL)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return write_notification_delivery(
                channel, intent, "failed", "設定錯誤", "Webhook URL 格式不正確"
            )
        url = ALERT_WEBHOOK_URL
        payload = {
            "source": "linux-ai-control-plane",
            "kind": intent["kind"],
            "severity": intent["severity"],
            "message": intent["message"],
            "alertEventId": intent.get("eventId"),
            "occurredAt": utc_now(),
        }
        destination = parsed.hostname
        if ALERT_WEBHOOK_TOKEN:
            headers["Authorization"] = f"Bearer {ALERT_WEBHOOK_TOKEN}"
    else:
        raise ValueError("unsupported notification channel")
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=NOTIFICATION_TIMEOUT_SECONDS) as response:
            detail = f"HTTP {response.status}"
        return write_notification_delivery(channel, intent, "sent", destination, detail)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as error:
        if isinstance(error, urllib.error.HTTPError):
            detail = f"HTTP {error.code}"
        else:
            detail = type(error).__name__
        return write_notification_delivery(channel, intent, "failed", destination, detail)


def enqueue_notification_retry(
    channel: str, intent: dict[str, Any], error_detail: str
) -> None:
    with connect_db() as connection:
        connection.execute(
            """
            INSERT INTO notification_retry_jobs (
                id, alert_event_id, channel, kind, severity, message,
                retry_key, status, attempt_count, max_attempts,
                next_attempt_at, last_error
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, 'queued', 1, 4,
                      NOW() + INTERVAL '1 minute', %s)
            ON CONFLICT (channel, retry_key) DO NOTHING
            """,
            (
                f"nrt-{uuid.uuid4().hex[:20]}", intent.get("eventId"), channel,
                intent["kind"], intent["severity"], intent["message"],
                intent["retryKey"], error_detail[:240],
            ),
        )


def claim_notification_retry() -> dict[str, Any] | None:
    with connect_db() as connection:
        connection.execute(
            """
            UPDATE notification_retry_jobs
            SET status = 'queued', next_attempt_at = NOW(), updated_at = NOW()
            WHERE status = 'sending' AND updated_at < NOW() - INTERVAL '10 minutes'
            """
        )
        return connection.execute(
            """
            WITH selected AS (
                SELECT id FROM notification_retry_jobs
                WHERE status = 'queued' AND next_attempt_at <= NOW()
                ORDER BY next_attempt_at
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            UPDATE notification_retry_jobs j
            SET status = 'sending', attempt_count = attempt_count + 1, updated_at = NOW()
            FROM selected
            WHERE j.id = selected.id
            RETURNING j.*
            """
        ).fetchone()


def finish_notification_retry(job: dict[str, Any], result: dict[str, Any]) -> None:
    sent = result["status"] == "sent"
    final_failure = not sent and job["attempt_count"] >= job["max_attempts"]
    delay_seconds = 300 if job["attempt_count"] == 2 else 900
    with connect_db() as connection:
        connection.execute(
            """
            UPDATE notification_retry_jobs
            SET status = %s,
                next_attempt_at = CASE WHEN %s THEN next_attempt_at ELSE NOW() + (%s * INTERVAL '1 second') END,
                last_error = %s,
                updated_at = NOW()
            WHERE id = %s
            """,
            (
                "sent" if sent else "failed" if final_failure else "queued",
                sent or final_failure,
                delay_seconds,
                None if sent else result.get("responseDetail", "傳送失敗")[:240],
                job["id"],
            ),
        )


async def notification_retry_loop() -> None:
    while True:
        try:
            job = await asyncio.to_thread(claim_notification_retry)
            if job:
                intent = {
                    "eventId": job["alert_event_id"], "kind": job["kind"],
                    "severity": job["severity"], "message": job["message"],
                    "retryKey": job["retry_key"],
                }
                result = await asyncio.to_thread(send_notification, job["channel"], intent)
                await asyncio.to_thread(finish_notification_retry, job, result)
                continue
        except (psycopg.Error, OSError, RuntimeError, ValueError):
            pass
        await asyncio.sleep(15)


async def dispatch_notifications(intents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    enabled = [channel["id"] for channel in notification_channels() if channel["enabled"]]
    if not intents or not enabled:
        return []
    pairs: list[tuple[str, dict[str, Any]]] = []
    for intent in intents:
        intent.setdefault("retryKey", str(uuid.uuid4()))
        selected,route,rendered=await asyncio.to_thread(resolve_notification_route,intent,enabled)
        intent["message"]=rendered["message"]; intent["routeId"]=route["id"] if route else None
        suppressed=False; reason=""
        if intent.get("kind") not in {"test"}:
            with connect_db() as connection:
                policy=connection.execute("SELECT * FROM notification_governance_policy WHERE id=1").fetchone()
                silence=None
                if intent.get("eventId"):
                    silence=connection.execute("""SELECT s.name FROM alert_silences s JOIN alert_events e ON e.id=%s WHERE s.starts_at<=NOW() AND s.ends_at>NOW() AND (s.host_id IS NULL OR s.host_id=e.host_id) AND (s.rule_id IS NULL OR s.rule_id=e.rule_id) ORDER BY s.created_at DESC LIMIT 1""",(intent["eventId"],)).fetchone()
                if silence: suppressed=True; reason=f"靜音規則：{silence['name']}"
                elif policy and policy["quiet_enabled"] and not(intent.get("severity")=="critical" and policy["critical_bypass"]):
                    hour=datetime.now(timezone.utc).hour; start=policy["quiet_start_hour"]; end=policy["quiet_end_hour"]
                    if (start<end and start<=hour<end) or (start>end and (hour>=start or hour<end)) or start==end: suppressed=True; reason="全域安靜時段"
        if suppressed:
            for channel in selected: await asyncio.to_thread(write_notification_delivery,channel,intent,"suppressed",next(c["destination"] for c in notification_channels() if c["id"]==channel),reason)
            continue
        pairs.extend((channel, intent) for channel in selected)
    results = await asyncio.gather(
        *(asyncio.to_thread(send_notification, channel, intent) for channel, intent in pairs)
    )
    for (channel, intent), result in zip(pairs, results, strict=True):
        if result["status"] == "failed":
            await asyncio.to_thread(
                enqueue_notification_retry,
                channel,
                intent,
                result.get("responseDetail", "傳送失敗"),
            )
    return results


def persist_sample_and_evaluate(
    host: dict[str, Any], result: dict[str, Any]
) -> list[dict[str, Any]]:
    notifications: list[dict[str, Any]] = []
    load_values = result.get("load") or []
    sample = {
        "state": result.get("state", "offline"),
        "cpu_percent": float(result.get("cpu", 0)),
        "ram_percent": float(result.get("ram", 0)),
        "disk_percent": float(result.get("disk", 0)),
        "load_one": float(load_values[0]) if load_values else None,
        "uptime_seconds": int(result.get("uptimeSeconds", 0)) if result.get("uptimeSeconds") is not None else None,
        "failed_service_count": len(result.get("failedServices") or []),
        "error": str(result.get("error", ""))[:240] or None,
    }
    with connect_db() as connection:
        connection.execute(
            """
            INSERT INTO host_metric_samples (
                host_id, state, cpu_percent, ram_percent, disk_percent,
                load_one, uptime_seconds, failed_service_count, error
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                host["id"], sample["state"], sample["cpu_percent"],
                sample["ram_percent"], sample["disk_percent"], sample["load_one"],
                sample["uptime_seconds"], sample["failed_service_count"], sample["error"],
            ),
        )
        rules = connection.execute(
            """
            SELECT id, name, metric, threshold, consecutive_samples, severity
            FROM alert_rules WHERE enabled = TRUE AND metric NOT IN ('log_collection','asset_drift','security_updates','security_baseline','capacity_forecast') ORDER BY created_at
            """
        ).fetchall()
        for rule in rules:
            recent = connection.execute(
                """
                SELECT state, cpu_percent, ram_percent, disk_percent,
                       failed_service_count
                FROM host_metric_samples
                WHERE host_id = %s
                ORDER BY collected_at DESC
                LIMIT %s
                """,
                (host["id"], rule["consecutive_samples"]),
            ).fetchall()
            firing = len(recent) == rule["consecutive_samples"] and all(
                rule_is_violated(row, rule["metric"], float(rule["threshold"]))
                for row in recent
            )
            active = connection.execute(
                """
                SELECT id FROM alert_events
                WHERE rule_id = %s AND host_id = %s
                  AND status IN ('firing', 'acknowledged')
                """,
                (rule["id"], host["id"]),
            ).fetchone()
            value = metric_value(sample, rule["metric"])
            if firing and active:
                connection.execute(
                    """
                    UPDATE alert_events
                    SET last_value = %s, message = %s, updated_at = NOW()
                    WHERE id = %s
                    """,
                    (value, alert_message(result["name"], rule, value), active["id"]),
                )
            elif firing:
                event_id = f"alt-{uuid.uuid4().hex[:20]}"
                message = alert_message(result["name"], rule, value)
                connection.execute(
                    """
                    INSERT INTO alert_events (
                        id, rule_id, host_id, status, severity, message, last_value
                    ) VALUES (%s, %s, %s, 'firing', %s, %s, %s)
                    """,
                    (
                        event_id, rule["id"], host["id"],
                        rule["severity"], message, value,
                    ),
                )
                notifications.append(
                    {
                        "eventId": event_id,
                        "kind": "firing",
                        "severity": rule["severity"],
                        "message": f"🚨 [Linux AI {rule['severity'].upper()}]\n{message}",
                    }
                )
            elif active:
                connection.execute(
                    """
                    UPDATE alert_events
                    SET status = 'resolved', last_value = %s,
                        updated_at = NOW(), resolved_at = NOW()
                    WHERE id = %s
                    """,
                    (value, active["id"]),
                )
                notifications.append(
                    {
                        "eventId": active["id"],
                        "kind": "resolved",
                        "severity": rule["severity"],
                        "message": f"✅ [Linux AI 已恢復]\n{result['name']}：{rule['name']}",
                    }
                )
        connection.execute(
            "DELETE FROM host_metric_samples WHERE collected_at < NOW() - (%s * INTERVAL '1 day')",
            (METRIC_RETENTION_DAYS,),
        )
    return notifications


async def collect_monitoring_cycle() -> None:
    async with monitor_cycle_lock:
        inventory = await asyncio.to_thread(load_inventory)
        async with probe_lock:
            results = await asyncio.gather(
                *(probe_host(host, force=True) for host in inventory)
            )
        notification_batches = await asyncio.gather(
            *(
                asyncio.to_thread(persist_sample_and_evaluate, host, result)
                for host, result in zip(inventory, results, strict=True)
            )
        )
        await dispatch_notifications(
            [intent for batch in notification_batches for intent in batch]
        )


async def monitor_loop() -> None:
    while True:
        try:
            await collect_monitoring_cycle()
        except (psycopg.Error, OSError, RuntimeError):
            # A failed cycle must not stop future monitoring attempts.
            pass
        await asyncio.sleep(MONITOR_INTERVAL_SECONDS)

def refresh_metric_rollups()->None:
    with connect_db() as connection:
        for table,bucket,window in (("host_metric_hourly","hour","48 hours"),("host_metric_daily","day","120 days")):
            connection.execute(f"""INSERT INTO {table}(host_id,bucket_at,sample_count,availability_percent,cpu_avg,cpu_max,ram_avg,ram_max,disk_avg,disk_max,failed_service_max)
              SELECT host_id,date_trunc('{bucket}',collected_at),COUNT(*),100.0*COUNT(*) FILTER(WHERE state<>'offline')/COUNT(*),AVG(cpu_percent),MAX(cpu_percent),AVG(ram_percent),MAX(ram_percent),AVG(disk_percent),MAX(disk_percent),MAX(failed_service_count)
              FROM host_metric_samples WHERE collected_at>=NOW()-INTERVAL '{window}' GROUP BY host_id,date_trunc('{bucket}',collected_at)
              ON CONFLICT(host_id,bucket_at) DO UPDATE SET sample_count=EXCLUDED.sample_count,availability_percent=EXCLUDED.availability_percent,cpu_avg=EXCLUDED.cpu_avg,cpu_max=EXCLUDED.cpu_max,ram_avg=EXCLUDED.ram_avg,ram_max=EXCLUDED.ram_max,disk_avg=EXCLUDED.disk_avg,disk_max=EXCLUDED.disk_max,failed_service_max=EXCLUDED.failed_service_max""")
        connection.execute("DELETE FROM host_metric_hourly WHERE bucket_at<NOW()-INTERVAL '120 days'")
        connection.execute("DELETE FROM host_metric_daily WHERE bucket_at<NOW()-INTERVAL '400 days'")

async def metric_rollup_loop()->None:
    while True:
        try: await asyncio.to_thread(refresh_metric_rollups)
        except Exception as error: print(f"metric rollup error: {error}",flush=True)
        await asyncio.sleep(300)

def claim_escalation_reminders()->list[dict[str,Any]]:
    claimed=[]
    with connect_db() as connection:
        policy=connection.execute("SELECT * FROM notification_escalation_policy WHERE id=1").fetchone()
        if not policy or not policy["enabled"]: return []
        rows=connection.execute("""SELECT e.id,e.severity,e.message,e.started_at,COUNT(n.id) AS reminders,MAX(n.attempted_at) AS last_attempt
          FROM alert_events e LEFT JOIN notification_escalations n ON n.alert_event_id=e.id
          WHERE e.status='firing' GROUP BY e.id HAVING COUNT(n.id)<%s ORDER BY e.started_at LIMIT 50""",(policy["max_reminders"],)).fetchall()
        now=datetime.now(timezone.utc)
        for row in rows:
            interval=policy["critical_interval_minutes"] if row["severity"]=="critical" else policy["warning_interval_minutes"]
            baseline=row["last_attempt"] or row["started_at"]
            if (now-baseline).total_seconds()<interval*60: continue
            number=row["reminders"]+1; escalated=row["severity"]=="critical" and (now-row["started_at"]).total_seconds()>=policy["critical_escalate_after_minutes"]*60
            rid=f"esc-{uuid.uuid4().hex[:20]}"
            inserted=connection.execute("INSERT INTO notification_escalations(id,alert_event_id,reminder_number,status,escalated) VALUES(%s,%s,%s,'queued',%s) ON CONFLICT(alert_event_id,reminder_number) DO NOTHING RETURNING id",(rid,row["id"],number,escalated)).fetchone()
            if inserted: claimed.append({"id":rid,"eventId":row["id"],"severity":row["severity"],"message":row["message"],"number":number,"escalated":escalated})
    return claimed

async def notification_escalation_loop()->None:
    while True:
        try:
            for item in await asyncio.to_thread(claim_escalation_reminders):
                prefix="🔥 [重大告警升級]" if item["escalated"] else "⏰ [告警再次提醒]"
                results=await dispatch_notifications([{"eventId":item["eventId"],"kind":"firing","severity":item["severity"],"message":f"{prefix} 第 {item['number']} 次\n{item['message']}","retryKey":f"escalation:{item['eventId']}:{item['number']}"}])
                enabled=any(channel["enabled"] for channel in notification_channels())
                status="sent" if any(r["status"]=="sent" for r in results) else "failed" if results else "suppressed" if enabled else "no_channel"
                with connect_db() as connection: connection.execute("UPDATE notification_escalations SET status=%s,delivery_count=%s,detail=%s WHERE id=%s",(status,sum(r["status"]=="sent" for r in results),"已交由通知管道" if results else "通知被治理政策抑制或沒有管道",item["id"]))
        except Exception as error: print(f"notification escalation error: {error}",flush=True)
        await asyncio.sleep(60)


def claim_failed_backup_notifications() -> list[dict[str, Any]]:
    with connect_db() as connection:
        rows = connection.execute(
            """
            SELECT id, detail, completed_at
            FROM database_backup_jobs
            WHERE status = 'failed' AND notified_at IS NULL
            ORDER BY completed_at
            FOR UPDATE SKIP LOCKED
            LIMIT 20
            """
        ).fetchall()
        if rows:
            connection.execute(
                "UPDATE database_backup_jobs SET notified_at = NOW() WHERE id = ANY(%s)",
                ([row["id"] for row in rows],),
            )
    return [
        {
            "eventId": None,
            "kind": "backup_failed",
            "severity": "critical",
            "message": (
                "🚨 [Linux AI 備份失敗]\n"
                f"工作：{row['id']}\n"
                f"原因：{row['detail'] or '未知錯誤'}\n"
                f"時間：{row['completed_at'].isoformat() if row['completed_at'] else utc_now()}"
            ),
        }
        for row in rows
    ]


async def backup_notification_loop() -> None:
    while True:
        try:
            if any(channel["enabled"] for channel in notification_channels()):
                intents = await asyncio.to_thread(claim_failed_backup_notifications)
                await dispatch_notifications(intents)
        except (psycopg.Error, OSError, RuntimeError):
            pass
        await asyncio.sleep(30)


@app.get("/api/health")
async def health() -> dict[str, Any]:
    def database_check() -> bool:
        with connect_db() as connection:
            return connection.execute("SELECT 1 AS ready").fetchone()["ready"] == 1

    try:
        database_ready = await asyncio.to_thread(database_check)
    except psycopg.Error:
        database_ready = False
    return {
        "status": "ok" if database_ready else "degraded",
        "time": utc_now(),
        "database": "postgresql",
        "databaseReady": database_ready,
        "inventoryHosts": len(await asyncio.to_thread(load_inventory)),
        "version": APP_VERSION,
        "schemaVersion": (await asyncio.to_thread(migration_status, connect_db))["currentVersion"] if database_ready else None,
    }


@app.get("/api/system/version")
async def system_version(request: Request) -> dict[str, Any]:
    require_permission(request, "audit.read")
    migrations = await asyncio.to_thread(migration_status, connect_db)
    return {
        "version": APP_VERSION, "apiVersion": APP_VERSION,
        "schema": migrations, "minimumCompatibleSchema": MIN_COMPATIBLE_SCHEMA,
        "compatible": migrations["currentVersion"] is not None and migrations["currentVersion"] >= MIN_COMPATIBLE_SCHEMA,
    }


def read_release_operations(limit: int = 50) -> list[dict[str, Any]]:
    with connect_db() as connection:
        rows = connection.execute(
            """SELECT r.*,b.status AS backup_status,b.restore_verified,
                      u.display_name AS requested_by_name
               FROM release_operations r
               LEFT JOIN database_backup_jobs b ON b.id=r.backup_job_id
               LEFT JOIN platform_users u ON u.id=r.requested_by
               ORDER BY r.requested_at DESC LIMIT %s""", (limit,)
        ).fetchall()
    return [{
        "id": row["id"], "version": row["version"], "previousVersion": row["previous_version"],
        "status": "ready" if row["status"] == "backup_queued" and row["backup_status"] == "success" and row["restore_verified"] else row["status"],
        "compatibility": row["compatibility"], "backupJobId": row["backup_job_id"],
        "backupStatus": row["backup_status"], "detail": row["detail"],
        "requestedBy": row["requested_by_name"] or "已刪除使用者",
        "requestedAt": row["requested_at"].isoformat(),
        "completedAt": row["completed_at"].isoformat() if row["completed_at"] else None,
    } for row in rows]


@app.get("/api/releases")
async def release_status(request: Request) -> dict[str, Any]:
    require_permission(request, "audit.read")
    return {"currentVersion": APP_VERSION, "operations": await asyncio.to_thread(read_release_operations)}


@app.post("/api/releases/preflight", status_code=201)
async def release_preflight(payload: ReleasePreflight, request: Request) -> dict[str, Any]:
    actor = require_permission(request, "backup.manage")
    migrations = await asyncio.to_thread(migration_status, connect_db)
    current_major = APP_VERSION.split(".", 1)[0]
    target_major = payload.version.split(".", 1)[0]
    compatibility = {
        "schemaCurrent": migrations["currentVersion"], "schemaLatest": migrations["latestVersion"],
        "schemaReady": not migrations["pending"], "majorCompatible": current_major == target_major,
        "pendingMigrations": migrations["pending"],
    }
    if not compatibility["schemaReady"] or not compatibility["majorCompatible"]:
        raise HTTPException(status_code=409, detail="版本相容性檢查未通過；請先完成 migration 或使用相同主版本")
    operation_id, backup_id = f"release-{uuid.uuid4().hex[:18]}", f"backup-{uuid.uuid4().hex[:18]}"
    with connect_db() as connection:
        active = connection.execute("SELECT id FROM database_backup_jobs WHERE status IN ('queued','running') LIMIT 1").fetchone()
        if active:
            raise HTTPException(status_code=409, detail="已有備份工作執行中，完成後再開始更新")
        connection.execute(
            "INSERT INTO database_backup_jobs(id,kind,status,requested_by) VALUES(%s,'manual','queued',%s)",
            (backup_id, actor["id"]),
        )
        connection.execute(
            """INSERT INTO release_operations(id,version,previous_version,status,compatibility,backup_job_id,detail,requested_by)
               VALUES(%s,%s,%s,'backup_queued',%s,%s,'等待更新前備份與還原驗證',%s)""",
            (operation_id, payload.version, APP_VERSION, json.dumps(compatibility), backup_id, actor["id"]),
        )
    await asyncio.to_thread(record_backend_audit, request, "release.preflight", "執行版本更新前檢查與備份", payload.version)
    return next(item for item in await asyncio.to_thread(read_release_operations) if item["id"] == operation_id)


def read_platform_health() -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    checks: list[dict[str, Any]] = []

    def add_check(
        check_id: str, category: str, label: str, status: str, detail: str,
        remediation: str = "", required: bool = True,
    ) -> None:
        checks.append({
            "id": check_id, "category": category, "label": label,
            "status": status, "detail": detail,
            "remediation": remediation, "required": required,
        })

    with connect_db() as connection:
        database_row = connection.execute(
            "SELECT current_database() AS name, current_user AS username, "
            "current_setting('server_version') AS version"
        ).fetchone()
        latest_backup = connection.execute(
            """SELECT id, completed_at, restore_verified, recovery_verified
               FROM database_backup_jobs WHERE status = 'success'
               ORDER BY completed_at DESC NULLS LAST LIMIT 1"""
        ).fetchone()
        watchdog = connection.execute(
            "SELECT node_name, last_seen_at FROM external_watchdogs "
            "ORDER BY last_seen_at DESC LIMIT 1"
        ).fetchone()
        maintenance_worker = connection.execute(
            "SELECT id,version,active_tasks,last_heartbeat_at FROM maintenance_workers "
            "ORDER BY last_heartbeat_at DESC LIMIT 1"
        ).fetchone()

    add_check(
        "postgres", "核心服務", "PostgreSQL",
        "healthy", f"{database_row['name']} · PostgreSQL {database_row['version']} · {database_row['username']}",
    )

    if maintenance_worker:
        worker_age = max(0, int((now - maintenance_worker["last_heartbeat_at"]).total_seconds()))
        add_check(
            "maintenance-worker", "核心服務", "維運任務 Worker",
            "healthy" if worker_age <= 30 else "critical",
            f"{maintenance_worker['id']} · v{maintenance_worker['version']} · {maintenance_worker['active_tasks']} 個執行中 · 心跳 {worker_age} 秒前",
            "執行 docker compose logs --tail=100 maintenance-worker" if worker_age > 30 else "",
        )
    else:
        add_check(
            "maintenance-worker", "核心服務", "維運任務 Worker", "critical",
            "尚未收到獨立維運 Worker 心跳",
            "確認 maintenance-worker 容器已啟動：docker compose up -d maintenance-worker",
        )

    heartbeat_path = BACKUP_STORAGE_PATH / ".worker-heartbeat"
    try:
        heartbeat_age = max(0, int(now.timestamp()) - int(heartbeat_path.read_text().strip()))
        add_check(
            "backup-worker", "備份與復原", "備份背景服務",
            "healthy" if heartbeat_age <= 120 else "critical",
            f"最後心跳距今 {heartbeat_age} 秒",
            "執行 docker compose logs --tail=100 backup" if heartbeat_age > 120 else "",
        )
    except (OSError, ValueError):
        add_check(
            "backup-worker", "備份與復原", "備份背景服務", "critical",
            "找不到有效的備份服務心跳",
            "確認 backup 容器已啟動：docker compose up -d backup",
        )

    if latest_backup and latest_backup["completed_at"]:
        backup_age = max(0, int((now - latest_backup["completed_at"]).total_seconds()))
        backup_ok = bool(latest_backup["restore_verified"] and latest_backup["recovery_verified"])
        overdue = backup_age > (BACKUP_INTERVAL_HOURS * 3600 + 7200)
        add_check(
            "latest-backup", "備份與復原", "最近可還原備份",
            "healthy" if backup_ok and not overdue else "critical",
            f"{latest_backup['id']} · {backup_age // 3600} 小時前 · "
            f"{'DB＋DR 驗證通過' if backup_ok else '還原驗證未完成'}",
            "前往備份管理建立新備份並確認還原演練" if overdue or not backup_ok else "",
        )
    else:
        add_check(
            "latest-backup", "備份與復原", "最近可還原備份", "critical",
            "尚無成功且可驗證的備份", "前往備份管理執行立即備份",
        )

    key_path = Path(SSH_KEY_PATH)
    try:
        key_mode = key_path.stat().st_mode & 0o777
        key_ok = key_path.is_file() and os.access(key_path, os.R_OK) and key_mode & 0o077 == 0
        add_check(
            "ssh-key", "SSH 管理", "中央 SSH 私鑰",
            "healthy" if key_ok else "critical",
            f"已掛載 · 權限 {key_mode:04o}" if key_path.is_file() else "檔案不存在",
            "確認 SSH_KEY_PATH 指向 linux_ai_agent，並執行 chmod 600" if not key_ok else "",
        )
    except OSError:
        add_check(
            "ssh-key", "SSH 管理", "中央 SSH 私鑰", "critical",
            "無法讀取 SSH 私鑰", "檢查 .env 的 SSH_KEY_PATH 與檔案權限",
        )

    known_hosts_path = Path(KNOWN_HOSTS_PATH)
    try:
        known_count = sum(
            1 for line in known_hosts_path.read_text(errors="replace").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
    except OSError:
        known_count = 0
    add_check(
        "known-hosts", "SSH 管理", "SSH 主機指紋",
        "healthy" if known_count else "warning", f"保存 {known_count} 筆主機指紋",
        "新增主機前先確認並保存 SSH 指紋" if not known_count else "", required=False,
    )

    try:
        git_result = subprocess.run(
            ["git", "-C", str(CONFIG_REPO_PATH), "rev-parse", "--verify", "HEAD"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        git_ok = git_result.returncode == 0
        git_detail = f"HEAD {git_result.stdout.strip()[:12]}" if git_ok else "尚未建立有效版本"
    except (OSError, subprocess.TimeoutExpired):
        git_ok, git_detail = False, "無法執行 Git 完整性檢查"
    add_check(
        "config-git", "設定治理", "本機 Git 設定版控",
        "healthy" if git_ok else "critical", git_detail,
        "前往設定版控建立基準快照" if not git_ok else "",
    )

    if WATCHDOG_SHARED_TOKEN:
        watchdog_age = int((now - watchdog["last_seen_at"]).total_seconds()) if watchdog else None
        watchdog_ok = watchdog_age is not None and watchdog_age <= WATCHDOG_STALE_SECONDS
        add_check(
            "watchdog", "外部監控", "外部 Watchdog",
            "healthy" if watchdog_ok else "critical",
            f"{watchdog['node_name']} · {watchdog_age} 秒前" if watchdog else "已設定 Token，但尚未收到心跳",
            "檢查遠端 linux-ai-watchdog 服務與中央網址" if not watchdog_ok else "",
        )
    else:
        add_check(
            "watchdog", "外部監控", "外部 Watchdog", "warning",
            "尚未設定共享 Token", "需要偵測中央離線時再部署", required=False,
        )

    enabled_channels = [item["name"] for item in notification_channels() if item["enabled"]]
    add_check(
        "notifications", "外部通知", "告警通知管道",
        "healthy" if enabled_channels else "warning",
        "、".join(enabled_channels) if enabled_channels else "尚未啟用通知管道",
        "可在 .env 設定 LINE、SMS、Telegram 或 Webhook" if not enabled_channels else "",
        required=False,
    )

    ai_ok = AI_DIAGNOSTIC_MODE == "local" or bool(OPENAI_API_KEY)
    add_check(
        "ai-mode", "AI 診斷", "AI 診斷模式",
        "healthy" if ai_ok else "critical",
        "免費本機規則" if AI_DIAGNOSTIC_MODE == "local" else f"OpenAI · {OPENAI_MODEL}",
        "未付費期間請將 AI_DIAGNOSTIC_MODE 設為 local" if not ai_ok else "",
    )
    add_check(
        "https-cookie", "傳輸安全", "HTTPS Session Cookie",
        "healthy" if COOKIE_SECURE else "warning",
        "Secure Cookie 已啟用" if COOKIE_SECURE else "目前使用 HTTP 實驗模式",
        "完成本機 CA 信任後，以 compose.https.yaml 啟動 HTTPS" if not COOKIE_SECURE else "",
        required=False,
    )

    required_checks = [item for item in checks if item["required"]]
    overall = (
        "critical" if any(item["status"] == "critical" for item in required_checks)
        else "warning" if any(item["status"] == "warning" for item in checks)
        else "healthy"
    )
    return {
        "status": overall, "checkedAt": now.isoformat(), "checks": checks,
        "summary": {
            "healthy": sum(item["status"] == "healthy" for item in checks),
            "warning": sum(item["status"] == "warning" for item in checks),
            "critical": sum(item["status"] == "critical" for item in checks),
        },
    }


@app.get("/api/platform-health")
async def platform_health(request: Request) -> dict[str, Any]:
    require_permission(request, "audit.read")
    return await asyncio.to_thread(read_platform_health)


@app.post("/api/watchdog/heartbeat")
async def watchdog_heartbeat(payload: WatchdogHeartbeat, request: Request) -> dict[str, Any]:
    supplied = request.headers.get("x-watchdog-token", "")
    if not WATCHDOG_SHARED_TOKEN:
        raise HTTPException(status_code=503, detail="外部 Watchdog 尚未啟用")
    if not supplied or not hmac.compare_digest(supplied, WATCHDOG_SHARED_TOKEN):
        raise HTTPException(status_code=401, detail="Watchdog 驗證失敗")
    source_address = request_source_address(request)
    received_at = datetime.now(timezone.utc)
    recovered_at = received_at if payload.status == "recovered" else None
    with connect_db() as connection:
        connection.execute(
            """
            INSERT INTO external_watchdogs (
                id, node_name, last_status, last_outage_seconds,
                source_address, version, last_seen_at, last_recovered_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET
                node_name = EXCLUDED.node_name,
                last_status = EXCLUDED.last_status,
                last_outage_seconds = CASE
                    WHEN EXCLUDED.last_outage_seconds > 0 THEN EXCLUDED.last_outage_seconds
                    ELSE external_watchdogs.last_outage_seconds
                END,
                source_address = EXCLUDED.source_address,
                version = EXCLUDED.version,
                last_seen_at = EXCLUDED.last_seen_at,
                last_recovered_at = COALESCE(
                    EXCLUDED.last_recovered_at,
                    external_watchdogs.last_recovered_at
                )
            """,
            (
                payload.watchdog_id, payload.node_name, payload.status,
                payload.outage_seconds, source_address, payload.version,
                received_at, recovered_at,
            ),
        )
        if payload.status == "recovered" and payload.outage_seconds > 0:
            connection.execute(
                """
                INSERT INTO watchdog_outages (
                    id, watchdog_id, started_at, recovered_at, duration_seconds
                ) VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (watchdog_id, recovered_at) DO NOTHING
                """,
                (
                    f"wdo-{uuid.uuid4().hex[:20]}", payload.watchdog_id,
                    received_at - timedelta(seconds=payload.outage_seconds),
                    received_at, payload.outage_seconds,
                ),
            )
    return {"status": "accepted", "receivedAt": received_at.isoformat()}


def read_monitoring_summary() -> dict[str, Any]:
    with connect_db() as connection:
        rules = connection.execute(
            """
            SELECT id, name, metric, threshold, consecutive_samples,
                   severity, enabled, created_at, updated_at
            FROM alert_rules ORDER BY created_at, name
            """
        ).fetchall()
        events = connection.execute(
            """
            SELECT e.id, e.rule_id, r.name AS rule_name, e.host_id,
                   h.name AS host_name, e.status, e.severity, e.message,
                   e.last_value, e.started_at, e.updated_at,
                   e.acknowledged_at, e.resolved_at, e.assignee_id,
                   assignee.display_name AS assignee_name, e.resolution_summary,
                   e.resolution_reason, e.closed_at,
                   (SELECT COUNT(*) FROM maintenance_tasks t WHERE t.source_alert_id = e.id) AS task_count
            FROM alert_events e
            JOIN alert_rules r ON r.id = e.rule_id
            JOIN managed_hosts h ON h.id = e.host_id
            LEFT JOIN platform_users assignee ON assignee.id=e.assignee_id
            ORDER BY CASE WHEN e.status IN ('firing', 'acknowledged') THEN 0 ELSE 1 END,
                     e.started_at DESC
            LIMIT 100
            """
        ).fetchall()
        stats = connection.execute(
            """
            SELECT
                COUNT(*) FILTER (WHERE status IN ('firing', 'acknowledged')) AS active,
                COUNT(*) FILTER (WHERE status IN ('firing', 'acknowledged') AND severity = 'critical') AS critical,
                COUNT(*) FILTER (WHERE status = 'resolved' AND resolved_at >= NOW() - INTERVAL '24 hours') AS resolved_24h
            FROM alert_events
            """
        ).fetchone()
        collection = connection.execute(
            """
            SELECT MAX(collected_at) AS last_collected_at, COUNT(*) AS samples
            FROM host_metric_samples
            """
        ).fetchone()
        deliveries = connection.execute(
            """
            SELECT id, alert_event_id, channel, kind, status,
                   destination_hint, message, response_detail, attempted_at
            FROM notification_deliveries
            ORDER BY attempted_at DESC
            LIMIT 50
            """
        ).fetchall()
        retries = connection.execute(
            """
            SELECT id, channel, kind, status, attempt_count, max_attempts,
                   next_attempt_at, last_error, created_at, updated_at
            FROM notification_retry_jobs
            ORDER BY created_at DESC
            LIMIT 50
            """
        ).fetchall()
    return {
        "rules": [
            {
                "id": row["id"], "name": row["name"], "metric": row["metric"],
                "threshold": float(row["threshold"]),
                "consecutiveSamples": row["consecutive_samples"],
                "severity": row["severity"], "enabled": row["enabled"],
                "createdAt": row["created_at"].isoformat(),
                "updatedAt": row["updated_at"].isoformat(),
            }
            for row in rules
        ],
        "events": [
            {
                "id": row["id"], "ruleId": row["rule_id"],
                "ruleName": row["rule_name"], "hostId": row["host_id"],
                "hostName": row["host_name"], "status": row["status"],
                "severity": row["severity"], "message": row["message"],
                "lastValue": float(row["last_value"]) if row["last_value"] is not None else None,
                "startedAt": row["started_at"].isoformat(),
                "updatedAt": row["updated_at"].isoformat(),
                "acknowledgedAt": row["acknowledged_at"].isoformat() if row["acknowledged_at"] else None,
                "resolvedAt": row["resolved_at"].isoformat() if row["resolved_at"] else None,
                "assigneeId": row["assignee_id"], "assigneeName": row["assignee_name"],
                "resolutionSummary": row["resolution_summary"],
                "resolutionReason": row["resolution_reason"],
                "closedAt": row["closed_at"].isoformat() if row["closed_at"] else None,
                "taskCount": row["task_count"],
            }
            for row in events
        ],
        "stats": {
            "active": stats["active"], "critical": stats["critical"],
            "resolved24h": stats["resolved_24h"], "samples": collection["samples"],
            "lastCollectedAt": collection["last_collected_at"].isoformat() if collection["last_collected_at"] else None,
            "intervalSeconds": MONITOR_INTERVAL_SECONDS,
            "retentionDays": METRIC_RETENTION_DAYS,
        },
        "channels": notification_channels(),
        "deliveries": [
            {
                "id": row["id"], "alertEventId": row["alert_event_id"],
                "channel": row["channel"], "kind": row["kind"],
                "status": row["status"], "destination": row["destination_hint"],
                "message": row["message"], "responseDetail": row["response_detail"],
                "attemptedAt": row["attempted_at"].isoformat(),
            }
            for row in deliveries
        ],
        "retries": [
            {
                "id": row["id"], "channel": row["channel"],
                "kind": row["kind"], "status": row["status"],
                "attemptCount": row["attempt_count"], "maxAttempts": row["max_attempts"],
                "nextAttemptAt": row["next_attempt_at"].isoformat(),
                "lastError": row["last_error"], "createdAt": row["created_at"].isoformat(),
                "updatedAt": row["updated_at"].isoformat(),
            }
            for row in retries
        ],
    }


@app.get("/api/monitoring")
async def monitoring_summary(request: Request) -> dict[str, Any]:
    require_permission(request, "alerts.read")
    return await asyncio.to_thread(read_monitoring_summary)

def read_notification_governance()->dict[str,Any]:
    with connect_db() as connection:
        p=connection.execute("SELECT * FROM notification_governance_policy WHERE id=1").fetchone(); rows=connection.execute("SELECT id,name,host_id,rule_id,starts_at,ends_at,reason,created_at,ends_at>NOW() AS active FROM alert_silences ORDER BY created_at DESC LIMIT 100").fetchall()
    return {"policy":{"quietEnabled":p["quiet_enabled"],"quietStartHour":p["quiet_start_hour"],"quietEndHour":p["quiet_end_hour"],"criticalBypass":p["critical_bypass"]},"silences":[{"id":r["id"],"name":r["name"],"hostId":r["host_id"],"ruleId":r["rule_id"],"startsAt":r["starts_at"].isoformat(),"endsAt":r["ends_at"].isoformat(),"reason":r["reason"],"active":r["active"]} for r in rows]}

@app.get("/api/notifications/governance")
async def get_notification_governance(request:Request)->dict[str,Any]: require_permission(request,"alerts.read"); return await asyncio.to_thread(read_notification_governance)

@app.put("/api/notifications/governance")
async def put_notification_governance(payload:NotificationGovernanceUpdate,request:Request)->dict[str,Any]:
    actor=require_permission(request,"alerts.manage")
    with connect_db() as connection: connection.execute("UPDATE notification_governance_policy SET quiet_enabled=%s,quiet_start_hour=%s,quiet_end_hour=%s,critical_bypass=%s,updated_by=%s,updated_at=NOW() WHERE id=1",(payload.quiet_enabled,payload.quiet_start_hour,payload.quiet_end_hour,payload.critical_bypass,actor["id"]))
    await asyncio.to_thread(record_backend_audit,request,"notifications.governance.update","更新通知治理政策",str(payload.quiet_enabled)); return await asyncio.to_thread(read_notification_governance)

@app.post("/api/notifications/silences",status_code=201)
async def create_alert_silence(payload:AlertSilenceCreate,request:Request)->dict[str,Any]:
    actor=require_permission(request,"alerts.manage")
    if payload.ends_at<=payload.starts_at: raise HTTPException(status_code=422,detail="靜音結束時間必須晚於開始時間")
    sid=f"sil-{uuid.uuid4().hex[:20]}"
    with connect_db() as connection: connection.execute("INSERT INTO alert_silences(id,name,host_id,rule_id,starts_at,ends_at,reason,created_by) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",(sid,payload.name,payload.host_id,payload.rule_id,payload.starts_at,payload.ends_at,payload.reason,actor["id"]))
    await asyncio.to_thread(record_backend_audit,request,"notifications.silence.create","建立告警靜音",payload.name); return await asyncio.to_thread(read_notification_governance)

@app.delete("/api/notifications/silences/{silence_id}",status_code=204)
async def delete_alert_silence(silence_id:str,request:Request)->Response:
    require_permission(request,"alerts.manage")
    with connect_db() as connection: row=connection.execute("DELETE FROM alert_silences WHERE id=%s RETURNING name",(silence_id,)).fetchone()
    if not row: raise HTTPException(status_code=404,detail="靜音規則不存在")
    await asyncio.to_thread(record_backend_audit,request,"notifications.silence.delete","刪除告警靜音",row["name"]); return Response(status_code=204)

def read_notification_escalation()->dict[str,Any]:
    with connect_db() as connection:
        p=connection.execute("SELECT * FROM notification_escalation_policy WHERE id=1").fetchone(); rows=connection.execute("""SELECT n.*,e.message,e.severity,h.name AS host_name FROM notification_escalations n JOIN alert_events e ON e.id=n.alert_event_id JOIN managed_hosts h ON h.id=e.host_id ORDER BY n.attempted_at DESC LIMIT 100""").fetchall()
    return {"policy":{"enabled":p["enabled"],"warningIntervalMinutes":p["warning_interval_minutes"],"criticalIntervalMinutes":p["critical_interval_minutes"],"maxReminders":p["max_reminders"],"criticalEscalateAfterMinutes":p["critical_escalate_after_minutes"]},"history":[{"id":r["id"],"alertEventId":r["alert_event_id"],"hostName":r["host_name"],"message":r["message"],"severity":r["severity"],"reminderNumber":r["reminder_number"],"status":r["status"],"escalated":r["escalated"],"deliveryCount":r["delivery_count"],"detail":r["detail"],"attemptedAt":r["attempted_at"].isoformat()} for r in rows]}

@app.get("/api/notifications/escalation")
async def get_notification_escalation(request:Request)->dict[str,Any]: require_permission(request,"alerts.read"); return await asyncio.to_thread(read_notification_escalation)

@app.put("/api/notifications/escalation")
async def put_notification_escalation(payload:NotificationEscalationUpdate,request:Request)->dict[str,Any]:
    actor=require_permission(request,"alerts.manage")
    with connect_db() as connection: connection.execute("UPDATE notification_escalation_policy SET enabled=%s,warning_interval_minutes=%s,critical_interval_minutes=%s,max_reminders=%s,critical_escalate_after_minutes=%s,updated_by=%s,updated_at=NOW() WHERE id=1",(payload.enabled,payload.warning_interval_minutes,payload.critical_interval_minutes,payload.max_reminders,payload.critical_escalate_after_minutes,actor["id"]))
    await asyncio.to_thread(record_backend_audit,request,"notifications.escalation.update","更新通知升級政策",str(payload.enabled)); return await asyncio.to_thread(read_notification_escalation)

def serialize_notification_test(row:dict[str,Any])->dict[str,Any]:
    return {"id":row["id"],"name":row["name"],"severity":row["severity"],"hostId":row["host_id"],"ruleId":row["rule_id"],"deliveryRequested":row["delivery_requested"],"status":row["status"],"steps":row["steps"],"result":row["result"],"createdAt":row["created_at"].isoformat()}

def read_notification_tests()->dict[str,Any]:
    with connect_db() as connection:
        rows=connection.execute("SELECT * FROM notification_test_runs ORDER BY created_at DESC LIMIT 100").fetchall()
    return {"runs":[serialize_notification_test(row) for row in rows]}

def serialize_notification_route(row:dict[str,Any])->dict[str,Any]:
    return {"id":row["id"],"name":row["name"],"enabled":row["enabled"],"priority":row["priority"],"severity":row["severity"],"hostId":row["host_id"],"ruleId":row["rule_id"],"channels":row["channels"],"titleTemplate":row["title_template"],"bodyTemplate":row["body_template"],"updatedAt":row["updated_at"].isoformat()}

def read_notification_routes()->dict[str,Any]:
    with connect_db() as connection: rows=connection.execute("SELECT * FROM notification_routes ORDER BY priority").fetchall()
    return {"routes":[serialize_notification_route(row) for row in rows],"channels":notification_channels(),"fallback":"沒有符合規則時使用所有已啟用管道"}

def validate_notification_route(payload:NotificationRouteCreate)->None:
    allowed={channel["id"] for channel in notification_channels()}
    if any(channel not in allowed for channel in payload.channels): raise HTTPException(status_code=422,detail="包含不支援的通知管道")
    with connect_db() as connection:
        if payload.host_id and not connection.execute("SELECT 1 FROM managed_hosts WHERE id=%s",(payload.host_id,)).fetchone(): raise HTTPException(status_code=404,detail="主機不存在")
        if payload.rule_id and not connection.execute("SELECT 1 FROM alert_rules WHERE id=%s",(payload.rule_id,)).fetchone(): raise HTTPException(status_code=404,detail="告警規則不存在")

@app.get("/api/notification-routes")
async def list_notification_routes(request:Request)->dict[str,Any]: require_permission(request,"alerts.read"); return await asyncio.to_thread(read_notification_routes)

@app.post("/api/notification-routes",status_code=201)
async def create_notification_route(payload:NotificationRouteCreate,request:Request)->dict[str,Any]:
    actor=require_permission(request,"alerts.manage"); await asyncio.to_thread(validate_notification_route,payload); route_id=f"ntr-{uuid.uuid4().hex[:20]}"
    try:
        with connect_db() as connection: connection.execute("INSERT INTO notification_routes(id,name,enabled,priority,severity,host_id,rule_id,channels,title_template,body_template,created_by) VALUES(%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s)",(route_id,payload.name,payload.enabled,payload.priority,payload.severity,payload.host_id,payload.rule_id,json.dumps(payload.channels),payload.title_template,payload.body_template,actor["id"]))
    except psycopg.errors.UniqueViolation: raise HTTPException(status_code=409,detail="路由優先順序不可重複") from None
    await asyncio.to_thread(record_backend_audit,request,"notifications.route.create","建立通知路由",payload.name); return await asyncio.to_thread(read_notification_routes)

@app.put("/api/notification-routes/{route_id}")
async def update_notification_route(route_id:str,payload:NotificationRouteCreate,request:Request)->dict[str,Any]:
    require_permission(request,"alerts.manage"); await asyncio.to_thread(validate_notification_route,payload)
    try:
        with connect_db() as connection: row=connection.execute("UPDATE notification_routes SET name=%s,enabled=%s,priority=%s,severity=%s,host_id=%s,rule_id=%s,channels=%s::jsonb,title_template=%s,body_template=%s,updated_at=NOW() WHERE id=%s RETURNING id",(payload.name,payload.enabled,payload.priority,payload.severity,payload.host_id,payload.rule_id,json.dumps(payload.channels),payload.title_template,payload.body_template,route_id)).fetchone()
    except psycopg.errors.UniqueViolation: raise HTTPException(status_code=409,detail="路由優先順序不可重複") from None
    if not row: raise HTTPException(status_code=404,detail="通知路由不存在")
    await asyncio.to_thread(record_backend_audit,request,"notifications.route.update","修改通知路由",payload.name); return await asyncio.to_thread(read_notification_routes)

@app.delete("/api/notification-routes/{route_id}",status_code=204)
async def delete_notification_route(route_id:str,request:Request)->Response:
    require_permission(request,"alerts.manage")
    with connect_db() as connection: row=connection.execute("DELETE FROM notification_routes WHERE id=%s RETURNING name",(route_id,)).fetchone()
    if not row: raise HTTPException(status_code=404,detail="通知路由不存在")
    await asyncio.to_thread(record_backend_audit,request,"notifications.route.delete","刪除通知路由",row["name"]); return Response(status_code=204)

def evaluate_notification_test(payload:NotificationTestCreate)->tuple[list[dict[str,Any]],dict[str,Any]]:
    channels=notification_channels(); enabled=[item for item in channels if item["enabled"]]
    with connect_db() as connection:
        if payload.host_id and not connection.execute("SELECT 1 FROM managed_hosts WHERE id=%s",(payload.host_id,)).fetchone(): raise HTTPException(status_code=404,detail="主機不存在")
        if payload.rule_id and not connection.execute("SELECT 1 FROM alert_rules WHERE id=%s",(payload.rule_id,)).fetchone(): raise HTTPException(status_code=404,detail="告警規則不存在")
        policy=connection.execute("SELECT * FROM notification_governance_policy WHERE id=1").fetchone()
        escalation=connection.execute("SELECT * FROM notification_escalation_policy WHERE id=1").fetchone()
        silence=connection.execute("SELECT name,reason FROM alert_silences WHERE starts_at<=NOW() AND ends_at>NOW() AND (host_id IS NULL OR host_id=%s) AND (rule_id IS NULL OR rule_id=%s) ORDER BY created_at DESC LIMIT 1",(payload.host_id,payload.rule_id)).fetchone()
    hour=datetime.now(timezone.utc).hour; quiet=False
    if policy and policy["quiet_enabled"] and not(payload.severity=="critical" and policy["critical_bypass"]):
        start=policy["quiet_start_hour"]; end=policy["quiet_end_hour"]
        quiet=(start<end and start<=hour<end) or (start>end and (hour>=start or hour<end)) or start==end
    suppressed=bool(silence) or quiet
    reason=f"靜音規則：{silence['name']}" if silence else "全域安靜時段" if quiet else None
    selected,route,_=resolve_notification_route({"kind":"test","severity":payload.severity,"message":payload.name,"hostId":payload.host_id,"ruleId":payload.rule_id},[item["id"] for item in enabled])
    steps=[
        {"key":"channels","label":"通知管道","status":"passed" if enabled else "warning","detail":f"{len(enabled)} 個已啟用 / {len(channels)} 個可用"},
        {"key":"routing","label":"路由規則","status":"passed","detail":f"{route['name']} → {len(selected)} 個管道" if route else "預設備援：所有已啟用管道"},
        {"key":"silence","label":"靜音規則","status":"blocked" if silence else "passed","detail":f"命中：{silence['name']}" if silence else "未命中作用中靜音"},
        {"key":"quiet","label":"安靜時段","status":"blocked" if quiet else "passed","detail":"目前通知會被抑制" if quiet else "目前允許通知"},
        {"key":"escalation","label":"升級政策","status":"passed" if escalation and escalation["enabled"] else "warning","detail":f"最多 {escalation['max_reminders']} 次提醒" if escalation and escalation["enabled"] else "再次提醒未啟用"},
    ]
    return steps,{"suppressed":suppressed,"suppressionReason":reason,"matchedRoute":{"id":route["id"],"name":route["name"]} if route else None,"enabledChannels":[{"id":c["id"],"name":c["name"],"destination":c["destination"]} for c in enabled if c["id"] in selected],"deliveryResults":[]}

@app.get("/api/notification-tests")
async def list_notification_tests(request:Request)->dict[str,Any]: require_permission(request,"alerts.read"); return await asyncio.to_thread(read_notification_tests)

@app.post("/api/notification-tests",status_code=201)
async def create_notification_test(payload:NotificationTestCreate,request:Request)->dict[str,Any]:
    actor=require_permission(request,"alerts.manage"); steps,result=await asyncio.to_thread(evaluate_notification_test,payload); status="completed"
    if payload.delivery_requested and not result["suppressed"]:
        intent={"eventId":None,"kind":"test","severity":payload.severity,"hostId":payload.host_id,"ruleId":payload.rule_id,"message":f"🔔 [Linux AI 隔離測試]\n{payload.name}\n等級：{payload.severity}\n時間：{utc_now()}"}
        deliveries=await dispatch_notifications([intent]); result["deliveryResults"]=deliveries
        failed=any(item["status"]!="sent" for item in deliveries) or not deliveries
        steps.append({"key":"delivery","label":"實際發送","status":"failed" if failed else "passed","detail":f"成功 {sum(item['status']=='sent' for item in deliveries)} / {len(deliveries)}"}); status="failed" if failed else status
    else:
        detail=f"已抑制：{result['suppressionReason']}" if result["suppressed"] else "僅模擬，未實際發送"
        steps.append({"key":"delivery","label":"實際發送","status":"blocked" if result["suppressed"] else "skipped","detail":detail})
    run_id=f"ntt-{uuid.uuid4().hex[:20]}"
    with connect_db() as connection:
        row=connection.execute("INSERT INTO notification_test_runs(id,name,severity,host_id,rule_id,delivery_requested,status,steps,result,requested_by) VALUES(%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s) RETURNING *",(run_id,payload.name,payload.severity,payload.host_id,payload.rule_id,payload.delivery_requested,status,json.dumps(steps,ensure_ascii=False),json.dumps(result,ensure_ascii=False),actor["id"])).fetchone()
    await asyncio.to_thread(record_backend_audit,request,"notifications.test.create","執行隔離通知測試",payload.name)
    return {"run":serialize_notification_test(row)}

@app.delete("/api/notification-tests/{run_id}",status_code=204)
async def delete_notification_test(run_id:str,request:Request)->Response:
    require_permission(request,"alerts.manage")
    with connect_db() as connection: row=connection.execute("DELETE FROM notification_test_runs WHERE id=%s RETURNING name",(run_id,)).fetchone()
    if not row: raise HTTPException(status_code=404,detail="測試紀錄不存在")
    await asyncio.to_thread(record_backend_audit,request,"notifications.test.delete","刪除通知測試紀錄",row["name"]); return Response(status_code=204)

@app.delete("/api/notification-tests",status_code=204)
async def clear_notification_tests(request:Request)->Response:
    require_permission(request,"alerts.manage")
    with connect_db() as connection: connection.execute("DELETE FROM notification_test_runs")
    await asyncio.to_thread(record_backend_audit,request,"notifications.test.clear","清除通知測試紀錄","all"); return Response(status_code=204)


@app.post("/api/monitoring/collect")
async def collect_now(request: Request) -> dict[str, Any]:
    require_permission(request, "alerts.manage")
    await collect_monitoring_cycle()
    return {"status": "ok", "collectedAt": utc_now()}


@app.post("/api/notifications/test")
async def test_notifications(request: Request) -> dict[str, Any]:
    require_permission(request, "alerts.manage")
    if not any(channel["enabled"] for channel in notification_channels()):
        raise HTTPException(status_code=409, detail="尚未設定通知管道")
    intent = {
        "eventId": None,
        "kind": "test",
        "severity": "warning",
        "message": f"🔔 [Linux AI 測試通知]\n中央告警通知管道測試成功\n時間：{utc_now()}",
    }
    results = await dispatch_notifications([intent])
    return {
        "results": results,
        "allSent": bool(results) and all(result["status"] == "sent" for result in results),
    }


def read_backup_summary() -> dict[str, Any]:
    with connect_db() as connection:
        rows = connection.execute(
            """
            SELECT b.id, b.kind, b.status, b.filename, b.size_bytes,
                   b.sha256, b.restore_verified, b.recovery_filename,
                   b.recovery_size_bytes, b.recovery_sha256, b.recovery_verified,
                   b.detail, b.requested_at,
                   b.started_at, b.completed_at, u.display_name AS requested_by_name
            FROM database_backup_jobs b
            LEFT JOIN platform_users u ON u.id = b.requested_by
            ORDER BY b.requested_at DESC
            LIMIT 100
            """
        ).fetchall()
        watchdog_rows = connection.execute(
            """
            SELECT id, node_name, last_status, last_outage_seconds,
                   source_address, version, last_seen_at, last_recovered_at
            FROM external_watchdogs
            ORDER BY last_seen_at DESC
            """
        ).fetchall()
        outage_rows = connection.execute(
            """
            SELECT o.id, o.watchdog_id, w.node_name, o.started_at,
                   o.recovered_at, o.duration_seconds
            FROM watchdog_outages o
            JOIN external_watchdogs w ON w.id = o.watchdog_id
            ORDER BY o.recovered_at DESC
            LIMIT 100
            """
        ).fetchall()
    latest_success = next((row for row in rows if row["status"] == "success"), None)
    now = datetime.now(timezone.utc)
    return {
        "settings": {
            "intervalHours": BACKUP_INTERVAL_HOURS,
            "retentionDays": BACKUP_RETENTION_DAYS,
            "watchdogStaleSeconds": WATCHDOG_STALE_SECONDS,
            "watchdogConfigured": bool(WATCHDOG_SHARED_TOKEN),
        },
        "healthy": bool(latest_success and latest_success["restore_verified"] and latest_success["recovery_verified"]),
        "jobs": [
            {
                "id": row["id"], "kind": row["kind"], "status": row["status"],
                "filename": row["filename"], "sizeBytes": row["size_bytes"],
                "sha256": row["sha256"], "restoreVerified": row["restore_verified"],
                "recoveryFilename": row["recovery_filename"],
                "recoverySizeBytes": row["recovery_size_bytes"],
                "recoverySha256": row["recovery_sha256"],
                "recoveryVerified": row["recovery_verified"],
                "detail": row["detail"],
                "requestedBy": row["requested_by_name"] or "系統排程",
                "requestedAt": row["requested_at"].isoformat(),
                "startedAt": row["started_at"].isoformat() if row["started_at"] else None,
                "completedAt": row["completed_at"].isoformat() if row["completed_at"] else None,
            }
            for row in rows
        ],
        "watchdogs": [
            {
                "id": row["id"], "nodeName": row["node_name"],
                "status": "online" if (now - row["last_seen_at"]).total_seconds() <= WATCHDOG_STALE_SECONDS else "stale",
                "lastReport": row["last_status"],
                "lastOutageSeconds": row["last_outage_seconds"],
                "lastRecoveredAt": row["last_recovered_at"].isoformat() if row["last_recovered_at"] else None,
                "sourceAddress": row["source_address"], "version": row["version"],
                "lastSeenAt": row["last_seen_at"].isoformat(),
            }
            for row in watchdog_rows
        ],
        "watchdogOutages": [
            {
                "id": row["id"], "watchdogId": row["watchdog_id"],
                "nodeName": row["node_name"],
                "startedAt": row["started_at"].isoformat(),
                "recoveredAt": row["recovered_at"].isoformat(),
                "durationSeconds": row["duration_seconds"],
            }
            for row in outage_rows
        ],
    }


@app.get("/api/backups")
async def list_backups(request: Request) -> dict[str, Any]:
    require_permission(request, "backup.read")
    return await asyncio.to_thread(read_backup_summary)


def read_replication_status() -> dict[str, Any]:
    with connect_db() as connection:
        role_row = connection.execute(
            "SELECT pg_is_in_recovery() AS in_recovery"
        ).fetchone()
        replica_rows = connection.execute(
            """
            SELECT application_name, client_addr::text AS client_address,
                   state, sync_state, sent_lsn::text AS sent_lsn,
                   replay_lsn::text AS replay_lsn,
                   COALESCE(pg_wal_lsn_diff(sent_lsn, replay_lsn), 0)::bigint AS lag_bytes,
                   EXTRACT(EPOCH FROM write_lag)::double precision AS write_lag_seconds,
                   EXTRACT(EPOCH FROM flush_lag)::double precision AS flush_lag_seconds,
                   EXTRACT(EPOCH FROM replay_lag)::double precision AS replay_lag_seconds
            FROM pg_stat_replication
            ORDER BY application_name, client_addr
            """
        ).fetchall()
        slot_rows = connection.execute(
            """
            SELECT slot_name, slot_type, active, active_pid,
                   restart_lsn::text AS restart_lsn, wal_status
            FROM pg_replication_slots
            ORDER BY slot_name
            """
        ).fetchall()
    replicas = [
        {
            "applicationName": row["application_name"] or "standby",
            "clientAddress": row["client_address"],
            "state": row["state"], "syncState": row["sync_state"],
            "sentLsn": row["sent_lsn"], "replayLsn": row["replay_lsn"],
            "lagBytes": int(row["lag_bytes"] or 0),
            "writeLagSeconds": row["write_lag_seconds"],
            "flushLagSeconds": row["flush_lag_seconds"],
            "replayLagSeconds": row["replay_lag_seconds"],
        }
        for row in replica_rows
    ]
    slots = [
        {
            "slotName": row["slot_name"], "slotType": row["slot_type"],
            "active": row["active"], "activePid": row["active_pid"],
            "restartLsn": row["restart_lsn"], "walStatus": row["wal_status"],
        }
        for row in slot_rows
    ]
    return {
        "role": "standby" if role_row and role_row["in_recovery"] else "primary",
        "enabled": bool(slots),
        "streaming": any(row["state"] == "streaming" for row in replica_rows),
        "replicas": replicas,
        "slots": slots,
    }


@app.get("/api/replication/status")
async def replication_status(request: Request) -> dict[str, Any]:
    require_permission(request, "backup.read")
    return await asyncio.to_thread(read_replication_status)


@app.post("/api/backups", status_code=202)
async def request_backup(request: Request) -> dict[str, Any]:
    actor = require_permission(request, "backup.manage")
    job_id = f"bkp-{uuid.uuid4().hex[:20]}"
    try:
        with connect_db() as connection:
            connection.execute(
                """
                INSERT INTO database_backup_jobs (id, kind, status, requested_by)
                VALUES (%s, 'manual', 'queued', %s)
                """,
                (job_id, actor["id"]),
            )
    except psycopg.errors.UniqueViolation as error:
        raise HTTPException(status_code=409, detail="已有備份工作正在排隊或執行") from error
    return {"id": job_id, "status": "queued"}


def verified_backup_file(job_id: str, artifact: str) -> tuple[Path, str]:
    columns = {
        "database": ("filename", "sha256"),
        "recovery": ("recovery_filename", "recovery_sha256"),
    }
    if artifact not in columns:
        raise HTTPException(status_code=404, detail="不支援的備份檔案類型")
    filename_column, checksum_column = columns[artifact]
    with connect_db() as connection:
        row = connection.execute(
            f"SELECT {filename_column} AS filename, {checksum_column} AS checksum "
            "FROM database_backup_jobs WHERE id = %s AND status = 'success'",
            (job_id,),
        ).fetchone()
    if not row or not row["filename"] or not row["checksum"]:
        raise HTTPException(status_code=404, detail="備份檔不存在或尚未完成")
    filename = str(row["filename"])
    if Path(filename).name != filename:
        raise HTTPException(status_code=409, detail="備份檔名驗證失敗")
    path = BACKUP_STORAGE_PATH / filename
    if not path.is_file():
        raise HTTPException(status_code=410, detail="備份檔已依保留政策刪除")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if not hmac.compare_digest(digest.hexdigest(), str(row["checksum"])):
        raise HTTPException(status_code=409, detail="備份檔 SHA-256 驗證失敗，已拒絕下載")
    return path, filename


@app.get("/api/backups/{job_id}/download/{artifact}")
async def download_backup_artifact(job_id: str, artifact: str, request: Request) -> FileResponse:
    require_permission(request, "backup.manage")
    path, filename = await asyncio.to_thread(verified_backup_file, job_id, artifact)
    return FileResponse(path, filename=filename, media_type="application/octet-stream")


def read_standby_preflights() -> list[dict[str, Any]]:
    with connect_db() as connection:
        rows = connection.execute(
            """SELECT c.id, c.host_id, h.name AS host_name, h.address, c.ready,
                      c.result, c.checked_at, u.display_name AS checked_by
               FROM standby_preflight_checks c
               JOIN managed_hosts h ON h.id = c.host_id
               LEFT JOIN platform_users u ON u.id = c.checked_by
               ORDER BY c.checked_at DESC LIMIT 50"""
        ).fetchall()
    return [{"id": row["id"], "hostId": row["host_id"], "hostName": row["host_name"],
             "address": row["address"], "ready": row["ready"], "result": row["result"],
             "checkedBy": row["checked_by"] or "系統", "checkedAt": row["checked_at"].isoformat()}
            for row in rows]


@app.get("/api/standby-preflights")
async def list_standby_preflights(request: Request) -> dict[str, Any]:
    require_permission(request, "backup.read")
    return {"checks": await asyncio.to_thread(read_standby_preflights)}


@app.post("/api/standby-preflights/{host_id}", status_code=201)
async def create_standby_preflight(host_id: str, request: Request) -> dict[str, Any]:
    actor = require_permission(request, "backup.manage")
    host = get_host(host_id)
    encoded = base64.b64encode(REMOTE_STANDBY_PREFLIGHT.encode()).decode()
    command = f"python3 -c \"import base64;exec(base64.b64decode('{encoded}'))\""
    try:
        raw = await run_ssh(host, command, timeout=12)
        facts = json.loads(raw)
        checks = [
            {"key": "cpu", "label": "CPU 至少 2 核心", "passed": int(facts.get("cpuCount", 0)) >= 2},
            {"key": "memory", "label": "記憶體至少 2 GB", "passed": int(facts.get("memoryBytes", 0)) >= 2 * 1024 ** 3},
            {"key": "disk", "label": "根目錄可用至少 20 GB", "passed": int(facts.get("diskFreeBytes", 0)) >= 20 * 1024 ** 3},
            {"key": "docker", "label": "Docker Engine 已安裝", "passed": bool(facts.get("dockerVersion"))},
            {"key": "compose", "label": "Docker Compose 已安裝", "passed": bool(facts.get("composeVersion"))},
            {"key": "ports", "label": "5432 與 8080 尚未被占用", "passed": bool(facts.get("port5432Free") and facts.get("port8080Free"))},
        ]
        result = {"facts": facts, "checks": checks, "error": None}
        ready = all(item["passed"] for item in checks)
    except (RuntimeError, json.JSONDecodeError) as error:
        result = {"facts": {}, "checks": [], "error": str(error)[:500]}
        ready = False
    check_id = f"preflight-{uuid.uuid4().hex[:18]}"
    with connect_db() as connection:
        connection.execute(
            """INSERT INTO standby_preflight_checks (id, host_id, ready, result, checked_by)
               VALUES (%s, %s, %s, %s::jsonb, %s)""",
            (check_id, host_id, ready, json.dumps(result), actor["id"]),
        )
    return next(item for item in await asyncio.to_thread(read_standby_preflights) if item["id"] == check_id)


def read_diagnostics(limit: int = 100) -> list[dict[str, Any]]:
    with connect_db() as connection:
        rows = connection.execute(
            """
            SELECT d.id, d.host_id, h.name AS host_name, d.status, d.model,
                   d.evidence, d.result, d.redaction_count, d.error,
                   d.requested_at, d.completed_at,
                   COALESCE(u.display_name, '已刪除使用者') AS requested_by_name
            FROM ai_diagnostics d
            JOIN managed_hosts h ON h.id = d.host_id
            LEFT JOIN platform_users u ON u.id = d.requested_by
            ORDER BY d.requested_at DESC
            LIMIT %s
            """,
            (limit,),
        ).fetchall()
    return [
        {
            "id": row["id"], "hostId": row["host_id"], "hostName": row["host_name"],
            "status": row["status"], "model": row["model"],
            "evidence": row["evidence"], "result": row["result"],
            "redactionCount": row["redaction_count"], "error": row["error"],
            "requestedBy": row["requested_by_name"],
            "requestedAt": row["requested_at"].isoformat(),
            "completedAt": row["completed_at"].isoformat() if row["completed_at"] else None,
        }
        for row in rows
    ]


@app.get("/api/diagnostics")
async def list_diagnostics(request: Request) -> dict[str, Any]:
    require_permission(request, "ai.read")
    return {
        "configured": AI_DIAGNOSTIC_MODE == "local" or bool(OPENAI_API_KEY),
        "mode": AI_DIAGNOSTIC_MODE,
        "openaiConfigured": bool(OPENAI_API_KEY),
        "model": OPENAI_MODEL if AI_DIAGNOSTIC_MODE == "openai" else LOCAL_DIAGNOSTIC_MODEL,
        "analysisOnly": True,
        "diagnostics": await asyncio.to_thread(read_diagnostics),
    }


@app.post("/api/hosts/{host_id}/diagnostics", status_code=201)
async def create_diagnostic(host_id: str, request: Request) -> dict[str, Any]:
    actor = require_permission(request, "ai.manage")
    if AI_DIAGNOSTIC_MODE == "openai" and not OPENAI_API_KEY:
        raise HTTPException(
            status_code=409,
            detail="目前選擇 OpenAI 模式，但尚未設定 OPENAI_API_KEY",
        )
    host = get_host(host_id)
    diagnosis_id = f"diag-{uuid.uuid4().hex[:20]}"
    selected_model = OPENAI_MODEL if AI_DIAGNOSTIC_MODE == "openai" else LOCAL_DIAGNOSTIC_MODEL
    with connect_db() as connection:
        connection.execute(
            """
            INSERT INTO ai_diagnostics (id, host_id, status, model, requested_by)
            VALUES (%s, %s, 'running', %s, %s)
            """,
            (diagnosis_id, host_id, selected_model, actor["id"]),
        )
    try:
        evidence, redaction_count = await collect_diagnostic_evidence(host)
        with connect_db() as connection:
            connection.execute(
                """
                UPDATE ai_diagnostics
                SET evidence = %s::jsonb, redaction_count = %s
                WHERE id = %s
                """,
                (json.dumps(evidence), redaction_count, diagnosis_id),
            )
        if AI_DIAGNOSTIC_MODE == "openai":
            result = await asyncio.to_thread(request_openai_diagnosis, evidence, actor["id"])
        else:
            result = await asyncio.to_thread(local_rule_diagnosis, evidence)
        with connect_db() as connection:
            connection.execute(
                """
                UPDATE ai_diagnostics
                SET status = 'completed', evidence = %s::jsonb, result = %s::jsonb,
                    redaction_count = %s, completed_at = NOW()
                WHERE id = %s
                """,
                (json.dumps(evidence), json.dumps(result), redaction_count, diagnosis_id),
            )
    except Exception as error:
        safe_error, _ = redact_diagnostic_text(str(error))
        with connect_db() as connection:
            connection.execute(
                """
                UPDATE ai_diagnostics
                SET status = 'failed', error = %s, completed_at = NOW()
                WHERE id = %s
                """,
                (safe_error[:800], diagnosis_id),
            )
        raise HTTPException(status_code=502, detail=safe_error[:500]) from error
    return next(item for item in await asyncio.to_thread(read_diagnostics) if item["id"] == diagnosis_id)


def parse_sudo_command_grants(output: str) -> set[str]:
    grants: set[str] = set()
    rule_pattern = re.compile(
        r"^\s*\([^)]*\)\s+(?:(?:NOPASSWD|PASSWD|SETENV|NOSETENV):\s*)*(.+?)\s*$"
    )
    for line in output.splitlines():
        match = rule_pattern.match(line)
        if match:
            grants.add(match.group(1).strip().rstrip("\\"))
    return grants


async def inspect_maintenance_sudo_policy(host: dict[str, Any]) -> dict[str, Any]:
    if host.get("user") != "linux-agent":
        return {
            "hostId": host["id"], "hostName": host["name"], "address": host["address"],
            "status": "unsupported", "ready": False, "missingCommands": sorted(MAINTENANCE_SUDO_COMMANDS),
            "unexpectedGrantCount": 0, "detail": "受控寫入目前只支援 linux-agent 帳號",
        }
    try:
        output = await run_ssh(host, "sudo -n -l", timeout=10)
        grants = parse_sudo_command_grants(output)
        missing = sorted(MAINTENANCE_SUDO_COMMANDS - grants)
        unexpected = grants - MAINTENANCE_SUDO_COMMANDS
        broad = any(grant == "ALL" or "*" in grant for grant in unexpected)
        ready = not missing and not unexpected
        if ready:
            status, detail = "ready", "三條受控維運命令均已授權，且未偵測到額外 sudo 命令"
        elif broad:
            status, detail = "overprivileged", "偵測到 ALL 或萬用字元 sudo 權限，已禁止受控寫入"
        elif unexpected:
            status, detail = "overprivileged", "偵測到白名單以外的 sudo 命令，已禁止受控寫入"
        else:
            status, detail = "missing", "缺少必要的受控維運 sudo 權限"
        return {
            "hostId": host["id"], "hostName": host["name"], "address": host["address"],
            "status": status, "ready": ready, "missingCommands": missing,
            "unexpectedGrantCount": len(unexpected), "detail": detail,
        }
    except RuntimeError as error:
        safe_error, _ = redact_diagnostic_text(str(error))
        return {
            "hostId": host["id"], "hostName": host["name"], "address": host["address"],
            "status": "unreachable", "ready": False,
            "missingCommands": sorted(MAINTENANCE_SUDO_COMMANDS), "unexpectedGrantCount": 0,
            "detail": safe_error[:300],
        }


def read_maintenance_tasks(
    limit: int = 200, source_alert_id: str | None = None
) -> list[dict[str, Any]]:
    where = "WHERE t.source_alert_id = %s" if source_alert_id else ""
    params: tuple[Any, ...] = (source_alert_id, limit) if source_alert_id else (limit,)
    with connect_db() as connection:
        rows = connection.execute(
            f"""
            SELECT t.id, t.host_id, h.name AS host_name, t.runbook_id, t.title,
                   t.command_preview, t.risk_level, t.approval_policy,
                   t.verification_method, t.verification_status, t.output_sha256,
                   t.duration_ms, t.source_alert_id, t.retry_of, t.attempt,
                   t.timeout_seconds, t.heartbeat_at, t.cancel_requested_at,
                   t.request_note, t.status, t.output, t.error,
                   t.decision_note, t.requested_at, t.decided_at, t.started_at,
                   t.completed_at, t.approval_expires_at,
                   COALESCE(requester.display_name, '已刪除使用者') AS requester_name,
                   approver.display_name AS approver_name
            FROM maintenance_tasks t
            JOIN managed_hosts h ON h.id = t.host_id
            LEFT JOIN platform_users requester ON requester.id = t.requested_by
            LEFT JOIN platform_users approver ON approver.id = t.approved_by
            {where}
            ORDER BY t.requested_at DESC
            LIMIT %s
            """,
            params,
        ).fetchall()
    return [
        {
            "id": row["id"], "hostId": row["host_id"], "hostName": row["host_name"],
            "runbookId": row["runbook_id"], "title": row["title"],
            "commandPreview": row["command_preview"], "requestNote": row["request_note"],
            "riskLevel": row["risk_level"], "approvalPolicy": row["approval_policy"],
            "verificationMethod": row["verification_method"],
            "verificationStatus": row["verification_status"],
            "outputSha256": row["output_sha256"], "durationMs": row["duration_ms"],
            "sourceAlertId": row["source_alert_id"],
            "retryOf": row["retry_of"], "attempt": row["attempt"],
            "timeoutSeconds": row["timeout_seconds"],
            "heartbeatAt": row["heartbeat_at"].isoformat() if row["heartbeat_at"] else None,
            "cancelRequestedAt": row["cancel_requested_at"].isoformat() if row["cancel_requested_at"] else None,
            "status": row["status"], "output": row["output"], "error": row["error"],
            "decisionNote": row["decision_note"], "requestedBy": row["requester_name"],
            "approvedBy": row["approver_name"],
            "requestedAt": row["requested_at"].isoformat(),
            "decidedAt": row["decided_at"].isoformat() if row["decided_at"] else None,
            "approvalExpiresAt": row["approval_expires_at"].isoformat() if row["approval_expires_at"] else None,
            "startedAt": row["started_at"].isoformat() if row["started_at"] else None,
            "completedAt": row["completed_at"].isoformat() if row["completed_at"] else None,
        }
        for row in rows
    ]


@app.get("/api/tasks")
async def list_maintenance_tasks(request: Request) -> dict[str, Any]:
    require_permission(request, "tasks.read")
    return {
        "runbooks": [
            {"id": runbook_id, "title": item["title"], "description": item["description"],
             "commandPreview": item["command"], "risk": item["risk"],
             "approvalPolicy": item["approval_policy"], "verification": item["verification"],
             "mutating": bool(item.get("mutating", False))}
            for runbook_id, item in SAFE_RUNBOOKS.items()
        ],
        "tasks": await asyncio.to_thread(read_maintenance_tasks),
        "arbitraryCommandsAllowed": False,
        "riskPolicy": {
            "low": "單一核准；可由申請者核准",
            "medium": "必須由另一位具核准權限的使用者核准",
            "high": "只允許固定修復 Runbook，且必須由另一位具權限使用者核准",
        },
        "approvalTtlMinutes": MAINTENANCE_APPROVAL_TTL_MINUTES,
    }


@app.get("/api/tasks/readiness")
async def maintenance_sudo_readiness(request: Request) -> dict[str, Any]:
    require_permission(request, "tasks.read")
    hosts = await asyncio.to_thread(load_inventory)
    checks = await asyncio.gather(*(inspect_maintenance_sudo_policy(host) for host in hosts))
    return {
        "readyHosts": sum(1 for check in checks if check["ready"]),
        "totalHosts": len(checks),
        "hosts": checks,
        "requiredCommands": sorted(MAINTENANCE_SUDO_COMMANDS),
    }


@app.get("/api/tasks/workers")
async def maintenance_worker_status(request: Request) -> dict[str, Any]:
    require_permission(request, "tasks.read")
    with connect_db() as connection:
        rows = connection.execute(
            """SELECT id,version,concurrency,active_tasks,last_heartbeat_at,started_at,
                      last_heartbeat_at > NOW() - INTERVAL '30 seconds' AS online
               FROM maintenance_workers ORDER BY last_heartbeat_at DESC"""
        ).fetchall()
        queue = connection.execute(
            """SELECT COUNT(*) FILTER(WHERE status='queued') AS queued,
                      COUNT(*) FILTER(WHERE status='running') AS running
               FROM maintenance_tasks"""
        ).fetchone()
    return {
        "queue": {"queued": queue["queued"], "running": queue["running"]},
        "workers": [
            {
                "id": row["id"], "version": row["version"],
                "concurrency": row["concurrency"], "activeTasks": row["active_tasks"],
                "online": row["online"],
                "lastHeartbeatAt": row["last_heartbeat_at"].isoformat(),
                "startedAt": row["started_at"].isoformat(),
            }
            for row in rows
        ],
    }


@app.get("/api/system/limits")
async def system_resource_limits(request: Request) -> dict[str, Any]:
    require_permission(request, "audit.read")
    return {
        "apiRateLimitPerMinute": API_RATE_LIMIT_PER_MINUTE,
        "sshMaxConcurrency": SSH_MAX_CONCURRENCY,
        "maintenanceWorker": {
            "configuredBy": "MAINTENANCE_WORKER_CONCURRENCY",
            "maximumAllowed": 8,
        },
        "resultLimits": {"hostMetricSamples": 1000, "taskOutputCharacters": 100000},
    }


RETENTION_DELETE_SQL: dict[str, tuple[str, str]] = {
    "alert_events": ("alert_events", "status='resolved' AND COALESCE(resolved_at,updated_at) < NOW() - make_interval(days => %s)"),
    "maintenance_tasks": ("maintenance_tasks", "status IN ('succeeded','failed','rejected','cancelled','timed_out') AND completed_at < NOW() - make_interval(days => %s)"),
    "host_metrics": ("host_metric_samples", "collected_at < NOW() - make_interval(days => %s)"),
    "automation_runs": ("automation_runs", "status <> 'running' AND completed_at < NOW() - make_interval(days => %s)"),
    "login_events": ("auth_login_events", "occurred_at < NOW() - make_interval(days => %s)"),
    "central_logs": ("central_log_events", "collected_at < NOW() - make_interval(days => %s)"),
}


def retention_snapshot(*, delete: bool = False, requested_by: str | None = None) -> dict[str, int]:
    results: dict[str, int] = {}
    verb = "DELETE FROM" if delete else "SELECT COUNT(*) AS count FROM"
    with connect_db() as connection:
        policies = connection.execute(
            "SELECT dataset,retention_days,protected FROM data_retention_policy ORDER BY dataset"
        ).fetchall()
        for policy in policies:
            dataset = policy["dataset"]
            if policy["protected"]:
                results[dataset] = 0
                continue
            days = policy["retention_days"]
            if dataset == "inventory_scans":
                count = 0
                for table in ("host_asset_scans", "host_patch_scans", "host_security_scans"):
                    cursor = connection.execute(
                        f"{verb} {table} WHERE checked_at < NOW() - make_interval(days => %s)", (days,)
                    )
                    count += cursor.rowcount if delete else cursor.fetchone()["count"]
                results[dataset] = count
                continue
            table, condition = RETENTION_DELETE_SQL[dataset]
            cursor = connection.execute(f"{verb} {table} WHERE {condition}", (days,))
            results[dataset] = cursor.rowcount if delete else cursor.fetchone()["count"]
    return results


def read_retention_policy() -> dict[str, Any]:
    with connect_db() as connection:
        policies = connection.execute(
            "SELECT dataset,retention_days,protected,updated_at FROM data_retention_policy ORDER BY dataset"
        ).fetchall()
        runs = connection.execute(
            "SELECT id,status,preview,result,error,started_at,completed_at FROM data_retention_runs ORDER BY started_at DESC LIMIT 20"
        ).fetchall()
    return {
        "policies": [{
            "dataset": row["dataset"], "retentionDays": row["retention_days"],
            "protected": row["protected"], "updatedAt": row["updated_at"].isoformat(),
        } for row in policies],
        "runs": [{
            "id": row["id"], "status": row["status"], "preview": row["preview"],
            "result": row["result"], "error": row["error"],
            "startedAt": row["started_at"].isoformat(),
            "completedAt": row["completed_at"].isoformat() if row["completed_at"] else None,
        } for row in runs],
    }


def run_retention(preview: bool, requested_by: str | None) -> dict[str, Any]:
    run_id = f"ret-{uuid.uuid4().hex[:20]}"
    with connect_db() as connection:
        connection.execute(
            "INSERT INTO data_retention_runs(id,status,preview,requested_by) VALUES(%s,'running',%s,%s)",
            (run_id, preview, requested_by),
        )
    try:
        result = retention_snapshot(delete=not preview, requested_by=requested_by)
        with connect_db() as connection:
            connection.execute(
                "UPDATE data_retention_runs SET status='success',result=%s,completed_at=NOW() WHERE id=%s",
                (json.dumps(result), run_id),
            )
        return {"id": run_id, "preview": preview, "result": result}
    except Exception as error:
        with connect_db() as connection:
            connection.execute(
                "UPDATE data_retention_runs SET status='failed',error=%s,completed_at=NOW() WHERE id=%s",
                (str(error)[:2000], run_id),
            )
        raise


@app.get("/api/retention")
async def get_retention_policy(request: Request) -> dict[str, Any]:
    require_permission(request, "backup.read")
    return await asyncio.to_thread(read_retention_policy)


@app.put("/api/retention")
async def update_retention_policy(payload: RetentionPolicyUpdate, request: Request) -> dict[str, Any]:
    actor = require_permission(request, "backup.manage")
    datasets = [item.dataset for item in payload.policies]
    if len(datasets) != len(set(datasets)):
        raise HTTPException(status_code=422, detail="保存政策資料類型不可重複")
    with connect_db() as connection:
        for item in payload.policies:
            connection.execute(
                "UPDATE data_retention_policy SET retention_days=%s,updated_by=%s,updated_at=NOW() WHERE dataset=%s AND protected=FALSE",
                (item.retention_days, actor["id"], item.dataset),
            )
    await asyncio.to_thread(record_backend_audit, request, "retention.update", "更新資料保存政策", ",".join(datasets))
    return await asyncio.to_thread(read_retention_policy)


@app.post("/api/retention/preview")
async def preview_retention(request: Request) -> dict[str, Any]:
    actor = require_permission(request, "backup.manage")
    return await asyncio.to_thread(run_retention, True, actor["id"])


@app.post("/api/retention/run")
async def execute_retention(request: Request) -> dict[str, Any]:
    actor = require_permission(request, "backup.manage")
    result = await asyncio.to_thread(run_retention, False, actor["id"])
    await asyncio.to_thread(record_backend_audit, request, "retention.run", "執行資料保存清理", result["id"])
    return result


def refresh_observability() -> None:
    now = datetime.now(timezone.utc)
    with connect_db() as connection:
        worker = connection.execute(
            "SELECT id,active_tasks,last_heartbeat_at FROM maintenance_workers ORDER BY last_heartbeat_at DESC LIMIT 1"
        ).fetchone()
        database = connection.execute(
            "SELECT pg_database_size(current_database()) AS bytes,"
            "(SELECT COUNT(*) FROM pg_stat_activity) AS connections"
        ).fetchone()
        queue = connection.execute(
            "SELECT COUNT(*) FILTER(WHERE status='queued') AS queued,COUNT(*) FILTER(WHERE status='running') AS running FROM maintenance_tasks"
        ).fetchone()
        worker_age = int((now-worker["last_heartbeat_at"]).total_seconds()) if worker else 999999
        connection.execute(
            "INSERT INTO service_health_samples(service,status,metrics,detail) VALUES('postgres','healthy',%s,%s)",
            (json.dumps({"databaseBytes": database["bytes"], "connections": database["connections"]}), "PostgreSQL 可查詢"),
        )
        connection.execute(
            "INSERT INTO service_health_samples(service,status,metrics,detail) VALUES('maintenance-worker',%s,%s,%s)",
            ("healthy" if worker_age <= 30 else "critical",
             json.dumps({"heartbeatAgeSeconds": worker_age, "activeTasks": worker["active_tasks"] if worker else 0,
                         "queuedTasks": queue["queued"], "runningTasks": queue["running"]}),
             worker["id"] if worker else "尚無 Worker 心跳"),
        )
        try:
            backup_age = max(0, int(now.timestamp()) - int((BACKUP_STORAGE_PATH / ".worker-heartbeat").read_text().strip()))
        except (OSError, ValueError):
            backup_age = 999999
        connection.execute(
            "INSERT INTO service_health_samples(service,status,metrics,detail) VALUES('backup-worker',%s,%s,%s)",
            ("healthy" if backup_age <= 120 else "critical", json.dumps({"heartbeatAgeSeconds": backup_age}), "備份 Worker 心跳"),
        )
        rows = connection.execute(
            """SELECT host_id,COUNT(*) AS samples,
                      (array_agg(cpu_percent ORDER BY collected_at DESC))[1] AS cpu_current,
                      (array_agg(ram_percent ORDER BY collected_at DESC))[1] AS ram_current,
                      (array_agg(disk_percent ORDER BY collected_at DESC))[1] AS disk_current,
                      COALESCE(regr_slope(cpu_percent::double precision,EXTRACT(EPOCH FROM collected_at))*86400,0) AS cpu_slope,
                      COALESCE(regr_slope(ram_percent::double precision,EXTRACT(EPOCH FROM collected_at))*86400,0) AS ram_slope,
                      COALESCE(regr_slope(disk_percent::double precision,EXTRACT(EPOCH FROM collected_at))*86400,0) AS disk_slope
               FROM host_metric_samples WHERE collected_at >= NOW()-INTERVAL '7 days'
               GROUP BY host_id"""
        ).fetchall()
        rule = connection.execute("SELECT enabled,severity,threshold FROM alert_rules WHERE id='rule-capacity-forecast'").fetchone()
        threshold_days = float(rule["threshold"]) if rule else 14.0
        risky_hosts: set[str] = set()
        for row in rows:
            confidence = "high" if row["samples"] >= 100 else "medium" if row["samples"] >= 20 else "low"
            for resource in ("cpu", "ram", "disk"):
                current, slope = float(row[f"{resource}_current"]), float(row[f"{resource}_slope"])
                predicted = round((85-current)/slope, 1) if slope > 0.05 and current < 85 else (0.0 if current >= 85 else None)
                if predicted is not None and predicted <= threshold_days:
                    risky_hosts.add(row["host_id"])
                connection.execute(
                    """INSERT INTO capacity_forecasts(host_id,resource,current_percent,slope_per_day,predicted_days,sample_count,confidence)
                       VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(host_id,resource) DO UPDATE SET
                       current_percent=EXCLUDED.current_percent,slope_per_day=EXCLUDED.slope_per_day,
                       predicted_days=EXCLUDED.predicted_days,sample_count=EXCLUDED.sample_count,
                       confidence=EXCLUDED.confidence,calculated_at=NOW()""",
                    (row["host_id"], resource, current, slope, predicted, row["samples"], confidence),
                )
        if rule and rule["enabled"]:
            for host_id in risky_hosts:
                connection.execute(
                    """INSERT INTO alert_events(id,rule_id,host_id,status,severity,message)
                       VALUES(%s,'rule-capacity-forecast',%s,'firing',%s,%s)
                       ON CONFLICT DO NOTHING""",
                    (f"alert-{uuid.uuid4().hex[:20]}", host_id, rule["severity"],
                     f"依最近 7 天趨勢，資源可能在 {threshold_days:g} 天內達到 85%"),
                )
            connection.execute(
                """UPDATE alert_events SET status='resolved',resolved_at=NOW(),updated_at=NOW()
                   WHERE rule_id='rule-capacity-forecast' AND status IN ('firing','acknowledged')
                     AND NOT(host_id=ANY(%s))""",
                (list(risky_hosts) or ["__none__"],),
            )
        connection.execute("DELETE FROM service_health_samples WHERE collected_at < NOW()-INTERVAL '30 days'")
        connection.execute("DELETE FROM maintenance_workers WHERE last_heartbeat_at < NOW()-INTERVAL '10 minutes'")


def read_observability() -> dict[str, Any]:
    with connect_db() as connection:
        services = connection.execute(
            """SELECT DISTINCT ON(service) service,status,metrics,detail,collected_at
               FROM service_health_samples ORDER BY service,collected_at DESC"""
        ).fetchall()
        history = connection.execute(
            """SELECT service,status,metrics,collected_at FROM service_health_samples
               WHERE collected_at>=NOW()-INTERVAL '24 hours' ORDER BY collected_at"""
        ).fetchall()
        forecasts = connection.execute(
            """SELECT f.host_id,h.name AS host_name,f.resource,f.current_percent,f.slope_per_day,
                      f.threshold_percent,f.predicted_days,f.sample_count,f.confidence,f.calculated_at
               FROM capacity_forecasts f JOIN managed_hosts h ON h.id=f.host_id
               ORDER BY f.predicted_days ASC NULLS LAST,h.name,f.resource"""
        ).fetchall()
        workers = connection.execute(
            """SELECT id,version,concurrency,active_tasks,last_heartbeat_at,
                      last_heartbeat_at>NOW()-INTERVAL '30 seconds' AS online
               FROM maintenance_workers ORDER BY last_heartbeat_at DESC"""
        ).fetchall()
    return {
        "services": [{"service":r["service"],"status":r["status"],"metrics":r["metrics"],"detail":r["detail"],"collectedAt":r["collected_at"].isoformat()} for r in services],
        "history": [{"service":r["service"],"status":r["status"],"metrics":r["metrics"],"collectedAt":r["collected_at"].isoformat()} for r in history],
        "forecasts": [{"hostId":r["host_id"],"hostName":r["host_name"],"resource":r["resource"],
            "currentPercent":float(r["current_percent"]),"slopePerDay":float(r["slope_per_day"]),
            "thresholdPercent":float(r["threshold_percent"]),"predictedDays":float(r["predicted_days"]) if r["predicted_days"] is not None else None,
            "sampleCount":r["sample_count"],"confidence":r["confidence"],"calculatedAt":r["calculated_at"].isoformat()} for r in forecasts],
        "workers": [{"id":r["id"],"version":r["version"],"concurrency":r["concurrency"],"activeTasks":r["active_tasks"],
            "online":r["online"],"lastHeartbeatAt":r["last_heartbeat_at"].isoformat()} for r in workers],
    }


@app.get("/api/observability")
async def observability_summary(request: Request, refresh: bool = False) -> dict[str, Any]:
    require_permission(request, "audit.read")
    if refresh:
        await asyncio.to_thread(refresh_observability)
    return await asyncio.to_thread(read_observability)


def read_reliability(window_days: int | None = None) -> dict[str, Any]:
    with connect_db() as connection:
        policy = connection.execute(
            "SELECT window_days,availability_target,mtta_target_minutes,mttr_target_minutes,updated_at FROM reliability_policy WHERE id=1"
        ).fetchone()
        days = window_days or policy["window_days"]
        services = connection.execute(
            """SELECT service,COUNT(*) AS samples,
                      COUNT(*) FILTER(WHERE status='healthy') AS healthy
               FROM service_health_samples
               WHERE collected_at>=NOW()-make_interval(days=>%s)
               GROUP BY service ORDER BY service""", (days,)
        ).fetchall()
        hosts = connection.execute(
            """SELECT s.host_id,h.name AS host_name,COUNT(*) AS samples,
                      COUNT(*) FILTER(WHERE s.state<>'offline') AS available
               FROM host_metric_samples s JOIN managed_hosts h ON h.id=s.host_id
               WHERE s.collected_at>=NOW()-make_interval(days=>%s)
               GROUP BY s.host_id,h.name ORDER BY h.name""", (days,)
        ).fetchall()
        incidents = connection.execute(
            """SELECT COUNT(*) AS total,
                      COUNT(*) FILTER(WHERE severity='critical') AS critical,
                      COUNT(*) FILTER(WHERE acknowledged_at IS NOT NULL) AS acknowledged,
                      COUNT(*) FILTER(WHERE resolved_at IS NOT NULL) AS resolved,
                      AVG(EXTRACT(EPOCH FROM(acknowledged_at-started_at))/60)
                        FILTER(WHERE acknowledged_at IS NOT NULL) AS mtta,
                      AVG(EXTRACT(EPOCH FROM(resolved_at-started_at))/60)
                        FILTER(WHERE resolved_at IS NOT NULL) AS mttr
               FROM alert_events WHERE started_at>=NOW()-make_interval(days=>%s)""", (days,)
        ).fetchone()
        trend = connection.execute(
            """SELECT date_trunc('day',started_at)::date AS day,COUNT(*) AS incidents,
                      COUNT(*) FILTER(WHERE severity='critical') AS critical
               FROM alert_events WHERE started_at>=NOW()-make_interval(days=>%s)
               GROUP BY 1 ORDER BY 1""", (days,)
        ).fetchall()
    target = float(policy["availability_target"])
    service_rows = [{"name":r["service"],"kind":"service","samples":r["samples"],
        "availability":round(100*r["healthy"]/r["samples"],3) if r["samples"] else None} for r in services]
    host_rows = [{"name":r["host_name"],"kind":"host","samples":r["samples"],
        "availability":round(100*r["available"]/r["samples"],3) if r["samples"] else None} for r in hosts]
    entities = service_rows+host_rows
    for item in entities:
        item["target"] = target
        item["met"] = item["availability"] is not None and item["availability"] >= target
    mtta = round(float(incidents["mtta"]),1) if incidents["mtta"] is not None else None
    mttr = round(float(incidents["mttr"]),1) if incidents["mttr"] is not None else None
    return {"policy":{"windowDays":days,"availabilityTarget":target,
        "mttaTargetMinutes":policy["mtta_target_minutes"],"mttrTargetMinutes":policy["mttr_target_minutes"],
        "updatedAt":policy["updated_at"].isoformat()},"entities":entities,
        "incidents":{"total":incidents["total"],"critical":incidents["critical"],
        "acknowledged":incidents["acknowledged"],"resolved":incidents["resolved"],"mttaMinutes":mtta,"mttrMinutes":mttr,
        "mttaMet":mtta is None or mtta<=policy["mtta_target_minutes"],"mttrMet":mttr is None or mttr<=policy["mttr_target_minutes"]},
        "trend":[{"day":r["day"].isoformat(),"incidents":r["incidents"],"critical":r["critical"]} for r in trend],
        "generatedAt":utc_now()}


@app.get("/api/reliability")
async def reliability_summary(request: Request) -> dict[str, Any]:
    require_permission(request, "audit.read")
    return await asyncio.to_thread(read_reliability)


@app.put("/api/reliability/policy")
async def update_reliability_policy(payload: ReliabilityPolicyUpdate, request: Request) -> dict[str, Any]:
    actor = require_permission(request, "backup.manage")
    with connect_db() as connection:
        connection.execute("""UPDATE reliability_policy SET window_days=%s,availability_target=%s,
            mtta_target_minutes=%s,mttr_target_minutes=%s,updated_by=%s,updated_at=NOW() WHERE id=1""",
            (payload.window_days,payload.availability_target,payload.mtta_target_minutes,payload.mttr_target_minutes,actor["id"]))
    await asyncio.to_thread(record_backend_audit, request, "reliability.policy.update", "更新可靠性目標", str(payload.window_days))
    return await asyncio.to_thread(read_reliability)


@app.get("/api/reliability/export.csv")
async def export_reliability(request: Request) -> Response:
    require_permission(request, "audit.read")
    report = await asyncio.to_thread(read_reliability)
    output = io.StringIO(); writer = csv.writer(output)
    writer.writerow(["類型","名稱","樣本數","可用率","目標","達標"])
    for item in report["entities"]:
        writer.writerow([item["kind"],item["name"],item["samples"],item["availability"],item["target"],"是" if item["met"] else "否"])
    return Response("\ufeff"+output.getvalue(),media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition":f'attachment; filename="linux-ai-reliability-{datetime.now(timezone.utc).date()}.csv"'})


def report_snapshot(days: int) -> dict[str, Any]:
    reliability = read_reliability(days)
    with connect_db() as connection:
        by_rule = connection.execute(
            """SELECT r.name,COUNT(*) AS count,COUNT(*) FILTER(WHERE e.severity='critical') AS critical
               FROM alert_events e JOIN alert_rules r ON r.id=e.rule_id
               WHERE e.started_at>=NOW()-make_interval(days=>%s)
               GROUP BY r.name ORDER BY count DESC,r.name LIMIT 10""", (days,)
        ).fetchall()
        by_host = connection.execute(
            """SELECT h.name,COUNT(*) AS count,COUNT(*) FILTER(WHERE e.severity='critical') AS critical
               FROM alert_events e JOIN managed_hosts h ON h.id=e.host_id
               WHERE e.started_at>=NOW()-make_interval(days=>%s)
               GROUP BY h.name ORDER BY count DESC,h.name LIMIT 10""", (days,)
        ).fetchall()
        tasks = connection.execute(
            """SELECT COUNT(*) AS total,COUNT(*) FILTER(WHERE status='succeeded') AS succeeded,
                      COUNT(*) FILTER(WHERE status IN ('failed','timed_out')) AS failed
               FROM maintenance_tasks WHERE requested_at>=NOW()-make_interval(days=>%s)""", (days,)
        ).fetchone()
    return {"days":days,"reliability":reliability,"alertsByRule":[dict(row) for row in by_rule],
        "alertsByHost":[dict(row) for row in by_host],"tasks":dict(tasks),"generatedAt":utc_now()}


def create_operational_report(report_type: str, days: int, actor_id: str | None = None) -> dict[str, Any]:
    end = datetime.now(timezone.utc).date(); start = end-timedelta(days=days)
    snapshot = report_snapshot(days); report_id = f"rpt-{uuid.uuid4().hex[:20]}"
    with connect_db() as connection:
        row = connection.execute(
            """INSERT INTO operational_reports(id,report_type,period_start,period_end,status,snapshot,requested_by)
               VALUES(%s,%s,%s,%s,'completed',%s::jsonb,%s)
               ON CONFLICT(report_type,period_start,period_end) WHERE report_type IN ('weekly','monthly') DO NOTHING
               RETURNING id""", (report_id,report_type,start,end,json.dumps(snapshot),actor_id)
        ).fetchone()
        if not row:
            existing = connection.execute("SELECT id FROM operational_reports WHERE report_type=%s AND period_start=%s AND period_end=%s",(report_type,start,end)).fetchone()
            report_id = existing["id"]
    return next(item for item in read_report_center()["reports"] if item["id"]==report_id)


def read_report_center() -> dict[str, Any]:
    with connect_db() as connection:
        policy = connection.execute("SELECT * FROM report_policy WHERE id=1").fetchone()
        rows = connection.execute("""SELECT id,report_type,period_start,period_end,status,snapshot,delivery_status,
            delivered_channels,error,requested_by,created_at FROM operational_reports ORDER BY created_at DESC LIMIT 100""").fetchall()
    return {"policy":{"enabled":policy["enabled"],"weeklyDay":policy["weekly_day"],"monthlyDay":policy["monthly_day"],
        "generateHourUtc":policy["generate_hour_utc"],"notifyEnabled":policy["notify_enabled"],"updatedAt":policy["updated_at"].isoformat()},
        "channels":notification_channels(),"reports":[{"id":r["id"],"reportType":r["report_type"],
        "periodStart":r["period_start"].isoformat(),"periodEnd":r["period_end"].isoformat(),"status":r["status"],
        "snapshot":r["snapshot"],"deliveryStatus":r["delivery_status"],"deliveredChannels":r["delivered_channels"],
        "error":r["error"],"createdAt":r["created_at"].isoformat()} for r in rows]}


async def notify_operational_report(report: dict[str, Any]) -> None:
    snapshot=report["snapshot"]; incidents=snapshot["reliability"]["incidents"]
    message=(f"Linux AI {report['reportType']} 營運報表\n期間 {report['periodStart']}～{report['periodEnd']}\n"
             f"告警 {incidents['total']}（重大 {incidents['critical']}）\nMTTA {incidents['mttaMinutes'] or '—'} 分／MTTR {incidents['mttrMinutes'] or '—'} 分")
    results=await dispatch_notifications([{"eventId":None,"kind":"report","severity":"warning","message":message,
        "retryKey":f"report:{report['id']}"}])
    status="no_channel" if not results else "sent" if any(item["status"]=="sent" for item in results) else "failed"
    with connect_db() as connection:
        connection.execute("UPDATE operational_reports SET delivery_status=%s,delivered_channels=%s::jsonb WHERE id=%s",
            (status,json.dumps([item["channel"] for item in results if item["status"]=="sent"]),report["id"]))


@app.get("/api/reports")
async def reports_center(request: Request) -> dict[str, Any]:
    require_permission(request,"audit.read"); return await asyncio.to_thread(read_report_center)


@app.put("/api/reports/policy")
async def save_report_policy(payload: ReportPolicyUpdate, request: Request) -> dict[str, Any]:
    actor=require_permission(request,"backup.manage")
    with connect_db() as connection:
        connection.execute("""UPDATE report_policy SET enabled=%s,weekly_day=%s,monthly_day=%s,generate_hour_utc=%s,
            notify_enabled=%s,updated_by=%s,updated_at=NOW() WHERE id=1""",
            (payload.enabled,payload.weekly_day,payload.monthly_day,payload.generate_hour_utc,payload.notify_enabled,actor["id"]))
    await asyncio.to_thread(record_backend_audit,request,"reports.policy.update","更新營運報表排程",str(payload.weekly_day))
    return await asyncio.to_thread(read_report_center)


@app.post("/api/reports",status_code=201)
async def generate_report(request: Request, notify: bool = False) -> dict[str, Any]:
    actor=require_permission(request,"backup.manage"); report=await asyncio.to_thread(create_operational_report,"manual",30,actor["id"])
    if notify: await notify_operational_report(report); report=next(item for item in (await asyncio.to_thread(read_report_center))["reports"] if item["id"]==report["id"])
    await asyncio.to_thread(record_backend_audit,request,"reports.generate","產生營運報表",report["id"]); return report


@app.get("/api/reports/{report_id}/export.csv")
async def export_report(report_id: str, request: Request) -> Response:
    require_permission(request,"audit.read"); center=await asyncio.to_thread(read_report_center)
    report=next((item for item in center["reports"] if item["id"]==report_id),None)
    if not report: raise HTTPException(status_code=404,detail="報表不存在")
    output=io.StringIO(); writer=csv.writer(output); writer.writerow(["類型","名稱","告警數","重大告警"])
    for item in report["snapshot"]["alertsByHost"]: writer.writerow(["主機",item["name"],item["count"],item["critical"]])
    for item in report["snapshot"]["alertsByRule"]: writer.writerow(["規則",item["name"],item["count"],item["critical"]])
    return Response("\ufeff"+output.getvalue(),media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition":f'attachment; filename="linux-ai-report-{report_id}.csv"'})


async def scheduled_report_loop() -> None:
    while True:
        try:
            center=await asyncio.to_thread(read_report_center); policy=center["policy"]; now=datetime.now(timezone.utc)
            if policy["enabled"] and now.hour==policy["generateHourUtc"]:
                schedules=[]
                if now.isoweekday()==policy["weeklyDay"]: schedules.append(("weekly",7))
                if now.day==policy["monthlyDay"]: schedules.append(("monthly",30))
                for kind,days in schedules:
                    report=await asyncio.to_thread(create_operational_report,kind,days,None)
                    if policy["notifyEnabled"] and report["deliveryStatus"]=="not_requested": await notify_operational_report(report)
        except Exception as error: print(f"scheduled report error: {error}",flush=True)
        await asyncio.sleep(900)


@app.post("/api/tasks", status_code=201)
async def create_maintenance_task(payload: MaintenanceTaskCreate, request: Request) -> dict[str, Any]:
    actor = require_permission(request, "tasks.request")
    host = get_host(payload.host_id)
    runbook = SAFE_RUNBOOKS.get(payload.runbook_id)
    if not runbook:
        raise HTTPException(status_code=422, detail="不允許的 Runbook；只能選擇中央預先定義項目")
    task_id = f"task-{uuid.uuid4().hex[:20]}"
    with connect_db() as connection:
        connection.execute(
            """
            INSERT INTO maintenance_tasks (
                id, host_id, runbook_id, title, command_preview, risk_level,
                approval_policy, verification_method, timeout_seconds, request_note, status, requested_by
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending', %s)
            """,
            (task_id, host["id"], payload.runbook_id, runbook["title"],
             runbook["command"], runbook["risk"], runbook["approval_policy"],
             runbook["verification"], int(runbook.get("timeout", 30)), payload.note.strip(), actor["id"]),
        )
    await asyncio.to_thread(record_backend_audit, request, "tasks.create", "建立安全維運任務", runbook["title"])
    return next(item for item in await asyncio.to_thread(read_maintenance_tasks) if item["id"] == task_id)


def alert_task_context(event_id: str) -> dict[str, Any]:
    """Return the fixed, least-privilege Runbooks permitted for one alert."""
    with connect_db() as connection:
        row = connection.execute(
            """
            SELECT e.id, e.rule_id, e.host_id, e.status, e.message,
                   r.name AS rule_name, h.name AS host_name
            FROM alert_events e
            JOIN alert_rules r ON r.id = e.rule_id
            JOIN managed_hosts h ON h.id = e.host_id
            WHERE e.id = %s
            """,
            (event_id,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="找不到告警事件")
    allowed_ids = ALERT_RUNBOOKS.get(row["rule_id"], ("system_overview",))
    runbooks = [
        {
            "id": runbook_id, "title": SAFE_RUNBOOKS[runbook_id]["title"],
            "description": SAFE_RUNBOOKS[runbook_id]["description"],
            "commandPreview": SAFE_RUNBOOKS[runbook_id]["command"],
            "risk": SAFE_RUNBOOKS[runbook_id]["risk"],
            "approvalPolicy": SAFE_RUNBOOKS[runbook_id]["approval_policy"],
            "verification": SAFE_RUNBOOKS[runbook_id]["verification"],
            "mutating": bool(SAFE_RUNBOOKS[runbook_id].get("mutating", False)),
        }
        for runbook_id in allowed_ids if runbook_id in SAFE_RUNBOOKS
    ]
    return {
        "id": row["id"], "hostId": row["host_id"], "hostName": row["host_name"],
        "ruleId": row["rule_id"], "ruleName": row["rule_name"],
        "status": row["status"], "message": row["message"], "runbooks": runbooks,
    }


@app.get("/api/alert-events/{event_id}/runbooks")
async def alert_event_runbooks(event_id: str, request: Request) -> dict[str, Any]:
    require_permission(request, "tasks.request")
    return await asyncio.to_thread(alert_task_context, event_id)


@app.get("/api/alert-events/{event_id}/tasks")
async def list_alert_maintenance_tasks(event_id: str, request: Request) -> dict[str, Any]:
    require_permission(request, "tasks.read")
    # Validate the alert first so a typo is not indistinguishable from no history.
    context = await asyncio.to_thread(alert_task_context, event_id)
    tasks = await asyncio.to_thread(read_maintenance_tasks, 200, event_id)
    return {
        "alert": {key: context[key] for key in ("id", "hostId", "hostName", "ruleId", "ruleName", "status", "message")},
        "tasks": tasks,
    }


@app.post("/api/alert-events/{event_id}/tasks", status_code=201)
async def create_alert_maintenance_task(
    event_id: str, payload: AlertMaintenanceTaskCreate, request: Request
) -> dict[str, Any]:
    actor = require_permission(request, "tasks.request")
    context = await asyncio.to_thread(alert_task_context, event_id)
    if context["status"] == "resolved":
        raise HTTPException(status_code=409, detail="已恢復的告警不可建立新的維運任務")
    allowed = {item["id"]: item for item in context["runbooks"]}
    runbook = allowed.get(payload.runbook_id)
    if not runbook:
        raise HTTPException(status_code=422, detail="不允許的告警 Runbook；只能選擇此告警指定的固定項目")
    task_id = f"task-{uuid.uuid4().hex[:20]}"
    note_parts = [f"由告警「{context['ruleName']}」建立：{context['message']}"]
    if payload.note.strip():
        note_parts.append(payload.note.strip())
    with connect_db() as connection:
        existing = connection.execute(
            """SELECT id FROM maintenance_tasks
               WHERE source_alert_id = %s AND runbook_id = %s
                 AND status IN ('pending', 'approved', 'queued', 'running')""",
            (event_id, payload.runbook_id),
        ).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="此告警已有相同 Runbook 的待處理維運任務")
        connection.execute(
            """
            INSERT INTO maintenance_tasks (
                id, host_id, runbook_id, title, command_preview, risk_level,
                approval_policy, verification_method, source_alert_id, request_note,
                timeout_seconds, status, requested_by
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending', %s)
            """,
            (task_id, context["hostId"], payload.runbook_id, runbook["title"],
             runbook["commandPreview"], runbook["risk"], runbook["approvalPolicy"],
             runbook["verification"], event_id, "\n".join(note_parts)[:500],
             int(SAFE_RUNBOOKS[payload.runbook_id].get("timeout", 30)), actor["id"]),
        )
    await asyncio.to_thread(
        record_backend_audit, request, "tasks.create_from_alert",
        "由告警建立受控維運任務", f"{context['hostName']} · {runbook['title']}"
    )
    return next(item for item in await asyncio.to_thread(read_maintenance_tasks) if item["id"] == task_id)


@app.post("/api/tasks/{task_id}/approve")
async def approve_maintenance_task(
    task_id: str, payload: MaintenanceTaskDecision, request: Request
) -> dict[str, Any]:
    actor = require_permission(request, "tasks.approve")
    with connect_db() as connection:
        task = connection.execute(
            "SELECT status, risk_level, requested_by FROM maintenance_tasks WHERE id = %s",
            (task_id,),
        ).fetchone()
        if not task or task["status"] != "pending":
            raise HTTPException(status_code=409, detail="任務不存在或已完成審核")
        if task["risk_level"] in {"medium", "high"} and task["requested_by"] == actor["id"]:
            raise HTTPException(status_code=403, detail="中高風險任務必須由另一位具核准權限的使用者核准")
        row = connection.execute(
            """
            UPDATE maintenance_tasks
            SET status = 'approved', approved_by = %s, decision_note = %s,
                decided_at = NOW(), approval_expires_at = NOW() + make_interval(mins => %s)
            WHERE id = %s AND status = 'pending'
            RETURNING id
            """,
            (actor["id"], payload.note.strip(), MAINTENANCE_APPROVAL_TTL_MINUTES, task_id),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=409, detail="任務不存在或已完成審核")
    await asyncio.to_thread(record_backend_audit, request, "tasks.approve", "核准安全維運任務", task_id)
    return {"id": task_id, "status": "approved"}


@app.post("/api/tasks/{task_id}/reject")
async def reject_maintenance_task(
    task_id: str, payload: MaintenanceTaskDecision, request: Request
) -> dict[str, Any]:
    actor = require_permission(request, "tasks.approve")
    with connect_db() as connection:
        row = connection.execute(
            """
            UPDATE maintenance_tasks
            SET status = 'rejected', approved_by = %s, decision_note = %s,
                decided_at = NOW(), completed_at = NOW()
            WHERE id = %s AND status = 'pending'
            RETURNING id
            """,
            (actor["id"], payload.note.strip(), task_id),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=409, detail="任務不存在或已完成審核")
    await asyncio.to_thread(record_backend_audit, request, "tasks.reject", "拒絕安全維運任務", task_id)
    return {"id": task_id, "status": "rejected"}


@app.post("/api/tasks/{task_id}/cancel")
async def cancel_maintenance_task(task_id: str, request: Request) -> dict[str, Any]:
    require_permission(request, "tasks.execute")
    with connect_db() as connection:
        row = connection.execute(
            """UPDATE maintenance_tasks
               SET cancel_requested_at=NOW(),
                   status=CASE WHEN status IN ('pending','approved','queued') THEN 'cancelled' ELSE status END,
                   completed_at=CASE WHEN status IN ('pending','approved','queued') THEN NOW() ELSE completed_at END,
                   error=CASE WHEN status IN ('pending','approved','queued') THEN '由管理者取消' ELSE error END
               WHERE id=%s AND status IN ('pending','approved','queued','running')
               RETURNING status""",
            (task_id,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=409, detail="任務已結束或不存在，無法取消")
    running = maintenance_execution_tasks.get(task_id)
    if running and not running.done():
        running.cancel()
    await asyncio.to_thread(record_backend_audit, request, "tasks.cancel", "取消維運任務", task_id)
    return {"id": task_id, "status": "cancelling" if row["status"] == "running" else "cancelled"}


@app.post("/api/tasks/{task_id}/retry", status_code=201)
async def retry_maintenance_task(task_id: str, request: Request) -> dict[str, Any]:
    actor = require_permission(request, "tasks.request")
    new_id = f"task-{uuid.uuid4().hex[:20]}"
    with connect_db() as connection:
        source = connection.execute(
            "SELECT * FROM maintenance_tasks WHERE id=%s AND status IN ('failed','timed_out','cancelled')",
            (task_id,),
        ).fetchone()
        if not source:
            raise HTTPException(status_code=409, detail="只有失敗、逾時或已取消的任務可以重試")
        connection.execute(
            """INSERT INTO maintenance_tasks(
                   id,host_id,runbook_id,title,command_preview,risk_level,approval_policy,
                   verification_method,source_alert_id,retry_of,attempt,timeout_seconds,
                   request_note,status,requested_by)
               VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'pending',%s)""",
            (new_id, source["host_id"], source["runbook_id"], source["title"],
             source["command_preview"], source["risk_level"], source["approval_policy"],
             source["verification_method"], source["source_alert_id"], task_id,
             source["attempt"] + 1, source["timeout_seconds"],
             f"重試 {task_id}：{source['request_note']}"[:500], actor["id"]),
        )
    await asyncio.to_thread(record_backend_audit, request, "tasks.retry", "重試維運任務", task_id)
    return next(item for item in await asyncio.to_thread(read_maintenance_tasks) if item["id"] == new_id)


def reap_stuck_maintenance_tasks() -> int:
    with connect_db() as connection:
        rows = connection.execute(
            """UPDATE maintenance_tasks SET status='timed_out',verification_status='failed',
                      error='任務超過執行逾時或心跳中斷，已由中央回收',completed_at=NOW()
               WHERE status='running'
                 AND COALESCE(heartbeat_at,started_at) < NOW() - make_interval(secs => timeout_seconds + 30)
               RETURNING id"""
        ).fetchall()
    for row in rows:
        running = maintenance_execution_tasks.get(row["id"])
        if running and not running.done():
            running.cancel()
    return len(rows)


async def maintenance_reaper_loop() -> None:
    while True:
        try:
            await asyncio.to_thread(reap_stuck_maintenance_tasks)
        except psycopg.Error:
            pass
        await asyncio.sleep(15)


async def retention_cleanup_loop() -> None:
    # Delay startup cleanup so migrations and the rest of the service settle first.
    await asyncio.sleep(60)
    while True:
        try:
            await asyncio.to_thread(run_retention, False, None)
        except (psycopg.Error, KeyError):
            pass
        await asyncio.sleep(24 * 60 * 60)


async def observability_loop() -> None:
    await asyncio.sleep(20)
    while True:
        try:
            await asyncio.to_thread(refresh_observability)
        except (psycopg.Error, OSError, ValueError):
            pass
        await asyncio.sleep(300)


@app.post("/api/tasks/recover-stuck")
async def recover_stuck_tasks(request: Request) -> dict[str, Any]:
    require_permission(request, "tasks.execute")
    count = await asyncio.to_thread(reap_stuck_maintenance_tasks)
    await asyncio.to_thread(record_backend_audit, request, "tasks.recover_stuck", "回收卡住的維運任務", str(count))
    return {"recovered": count}


@app.post("/api/tasks/{task_id}/execute")
async def execute_maintenance_task(
    task_id: str, payload: MaintenanceTaskExecute, request: Request
) -> dict[str, Any]:
    require_permission(request, "tasks.execute")
    with connect_db() as connection:
        expired = connection.execute(
            """UPDATE maintenance_tasks SET status='failed', verification_status='failed',
                      error='核准已超過有效期限，請重新建立任務', completed_at=NOW()
               WHERE id=%s AND status='approved' AND approval_expires_at <= NOW()
               RETURNING id""",
            (task_id,),
        ).fetchone()
        task = None if expired else connection.execute(
            "SELECT host_id,runbook_id FROM maintenance_tasks WHERE id=%s AND status='approved'",
            (task_id,),
        ).fetchone()
    if expired:
        raise HTTPException(status_code=409, detail="任務核准已過期，請重新建立並核准")
    if not task:
        raise HTTPException(status_code=409, detail="任務必須先核准，且不能重複排入佇列")
    runbook = SAFE_RUNBOOKS.get(task["runbook_id"])
    if not runbook:
        raise HTTPException(status_code=409, detail="Runbook 已不存在")
    if runbook["risk"] == "high" and payload.confirmation != "EXECUTE":
        raise HTTPException(status_code=422, detail="高風險任務必須輸入 EXECUTE 才能執行")
    host = get_host(task["host_id"])
    if runbook.get("mutating"):
        readiness = await inspect_maintenance_sudo_policy(host)
        if not readiness["ready"]:
            raise HTTPException(status_code=409, detail=f"目標主機未通過維運權限檢查：{readiness['detail']}")
    with connect_db() as connection:
        queued = connection.execute(
            """UPDATE maintenance_tasks SET status='queued',queued_at=NOW(),heartbeat_at=NULL
               WHERE id=%s AND status='approved' AND approval_expires_at>NOW() RETURNING id""",
            (task_id,),
        ).fetchone()
    if not queued:
        raise HTTPException(status_code=409, detail="任務已由其他操作排入佇列")
    await asyncio.to_thread(record_backend_audit, request, "tasks.queue", "維運任務排入獨立 Worker", runbook["title"])
    return next(item for item in await asyncio.to_thread(read_maintenance_tasks) if item["id"] == task_id)


@app.get("/api/hosts/{host_id}/metrics")
async def host_metrics(
    host_id: str,
    request: Request,
    hours: int = Query(default=24, ge=1, le=720),
) -> dict[str, Any]:
    require_permission(request, "alerts.read")
    get_host(host_id)
    def read_metrics() -> list[dict[str, Any]]:
        with connect_db() as connection:
            rows = connection.execute(
                """
                SELECT collected_at, state, cpu_percent, ram_percent,
                       disk_percent, load_one, uptime_seconds,
                       failed_service_count, error
                FROM host_metric_samples
                WHERE host_id = %s
                  AND collected_at >= NOW() - (%s * INTERVAL '1 hour')
                ORDER BY collected_at ASC
                LIMIT 1000
                """,
                (host_id, hours),
            ).fetchall()
        return [
            {
                "collectedAt": row["collected_at"].isoformat(),
                "state": row["state"], "cpu": float(row["cpu_percent"]),
                "ram": float(row["ram_percent"]), "disk": float(row["disk_percent"]),
                "load": float(row["load_one"]) if row["load_one"] is not None else None,
                "uptimeSeconds": row["uptime_seconds"],
                "failedServices": row["failed_service_count"], "error": row["error"],
            }
            for row in rows
        ]
    return {"hostId": host_id, "hours": hours, "samples": await asyncio.to_thread(read_metrics)}

@app.get("/api/hosts/{host_id}/metric-trends")
async def host_metric_trends(host_id:str,request:Request,range_name:str=Query(default="24h",alias="range",pattern="^(24h|7d|30d|90d)$"))->dict[str,Any]:
    require_permission(request,"alerts.read"); get_host(host_id)
    if range_name=="24h": return await host_metrics(host_id,request,24)
    table="host_metric_hourly" if range_name=="7d" else "host_metric_daily"; days={"7d":7,"30d":30,"90d":90}[range_name]
    with connect_db() as connection:
        rows=connection.execute(f"SELECT * FROM {table} WHERE host_id=%s AND bucket_at>=NOW()-make_interval(days=>%s) ORDER BY bucket_at",(host_id,days)).fetchall()
    samples=[{"collectedAt":r["bucket_at"].isoformat(),"state":"healthy" if float(r["availability_percent"])>=99 else "warning" if float(r["availability_percent"])>=80 else "offline","cpu":float(r["cpu_avg"]),"ram":float(r["ram_avg"]),"disk":float(r["disk_avg"]),"failedServices":r["failed_service_max"],"sampleCount":r["sample_count"],"availability":float(r["availability_percent"])} for r in rows]
    return {"hostId":host_id,"range":range_name,"resolution":"hour" if table.endswith("hourly") else "day","samples":samples}


def ubuntu_security_notice_index(codename: str) -> dict[str, list[dict[str, Any]]]:
    if not codename or not re.fullmatch(r"[a-z][a-z0-9-]{1,30}", codename):
        return {}
    now = time.monotonic()
    with ubuntu_security_notice_lock:
        cached = ubuntu_security_notice_cache.get(codename)
        if cached and now - cached[0] < UBUNTU_SECURITY_CACHE_SECONDS:
            return cached[1]
        def fetch_page(offset: int) -> dict[str, Any]:
            url = UBUNTU_SECURITY_API_URL + "?" + urllib.parse.urlencode(
                {"release": codename, "limit": 20, "offset": offset}
            )
            request = urllib.request.Request(
                url, headers={"User-Agent": "Linux-AI-Control-Plane/0.1 security-inventory"}
            )
            with urllib.request.urlopen(request, timeout=20) as response:
                return json.loads(response.read(50_000_000).decode("utf-8"))

        first_page = fetch_page(0)
        notices = list(first_page.get("notices", [])) if isinstance(first_page, dict) else []
        total_results = max(0, int(first_page.get("total_results", len(notices))))
        offsets = list(range(20, total_results, 20))
        if offsets:
            with ThreadPoolExecutor(max_workers=min(6, len(offsets))) as executor:
                for page in executor.map(fetch_page, offsets):
                    page_notices = page.get("notices", []) if isinstance(page, dict) else []
                    if isinstance(page_notices, list):
                        notices.extend(page_notices)
        index: dict[str, list[dict[str, Any]]] = {}
        for notice in notices:
            if not isinstance(notice, dict):
                continue
            release_packages = notice.get("release_packages", {})
            items = release_packages.get(codename, []) if isinstance(release_packages, dict) else []
            cves = [
                item for item in notice.get("cves_ids", [])
                if isinstance(item, str) and re.fullmatch(r"CVE-\d{4}-\d{4,}", item)
            ][:100]
            for package in items:
                if not isinstance(package, dict) or package.get("is_source"):
                    continue
                name = str(package.get("name", ""))
                if not name:
                    continue
                index.setdefault(name, []).append({
                    "notice": str(notice.get("id", "")),
                    "version": str(package.get("version", "")),
                    "pocket": str(package.get("pocket", "")),
                    "cves": cves,
                })
        ubuntu_security_notice_cache[codename] = (now, index)
        return index


def enrich_patch_packages(
    codename: str, packages: list[dict[str, Any]], reboot_required: bool
) -> tuple[list[dict[str, Any]], int, int, dict[str, int], str]:
    notice_index: dict[str, list[dict[str, Any]]] = {}
    source_status = "canonical"
    try:
        notice_index = ubuntu_security_notice_index(codename)
        if not codename:
            source_status = "unsupported-release"
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError):
        source_status = "local-only"

    sensitive_names = (
        "linux-image", "linux-generic", "linux-modules", "openssl", "libssl",
        "openssh", "sudo", "systemd", "libc6", "glibc", "grub", "docker",
        "containerd", "postgresql",
    )
    security_count = 0
    all_cves: set[str] = set()
    risk_summary = {"high": 0, "medium": 0, "normal": 0}
    enriched: list[dict[str, Any]] = []
    for raw_package in packages[:200]:
        package = dict(raw_package) if isinstance(raw_package, dict) else {}
        name = str(package.get("name", ""))
        candidate = str(package.get("candidateVersion", ""))
        exact_matches = [
            item for item in notice_index.get(name, [])
            if item.get("version") == candidate
        ]
        notices = sorted({item["notice"] for item in exact_matches if item.get("notice")})
        cves = sorted({cve for item in exact_matches for cve in item.get("cves", [])})
        pockets = sorted({item["pocket"] for item in exact_matches if item.get("pocket")})
        is_security = bool(package.get("securityHint") or exact_matches)
        if is_security:
            security_count += 1
            is_sensitive = name.startswith(sensitive_names)
            risk = "high" if is_sensitive or (reboot_required and name.startswith("linux-")) else "medium"
        else:
            risk = "normal"
        all_cves.update(cves)
        risk_summary[risk] += 1
        package.update({
            "isSecurity": is_security,
            "risk": risk,
            "cves": cves[:50],
            "notices": notices[:20],
            "securityPockets": pockets,
        })
        enriched.append(package)
    if source_status == "canonical" and not notice_index:
        source_status = "canonical-empty"
    return enriched, security_count, len(all_cves), risk_summary, source_status


AUTOMATION_SCAN_TABLES = {
    "asset_inventory": "host_asset_scans",
    "patch_inventory": "host_patch_scans",
    "security_baseline": "host_security_scans",
}


def start_automation_run(
    job_type: str, trigger_type: str, actor_id: str | None, total_hosts: int
) -> str:
    if job_type not in AUTOMATION_SCAN_TABLES or trigger_type not in {"scheduled", "manual"}:
        raise ValueError("不支援的自動巡檢工作")
    run_id = f"auto-{uuid.uuid4().hex[:20]}"
    with connect_db() as connection:
        connection.execute(
            """INSERT INTO automation_runs(
                   id,job_type,trigger_type,status,requested_by,total_hosts)
               VALUES(%s,%s,%s,'running',%s,%s)""",
            (run_id, job_type, trigger_type, actor_id, total_hosts),
        )
    return run_id


def finish_automation_run(
    run_id: str, job_type: str, host_ids: list[str], error: str | None = None
) -> None:
    table = AUTOMATION_SCAN_TABLES[job_type]
    succeeded = 0
    if host_ids and not error:
        with connect_db() as connection:
            rows = connection.execute(
                f"""SELECT DISTINCT ON (host_id) host_id,status FROM {table}
                    WHERE host_id=ANY(%s) ORDER BY host_id,checked_at DESC""",
                (host_ids,),
            ).fetchall()
        succeeded = sum(1 for row in rows if row["status"] == "success")
    failed = len(host_ids) - succeeded
    status = "failed" if error or (host_ids and succeeded == 0) else "partial" if failed else "success"
    with connect_db() as connection:
        connection.execute(
            """UPDATE automation_runs SET status=%s,succeeded_hosts=%s,failed_hosts=%s,error=%s,
                      completed_at=NOW(),duration_ms=GREATEST(0,(EXTRACT(EPOCH FROM (NOW()-started_at))*1000)::int)
               WHERE id=%s""",
            (status, succeeded, failed, error[:500] if error else None, run_id),
        )


def read_automation_runs(limit: int = 30) -> list[dict[str, Any]]:
    with connect_db() as connection:
        rows = connection.execute(
            """SELECT r.*,u.display_name AS requested_by_name FROM automation_runs r
               LEFT JOIN platform_users u ON u.id=r.requested_by
               ORDER BY r.started_at DESC LIMIT %s""", (limit,),
        ).fetchall()
    return [{
        "id": row["id"], "jobType": row["job_type"], "triggerType": row["trigger_type"],
        "status": row["status"], "requestedBy": row["requested_by_name"] or "系統排程",
        "totalHosts": row["total_hosts"], "succeededHosts": row["succeeded_hosts"],
        "failedHosts": row["failed_hosts"], "error": row["error"],
        "startedAt": row["started_at"].isoformat(),
        "completedAt": row["completed_at"].isoformat() if row["completed_at"] else None,
        "durationMs": row["duration_ms"],
    } for row in rows]


def read_patch_inventory() -> list[dict[str, Any]]:
    with connect_db() as connection:
        rows = connection.execute(
            """
            SELECT h.id AS host_id, h.name AS host_name, h.address,
                   scan.id, scan.status, scan.kernel_version,
                   scan.reboot_required, scan.reboot_packages,
                   scan.unattended_upgrades, scan.pending_count,
                   scan.packages, scan.os_codename, scan.security_count,
                   scan.cve_count, scan.risk_summary, scan.security_source_status,
                   scan.truncated, scan.error,
                   scan.checked_at, u.display_name AS checked_by
            FROM managed_hosts h
            LEFT JOIN LATERAL (
                SELECT * FROM host_patch_scans p
                WHERE p.host_id = h.id ORDER BY p.checked_at DESC LIMIT 1
            ) scan ON TRUE
            LEFT JOIN platform_users u ON u.id = scan.checked_by
            WHERE h.enabled = TRUE
            ORDER BY h.name
            """
        ).fetchall()
    return [
        {
            "hostId": row["host_id"], "hostName": row["host_name"],
            "address": row["address"], "scanId": row["id"],
            "status": row["status"] or "never",
            "kernelVersion": row["kernel_version"],
            "rebootRequired": bool(row["reboot_required"]),
            "rebootPackages": row["reboot_packages"] or [],
            "unattendedUpgrades": row["unattended_upgrades"],
            "pendingCount": row["pending_count"] or 0,
            "osCodename": row["os_codename"],
            "securityCount": row["security_count"] or 0,
            "cveCount": row["cve_count"] or 0,
            "riskSummary": row["risk_summary"] or {"high": 0, "medium": 0, "normal": 0},
            "securitySourceStatus": row["security_source_status"],
            "packages": row["packages"] or [], "truncated": bool(row["truncated"]),
            "error": row["error"], "checkedBy": row["checked_by"],
            "checkedAt": row["checked_at"].isoformat() if row["checked_at"] else None,
        }
        for row in rows
    ]


def read_patch_inventory_policy() -> dict[str, Any]:
    with connect_db() as connection:
        row = connection.execute(
            """SELECT enabled,interval_hours,security_threshold,notify_security_updates,
                      last_started_at,last_completed_at,updated_at
               FROM patch_inventory_policy WHERE id=1"""
        ).fetchone()
    return {
        "enabled": row["enabled"], "intervalHours": row["interval_hours"],
        "securityThreshold": row["security_threshold"],
        "notifySecurityUpdates": row["notify_security_updates"],
        "lastStartedAt": row["last_started_at"].isoformat() if row["last_started_at"] else None,
        "lastCompletedAt": row["last_completed_at"].isoformat() if row["last_completed_at"] else None,
        "updatedAt": row["updated_at"].isoformat(),
    }


def update_security_update_alert(
    host: dict[str, Any], security_count: int, cve_count: int,
    threshold: int, notify: bool,
) -> list[dict[str, Any]]:
    firing = security_count >= threshold
    intents: list[dict[str, Any]] = []
    with connect_db() as connection:
        rule = connection.execute(
            "SELECT id,severity,enabled FROM alert_rules WHERE id='rule-security-updates'"
        ).fetchone()
        if not rule or not rule["enabled"]:
            return []
        active = connection.execute(
            """SELECT id FROM alert_events WHERE rule_id=%s AND host_id=%s
               AND status IN ('firing','acknowledged')""",
            (rule["id"], host["id"]),
        ).fetchone()
        message = f"{host['name']} 有 {security_count} 項安全更新待處理，關聯 {cve_count} 個 CVE"
        if firing and active:
            connection.execute(
                "UPDATE alert_events SET last_value=%s,message=%s,updated_at=NOW() WHERE id=%s",
                (security_count, message, active["id"]),
            )
        elif firing:
            event_id = f"alt-{uuid.uuid4().hex[:20]}"
            connection.execute(
                """INSERT INTO alert_events(id,rule_id,host_id,status,severity,message,last_value)
                   VALUES(%s,%s,%s,'firing',%s,%s,%s)""",
                (event_id, rule["id"], host["id"], rule["severity"], message, security_count),
            )
            if notify:
                intents.append({"eventId": event_id, "kind": "firing", "severity": rule["severity"],
                                "message": f"🚨 [Linux AI SECURITY UPDATES]\n{message}"})
        elif active:
            connection.execute(
                """UPDATE alert_events SET status='resolved',last_value=0,updated_at=NOW(),resolved_at=NOW()
                   WHERE id=%s""", (active["id"],),
            )
            if notify:
                intents.append({"eventId": active["id"], "kind": "resolved", "severity": rule["severity"],
                                "message": f"✅ [Linux AI 已恢復]\n{host['name']} 已無達到門檻的安全更新"})
    return intents


async def scan_patch_host(host: dict[str, Any], actor_id: str | None) -> list[dict[str, Any]]:
    encoded = base64.b64encode(REMOTE_PATCH_STATUS.encode()).decode()
    command = f"python3 -c \"import base64;exec(base64.b64decode('{encoded}'))\""
    status = "success"
    error: str | None = None
    payload: dict[str, Any] = {}
    try:
        payload = json.loads(await run_ssh(host, command, timeout=25))
        pending_count = max(0, int(payload.get("pendingCount", 0)))
        packages = payload.get("packages", [])
        if not isinstance(packages, list):
            raise ValueError("套件清單格式錯誤")
        (
            packages, security_count, cve_count, risk_summary, security_source_status,
        ) = await asyncio.to_thread(
            enrich_patch_packages,
            str(payload.get("osCodename", "")), packages,
            bool(payload.get("rebootRequired", False)),
        )
    except (RuntimeError, json.JSONDecodeError, ValueError, TypeError) as reason:
        status = "failed"
        error = str(reason)[:500]
        pending_count = 0
        packages = []
        security_count, cve_count = 0, 0
        risk_summary = {"high": 0, "medium": 0, "normal": 0}
        security_source_status = "failed"
    with connect_db() as connection:
        connection.execute(
            """INSERT INTO host_patch_scans (
                   id, host_id, status, kernel_version, reboot_required,
                   reboot_packages, unattended_upgrades, pending_count,
                   packages, os_codename, security_count, cve_count,
                   risk_summary, security_source_status, truncated, error, checked_by
               ) VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s::jsonb,
                         %s, %s, %s, %s::jsonb, %s, %s, %s, %s)""",
            (
                f"patch-{uuid.uuid4().hex[:20]}", host["id"], status,
                payload.get("kernelVersion"), bool(payload.get("rebootRequired", False)),
                json.dumps(payload.get("rebootPackages", [])),
                payload.get("unattendedUpgrades"), pending_count,
                json.dumps(packages), payload.get("osCodename"), security_count, cve_count,
                json.dumps(risk_summary), security_source_status,
                bool(payload.get("truncated", False)), error, actor_id,
            ),
        )
    if status != "success":
        return []
    policy = await asyncio.to_thread(read_patch_inventory_policy)
    return await asyncio.to_thread(
        update_security_update_alert, host, security_count, cve_count,
        policy["securityThreshold"], policy["notifySecurityUpdates"],
    )


async def collect_patch_inventory_cycle(
    inventory: list[dict[str, Any]], actor_id: str | None, update_schedule: bool = True,
    trigger_type: str = "manual",
) -> None:
    run_id = await asyncio.to_thread(start_automation_run, "patch_inventory", trigger_type, actor_id, len(inventory))
    host_ids = [host["id"] for host in inventory]
    try:
        if update_schedule:
            with connect_db() as connection:
                connection.execute("UPDATE patch_inventory_policy SET last_started_at=NOW() WHERE id=1")
        semaphore = asyncio.Semaphore(4)

        async def limited_scan(host: dict[str, Any]) -> list[dict[str, Any]]:
            async with semaphore:
                return await scan_patch_host(host, actor_id)

        notifications = await asyncio.gather(*(limited_scan(host) for host in inventory))
        if update_schedule:
            with connect_db() as connection:
                connection.execute("UPDATE patch_inventory_policy SET last_completed_at=NOW() WHERE id=1")
        await dispatch_notifications([intent for batch in notifications for intent in batch])
    except Exception as reason:
        await asyncio.to_thread(finish_automation_run, run_id, "patch_inventory", host_ids, str(reason))
        raise
    await asyncio.to_thread(finish_automation_run, run_id, "patch_inventory", host_ids)


async def patch_inventory_loop() -> None:
    while True:
        try:
            policy = await asyncio.to_thread(read_patch_inventory_policy)
            completed_at = policy.get("lastCompletedAt")
            last_completed = datetime.fromisoformat(completed_at) if completed_at else None
            due = last_completed is None or datetime.now(timezone.utc) >= (
                last_completed + timedelta(hours=policy["intervalHours"])
            )
            if policy["enabled"] and due and not patch_scan_lock.locked():
                inventory = await asyncio.to_thread(load_inventory)
                async with patch_scan_lock:
                    await collect_patch_inventory_cycle(inventory, None, trigger_type="scheduled")
        except asyncio.CancelledError:
            raise
        except (OSError, RuntimeError, ValueError, psycopg.Error):
            pass
        await asyncio.sleep(60)


@app.get("/api/patch-inventory")
async def list_patch_inventory(request: Request) -> dict[str, Any]:
    require_permission(request, "hosts.read")
    return {"hosts": await asyncio.to_thread(read_patch_inventory),
            "policy": await asyncio.to_thread(read_patch_inventory_policy)}


@app.post("/api/patch-inventory/scan", status_code=201)
async def create_patch_inventory_scan(
    payload: PatchScanRequest, request: Request
) -> dict[str, Any]:
    actor = require_permission(request, "hosts.manage")
    if patch_scan_lock.locked():
        raise HTTPException(status_code=409, detail="已有更新盤點正在執行")
    inventory = await asyncio.to_thread(load_inventory)
    if payload.host_id:
        inventory = [host for host in inventory if host["id"] == payload.host_id]
        if not inventory:
            raise HTTPException(status_code=404, detail="找不到指定的受管主機")
    async with patch_scan_lock:
        await collect_patch_inventory_cycle(
            inventory, actor["id"], update_schedule=not bool(payload.host_id)
        )
    await asyncio.to_thread(
        record_backend_audit, request, "patch.scan", "執行更新與安全風險盤點",
        payload.host_id or "all-hosts",
    )
    return {"hosts": await asyncio.to_thread(read_patch_inventory),
            "policy": await asyncio.to_thread(read_patch_inventory_policy)}


@app.put("/api/patch-inventory/policy")
async def update_patch_inventory_policy(
    payload: PatchInventoryPolicyUpdate, request: Request
) -> dict[str, Any]:
    actor = require_permission(request, "hosts.manage")
    with connect_db() as connection:
        connection.execute(
            """UPDATE patch_inventory_policy SET enabled=%s,interval_hours=%s,
                      security_threshold=%s,notify_security_updates=%s,
                      updated_by=%s,updated_at=NOW() WHERE id=1""",
            (payload.enabled, payload.interval_hours, payload.security_threshold,
             payload.notify_security_updates, actor["id"]),
        )
        connection.execute(
            "UPDATE alert_rules SET threshold=%s,updated_at=NOW() WHERE id='rule-security-updates'",
            (payload.security_threshold,),
        )
    await asyncio.to_thread(
        record_backend_audit, request, "patch.policy.update", "更新自動安全更新盤點政策",
        "patch-inventory",
    )
    return {"policy": await asyncio.to_thread(read_patch_inventory_policy)}


ASSET_LIST_FIELDS = ("interfaces", "listeningPorts", "enabledServices", "interactiveUsers")


def normalize_asset_snapshot(payload: dict[str, Any]) -> dict[str, Any]:
    snapshot: dict[str, Any] = {
        "hostname": str(payload.get("hostname", ""))[:200],
        "osName": str(payload.get("osName", ""))[:300],
        "kernelVersion": str(payload.get("kernelVersion", ""))[:200],
        "installedPackageCount": max(0, int(payload.get("installedPackageCount", 0))),
    }
    limits = {"interfaces": 100, "listeningPorts": 500, "enabledServices": 500, "interactiveUsers": 200}
    for field in ASSET_LIST_FIELDS:
        values = payload.get(field, [])
        if not isinstance(values, list):
            raise ValueError(f"{field} 格式錯誤")
        snapshot[field] = sorted({str(value)[:1000] for value in values if str(value).strip()})[:limits[field]]
    return snapshot


def compare_asset_snapshots(previous: dict[str, Any] | None, current: dict[str, Any]) -> dict[str, Any]:
    if not previous:
        return {"baseline": True, "changed": False, "fields": {}}
    fields: dict[str, Any] = {}
    for field in ASSET_LIST_FIELDS:
        before = {str(value) for value in previous.get(field, [])}
        after = {str(value) for value in current.get(field, [])}
        added, removed = sorted(after - before), sorted(before - after)
        if added or removed:
            fields[field] = {"added": added[:100], "removed": removed[:100]}
    for field in ("hostname", "osName", "kernelVersion", "installedPackageCount"):
        if previous.get(field) != current.get(field):
            fields[field] = {"before": previous.get(field), "after": current.get(field)}
    return {"baseline": False, "changed": bool(fields), "fields": fields}


def read_asset_inventory_policy() -> dict[str, Any]:
    with connect_db() as connection:
        row = connection.execute(
            """SELECT enabled,interval_hours,notify_drift,last_started_at,last_completed_at,updated_at
               FROM asset_inventory_policy WHERE id=1"""
        ).fetchone()
    return {
        "enabled": row["enabled"], "intervalHours": row["interval_hours"],
        "notifyDrift": row["notify_drift"],
        "lastStartedAt": row["last_started_at"].isoformat() if row["last_started_at"] else None,
        "lastCompletedAt": row["last_completed_at"].isoformat() if row["last_completed_at"] else None,
        "updatedAt": row["updated_at"].isoformat(),
    }


def update_asset_drift_alert(
    host: dict[str, Any], changes: dict[str, Any], notify_drift: bool
) -> list[dict[str, Any]]:
    if changes.get("baseline"):
        return []
    fields = changes.get("fields", {}) if isinstance(changes.get("fields"), dict) else {}
    changed = bool(changes.get("changed"))
    intents: list[dict[str, Any]] = []
    labels = {"interfaces": "網路介面", "listeningPorts": "監聽連接埠", "enabledServices": "啟用服務", "interactiveUsers": "互動帳號", "hostname": "主機名稱", "osName": "作業系統", "kernelVersion": "Kernel", "installedPackageCount": "套件數量"}
    summary = "、".join(labels.get(key, key) for key in fields)[:400]
    with connect_db() as connection:
        rule = connection.execute(
            "SELECT id,name,severity,enabled FROM alert_rules WHERE id='rule-asset-drift'"
        ).fetchone()
        if not rule or not rule["enabled"]:
            return []
        active = connection.execute(
            """SELECT id FROM alert_events WHERE rule_id=%s AND host_id=%s
               AND status IN ('firing','acknowledged')""",
            (rule["id"], host["id"]),
        ).fetchone()
        if changed and active:
            connection.execute(
                "UPDATE alert_events SET last_value=%s,message=%s,updated_at=NOW() WHERE id=%s",
                (len(fields), f"{host['name']} 偵測到資產漂移：{summary}", active["id"]),
            )
        elif changed:
            event_id = f"alt-{uuid.uuid4().hex[:20]}"
            message = f"{host['name']} 偵測到資產漂移：{summary}"
            connection.execute(
                """INSERT INTO alert_events(id,rule_id,host_id,status,severity,message,last_value)
                   VALUES(%s,%s,%s,'firing',%s,%s,%s)""",
                (event_id, rule["id"], host["id"], rule["severity"], message, len(fields)),
            )
            if notify_drift:
                intents.append({"eventId": event_id, "kind": "firing", "severity": rule["severity"],
                                "message": f"🚨 [Linux AI ASSET DRIFT]\n{message}"})
        elif active:
            connection.execute(
                """UPDATE alert_events SET status='resolved',last_value=0,updated_at=NOW(),resolved_at=NOW()
                   WHERE id=%s""",
                (active["id"],),
            )
            if notify_drift:
                intents.append({"eventId": active["id"], "kind": "resolved", "severity": rule["severity"],
                                "message": f"✅ [Linux AI 已恢復]\n{host['name']} 資產盤點未再偵測到漂移"})
    return intents


def read_asset_inventory() -> list[dict[str, Any]]:
    with connect_db() as connection:
        rows = connection.execute(
            """SELECT h.id AS host_id,h.name AS host_name,h.address,scan.id,scan.status,
                      scan.snapshot,scan.changes,scan.snapshot_sha256,scan.error,scan.checked_at,
                      u.display_name AS checked_by,
                      (SELECT COUNT(*) FROM host_asset_scans history WHERE history.host_id=h.id) AS history_count
               FROM managed_hosts h
               LEFT JOIN LATERAL (
                   SELECT * FROM host_asset_scans item WHERE item.host_id=h.id
                   ORDER BY item.checked_at DESC LIMIT 1
               ) scan ON TRUE
               LEFT JOIN platform_users u ON u.id=scan.checked_by
               WHERE h.enabled=TRUE ORDER BY h.name"""
        ).fetchall()
    return [{
        "hostId": row["host_id"], "hostName": row["host_name"], "address": row["address"],
        "scanId": row["id"], "status": row["status"] or "never", "snapshot": row["snapshot"] or {},
        "changes": row["changes"] or {}, "snapshotSha256": row["snapshot_sha256"],
        "error": row["error"], "checkedBy": row["checked_by"], "historyCount": row["history_count"],
        "checkedAt": row["checked_at"].isoformat() if row["checked_at"] else None,
    } for row in rows]


async def scan_asset_host(host: dict[str, Any], actor_id: str | None) -> list[dict[str, Any]]:
    encoded = base64.b64encode(REMOTE_ASSET_INVENTORY.encode()).decode()
    command = f"python3 -c \"import base64;exec(base64.b64decode('{encoded}'))\""
    status, error = "success", None
    snapshot: dict[str, Any] = {}
    changes: dict[str, Any] = {}
    snapshot_sha256: str | None = None
    try:
        payload = json.loads(await run_ssh(host, command, timeout=25))
        if not isinstance(payload, dict):
            raise ValueError("資產盤點格式錯誤")
        snapshot = normalize_asset_snapshot(payload)
        with connect_db() as connection:
            previous_row = connection.execute(
                """SELECT snapshot FROM host_asset_scans
                   WHERE host_id=%s AND status='success' ORDER BY checked_at DESC LIMIT 1""",
                (host["id"],),
            ).fetchone()
        previous = previous_row["snapshot"] if previous_row else None
        changes = compare_asset_snapshots(previous, snapshot)
        canonical = json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        snapshot_sha256 = hashlib.sha256(canonical.encode()).hexdigest()
    except (RuntimeError, json.JSONDecodeError, ValueError, TypeError) as reason:
        status, error = "failed", str(reason)[:500]
    with connect_db() as connection:
        connection.execute(
            """INSERT INTO host_asset_scans(
                   id,host_id,status,snapshot,changes,snapshot_sha256,error,checked_by)
               VALUES(%s,%s,%s,%s::jsonb,%s::jsonb,%s,%s,%s)""",
            (f"asset-{uuid.uuid4().hex[:20]}", host["id"], status,
             json.dumps(snapshot, ensure_ascii=False), json.dumps(changes, ensure_ascii=False),
             snapshot_sha256, error, actor_id),
        )
    if status != "success":
        return []
    policy = await asyncio.to_thread(read_asset_inventory_policy)
    return await asyncio.to_thread(update_asset_drift_alert, host, changes, policy["notifyDrift"])


async def collect_asset_inventory_cycle(
    inventory: list[dict[str, Any]], actor_id: str | None, update_schedule: bool = True,
    trigger_type: str = "manual",
) -> None:
    run_id = await asyncio.to_thread(start_automation_run, "asset_inventory", trigger_type, actor_id, len(inventory))
    host_ids = [host["id"] for host in inventory]
    try:
        if update_schedule:
            with connect_db() as connection:
                connection.execute("UPDATE asset_inventory_policy SET last_started_at=NOW() WHERE id=1")
        semaphore = asyncio.Semaphore(4)

        async def limited_scan(host: dict[str, Any]) -> list[dict[str, Any]]:
            async with semaphore:
                return await scan_asset_host(host, actor_id)

        notifications = await asyncio.gather(*(limited_scan(host) for host in inventory))
        if update_schedule:
            with connect_db() as connection:
                connection.execute("UPDATE asset_inventory_policy SET last_completed_at=NOW() WHERE id=1")
        await dispatch_notifications([intent for batch in notifications for intent in batch])
    except Exception as reason:
        await asyncio.to_thread(finish_automation_run, run_id, "asset_inventory", host_ids, str(reason))
        raise
    await asyncio.to_thread(finish_automation_run, run_id, "asset_inventory", host_ids)


async def asset_inventory_loop() -> None:
    while True:
        try:
            policy = await asyncio.to_thread(read_asset_inventory_policy)
            completed_at = policy.get("lastCompletedAt")
            last_completed = datetime.fromisoformat(completed_at) if completed_at else None
            due = last_completed is None or datetime.now(timezone.utc) >= (
                last_completed + timedelta(hours=policy["intervalHours"])
            )
            if policy["enabled"] and due and not asset_scan_lock.locked():
                inventory = await asyncio.to_thread(load_inventory)
                async with asset_scan_lock:
                    await collect_asset_inventory_cycle(inventory, None, trigger_type="scheduled")
        except asyncio.CancelledError:
            raise
        except (OSError, RuntimeError, ValueError, psycopg.Error):
            # A single failed cycle must not stop future scheduled inventory scans.
            pass
        await asyncio.sleep(60)


@app.get("/api/asset-inventory")
async def list_asset_inventory(request: Request) -> dict[str, Any]:
    require_permission(request, "hosts.read")
    return {"hosts": await asyncio.to_thread(read_asset_inventory),
            "policy": await asyncio.to_thread(read_asset_inventory_policy)}


@app.get("/api/asset-inventory/{host_id}/history")
async def asset_inventory_history(
    host_id: str, request: Request, limit: int = Query(default=10, ge=1, le=50)
) -> dict[str, Any]:
    require_permission(request, "hosts.read")
    get_host(host_id)
    with connect_db() as connection:
        rows = connection.execute(
            """SELECT id,status,snapshot,changes,snapshot_sha256,error,checked_at
               FROM host_asset_scans WHERE host_id=%s ORDER BY checked_at DESC LIMIT %s""",
            (host_id, limit),
        ).fetchall()
    return {"history": [{
        "id": row["id"], "status": row["status"], "snapshot": row["snapshot"] or {},
        "changes": row["changes"] or {}, "snapshotSha256": row["snapshot_sha256"],
        "error": row["error"], "checkedAt": row["checked_at"].isoformat(),
    } for row in rows]}


@app.post("/api/asset-inventory/scan", status_code=201)
async def create_asset_inventory_scan(
    payload: PatchScanRequest, request: Request
) -> dict[str, Any]:
    actor = require_permission(request, "hosts.manage")
    if asset_scan_lock.locked():
        raise HTTPException(status_code=409, detail="已有資產盤點正在執行")
    inventory = await asyncio.to_thread(load_inventory)
    if payload.host_id:
        inventory = [host for host in inventory if host["id"] == payload.host_id]
        if not inventory:
            raise HTTPException(status_code=404, detail="找不到指定的受管主機")
    async with asset_scan_lock:
        await collect_asset_inventory_cycle(
            inventory, actor["id"], update_schedule=not bool(payload.host_id)
        )
    await asyncio.to_thread(
        record_backend_audit, request, "assets.scan", "執行主機資產與漂移盤點",
        payload.host_id or "all-hosts",
    )
    return {"hosts": await asyncio.to_thread(read_asset_inventory),
            "policy": await asyncio.to_thread(read_asset_inventory_policy)}


@app.put("/api/asset-inventory/policy")
async def update_asset_inventory_policy(
    payload: AssetInventoryPolicyUpdate, request: Request
) -> dict[str, Any]:
    actor = require_permission(request, "hosts.manage")
    with connect_db() as connection:
        connection.execute(
            """UPDATE asset_inventory_policy SET enabled=%s,interval_hours=%s,notify_drift=%s,
                      updated_by=%s,updated_at=NOW() WHERE id=1""",
            (payload.enabled, payload.interval_hours, payload.notify_drift, actor["id"]),
        )
    await asyncio.to_thread(record_backend_audit, request, "assets.policy.update", "更新資產自動盤點政策", "asset-inventory")
    return {"policy": await asyncio.to_thread(read_asset_inventory_policy)}


def read_security_baselines() -> list[dict[str, Any]]:
    with connect_db() as connection:
        rows = connection.execute(
            """
            SELECT h.id AS host_id, h.name AS host_name, h.address,
                   scan.id, scan.status, scan.score, scan.checks, scan.error,
                   scan.checked_at, u.display_name AS checked_by
            FROM managed_hosts h
            LEFT JOIN LATERAL (
                SELECT * FROM host_security_scans s
                WHERE s.host_id = h.id ORDER BY s.checked_at DESC LIMIT 1
            ) scan ON TRUE
            LEFT JOIN platform_users u ON u.id = scan.checked_by
            WHERE h.enabled = TRUE
            ORDER BY h.name
            """
        ).fetchall()
        history_rows = connection.execute(
            """
            SELECT * FROM (
                SELECT s.host_id, s.id, s.status, s.score, s.checks, s.error,
                       s.checked_at, u.display_name AS checked_by,
                       ROW_NUMBER() OVER (
                           PARTITION BY s.host_id ORDER BY s.checked_at DESC
                       ) AS scan_rank
                FROM host_security_scans s
                LEFT JOIN platform_users u ON u.id = s.checked_by
                JOIN managed_hosts h ON h.id = s.host_id AND h.enabled = TRUE
            ) ranked
            WHERE scan_rank <= 12
            ORDER BY host_id, checked_at ASC
            """
        ).fetchall()
    history_by_host: dict[str, list[dict[str, Any]]] = {}
    for item in history_rows:
        history_by_host.setdefault(item["host_id"], []).append({
            "scanId": item["id"], "status": item["status"], "score": item["score"],
            "checks": item["checks"] or [], "error": item["error"],
            "checkedBy": item["checked_by"], "checkedAt": item["checked_at"].isoformat(),
        })
    result: list[dict[str, Any]] = []
    status_points = {"fail": 0, "warn": 1, "pass": 2}
    for row in rows:
        history = history_by_host.get(row["host_id"], [])
        comparison: dict[str, Any] | None = None
        successful = [item for item in history if item["status"] == "success"]
        if len(successful) >= 2:
            previous, current = successful[-2], successful[-1]
            previous_checks = {
                item.get("key"): item for item in previous["checks"] if isinstance(item, dict)
            }
            changes = []
            for current_check in current["checks"]:
                if not isinstance(current_check, dict):
                    continue
                old = previous_checks.get(current_check.get("key"))
                if not old or old.get("status") == current_check.get("status"):
                    continue
                old_status, new_status = old.get("status"), current_check.get("status")
                changes.append({
                    "key": current_check.get("key"), "label": current_check.get("label"),
                    "from": old_status, "to": new_status,
                    "direction": "improved" if status_points.get(new_status, 0) > status_points.get(old_status, 0) else "regressed",
                })
            comparison = {
                "previousAt": previous["checkedAt"],
                "scoreDelta": current["score"] - previous["score"],
                "improved": sum(1 for item in changes if item["direction"] == "improved"),
                "regressed": sum(1 for item in changes if item["direction"] == "regressed"),
                "changes": changes,
            }
        result.append({
            "hostId": row["host_id"], "hostName": row["host_name"],
            "address": row["address"], "scanId": row["id"],
            "status": row["status"] or "never", "score": row["score"] or 0,
            "checks": row["checks"] or [], "error": row["error"],
            "checkedBy": row["checked_by"],
            "checkedAt": row["checked_at"].isoformat() if row["checked_at"] else None,
            "history": history, "comparison": comparison,
        })
    return result


def read_security_history(host_id: str, limit: int) -> list[dict[str, Any]]:
    with connect_db() as connection:
        rows = connection.execute(
            """
            SELECT s.id, s.status, s.score, s.checks, s.error, s.checked_at,
                   u.display_name AS checked_by
            FROM host_security_scans s
            LEFT JOIN platform_users u ON u.id = s.checked_by
            WHERE s.host_id = %s
            ORDER BY s.checked_at DESC
            LIMIT %s
            """,
            (host_id, limit),
        ).fetchall()
    return [{
        "scanId": row["id"], "status": row["status"], "score": row["score"],
        "checks": row["checks"] or [], "error": row["error"],
        "checkedBy": row["checked_by"], "checkedAt": row["checked_at"].isoformat(),
    } for row in rows]


def read_security_baseline_policy() -> dict[str, Any]:
    with connect_db() as connection:
        row = connection.execute(
            """SELECT enabled,interval_hours,minimum_score,notify_regression,
                      last_started_at,last_completed_at,updated_at
               FROM security_baseline_policy WHERE id=1"""
        ).fetchone()
    return {
        "enabled": row["enabled"], "intervalHours": row["interval_hours"],
        "minimumScore": row["minimum_score"], "notifyRegression": row["notify_regression"],
        "lastStartedAt": row["last_started_at"].isoformat() if row["last_started_at"] else None,
        "lastCompletedAt": row["last_completed_at"].isoformat() if row["last_completed_at"] else None,
        "updatedAt": row["updated_at"].isoformat(),
    }


def security_regression_count(previous: list[dict[str, Any]], current: list[dict[str, Any]]) -> int:
    status_points = {"fail": 0, "warn": 1, "pass": 2}
    before = {item.get("key"): item.get("status") for item in previous if isinstance(item, dict)}
    return sum(
        1 for item in current if isinstance(item, dict) and item.get("key") in before
        and status_points.get(item.get("status"), 0) < status_points.get(before[item.get("key")], 0)
    )


def update_security_baseline_alert(
    host: dict[str, Any], score: int, minimum_score: int, regressions: int, notify: bool
) -> list[dict[str, Any]]:
    firing = score < minimum_score or regressions > 0
    intents: list[dict[str, Any]] = []
    with connect_db() as connection:
        rule = connection.execute(
            "SELECT id,severity,enabled FROM alert_rules WHERE id='rule-security-baseline'"
        ).fetchone()
        if not rule or not rule["enabled"]:
            return []
        active = connection.execute(
            """SELECT id FROM alert_events WHERE rule_id=%s AND host_id=%s
               AND status IN ('firing','acknowledged')""", (rule["id"], host["id"]),
        ).fetchone()
        reasons = []
        if score < minimum_score:
            reasons.append(f"分數 {score} 低於門檻 {minimum_score}")
        if regressions:
            reasons.append(f"{regressions} 個檢查項目退步")
        message = f"{host['name']} 安全基準異常：{'；'.join(reasons)}"
        if firing and active:
            connection.execute(
                "UPDATE alert_events SET last_value=%s,message=%s,updated_at=NOW() WHERE id=%s",
                (score, message, active["id"]),
            )
        elif firing:
            event_id = f"alt-{uuid.uuid4().hex[:20]}"
            connection.execute(
                """INSERT INTO alert_events(id,rule_id,host_id,status,severity,message,last_value)
                   VALUES(%s,%s,%s,'firing',%s,%s,%s)""",
                (event_id, rule["id"], host["id"], rule["severity"], message, score),
            )
            if notify:
                intents.append({"eventId": event_id, "kind": "firing", "severity": rule["severity"],
                                "message": f"🚨 [Linux AI SECURITY BASELINE]\n{message}"})
        elif active:
            connection.execute(
                """UPDATE alert_events SET status='resolved',last_value=%s,updated_at=NOW(),resolved_at=NOW()
                   WHERE id=%s""", (score, active["id"]),
            )
            if notify:
                intents.append({"eventId": active["id"], "kind": "resolved", "severity": rule["severity"],
                                "message": f"✅ [Linux AI 已恢復]\n{host['name']} 安全基準回到正常範圍，目前 {score} 分"})
    return intents


async def scan_security_host(host: dict[str, Any], actor_id: str | None) -> list[dict[str, Any]]:
    encoded = base64.b64encode(REMOTE_SECURITY_BASELINE.encode()).decode()
    command = f"python3 -c \"import base64;exec(base64.b64decode('{encoded}'))\""
    status, error, score, checks = "success", None, 0, []
    try:
        payload = json.loads(await run_ssh(host, command, timeout=25))
        score = max(0, min(100, int(payload.get("score", 0))))
        checks = payload.get("checks", [])
        if not isinstance(checks, list) or any(
            not isinstance(item, dict) or item.get("status") not in {"pass", "warn", "fail"}
            for item in checks
        ):
            raise ValueError("安全基準結果格式錯誤")
    except (RuntimeError, json.JSONDecodeError, ValueError, TypeError) as reason:
        status, error, score, checks = "failed", str(reason)[:500], 0, []
    with connect_db() as connection:
        previous_row = connection.execute(
            """SELECT checks FROM host_security_scans WHERE host_id=%s AND status='success'
               ORDER BY checked_at DESC LIMIT 1""", (host["id"],),
        ).fetchone()
        connection.execute(
            """INSERT INTO host_security_scans (
                   id, host_id, status, score, checks, error, checked_by
               ) VALUES (%s, %s, %s, %s, %s::jsonb, %s, %s)""",
            (
                f"security-{uuid.uuid4().hex[:18]}", host["id"], status,
                score, json.dumps(checks), error, actor_id,
            ),
        )
    if status != "success":
        return []
    previous_checks = previous_row["checks"] if previous_row else []
    regressions = security_regression_count(previous_checks, checks)
    policy = await asyncio.to_thread(read_security_baseline_policy)
    return await asyncio.to_thread(
        update_security_baseline_alert, host, score, policy["minimumScore"],
        regressions, policy["notifyRegression"],
    )


async def collect_security_baseline_cycle(
    inventory: list[dict[str, Any]], actor_id: str | None, update_schedule: bool = True,
    trigger_type: str = "manual",
) -> None:
    run_id = await asyncio.to_thread(start_automation_run, "security_baseline", trigger_type, actor_id, len(inventory))
    host_ids = [host["id"] for host in inventory]
    try:
        if update_schedule:
            with connect_db() as connection:
                connection.execute("UPDATE security_baseline_policy SET last_started_at=NOW() WHERE id=1")
        semaphore = asyncio.Semaphore(4)

        async def limited_scan(host: dict[str, Any]) -> list[dict[str, Any]]:
            async with semaphore:
                return await scan_security_host(host, actor_id)

        notifications = await asyncio.gather(*(limited_scan(host) for host in inventory))
        if update_schedule:
            with connect_db() as connection:
                connection.execute("UPDATE security_baseline_policy SET last_completed_at=NOW() WHERE id=1")
        await dispatch_notifications([intent for batch in notifications for intent in batch])
    except Exception as reason:
        await asyncio.to_thread(finish_automation_run, run_id, "security_baseline", host_ids, str(reason))
        raise
    await asyncio.to_thread(finish_automation_run, run_id, "security_baseline", host_ids)


async def security_baseline_loop() -> None:
    while True:
        try:
            policy = await asyncio.to_thread(read_security_baseline_policy)
            completed_at = policy.get("lastCompletedAt")
            last_completed = datetime.fromisoformat(completed_at) if completed_at else None
            due = last_completed is None or datetime.now(timezone.utc) >= (
                last_completed + timedelta(hours=policy["intervalHours"])
            )
            if policy["enabled"] and due and not security_scan_lock.locked():
                inventory = await asyncio.to_thread(load_inventory)
                async with security_scan_lock:
                    await collect_security_baseline_cycle(inventory, None, trigger_type="scheduled")
        except asyncio.CancelledError:
            raise
        except (OSError, RuntimeError, ValueError, psycopg.Error):
            pass
        await asyncio.sleep(60)


@app.get("/api/security-baselines")
async def list_security_baselines(request: Request) -> dict[str, Any]:
    require_permission(request, "hosts.read")
    return {"hosts": await asyncio.to_thread(read_security_baselines),
            "policy": await asyncio.to_thread(read_security_baseline_policy)}


@app.get("/api/security-baselines/{host_id}/history")
async def security_baseline_history(
    host_id: str, request: Request, limit: int = Query(default=30, ge=2, le=100)
) -> dict[str, Any]:
    require_permission(request, "hosts.read")
    get_host(host_id)
    return {
        "hostId": host_id,
        "scans": await asyncio.to_thread(read_security_history, host_id, limit),
    }


@app.post("/api/security-baselines/scan", status_code=201)
async def create_security_baseline_scan(
    payload: SecurityBaselineScanRequest, request: Request
) -> dict[str, Any]:
    actor = require_permission(request, "hosts.manage")
    if security_scan_lock.locked():
        raise HTTPException(status_code=409, detail="已有安全基準盤點正在執行")
    inventory = await asyncio.to_thread(load_inventory)
    if payload.host_id:
        inventory = [host for host in inventory if host["id"] == payload.host_id]
        if not inventory:
            raise HTTPException(status_code=404, detail="找不到指定的受管主機")
    async with security_scan_lock:
        await collect_security_baseline_cycle(
            inventory, actor["id"], update_schedule=not bool(payload.host_id)
        )
    await asyncio.to_thread(
        record_backend_audit, request, "security.baseline.scan", "執行主機安全基準盤點",
        payload.host_id or "all-hosts",
    )
    return {"hosts": await asyncio.to_thread(read_security_baselines),
            "policy": await asyncio.to_thread(read_security_baseline_policy)}


@app.put("/api/security-baselines/policy")
async def update_security_baseline_policy(
    payload: SecurityBaselinePolicyUpdate, request: Request
) -> dict[str, Any]:
    actor = require_permission(request, "hosts.manage")
    with connect_db() as connection:
        connection.execute(
            """UPDATE security_baseline_policy SET enabled=%s,interval_hours=%s,
                      minimum_score=%s,notify_regression=%s,updated_by=%s,updated_at=NOW()
               WHERE id=1""",
            (payload.enabled, payload.interval_hours, payload.minimum_score,
             payload.notify_regression, actor["id"]),
        )
        connection.execute(
            "UPDATE alert_rules SET threshold=%s,updated_at=NOW() WHERE id='rule-security-baseline'",
            (payload.minimum_score,),
        )
    await asyncio.to_thread(
        record_backend_audit, request, "security.baseline.policy.update",
        "更新自動安全基準政策", "security-baseline",
    )
    return {"policy": await asyncio.to_thread(read_security_baseline_policy)}


def automation_job_summary() -> list[dict[str, Any]]:
    definitions = (
        ("asset_inventory", "資產與漂移盤點", read_asset_inventory_policy),
        ("patch_inventory", "更新與 CVE 風險", read_patch_inventory_policy),
        ("security_baseline", "主機安全基準", read_security_baseline_policy),
    )
    jobs = []
    for job_type, name, reader in definitions:
        policy = reader()
        completed = datetime.fromisoformat(policy["lastCompletedAt"]) if policy.get("lastCompletedAt") else None
        next_run = completed + timedelta(hours=policy["intervalHours"]) if completed else None
        jobs.append({
            "jobType": job_type, "name": name, "enabled": policy["enabled"],
            "intervalHours": policy["intervalHours"], "lastStartedAt": policy.get("lastStartedAt"),
            "lastCompletedAt": policy.get("lastCompletedAt"),
            "nextRunAt": next_run.isoformat() if policy["enabled"] and next_run else None,
            "dueNow": bool(policy["enabled"] and (next_run is None or next_run <= datetime.now(timezone.utc))),
        })
    return jobs


async def automation_center_payload() -> dict[str, Any]:
    jobs, runs = await asyncio.gather(
        asyncio.to_thread(automation_job_summary), asyncio.to_thread(read_automation_runs, 50)
    )
    return {"jobs": jobs, "runs": runs}


@app.get("/api/automation")
async def automation_center(request: Request) -> dict[str, Any]:
    require_permission(request, "hosts.read")
    return await automation_center_payload()


def read_automation_run_detail(run_id: str) -> dict[str, Any] | None:
    with connect_db() as connection:
        run = connection.execute(
            "SELECT * FROM automation_runs WHERE id=%s", (run_id,),
        ).fetchone()
        if not run:
            return None
        table = AUTOMATION_SCAN_TABLES[run["job_type"]]
        rows = connection.execute(
            f"""SELECT DISTINCT ON (s.host_id) s.*,h.name AS host_name,h.address
                FROM {table} s JOIN managed_hosts h ON h.id=s.host_id
                WHERE s.checked_at >= %s
                  AND s.checked_at <= COALESCE(%s::timestamptz,NOW()) + INTERVAL '1 second'
                ORDER BY s.host_id,s.checked_at DESC""",
            (run["started_at"], run["completed_at"]),
        ).fetchall()
    results: list[dict[str, Any]] = []
    for row in rows:
        common = {
            "hostId": row["host_id"], "hostName": row["host_name"], "address": row["address"],
            "status": row["status"], "error": row["error"], "checkedAt": row["checked_at"].isoformat(),
        }
        if run["job_type"] == "asset_inventory":
            common.update({"snapshot": row["snapshot"] or {}, "changes": row["changes"] or {},
                           "snapshotSha256": row["snapshot_sha256"]})
        elif run["job_type"] == "patch_inventory":
            security_packages = [
                item for item in (row["packages"] or []) if isinstance(item, dict) and item.get("isSecurity")
            ][:100]
            common.update({
                "pendingCount": row["pending_count"], "securityCount": row["security_count"],
                "cveCount": row["cve_count"], "riskSummary": row["risk_summary"] or {},
                "rebootRequired": row["reboot_required"], "securityPackages": security_packages,
            })
        else:
            common.update({"score": row["score"], "checks": row["checks"] or []})
        results.append(common)
    return {
        "run": {
            "id": run["id"], "jobType": run["job_type"], "triggerType": run["trigger_type"],
            "status": run["status"], "totalHosts": run["total_hosts"],
            "succeededHosts": run["succeeded_hosts"], "failedHosts": run["failed_hosts"],
            "error": run["error"], "startedAt": run["started_at"].isoformat(),
            "completedAt": run["completed_at"].isoformat() if run["completed_at"] else None,
            "durationMs": run["duration_ms"],
        },
        "results": results,
    }


@app.get("/api/automation/runs/{run_id}")
async def automation_run_detail(run_id: str, request: Request) -> dict[str, Any]:
    require_permission(request, "hosts.read")
    detail = await asyncio.to_thread(read_automation_run_detail, run_id)
    if not detail:
        raise HTTPException(status_code=404, detail="找不到巡檢執行紀錄")
    return detail


@app.post("/api/automation/{job_type}/run", status_code=201)
async def run_automation_job(job_type: str, request: Request) -> dict[str, Any]:
    actor = require_permission(request, "hosts.manage")
    inventory = await asyncio.to_thread(load_inventory)
    if job_type == "asset_inventory":
        lock, collector = asset_scan_lock, collect_asset_inventory_cycle
    elif job_type == "patch_inventory":
        lock, collector = patch_scan_lock, collect_patch_inventory_cycle
    elif job_type == "security_baseline":
        lock, collector = security_scan_lock, collect_security_baseline_cycle
    else:
        raise HTTPException(status_code=404, detail="找不到指定的巡檢工作")
    if lock.locked():
        raise HTTPException(status_code=409, detail="這項巡檢正在執行")
    async with lock:
        await collector(inventory, actor["id"], True, "manual")
    await asyncio.to_thread(
        record_backend_audit, request, "automation.run", "從巡檢中心立即執行工作", job_type,
    )
    return await automation_center_payload()


@app.post("/api/alert-rules", status_code=201)
async def create_alert_rule(payload: AlertRuleCreate, request: Request) -> dict[str, Any]:
    actor = require_permission(request, "alerts.manage")
    if payload.metric in {"log_collection", "asset_drift", "security_updates", "security_baseline", "capacity_forecast"}:
        raise HTTPException(status_code=409,detail="此監控項目使用系統內建規則，請修改既有規則或對應政策")
    rule_id = f"rule-{uuid.uuid4().hex[:16]}"
    try:
        with connect_db() as connection:
            connection.execute(
                """
                INSERT INTO alert_rules (
                    id, name, metric, threshold, consecutive_samples,
                    severity, created_by
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    rule_id, payload.name.strip(), payload.metric, payload.threshold,
                    payload.consecutive_samples, payload.severity, actor["id"],
                ),
            )
    except psycopg.errors.UniqueViolation as error:
        raise HTTPException(status_code=409, detail="告警規則名稱已存在") from error
    return {"id": rule_id, "status": "created"}


@app.put("/api/alert-rules/{rule_id}")
async def update_alert_rule(
    rule_id: str, payload: AlertRuleUpdate, request: Request
) -> dict[str, Any]:
    require_permission(request, "alerts.manage")
    if rule_id == "rule-security-updates" and (
        payload.threshold < 1 or payload.threshold > 1000 or not float(payload.threshold).is_integer()
    ):
        raise HTTPException(status_code=422, detail="安全更新告警門檻必須是 1～1000 的整數")
    if rule_id == "rule-security-baseline" and (
        payload.threshold < 0 or payload.threshold > 100 or not float(payload.threshold).is_integer()
    ):
        raise HTTPException(status_code=422, detail="安全基準分數門檻必須是 0～100 的整數")
    try:
        with connect_db() as connection:
            row = connection.execute(
                """
                UPDATE alert_rules
                SET name = %s, metric = %s, threshold = %s,
                    consecutive_samples = %s, severity = %s,
                    enabled = %s, updated_at = NOW()
                WHERE id = %s RETURNING id
                """,
                (
                    payload.name.strip(), payload.metric, payload.threshold,
                    payload.consecutive_samples, payload.severity,
                    payload.enabled, rule_id,
                ),
            ).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="找不到告警規則")
            system_metrics = {"rule-log-collection": "log_collection", "rule-asset-drift": "asset_drift", "rule-security-updates": "security_updates", "rule-security-baseline": "security_baseline", "rule-capacity-forecast": "capacity_forecast"}
            if rule_id in system_metrics:
                if payload.metric != system_metrics[rule_id]:
                    raise HTTPException(status_code=409,detail="系統內建規則不能改成其他監控項目")
            if rule_id == "rule-log-collection":
                connection.execute("UPDATE central_log_policy SET failure_threshold=%s,updated_at=NOW() WHERE id=1",(payload.consecutive_samples,))
            if rule_id == "rule-security-updates":
                threshold = int(payload.threshold)
                connection.execute(
                    "UPDATE patch_inventory_policy SET security_threshold=%s,updated_at=NOW() WHERE id=1",
                    (threshold,),
                )
            if rule_id == "rule-security-baseline":
                connection.execute(
                    "UPDATE security_baseline_policy SET minimum_score=%s,updated_at=NOW() WHERE id=1",
                    (int(payload.threshold),),
                )
            if not payload.enabled:
                connection.execute(
                    """
                    UPDATE alert_events SET status = 'resolved', updated_at = NOW(), resolved_at = NOW()
                    WHERE rule_id = %s AND status IN ('firing', 'acknowledged')
                    """,
                    (rule_id,),
                )
    except psycopg.errors.UniqueViolation as error:
        raise HTTPException(status_code=409, detail="告警規則名稱已存在") from error
    return {"status": "ok"}


@app.delete("/api/alert-rules/{rule_id}", status_code=204)
async def delete_alert_rule(rule_id: str, request: Request) -> None:
    require_permission(request, "alerts.manage")
    if rule_id in {"rule-log-collection", "rule-asset-drift", "rule-security-updates", "rule-security-baseline"}:
        raise HTTPException(status_code=403,detail="系統內建規則不可刪除，可改為停用")
    with connect_db() as connection:
        row = connection.execute(
            "DELETE FROM alert_rules WHERE id = %s RETURNING id", (rule_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="找不到告警規則")


@app.post("/api/alert-events/{event_id}/acknowledge")
async def acknowledge_alert(event_id: str, request: Request) -> dict[str, Any]:
    actor = require_permission(request, "alerts.manage")
    with connect_db() as connection:
        row = connection.execute(
            """
            UPDATE alert_events
            SET status = 'acknowledged', acknowledged_at = NOW(),
                acknowledged_by = %s, updated_at = NOW()
            WHERE id = %s AND status = 'firing'
            RETURNING id
            """,
            (actor["id"], event_id),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=409, detail="告警已處理或不存在")
    with connect_db() as connection:
        connection.execute(
            "INSERT INTO incident_timeline(id,alert_event_id,event_type,message,actor_id) VALUES(%s,%s,'acknowledged','管理者確認告警',%s)",
            (f"timeline-{uuid.uuid4().hex[:18]}", event_id, actor["id"]),
        )
    return {"status": "acknowledged"}


def read_incident_detail(event_id: str) -> dict[str, Any]:
    with connect_db() as connection:
        event = connection.execute(
            """SELECT e.*,r.name AS rule_name,h.name AS host_name,
                      assignee.display_name AS assignee_name,closer.display_name AS closed_by_name
               FROM alert_events e JOIN alert_rules r ON r.id=e.rule_id
               JOIN managed_hosts h ON h.id=e.host_id
               LEFT JOIN platform_users assignee ON assignee.id=e.assignee_id
               LEFT JOIN platform_users closer ON closer.id=e.closed_by WHERE e.id=%s""", (event_id,)
        ).fetchone()
        if not event:
            raise HTTPException(status_code=404, detail="找不到告警事件")
        timeline = connection.execute(
            """SELECT t.id,t.event_type,t.message,t.created_at,u.display_name AS actor
               FROM incident_timeline t LEFT JOIN platform_users u ON u.id=t.actor_id
               WHERE t.alert_event_id=%s ORDER BY t.created_at""", (event_id,)
        ).fetchall()
    return {
        "id": event["id"], "hostName": event["host_name"], "ruleName": event["rule_name"],
        "status": event["status"], "message": event["message"],
        "assigneeId": event["assignee_id"], "assigneeName": event["assignee_name"],
        "resolutionSummary": event["resolution_summary"], "resolutionReason": event["resolution_reason"],
        "closedAt": event["closed_at"].isoformat() if event["closed_at"] else None,
        "closedBy": event["closed_by_name"],
        "timeline": [{"id": row["id"], "eventType": row["event_type"], "message": row["message"],
                      "actor": row["actor"] or "系統", "createdAt": row["created_at"].isoformat()} for row in timeline],
    }


@app.get("/api/alert-events/{event_id}/incident")
async def incident_detail(event_id: str, request: Request) -> dict[str, Any]:
    require_permission(request, "alerts.read")
    return await asyncio.to_thread(read_incident_detail, event_id)


@app.get("/api/incidents/assignees")
async def incident_assignees(request: Request) -> dict[str, Any]:
    require_permission(request, "alerts.manage")
    with connect_db() as connection:
        rows = connection.execute(
            "SELECT id,username,display_name FROM platform_users WHERE enabled=TRUE ORDER BY display_name"
        ).fetchall()
    return {"users": [{"id": row["id"], "username": row["username"], "displayName": row["display_name"]} for row in rows]}


@app.post("/api/alert-events/{event_id}/timeline", status_code=201)
async def add_incident_note(event_id: str, payload: IncidentTimelineNote, request: Request) -> dict[str, Any]:
    actor = require_permission(request, "alerts.manage")
    await asyncio.to_thread(read_incident_detail, event_id)
    with connect_db() as connection:
        connection.execute(
            "INSERT INTO incident_timeline(id,alert_event_id,event_type,message,actor_id) VALUES(%s,%s,'note',%s,%s)",
            (f"timeline-{uuid.uuid4().hex[:18]}", event_id, payload.message.strip(), actor["id"]),
        )
    await asyncio.to_thread(record_backend_audit, request, "alerts.timeline", "新增事件處理紀錄", event_id)
    return await asyncio.to_thread(read_incident_detail, event_id)


@app.post("/api/alert-events/{event_id}/close")
async def close_incident(event_id: str, payload: IncidentClose, request: Request) -> dict[str, Any]:
    actor = require_permission(request, "alerts.manage")
    assignee_id = payload.assignee_id or actor["id"]
    with connect_db() as connection:
        assignee = connection.execute("SELECT id FROM platform_users WHERE id=%s AND enabled=TRUE", (assignee_id,)).fetchone()
        if not assignee:
            raise HTTPException(status_code=422, detail="指定的負責人不存在或已停用")
        row = connection.execute(
            """UPDATE alert_events SET status='resolved',assignee_id=%s,resolution_summary=%s,
                      resolution_reason=%s,closed_at=NOW(),closed_by=%s,resolved_at=COALESCE(resolved_at,NOW()),updated_at=NOW()
               WHERE id=%s AND closed_at IS NULL RETURNING id""",
            (assignee_id, payload.summary.strip(), payload.reason.strip(), actor["id"], event_id),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=409, detail="事件已結案或不存在")
        connection.execute(
            "INSERT INTO incident_timeline(id,alert_event_id,event_type,message,actor_id) VALUES(%s,%s,'closed',%s,%s)",
            (f"timeline-{uuid.uuid4().hex[:18]}", event_id,
             f"結案：{payload.reason.strip()}｜{payload.summary.strip()}"[:2000], actor["id"]),
        )
    await asyncio.to_thread(record_backend_audit, request, "alerts.close", "告警事件結案", event_id)
    return await asyncio.to_thread(read_incident_detail, event_id)


@app.get("/api/hosts")
async def list_hosts(request: Request, refresh: bool = False) -> dict[str, Any]:
    require_permission(request, "hosts.read")
    inventory = await asyncio.to_thread(load_inventory)
    async with probe_lock:
        hosts = await asyncio.gather(*(probe_host(host, refresh) for host in inventory))
    return {"hosts": hosts, "collectedAt": utc_now()}


def insert_managed_host(host: dict[str, Any]) -> str:
    try:
        with connect_db() as connection:
            existing = connection.execute(
                """
                SELECT id, enabled
                FROM managed_hosts
                WHERE address = %s AND port = %s AND ssh_user = %s
                """,
                (host["address"], host["port"], host["user"]),
            ).fetchone()
            if existing:
                if existing["enabled"]:
                    raise HTTPException(status_code=409, detail="這台主機已在監控清單中")
                connection.execute(
                    """
                    UPDATE managed_hosts
                    SET name = %s, group_name = %s, machine_id = %s,
                        host_key_fingerprint = %s, enabled = TRUE
                    WHERE id = %s
                    """,
                    (
                        host["name"], host["group"], host["machine_id"],
                        host["host_key_fingerprint"], existing["id"],
                    ),
                )
                return existing["id"]
            connection.execute(
                """
                INSERT INTO managed_hosts (
                    id, name, address, port, ssh_user, group_name,
                    machine_id, host_key_fingerprint
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    host["id"], host["name"], host["address"], host["port"],
                    host["user"], host["group"], host["machine_id"],
                    host["host_key_fingerprint"],
                ),
            )
            return host["id"]
    except psycopg.errors.UniqueViolation as error:
        raise HTTPException(status_code=409, detail="主機名稱、位址或 SSH 帳號已存在") from error


@app.post("/api/hosts", status_code=201)
async def create_host(payload: HostCreate, request: Request) -> dict[str, Any]:
    require_permission(request, "hosts.manage")
    try:
        normalized_address = str(ipaddress.ip_address(payload.address.strip()))
    except ValueError as error:
        raise HTTPException(status_code=422, detail="目前只接受有效的 IPv4 或 IPv6 位址") from error

    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,31}", payload.user):
        raise HTTPException(status_code=422, detail="SSH 帳號格式不正確")

    slug = re.sub(r"[^a-z0-9]+", "-", payload.name.lower()).strip("-")
    host_id = (slug or f"host-{uuid.uuid4().hex[:8]}")[:80]
    candidate = {
        "id": host_id,
        "name": payload.name.strip(),
        "address": normalized_address,
        "port": payload.port,
        "user": payload.user,
        "group": payload.group.strip(),
        "machine_id": "",
        "host_key_fingerprint": "",
    }

    encoded_identity = base64.b64encode(REMOTE_IDENTITY.encode()).decode()
    command = f"python3 -c \"import base64;exec(base64.b64decode('{encoded_identity}'))\""
    try:
        identity = json.loads(await run_ssh(candidate, command, timeout=8))
    except (RuntimeError, json.JSONDecodeError) as error:
        raise HTTPException(
            status_code=422,
            detail=(
                "SSH 驗證失敗。請先從中央機完成 ssh-copy-id，並確認 known_hosts 已有這台主機。"
                f" 詳細原因：{str(error)[:180]}"
            ),
        ) from error

    candidate["name"] = identity.get("hostname") or candidate["name"]
    candidate["machine_id"] = identity.get("machine_id", "")
    candidate["host_key_fingerprint"] = identity.get("host_key_fingerprint", "")
    candidate["id"] = await asyncio.to_thread(insert_managed_host, candidate)
    probe_cache.pop(candidate["id"], None)
    return {"host": await probe_host(candidate, force=True)}


@app.post("/api/hosts/bootstrap/inspect")
async def inspect_bootstrap_host(payload: BootstrapInspect, request: Request) -> dict[str, Any]:
    require_permission(request, "hosts.manage")
    address, admin_user = normalize_bootstrap_target(
        payload.address, payload.admin_user, payload.password
    )
    connection = await bootstrap_connection(
        address, payload.port, admin_user, payload.password
    )
    try:
        fingerprint, _ = server_identity(connection)
        result = await connection.run("hostnamectl --static 2>/dev/null || hostname", check=False)
        if result.exit_status != 0:
            raise HTTPException(status_code=422, detail="已連線，但無法讀取主機名稱")
        return {
            "address": address,
            "hostname": result.stdout.strip()[:80],
            "fingerprint": fingerprint,
        }
    finally:
        connection.close()
        await connection.wait_closed()


@app.post("/api/hosts/bootstrap", status_code=201)
async def bootstrap_host(payload: BootstrapConfirm, request: Request) -> dict[str, Any]:
    require_permission(request, "hosts.manage")
    address, admin_user = normalize_bootstrap_target(
        payload.address, payload.admin_user, payload.password
    )
    connection = await bootstrap_connection(
        address, payload.port, admin_user, payload.password
    )
    try:
        fingerprint, server_public_key = server_identity(connection)
        if fingerprint != payload.expected_fingerprint:
            raise HTTPException(
                status_code=409,
                detail="SSH 主機指紋在確認前已改變，已停止自動佈署",
            )

        public_key = control_plane_public_key()
        encoded_key = base64.b64encode(public_key.encode()).decode()
        script = f"""set -eu
if ! id -u linux-agent >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash linux-agent
fi
usermod -aG adm,systemd-journal linux-agent
install -d -m 700 -o linux-agent -g linux-agent /home/linux-agent/.ssh
touch /home/linux-agent/.ssh/authorized_keys
chown linux-agent:linux-agent /home/linux-agent/.ssh/authorized_keys
chmod 600 /home/linux-agent/.ssh/authorized_keys
key=$(printf '%s' '{encoded_key}' | base64 -d)
grep -qxF "$key" /home/linux-agent/.ssh/authorized_keys || printf '%s\n' "$key" >> /home/linux-agent/.ssh/authorized_keys
sudoers_tmp=$(mktemp)
printf '%s\n' \
  'linux-agent ALL=(root) NOPASSWD: /usr/bin/systemctl reset-failed' \
  'linux-agent ALL=(root) NOPASSWD: /usr/bin/apt-get update' \
  'linux-agent ALL=(root) NOPASSWD: /usr/bin/unattended-upgrade -d' > "$sudoers_tmp"
chmod 0440 "$sudoers_tmp"
visudo -cf "$sudoers_tmp"
install -m 0440 -o root -g root "$sudoers_tmp" /etc/sudoers.d/linux-ai-agent
rm -f "$sudoers_tmp"
if id -nG linux-agent | tr ' ' '\n' | grep -qx sudo; then
  gpasswd -d linux-agent sudo
fi
"""
        encoded_script = base64.b64encode(script.encode()).decode()
        provision = await connection.run(
            (
                "sudo -S -p '' /bin/sh -c \""
                f"printf '%s' '{encoded_script}' | base64 -d | /bin/sh"
                "\""
            ),
            input=f"{payload.password}\n",
            check=False,
        )
        if provision.exit_status != 0:
            detail = (provision.stderr or provision.stdout).strip()
            raise HTTPException(
                status_code=422,
                detail=f"建立 linux-agent 失敗，請確認首次設定帳號具有 sudo 權限：{detail[:180]}",
            )
    finally:
        connection.close()
        await connection.wait_closed()

    await save_known_host(address, payload.port, server_public_key)
    direct_payload = HostCreate(
        name=payload.name,
        address=address,
        port=payload.port,
        user="linux-agent",
        group=payload.group,
    )
    return await create_host(direct_payload, request)


def disable_managed_host(host_id: str) -> None:
    with connect_db() as connection:
        row = connection.execute(
            """
            UPDATE managed_hosts
            SET enabled = FALSE
            WHERE id = %s AND enabled = TRUE
            RETURNING id
            """,
            (host_id,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="找不到這台受管主機")


@app.delete("/api/hosts/{host_id}", status_code=204)
async def delete_host(host_id: str, request: Request) -> None:
    require_permission(request, "hosts.manage")
    await asyncio.to_thread(disable_managed_host, host_id)
    probe_cache.pop(host_id, None)


@app.get("/api/hosts/{host_id}")
async def host_detail(host_id: str, request: Request, refresh: bool = False) -> dict[str, Any]:
    require_permission(request, "hosts.read")
    return await probe_host(get_host(host_id), refresh)


def read_central_log_policy() -> dict[str, Any]:
    with connect_db() as connection:
        row = connection.execute("SELECT retention_days,interval_seconds,failure_threshold,updated_at FROM central_log_policy WHERE id=1").fetchone()
    return {"retentionDays":row["retention_days"],"intervalSeconds":row["interval_seconds"],
            "failureThreshold":row["failure_threshold"],"updatedAt":row["updated_at"].isoformat()}


def update_log_collection_state(host: dict[str, Any], success: bool, count: int = 0,
                                last_event_at: datetime | None = None, error: str | None = None) -> list[dict[str, Any]]:
    intents: list[dict[str, Any]] = []
    with connect_db() as connection:
        status = connection.execute("""INSERT INTO central_log_collection_status(
            host_id,last_attempt_at,last_success_at,last_event_at,last_event_count,consecutive_failures,last_error)
            VALUES(%s,NOW(),CASE WHEN %s THEN NOW() END,%s,%s,CASE WHEN %s THEN 0 ELSE 1 END,%s)
            ON CONFLICT(host_id) DO UPDATE SET last_attempt_at=NOW(),
              last_success_at=CASE WHEN %s THEN NOW() ELSE central_log_collection_status.last_success_at END,
              last_event_at=COALESCE(EXCLUDED.last_event_at,central_log_collection_status.last_event_at),
              last_event_count=EXCLUDED.last_event_count,
              consecutive_failures=CASE WHEN %s THEN 0 ELSE central_log_collection_status.consecutive_failures+1 END,
              last_error=CASE WHEN %s THEN NULL ELSE EXCLUDED.last_error END,updated_at=NOW()
            RETURNING consecutive_failures""",
            (host["id"],success,last_event_at,count,success,error,success,success,success)).fetchone()
        rule = connection.execute("SELECT id,name,severity,enabled FROM alert_rules WHERE id='rule-log-collection'").fetchone()
        if not rule or not rule["enabled"]: return intents
        threshold = connection.execute("SELECT failure_threshold FROM central_log_policy WHERE id=1").fetchone()["failure_threshold"]
        active = connection.execute("SELECT id FROM alert_events WHERE rule_id=%s AND host_id=%s AND status IN ('firing','acknowledged')",(rule["id"],host["id"])).fetchone()
        failures = status["consecutive_failures"]
        if not success and failures >= threshold and not active:
            event_id=f"alt-{uuid.uuid4().hex[:20]}"; message=f"{host['name']} 集中日誌連續 {failures} 次採集失敗：{error or '未知錯誤'}"
            connection.execute("INSERT INTO alert_events(id,rule_id,host_id,status,severity,message,last_value) VALUES(%s,%s,%s,'firing',%s,%s,%s)",
                               (event_id,rule["id"],host["id"],rule["severity"],message,failures))
            intents.append({"eventId":event_id,"kind":"firing","severity":rule["severity"],"message":f"🚨 [Linux AI LOG COLLECTION]\n{message}"})
        elif not success and active:
            connection.execute("UPDATE alert_events SET last_value=%s,message=%s,updated_at=NOW() WHERE id=%s",
                               (failures,f"{host['name']} 集中日誌連續 {failures} 次採集失敗：{error or '未知錯誤'}",active["id"]))
        elif success and active:
            connection.execute("UPDATE alert_events SET status='resolved',last_value=0,updated_at=NOW(),resolved_at=NOW() WHERE id=%s",(active["id"],))
            intents.append({"eventId":active["id"],"kind":"resolved","severity":rule["severity"],"message":f"✅ [Linux AI 已恢復]\n{host['name']} 集中日誌採集已恢復"})
    return intents


async def collect_central_logs_for_host(host: dict[str, Any], command: str) -> dict[str, Any]:
    try:
        output = await run_ssh(host, command, timeout=15)
        records: list[tuple[Any, ...]] = []
        last_event_at: datetime | None = None
        for raw in output.splitlines():
            try:
                item = json.loads(raw)
                cursor = str(item.get("__CURSOR") or hashlib.sha256(raw.encode()).hexdigest())
                timestamp = item.get("__REALTIME_TIMESTAMP")
                occurred = datetime.fromtimestamp(int(timestamp) / 1_000_000, timezone.utc) if timestamp else None
                if occurred and (last_event_at is None or occurred > last_event_at): last_event_at = occurred
                message, _ = redact_diagnostic_text(str(item.get("MESSAGE", "")))
                records.append((host["id"],cursor,occurred,str(item.get("PRIORITY","6")),
                    str(item.get("_SYSTEMD_UNIT",""))[:200] or None,str(item.get("SYSLOG_IDENTIFIER",""))[:200] or None,
                    str(item.get("_PID",""))[:40] or None,str(item.get("_TRANSPORT",""))[:80] or None,
                    str(item.get("_BOOT_ID",""))[:80] or None,message[:8000]))
            except (ValueError,TypeError,OverflowError): continue
        inserted=0
        if records:
            with connect_db() as connection:
                before=connection.execute("SELECT COUNT(*) AS count FROM central_log_events WHERE host_id=%s",(host["id"],)).fetchone()["count"]
                with connection.cursor() as cursor:
                    cursor.executemany("""INSERT INTO central_log_events(host_id,cursor,occurred_at,priority,systemd_unit,identifier,process_id,transport,boot_id,message)
                        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(host_id,cursor) DO NOTHING""",records)
                after=connection.execute("SELECT COUNT(*) AS count FROM central_log_events WHERE host_id=%s",(host["id"],)).fetchone()["count"]
                inserted=max(0,after-before)
        intents=await asyncio.to_thread(update_log_collection_state,host,True,len(records),last_event_at,None)
        return {"success":True,"newEvents":inserted,"notifications":intents}
    except Exception as error:
        print(f"central log collection failed for {host['id']}: {error}",flush=True)
        intents=await asyncio.to_thread(update_log_collection_state,host,False,0,None,str(error)[:500])
        return {"success":False,"newEvents":0,"notifications":intents}


async def collect_central_logs_once() -> dict[str, Any]:
    if central_log_collection_lock.locked():
        raise HTTPException(status_code=409,detail="集中日誌採集已在執行中，請稍後再試")
    async with central_log_collection_lock:
        hosts=await asyncio.to_thread(load_inventory)
        command="journalctl --since '-6 minutes' -n 500 --no-pager --output=json"
        results=await asyncio.gather(*(collect_central_logs_for_host(host,command) for host in hosts))
        notifications=[intent for result in results for intent in result["notifications"]]
        policy=await asyncio.to_thread(read_central_log_policy)
        with connect_db() as connection:
            connection.execute("DELETE FROM central_log_events WHERE collected_at < NOW() - make_interval(days => %s)",(policy["retentionDays"],))
        await dispatch_notifications(notifications)
        return {"successfulHosts":sum(1 for result in results if result["success"]),
                "failedHosts":sum(1 for result in results if not result["success"]),
                "newEvents":sum(result["newEvents"] for result in results)}


async def central_log_collection_loop() -> None:
    while True:
        try:
            await collect_central_logs_once()
        except Exception as error:
            print(f"central log collector error: {error}", flush=True)
        try: interval=(await asyncio.to_thread(read_central_log_policy))["intervalSeconds"]
        except Exception: interval=CENTRAL_LOG_INTERVAL_SECONDS
        await asyncio.sleep(interval)


@app.post("/api/logs/collect")
async def collect_central_logs(request: Request) -> dict[str, Any]:
    require_permission(request, "logs.read")
    try:
        summary = await asyncio.wait_for(collect_central_logs_once(),timeout=35)
    except TimeoutError as error:
        raise HTTPException(status_code=504,detail="集中日誌採集超過 35 秒，請檢查離線主機與 API 日誌") from error
    with connect_db() as connection:
        count = connection.execute("SELECT COUNT(*) AS count FROM central_log_events").fetchone()["count"]
    return {"status": "ok", "events": count, **summary, "policy": await asyncio.to_thread(read_central_log_policy)}


@app.get("/api/logs/status")
async def central_log_status(request: Request) -> dict[str, Any]:
    require_permission(request,"logs.read")
    with connect_db() as connection:
        rows=connection.execute("""SELECT h.id,h.name,h.address,s.last_attempt_at,s.last_success_at,s.last_event_at,
            COALESCE(s.last_event_count,0) AS last_event_count,COALESCE(s.consecutive_failures,0) AS consecutive_failures,s.last_error,
            (SELECT COUNT(*) FROM central_log_events e WHERE e.host_id=h.id) AS stored_events
            FROM managed_hosts h LEFT JOIN central_log_collection_status s ON s.host_id=h.id WHERE h.enabled=TRUE ORDER BY h.name""").fetchall()
        total=connection.execute("SELECT COUNT(*) AS count,MIN(occurred_at) AS oldest,MAX(occurred_at) AS newest FROM central_log_events").fetchone()
        units=[row["systemd_unit"] for row in connection.execute("SELECT DISTINCT systemd_unit FROM central_log_events WHERE systemd_unit IS NOT NULL ORDER BY systemd_unit LIMIT 500").fetchall()]
    return {"policy":await asyncio.to_thread(read_central_log_policy),"totalEvents":total["count"],
            "oldestAt":total["oldest"].isoformat() if total["oldest"] else None,"newestAt":total["newest"].isoformat() if total["newest"] else None,
            "units":units,"hosts":[{"hostId":r["id"],"hostName":r["name"],"address":r["address"],
              "lastAttemptAt":r["last_attempt_at"].isoformat() if r["last_attempt_at"] else None,
              "lastSuccessAt":r["last_success_at"].isoformat() if r["last_success_at"] else None,
              "lastEventAt":r["last_event_at"].isoformat() if r["last_event_at"] else None,
              "lastEventCount":r["last_event_count"],"consecutiveFailures":r["consecutive_failures"],
              "lastError":r["last_error"],"storedEvents":r["stored_events"]} for r in rows]}


@app.put("/api/logs/policy")
async def update_central_log_policy(payload: CentralLogPolicyUpdate,request:Request)->dict[str,Any]:
    actor=require_permission(request,"alerts.manage")
    with connect_db() as connection:
        connection.execute("""UPDATE central_log_policy SET retention_days=%s,interval_seconds=%s,
            failure_threshold=%s,updated_by=%s,updated_at=NOW() WHERE id=1""",
            (payload.retention_days,payload.interval_seconds,payload.failure_threshold,actor["id"]))
        connection.execute("UPDATE alert_rules SET consecutive_samples=%s,updated_at=NOW() WHERE id='rule-log-collection'",
                           (payload.failure_threshold,))
    await asyncio.to_thread(record_backend_audit,request,"logs.policy.update","更新集中日誌保存與採集政策","central-log-policy")
    return {"policy":await asyncio.to_thread(read_central_log_policy)}


LOG_PRIORITY_MAX={"emerg":0,"alert":1,"crit":2,"err":3,"warning":4,"notice":5,"info":6,"debug":7}


def search_central_logs(host_id:str|None,priority:str,unit:str|None,query:str|None,
                        from_at:datetime|None,to_at:datetime|None,limit:int)->list[dict[str,Any]]:
    clauses=["e.priority ~ '^[0-7]$'","e.priority::int <= %s"]
    params:list[Any]=[LOG_PRIORITY_MAX[priority]]
    if host_id and host_id != "all": clauses.append("e.host_id=%s"); params.append(host_id)
    if unit: clauses.append("e.systemd_unit=%s"); params.append(unit)
    if query: clauses.append("(e.message ILIKE %s OR COALESCE(e.identifier,'') ILIKE %s)"); params.extend([f"%{query}%",f"%{query}%"])
    if from_at: clauses.append("e.occurred_at >= %s"); params.append(from_at)
    if to_at: clauses.append("e.occurred_at <= %s"); params.append(to_at)
    params.append(limit)
    with connect_db() as connection:
        rows=connection.execute(f"""SELECT e.id,e.host_id,h.name AS host_name,e.occurred_at,e.priority,e.systemd_unit,
            e.identifier,e.process_id,e.transport,e.message FROM central_log_events e JOIN managed_hosts h ON h.id=e.host_id
            WHERE {' AND '.join(clauses)} ORDER BY e.occurred_at DESC NULLS LAST LIMIT %s""",params).fetchall()
    return [{"id":r["id"],"hostId":r["host_id"],"hostName":r["host_name"],
             "occurredAt":r["occurred_at"].isoformat() if r["occurred_at"] else None,"priority":r["priority"],
             "unit":r["systemd_unit"],"identifier":r["identifier"],"processId":r["process_id"],
             "transport":r["transport"],"message":r["message"]} for r in rows]


@app.get("/api/logs/search")
async def advanced_log_search(request:Request,host_id:str|None=Query(default=None,alias="hostId"),
    priority:str=Query(default="warning",pattern="^(emerg|alert|crit|err|warning|notice|info|debug)$"),
    unit:str|None=Query(default=None,max_length=200),q:str|None=Query(default=None,max_length=200),
    from_at:datetime|None=Query(default=None,alias="from"),to_at:datetime|None=Query(default=None,alias="to"),
    limit:int=Query(default=200,ge=1,le=1000))->dict[str,Any]:
    require_permission(request,"logs.read")
    if from_at and to_at and from_at>to_at: raise HTTPException(status_code=422,detail="開始時間不能晚於結束時間")
    events=await asyncio.to_thread(search_central_logs,host_id,priority,unit,q,from_at,to_at,limit)
    return {"events":events,"count":len(events),"truncated":len(events)==limit}


@app.get("/api/logs/export.csv")
async def export_central_logs(request:Request,host_id:str|None=Query(default=None,alias="hostId"),
    priority:str=Query(default="warning",pattern="^(emerg|alert|crit|err|warning|notice|info|debug)$"),
    unit:str|None=Query(default=None,max_length=200),q:str|None=Query(default=None,max_length=200),
    from_at:datetime|None=Query(default=None,alias="from"),to_at:datetime|None=Query(default=None,alias="to"))->Response:
    require_permission(request,"logs.read")
    events=await asyncio.to_thread(search_central_logs,host_id,priority,unit,q,from_at,to_at,10000)
    stream=io.StringIO(); writer=csv.writer(stream); writer.writerow(["time","host","priority","systemd_unit","identifier","pid","transport","message"])
    for event in events: writer.writerow([event["occurredAt"],event["hostName"],event["priority"],event["unit"],event["identifier"],event["processId"],event["transport"],event["message"]])
    await asyncio.to_thread(record_backend_audit,request,"logs.export","匯出集中日誌 CSV",f"{len(events)} events")
    filename=f"linux-ai-logs-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
    return Response(content="\ufeff"+stream.getvalue(),media_type="text/csv; charset=utf-8",headers={"Content-Disposition":f'attachment; filename="{filename}"'})


@app.get("/api/hosts/{host_id}/logs")
async def host_logs(
    host_id: str,
    request: Request,
    priority: str = Query(default="warning", pattern="^(emerg|alert|crit|err|warning|notice|info|debug)$"),
    limit: int = Query(default=50, ge=1, le=200),
    source: str = Query(default="live", pattern="^(live|central)$"),
) -> dict[str, Any]:
    require_permission(request, "logs.read")
    host = get_host(host_id)
    if source == "central":
        with connect_db() as connection:
            rows = connection.execute(
                """SELECT occurred_at, priority, message FROM central_log_events
                   WHERE host_id=%s AND CASE %s
                     WHEN 'emerg' THEN priority IN ('0') WHEN 'alert' THEN priority IN ('0','1')
                     WHEN 'crit' THEN priority IN ('0','1','2') WHEN 'err' THEN priority IN ('0','1','2','3')
                     WHEN 'warning' THEN priority IN ('0','1','2','3','4')
                     WHEN 'notice' THEN priority IN ('0','1','2','3','4','5')
                     WHEN 'info' THEN priority IN ('0','1','2','3','4','5','6') ELSE TRUE END
                   ORDER BY occurred_at DESC NULLS LAST LIMIT %s""",
                (host_id, priority, limit),
            ).fetchall()
        lines = [f"{r['occurred_at'].isoformat() if r['occurred_at'] else '-'} [{r['priority']}] {r['message']}" for r in rows]
        return {"hostId": host_id, "priority": priority, "source": "central", "lines": lines}
    command = f"journalctl -p {priority} -n {limit} --no-pager --output=short-iso"
    try:
        output = await run_ssh(host, command, timeout=10)
    except RuntimeError as error:
        raise HTTPException(status_code=502, detail=str(error)) from error
    return {"hostId": host_id, "priority": priority, "source": "live", "lines": output.splitlines()}


@app.websocket("/api/hosts/{host_id}/terminal")
async def host_terminal(websocket: WebSocket, host_id: str) -> None:
    user = await asyncio.to_thread(
        session_user, websocket.cookies.get(SESSION_COOKIE)
    )
    if not user:
        await websocket.close(code=4401, reason="authentication required")
        return
    if not has_permission(user, "terminal.open"):
        await websocket.close(code=4403, reason="permission denied")
        return
    await websocket.accept()
    try:
        host = await asyncio.to_thread(get_host, host_id)
        with connect_db() as database:
            active_key = database.execute("SELECT private_key_encrypted FROM ssh_key_rotations WHERE status='active' ORDER BY promoted_at DESC LIMIT 1").fetchone()
        terminal_keys = [asyncssh.import_private_key(decrypt_secret(active_key["private_key_encrypted"]))] if active_key else [SSH_KEY_PATH]
        connection = await asyncssh.connect(
            host["address"],
            port=host.get("port", 22),
            username=host["user"],
            client_keys=terminal_keys,
            known_hosts=KNOWN_HOSTS_PATH,
        )
        process = await connection.create_process(
            term_type="xterm-256color",
            term_size=(100, 30),
            encoding=None,
        )
        # Some minimal SSH accounts inherit a PTY with local echo disabled.
        # Restore normal terminal modes on connection instead of echoing in the
        # browser, so password prompts can still disable echo safely.
        process.stdin.write(b"stty sane echo 2>/dev/null\r")
        await process.stdin.drain()
        await websocket.send_json({"type": "ready", "host": host["name"]})

        async def send_output() -> None:
            # SSHReader's async iterator is line-oriented and waits for a
            # newline. Read raw chunks instead so PTY echo is visible for each
            # character before Enter is pressed.
            while True:
                chunk = await process.stdout.read(4096)
                if not chunk:
                    break
                await websocket.send_bytes(chunk)

        async def receive_input() -> None:
            while True:
                message = await websocket.receive_json()
                if message.get("type") == "input":
                    process.stdin.write(str(message.get("data", "")).encode())
                    # Flush every keyboard event immediately so the remote PTY
                    # can echo characters before Enter is pressed.
                    await process.stdin.drain()
                elif message.get("type") == "resize":
                    cols = max(20, min(int(message.get("cols", 100)), 400))
                    rows = max(5, min(int(message.get("rows", 30)), 200))
                    process.change_terminal_size(cols, rows)

        output_task = asyncio.create_task(send_output())
        input_task = asyncio.create_task(receive_input())
        done, pending = await asyncio.wait(
            {output_task, input_task}, return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            task.result()
    except WebSocketDisconnect:
        pass
    except (HTTPException, asyncssh.Error, OSError, ValueError) as error:
        try:
            detail = error.detail if isinstance(error, HTTPException) else str(error)
            await websocket.send_json({"type": "error", "detail": detail[:240]})
        except RuntimeError:
            pass
    finally:
        if "process" in locals():
            process.close()
        if "connection" in locals():
            connection.close()
            await connection.wait_closed()
        try:
            await websocket.close()
        except RuntimeError:
            pass


def save_audit_events(events: list[AuditEvent]) -> int:
    with connect_db() as connection:
        # Serialize writers so the SHA-256 audit chain cannot fork.
        connection.execute("SELECT pg_advisory_xact_lock(hashtext('audit_events_hash_chain'))")
        row = connection.execute(
            "SELECT integrity_hash FROM audit_events ORDER BY chain_seq DESC LIMIT 1"
        ).fetchone()
        previous_hash = row["integrity_hash"] if row else "genesis"
        accepted = 0
        for event in events[:100]:
            event_id = (event.id or str(uuid.uuid4()))[:80]
            occurred_datetime = event.occurred_at or datetime.now(timezone.utc)
            occurred_at = occurred_datetime.isoformat()
            event_hash = integrity_hash(
                previous_hash,
                event_id,
                occurred_at,
                event.actor_id,
                event.event_type,
                event.action,
            )
            cursor = connection.execute(
                """
                INSERT INTO audit_events (
                    id, occurred_at, session_id, actor_id, actor_name, event_type,
                    page, action, target, result, previous_hash, integrity_hash
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
                RETURNING id
                """,
                (
                    event_id,
                    occurred_datetime,
                    event.session_id[:100],
                    event.actor_id[:80],
                    event.actor_name[:80],
                    event.event_type[:100],
                    event.page[:100],
                    event.action[:240],
                    event.target[:180] if event.target else None,
                    event.result[:40],
                    previous_hash,
                    event_hash,
                ),
            )
            if cursor.fetchone():
                accepted += 1
                previous_hash = event_hash
        return accepted


@app.post("/api/audit-events", status_code=201)
async def create_audit_events(batch: AuditBatch, request: Request) -> dict[str, Any]:
    if not batch.events:
        raise HTTPException(status_code=400, detail="events are required")
    user = request.state.user
    for event in batch.events:
        event.actor_id = user["id"]
        event.actor_name = user["displayName"]
    accepted = await asyncio.to_thread(save_audit_events, batch.events)
    return {"accepted": accepted}


def read_audit_events(limit: int) -> list[dict[str, Any]]:
    with connect_db() as connection:
        rows = connection.execute(
            """
            SELECT id, occurred_at, session_id, actor_id, actor_name, event_type,
                   page, action, target, result, previous_hash, integrity_hash
            FROM audit_events
            ORDER BY occurred_at DESC, created_at DESC
            LIMIT %s
            """,
            (limit,),
        ).fetchall()
    return [
        {
            "id": row["id"],
            "occurredAt": row["occurred_at"].isoformat(),
            "sessionId": row["session_id"],
            "actorId": row["actor_id"],
            "actorName": row["actor_name"],
            "eventType": row["event_type"],
            "page": row["page"],
            "action": row["action"],
            "target": row["target"],
            "result": row["result"],
            "previousHash": row["previous_hash"],
            "integrityHash": row["integrity_hash"],
        }
        for row in rows
    ]


def read_audit_stats() -> dict[str, Any]:
    with connect_db() as connection:
        counts = connection.execute(
            """
            SELECT
                COUNT(*) AS total_events,
                COUNT(*) FILTER (
                    WHERE occurred_at >= date_trunc('day', NOW())
                ) AS today_events,
                COUNT(DISTINCT session_id) FILTER (
                    WHERE occurred_at >= NOW() - INTERVAL '24 hours'
                ) AS active_sessions
            FROM audit_events
            """
        ).fetchone()
        chain = connection.execute(
            """
            SELECT id, occurred_at, actor_id, event_type, action,
                   previous_hash, integrity_hash
            FROM audit_events
            ORDER BY chain_seq ASC
            """
        ).fetchall()

    expected_previous = "genesis"
    chain_verified = True
    for row in chain:
        expected_hash = integrity_hash(
            expected_previous,
            row["id"],
            row["occurred_at"].isoformat(),
            row["actor_id"],
            row["event_type"],
            row["action"],
        )
        if row["previous_hash"] != expected_previous or row["integrity_hash"] != expected_hash:
            chain_verified = False
            break
        expected_previous = row["integrity_hash"]

    return {
        "totalEvents": counts["total_events"],
        "todayEvents": counts["today_events"],
        "activeSessions24h": counts["active_sessions"],
        "chainVerified": chain_verified,
    }


@app.get("/api/audit-events")
async def list_audit_events(request: Request, limit: int = Query(default=100, ge=1, le=500)) -> dict[str, Any]:
    require_permission(request, "audit.read")
    events, stats = await asyncio.gather(
        asyncio.to_thread(read_audit_events, limit),
        asyncio.to_thread(read_audit_stats),
    )
    return {"events": events, "stats": stats}

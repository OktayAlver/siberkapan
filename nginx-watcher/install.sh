#!/usr/bin/env bash
#
# SiberKapan Nginx Watcher - Kurulum Scripti
# ============================================
# Kullanim:
#   curl -fsSL https://siberkapan.org/nginx-watcher/install.sh | sudo bash -s -- --key=SIBERKAPAN_API_KEY
#
# Veya interaktif (key sormasini istersen):
#   curl -fsSL https://siberkapan.org/nginx-watcher/install.sh | sudo bash
#
# Bu script:
#   1. Python3 kontrolu yapar
#   2. nginx_watcher.py'yi /opt/siberkapan-nginx-watcher/ altina indirir
#   3. SiberKapan API key'i alir (arg ya da interaktif soru)
#   4. Nginx access.log yolunu tespit eder/sorar
#   5. config.json uretir
#   6. systemd servisi kurar ve baslatir
#
# Tekrar calistirilirsa (guncelleme): mevcut config.json'u korur, sadece
# nginx_watcher.py dosyasini ve systemd unit'ini günceller.

set -euo pipefail

INSTALL_DIR="/opt/siberkapan-nginx-watcher"
CONFIG_DIR="/etc/siberkapan-nginx-watcher"
CONFIG_FILE="$CONFIG_DIR/config.json"
SERVICE_FILE="/etc/systemd/system/siberkapan-nginx-watcher.service"
SCRIPT_URL="https://siberkapan.org/nginx-watcher/nginx_watcher.py"
DEFAULT_LOG_PATH="/var/log/nginx/access.log"
API_URL="https://siberkapan.org/feed/nginx"

API_KEY=""
LOG_PATH=""

# ── ARGUMAN PARSING ───────────────────────────────────────────────────────────

for arg in "$@"; do
    case $arg in
        --key=*)
            API_KEY="${arg#*=}"
            shift
            ;;
        --log-path=*)
            LOG_PATH="${arg#*=}"
            shift
            ;;
        *)
            ;;
    esac
done

# ── ROOT KONTROLU ─────────────────────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    echo "HATA: Bu script root yetkisiyle calistirilmali. 'sudo bash' ile tekrar deneyin." >&2
    exit 1
fi

echo "=== SiberKapan Nginx Watcher Kurulumu ==="
echo ""

# ── PYTHON3 KONTROLU ──────────────────────────────────────────────────────────

if ! command -v python3 >/dev/null 2>&1; then
    echo "HATA: python3 bulunamadi. Lutfen once python3 kurun (apt install python3 / yum install python3)." >&2
    exit 1
fi
echo "[1/6] python3 bulundu: $(python3 --version)"

# ── API KEY ───────────────────────────────────────────────────────────────────

if [ -z "$API_KEY" ]; then
    # Mevcut config'de key var mi diye once bakalim (guncelleme senaryosu)
    if [ -f "$CONFIG_FILE" ]; then
        EXISTING_KEY=$(python3 -c "
import json
try:
    with open('$CONFIG_FILE') as f:
        print(json.load(f).get('api_key', ''))
except Exception:
    print('')
" 2>/dev/null || echo "")
        if [ -n "$EXISTING_KEY" ]; then
            API_KEY="$EXISTING_KEY"
            echo "[2/6] Mevcut config.json'dan API key bulundu, korunuyor."
        fi
    fi
fi

if [ -z "$API_KEY" ]; then
    if [ -t 0 ]; then
        read -r -p "SiberKapan API key girin: " API_KEY
    else
        echo "HATA: API key gerekli. --key=ANAHTAR parametresiyle calistirin veya interaktif terminalde calistirin." >&2
        exit 1
    fi
fi

if [ -z "$API_KEY" ]; then
    echo "HATA: API key bos olamaz." >&2
    exit 1
fi
echo "[2/6] API key alindi."

# ── LOG PATH ───────────────────────────────────────────────────────────────────

if [ -z "$LOG_PATH" ]; then
    if [ -f "$CONFIG_FILE" ]; then
        EXISTING_LOG_PATH=$(python3 -c "
import json
try:
    with open('$CONFIG_FILE') as f:
        print(json.load(f).get('log_path', ''))
except Exception:
    print('')
" 2>/dev/null || echo "")
        if [ -n "$EXISTING_LOG_PATH" ]; then
            LOG_PATH="$EXISTING_LOG_PATH"
        fi
    fi
fi

if [ -z "$LOG_PATH" ]; then
    if [ -f "$DEFAULT_LOG_PATH" ]; then
        LOG_PATH="$DEFAULT_LOG_PATH"
    elif [ -t 0 ]; then
        read -r -p "Nginx access.log yolu [$DEFAULT_LOG_PATH bulunamadi, kendi yolunu yaz]: " LOG_PATH
        LOG_PATH="${LOG_PATH:-$DEFAULT_LOG_PATH}"
    else
        LOG_PATH="$DEFAULT_LOG_PATH"
        echo "UYARI: $DEFAULT_LOG_PATH bulunamadi, varsayilan olarak kullaniliyor. Watcher dosya olusana kadar bekleyecek."
    fi
fi
echo "[3/6] Log yolu: $LOG_PATH"

# ── DOSYA INDIRME ─────────────────────────────────────────────────────────────

mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"

if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$SCRIPT_URL" -o "$INSTALL_DIR/nginx_watcher.py"
elif command -v wget >/dev/null 2>&1; then
    wget -q "$SCRIPT_URL" -O "$INSTALL_DIR/nginx_watcher.py"
else
    echo "HATA: curl veya wget bulunamadi, dosya indirilemedi." >&2
    exit 1
fi

if [ ! -s "$INSTALL_DIR/nginx_watcher.py" ]; then
    echo "HATA: nginx_watcher.py indirilemedi veya bos." >&2
    exit 1
fi

python3 -m py_compile "$INSTALL_DIR/nginx_watcher.py"
echo "[4/6] nginx_watcher.py indirildi ve dogrulandi: $INSTALL_DIR/nginx_watcher.py"

# ── CONFIG.JSON URETIMI ───────────────────────────────────────────────────────

python3 - "$CONFIG_FILE" "$API_KEY" "$API_URL" "$LOG_PATH" << 'PYEOF'
import json
import sys
import os

config_file, api_key, api_url, log_path = sys.argv[1:5]

default_config = {
    "api_key": api_key,
    "api_url": api_url,
    "log_path": log_path,
    "poll_interval_s": 1.0,
    "cooldown_s": 1800,
    "thresholds": {
        "404_flood": {"enabled": True, "count": 10, "window_s": 60},
        "auth_flood": {"enabled": True, "count": 8, "window_s": 60},
        "rate_flood": {"enabled": True, "count": 30, "window_s": 10},
        "path_signature": {"enabled": True},
        "ua_signature": {"enabled": True, "flag_empty_ua": False}
    },
    "ignore_ips": [],
    "ignore_path_prefixes": [],
    "log_file": "/var/log/siberkapan-nginx-watcher.log"
}

if os.path.isfile(config_file):
    try:
        with open(config_file) as f:
            existing = json.load(f)
        existing["api_key"] = api_key
        existing["api_url"] = api_url
        existing["log_path"] = log_path
        final_config = existing
    except Exception:
        final_config = default_config
else:
    final_config = default_config

with open(config_file, "w") as f:
    json.dump(final_config, f, indent=2)

print(f"config.json yazildi: {config_file}")
PYEOF

echo "[5/6] Config dosyasi hazirlandi: $CONFIG_FILE"

# ── SYSTEMD SERVISI ───────────────────────────────────────────────────────────

cat > "$SERVICE_FILE" << EOF
[Unit]
Description=SiberKapan Nginx Watcher
After=network.target nginx.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 $INSTALL_DIR/nginx_watcher.py --config $CONFIG_FILE
Restart=always
RestartSec=5
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable siberkapan-nginx-watcher >/dev/null 2>&1
systemctl restart siberkapan-nginx-watcher

sleep 2

if systemctl is-active --quiet siberkapan-nginx-watcher; then
    echo "[6/6] Servis basariyla baslatildi."
    echo ""
    echo "=== Kurulum tamamlandi ==="
    echo "Durum kontrolu:  systemctl status siberkapan-nginx-watcher"
    echo "Canli log:       journalctl -u siberkapan-nginx-watcher -f"
    echo "Config dosyasi:  $CONFIG_FILE"
else
    echo "HATA: Servis baslatilamadi. Detay icin: journalctl -u siberkapan-nginx-watcher -n 50" >&2
    exit 1
fi

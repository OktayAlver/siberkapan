#!/usr/bin/env python3
"""
SiberKapan Nginx Watcher
=========================
Nginx access log'unu izler, saldiri paternlerini tespit eder ve
SiberKapan threat intelligence platformuna (https://siberkapan.org) bildirir.

Bagimlilik: yalnizca Python 3.6+ standart kutuphanesi. Ekstra pip paketi gerekmez.

Calistirma:
    python3 nginx_watcher.py --config /etc/siberkapan-nginx-watcher/config.json

Config dosyasi yoksa varsayilan degerlerle + ortam degiskenleriyle calismayi dener:
    SIBERKAPAN_API_KEY, SIBERKAPAN_LOG_PATH, SIBERKAPAN_API_URL
"""

import argparse
import json
import os
import re
import sys
import time
import logging
import collections
import urllib.request
import urllib.error
from datetime import datetime, timezone

# â”€â”€ VARSAYILAN AYARLAR â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

DEFAULT_CONFIG = {
    "api_key": "",
    "api_url": "https://siberkapan.org/feed/nginx",
    "log_path": "/var/log/nginx/access.log",
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

# Bilinen exploit/scanner path imzalari (regex, case-insensitive)
PATH_SIGNATURES = [
    r"/wp-login\.php",
    r"/wp-admin/",
    r"/\.env",
    r"/\.git/config",
    r"/admin/?$",
    r"/phpmyadmin",
    r"\.\./",
    r"%2e%2e%2f",
    r"union\s+select",
    r"<script",
    r"/xmlrpc\.php",
    r"/\.aws/credentials",
    r"/vendor/phpunit",
    r"/etc/passwd",
    r"/\.ssh/",
    r"cmd=",
    r"/console/",
    r"/actuator/",
]

# Bilinen tarama araci User-Agent imzalari (case-insensitive)
# NOT: bos/eksik UA buraya dahil edilmiyor cunku cok yaygin meÅŸru kullanim var
# (curl/webhook/API client'lar). Bos UA tespiti ayri bir flag ile yonetiliyor
# (thresholds.ua_signature.flag_empty_ua), varsayilan kapali.
UA_SIGNATURES = [
    r"sqlmap",
    r"nikto",
    r"nmap",
    r"masscan",
    r"nuclei",
    r"gobuster",
    r"dirbuster",
    r"acunetix",
    r"netsparker",
    r"zgrab",
]

# Nginx 'combined' log format:
# $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
LOG_LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+)(?: \S+)?" '
    r'(?P<status>\d+) (?P<bytes>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

PATH_SIG_RE = re.compile("|".join(PATH_SIGNATURES), re.IGNORECASE)
UA_SIG_RE = re.compile("|".join(UA_SIGNATURES), re.IGNORECASE)

log = logging.getLogger("nginx_watcher")


# â”€â”€ CONFIG YUKLEME â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def load_config(path):
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy

    if path and os.path.isfile(path):
        try:
            with open(path, "r") as f:
                user_cfg = json.load(f)
            cfg.update({k: v for k, v in user_cfg.items() if k != "thresholds"})
            if "thresholds" in user_cfg:
                for k, v in user_cfg["thresholds"].items():
                    if k in cfg["thresholds"]:
                        cfg["thresholds"][k].update(v)
                    else:
                        cfg["thresholds"][k] = v
        except Exception as e:
            print(f"[config] UYARI: {path} okunamadi ({e}), varsayilan + env kullaniliyor")

    # Ortam degiskenleri config dosyasini ezer (varsa)
    if os.environ.get("SIBERKAPAN_API_KEY"):
        cfg["api_key"] = os.environ["SIBERKAPAN_API_KEY"]
    if os.environ.get("SIBERKAPAN_LOG_PATH"):
        cfg["log_path"] = os.environ["SIBERKAPAN_LOG_PATH"]
    if os.environ.get("SIBERKAPAN_API_URL"):
        cfg["api_url"] = os.environ["SIBERKAPAN_API_URL"]

    return cfg


def setup_logging(cfg, verbose):
    level = logging.DEBUG if verbose else logging.INFO
    log.setLevel(level)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    log.addHandler(sh)

    log_file = cfg.get("log_file")
    if log_file:
        try:
            fh = logging.FileHandler(log_file)
            fh.setFormatter(fmt)
            log.addHandler(fh)
        except Exception as e:
            log.warning(f"Dosyaya loglama acilamadi ({log_file}): {e}")


# â”€â”€ LOG TAILER (polling tabanli, rotate-aware) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class LogTailer:
    """
    Bir log dosyasini periyodik olarak yeni satirlar icin okur.
    Logrotate sonrasi dosya boyutu kuculurse (ya da inode degisirse) basa sarar.
    """

    def __init__(self, path):
        self.path = path
        self._fh = None
        self._inode = None
        self._open_at_end()

    def _open_at_end(self):
        try:
            self._fh = open(self.path, "r", errors="replace")
            self._fh.seek(0, os.SEEK_END)
            self._inode = os.fstat(self._fh.fileno()).st_ino
        except FileNotFoundError:
            self._fh = None
            self._inode = None

    def _reopen_if_rotated(self):
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return
        if self._fh is None:
            self._open_at_end()
            return
        try:
            cur_inode = os.fstat(self._fh.fileno()).st_ino
        except Exception:
            cur_inode = None
        if st.st_ino != cur_inode:
            log.info(f"Log rotate algilandi ({self.path}), yeniden aciliyor")
            try:
                self._fh.close()
            except Exception:
                pass
            try:
                self._fh = open(self.path, "r", errors="replace")
                self._inode = os.fstat(self._fh.fileno()).st_ino
            except FileNotFoundError:
                self._fh = None
                self._inode = None

    def read_new_lines(self):
        self._reopen_if_rotated()
        if self._fh is None:
            self._open_at_end()
            if self._fh is None:
                return []
        lines = self._fh.readlines()
        return lines


# â”€â”€ PATTERN MOTORU â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class PatternEngine:
    def __init__(self, thresholds, cooldown_s, ignore_ips, ignore_path_prefixes=None):
        self.thresholds = thresholds
        self.cooldown_s = cooldown_s
        self.ignore_ips = set(ignore_ips or [])
        self.ignore_path_prefixes = tuple(ignore_path_prefixes or [])
        # ip -> pattern_type -> deque[timestamp]
        self.windows = collections.defaultdict(lambda: collections.defaultdict(collections.deque))
        # (ip, pattern_type) -> last_sent_epoch
        self.cooldowns = {}

    def _on_cooldown(self, ip, pattern_type, now):
        key = (ip, pattern_type)
        last = self.cooldowns.get(key)
        if last is not None and (now - last) < self.cooldown_s:
            return True
        return False

    def _mark_sent(self, ip, pattern_type, now):
        self.cooldowns[(ip, pattern_type)] = now

    def _check_window(self, ip, pattern_type, now, window_s, count_threshold):
        dq = self.windows[ip][pattern_type]
        dq.append(now)
        while dq and (now - dq[0]) > window_s:
            dq.popleft()
        return len(dq) >= count_threshold

    def process(self, parsed, now):
        """
        parsed: dict with ip, status, path, ua (zaten LOG_LINE_RE'den cikarilmis)
        Donus: list of (pattern_type, detail_dict) -- bir satir birden fazla pattern tetikleyebilir
        """
        ip = parsed["ip"]
        if ip in self.ignore_ips:
            return []

        status = parsed["status"]
        path = parsed["path"]
        ua = parsed["ua"]

        if path and self.ignore_path_prefixes and path.startswith(self.ignore_path_prefixes):
            return []

        events = []

        # 404 flood
        cfg = self.thresholds.get("404_flood", {})
        if cfg.get("enabled") and status == 404:
            if self._check_window(ip, "404_flood", now, cfg.get("window_s", 60), cfg.get("count", 10)):
                if not self._on_cooldown(ip, "404_flood", now):
                    events.append(("404_flood", {
                        "status": status, "path": path,
                        "hit_count": cfg.get("count", 10), "window_s": cfg.get("window_s", 60)
                    }))

        # auth flood (401/403)
        cfg = self.thresholds.get("auth_flood", {})
        if cfg.get("enabled") and status in (401, 403):
            if self._check_window(ip, "auth_flood", now, cfg.get("window_s", 60), cfg.get("count", 8)):
                if not self._on_cooldown(ip, "auth_flood", now):
                    events.append(("auth_flood", {
                        "status": status, "path": path,
                        "hit_count": cfg.get("count", 8), "window_s": cfg.get("window_s", 60)
                    }))

        # rate flood (genel istek hizi, status'tan bagimsiz)
        cfg = self.thresholds.get("rate_flood", {})
        if cfg.get("enabled"):
            if self._check_window(ip, "rate_flood", now, cfg.get("window_s", 10), cfg.get("count", 30)):
                if not self._on_cooldown(ip, "rate_flood", now):
                    events.append(("rate_flood", {
                        "status": status, "path": path,
                        "hit_count": cfg.get("count", 30), "window_s": cfg.get("window_s", 10)
                    }))

        # path signature (anlik, count gerekmez)
        cfg = self.thresholds.get("path_signature", {})
        if cfg.get("enabled") and PATH_SIG_RE.search(path or ""):
            if not self._on_cooldown(ip, "path_signature", now):
                events.append(("path_signature", {
                    "status": status, "path": path, "hit_count": 1
                }))

        # user-agent signature (anlik)
        cfg = self.thresholds.get("ua_signature", {})
        if cfg.get("enabled"):
            ua_is_empty = (not ua) or ua == "-"
            is_known_tool = bool(UA_SIG_RE.search(ua or ""))
            should_flag = is_known_tool or (ua_is_empty and cfg.get("flag_empty_ua", False))
            if should_flag and not self._on_cooldown(ip, "ua_signature", now):
                events.append(("ua_signature", {
                    "status": status, "path": path, "user_agent": ua, "hit_count": 1
                }))

        for pattern_type, _ in events:
            self._mark_sent(ip, pattern_type, now)

        return events

    def cleanup_old(self, now, max_age_s=3600):
        """Bellek sismesini onlemek icin eski windows/cooldown girdilerini temizler."""
        stale_ips = []
        for ip, pmap in self.windows.items():
            all_old = True
            for pattern_type, dq in pmap.items():
                if dq and (now - dq[-1]) < max_age_s:
                    all_old = False
                    break
            if all_old:
                stale_ips.append(ip)
        for ip in stale_ips:
            del self.windows[ip]

        stale_keys = [k for k, t in self.cooldowns.items() if (now - t) > max(max_age_s, self.cooldown_s)]
        for k in stale_keys:
            del self.cooldowns[k]


# â”€â”€ PARSE â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def parse_line(line):
    m = LOG_LINE_RE.match(line)
    if not m:
        return None
    try:
        status = int(m.group("status"))
    except (ValueError, TypeError):
        return None
    return {
        "ip": m.group("ip"),
        "method": m.group("method"),
        "path": m.group("path"),
        "status": status,
        "ua": m.group("ua"),
    }


# â”€â”€ SIBERKAPAN'A GONDERIM â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def send_to_siberkapan(api_url, api_key, ip, pattern_type, detail, timeout=8):
    payload = json.dumps({
        "ip": ip,
        "pattern_type": pattern_type,
        "detail": detail,
    }).encode("utf-8")

    req = urllib.request.Request(
        api_url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-SiberKapan-Key": api_key,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return e.code, body
    except urllib.error.URLError as e:
        return None, str(e)
    except (TimeoutError, OSError) as e:
        # Bazi Python surumlerinde SSL/socket read timeout'u URLError'a
        # sarilmadan dogrudan TimeoutError/OSError olarak gelebiliyor.
        # Bu durumda watcher'i cokertmemek icin burada da yakaliyoruz.
        return None, f"timeout_or_os_error: {e}"
    except Exception as e:
        # Son guvenlik agi: hicbir network hatasi watcher'in ana dongusunu
        # cokertmemeli, tek bir gonderim basarisiz olsa da watcher calismaya
        # devam etmeli.
        return None, f"unexpected_error: {e}"


# â”€â”€ ANA DONGU â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def run(cfg, verbose=False):
    setup_logging(cfg, verbose)

    if not cfg.get("api_key"):
        log.error("api_key bos. Config dosyasina veya SIBERKAPAN_API_KEY ortam degiskenine key girilmeli.")
        sys.exit(1)

    if not os.path.isfile(cfg["log_path"]):
        log.warning(f"Log dosyasi henuz yok: {cfg['log_path']} - bekleniyor...")

    log.info(f"SiberKapan Nginx Watcher baslatildi. log={cfg['log_path']} api={cfg['api_url']}")

    tailer = LogTailer(cfg["log_path"])
    engine = PatternEngine(
        cfg["thresholds"], cfg["cooldown_s"], cfg.get("ignore_ips"),
        cfg.get("ignore_path_prefixes")
    )

    last_cleanup = time.time()

    while True:
        now = time.time()
        lines = tailer.read_new_lines()

        for raw_line in lines:
            parsed = parse_line(raw_line.rstrip("\n"))
            if not parsed:
                continue

            events = engine.process(parsed, now)
            for pattern_type, detail in events:
                try:
                    status, body = send_to_siberkapan(
                        cfg["api_url"], cfg["api_key"], parsed["ip"], pattern_type, detail
                    )
                except Exception as e:
                    log.error(f"BEKLENMEYEN HATA gonderim sirasinda ip={parsed['ip']} pattern={pattern_type}: {e}")
                    continue

                if status == 200:
                    log.info(f"GONDERILDI ip={parsed['ip']} pattern={pattern_type} -> {body}")
                else:
                    log.warning(f"GONDERIM HATASI ip={parsed['ip']} pattern={pattern_type} status={status} body={body}")

        if (now - last_cleanup) > 300:
            engine.cleanup_old(now)
            last_cleanup = now

        time.sleep(cfg.get("poll_interval_s", 1.0))


def main():
    parser = argparse.ArgumentParser(description="SiberKapan Nginx Watcher")
    parser.add_argument("--config", default="/etc/siberkapan-nginx-watcher/config.json",
                         help="Config JSON dosya yolu")
    parser.add_argument("--verbose", action="store_true", help="Debug seviyesinde log")
    args = parser.parse_args()

    cfg = load_config(args.config)

    try:
        run(cfg, verbose=args.verbose)
    except KeyboardInterrupt:
        print("\n[nginx_watcher] Durduruldu.")
        sys.exit(0)


if __name__ == "__main__":
    main()

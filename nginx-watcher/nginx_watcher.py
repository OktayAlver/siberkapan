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

Imza listeleri (path_signatures / ua_signatures) artik koda gomulu degil.
Watcher, gunde bir kez (varsayilan) config'teki patterns.url adresinden
guncel listeyi ceker, diskte cache'ler ve basarisiz olursa son bilinen
(cache ya da builtin) listeyle calismaya devam eder. Bkz. PatternStore.
"""

import argparse
import copy
import glob
import json
import os
import re
import sys
import time
import logging
import collections
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone

# ── VARSAYILAN AYARLAR ──────────────────────────────────────────────
DEFAULT_CONFIG = {
    "api_key": "",
    "api_url": "https://siberkapan.org/feed/nginx",
    "log_path": "/var/log/nginx/access.log",
    # YENI: birden fazla site/vhost log dosyasini ayni anda izlemek icin.
    # log_paths: acik liste. log_path_glob: CloudPanel/Plesk gibi panellerde
    # her sitenin kendi log dosyasi oldugunda otomatik kesif icin glob pattern
    # (ornek: "/home/*/logs/nginx/access.log"). Yeni site eklendiginde config'e
    # dokunmaya gerek kalmadan discover_interval_s surede otomatik eklenir.
    "log_paths": [],
    "log_path_glob": None,
    "log_discover_interval_s": 300,
    "poll_interval_s": 1.0,
    "cooldown_s": 1800,
    "thresholds": {
        "404_flood": {"enabled": True, "count": 10, "window_s": 60},
        "auth_flood": {"enabled": True, "count": 8, "window_s": 60},
        "rate_flood": {"enabled": True, "count": 30, "window_s": 10},
        "path_signature": {"enabled": True},
        "ua_signature": {"enabled": True, "flag_empty_ua": False},
        # YENI: bozuk/parse edilemeyen satirlar da artik sessizce atilmiyor
        "malformed_request": {"enabled": True, "count": 5, "window_s": 60},
        # YENI: ayni imzayi tetikleyen farkli IP sayisi bir esigi asarsa
        # (dagitik / low-and-slow tarama) ayri bir olay olarak bildirilir
        "distributed_signature": {"enabled": True, "distinct_ips": 5, "window_s": 300},
    },
    "ignore_ips": [],
    "ignore_path_prefixes": [],
    "log_file": "/var/log/siberkapan-nginx-watcher.log",
    # YENI: reverse proxy/CDN arkasindaysa gercek istemci IP'sini
    # X-Forwarded-For'dan almak icin. nginx log_format'a
    # '"$http_x_forwarded_for"' alani EKLENMIS OLMALI (asagida ornek var).
    "trust_x_forwarded_for": False,
    # YENI: uzaktan guncellenen imza listesi ayarlari
    "patterns": {
        "url": "https://siberkapan.org/patterns/nginx-watcher.json",
        "cache_path": "/etc/siberkapan-nginx-watcher/patterns_cache.json",
        "update_interval_s": 86400,
        "fetch_timeout_s": 10,
    },
}

# Koda gomulu FALLBACK imzalar (uzak liste hic cekilemezse ve cache de
# yoksa kullanilir). Guncel/genis liste artik patterns.url'de tutulur.
BUILTIN_PATH_SIGNATURES = [
    # -- recon / hassas dosyalar --
    r"/wp-login\.php", r"/wp-admin", r"/\.env", r"/\.git/config", r"/\.git/HEAD",
    r"/admin(?:[/?]|$)", r"/phpmyadmin", r"/\.aws/credentials", r"/\.ssh/",
    r"/\.docker", r"/vendor/phpunit", r"/etc/passwd", r"/xmlrpc\.php",
    r"/server-status", r"/elmah\.axd", r"/actuator", r"/console/",
    r"/\.htpasswd", r"/config\.php\.bak", r"/backup\.(zip|tar|sql|tar\.gz)",
    r"/\.idea/", r"/\.vscode/",
    # -- path traversal / LFI / RFI --
    r"\.\./", r"\.\.\\", r"%2e%2e%2f", r"%252e%252e%252f", r"%c0%ae%c0%ae",
    r"php://(filter|input)", r"data://", r"expect://",
    # -- injection --
    r"union\s+select", r"insert\s+into\s+\w+", r"sleep\(\d", r"waitfor\s+delay",
    r"\bor\s+1=1\b", r"benchmark\(",
    r"<script", r"onerror\s*=", r"javascript:",
    r";\s*(cat|whoami|id|ls|wget|curl)\b", r"\$\(.+\)",
    r"\$\{jndi:", r"[?&](cmd|exec|execute)=",
    # -- webshell / backdoor isimleri --
    r"/(shell|c99|r57|wso|b374k)\.(php|jsp|asp|aspx)",
]

BUILTIN_UA_SIGNATURES = [
    r"sqlmap", r"nikto", r"nmap", r"masscan", r"nuclei", r"gobuster",
    r"dirbuster", r"acunetix", r"netsparker", r"zgrab", r"whatweb",
    r"wpscan", r"havij",
]

# Nginx 'combined' log format:
# $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
LOG_LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+)(?: \S+)?" '
    r'(?P<status>\d+) (?P<bytes>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

# X-Forwarded-For eklenmis genisletilmis format (trust_x_forwarded_for=true
# icin). nginx.conf'ta log_format'in sonuna '"$http_x_forwarded_for"'
# eklenmis olmasi gerekir, ornek asagida.
EXTENDED_LOG_LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+)(?: \S+)?" '
    r'(?P<status>\d+) (?P<bytes>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)" "(?P<xff>[^"]*)"'
)

# Ana format hic eslesmezse (bozuk/binary/protokol ihlali satirlar) en
# azindan IP'yi cikarmayi dene -- ONCEDEN bu satirlar sessizce atiliyordu.
LOOSE_IP_RE = re.compile(r'^(?P<ip>\S+)\s')

log = logging.getLogger("nginx_watcher")


# ── PATH NORMALIZASYONU ─────────────────────────────────────────────
def _safe_unquote(s, rounds=1):
    """
    Path'i en fazla `rounds` kez yuzde-decode eder (double/triple encoding
    ile imza atlatmaya karsi). Sonsuz donguye girmemesi icin sabit sayida
    tur uygular ve degisim durmussa erken cikar.
    """
    out = s
    seen = {out}
    for _ in range(rounds):
        try:
            nxt = urllib.parse.unquote(out, errors="replace")
        except Exception:
            break
        if nxt == out or nxt in seen:
            break
        out = nxt
        seen.add(out)
    return out


# ── UZAKTAN GUNCELLENEN IMZA LISTESI ────────────────────────────────
class PatternStore:
    """
    Saldiri imzalarini (path + UA regex listeleri) yonetir.
    Oncelik sirasi:
      1) Bellekte aktif olan (once yuklenen) liste
      2) Diskteki cache dosyasi
      3) Koddaki BUILTIN_* varsayilanlari
    Varsayilan olarak gunde bir kez patterns.url'den guncel listeyi
    cekmeyi dener; basarisiz olursa sessizce elindeki listeyle calismaya
    devam eder (watcher hicbir zaman network hatasindan dolayi durmaz).
    """

    def __init__(self, cfg):
        self.url = cfg.get("url")
        self.cache_path = cfg.get("cache_path")
        self.update_interval_s = cfg.get("update_interval_s", 86400)
        self.fetch_timeout_s = cfg.get("fetch_timeout_s", 10)
        self.version = None
        self._last_check = 0.0
        self.path_signatures = list(BUILTIN_PATH_SIGNATURES)
        self.ua_signatures = list(BUILTIN_UA_SIGNATURES)
        self.path_re = None
        self.ua_re = None
        self._load_initial()
        self._compile()

    def _compile(self):
        try:
            self.path_re = re.compile("|".join(self.path_signatures), re.IGNORECASE)
        except re.error as e:
            log.error(f"[patterns] path signature listesi derlenemedi ({e}), builtin'e donuluyor")
            self.path_signatures = list(BUILTIN_PATH_SIGNATURES)
            self.path_re = re.compile("|".join(self.path_signatures), re.IGNORECASE)
        try:
            self.ua_re = re.compile("|".join(self.ua_signatures), re.IGNORECASE)
        except re.error as e:
            log.error(f"[patterns] UA signature listesi derlenemedi ({e}), builtin'e donuluyor")
            self.ua_signatures = list(BUILTIN_UA_SIGNATURES)
            self.ua_re = re.compile("|".join(self.ua_signatures), re.IGNORECASE)

    def _load_initial(self):
        if self.cache_path and os.path.isfile(self.cache_path):
            try:
                with open(self.cache_path, "r") as f:
                    data = json.load(f)
                self._apply(data, source="cache")
            except Exception as e:
                log.warning(f"[patterns] cache okunamadi ({self.cache_path}): {e}, builtin ile baslaniyor")

    def _apply(self, data, source):
        ps = data.get("path_signatures")
        us = data.get("ua_signatures")
        if isinstance(ps, list) and ps:
            self.path_signatures = ps
        if isinstance(us, list) and us:
            self.ua_signatures = us
        self.version = data.get("version")
        log.info(
            f"[patterns] {source} yuklendi (version={self.version}, "
            f"path_sig={len(self.path_signatures)}, ua_sig={len(self.ua_signatures)})"
        )

    def maybe_update(self, now):
        """Ana donguden her turda cagrilir; interval dolmadiysa hemen doner."""
        if not self.url:
            return
        if (now - self._last_check) < self.update_interval_s:
            return
        self._last_check = now
        try:
            req = urllib.request.Request(self.url, headers={"User-Agent": "siberkapan-nginx-watcher"})
            with urllib.request.urlopen(req, timeout=self.fetch_timeout_s) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            data = json.loads(raw)
            if not isinstance(data, dict) or "path_signatures" not in data:
                raise ValueError("beklenmeyen format (path_signatures alani yok)")
            if data.get("version") is not None and data.get("version") == self.version:
                log.info(f"[patterns] guncel (version={self.version}), degisiklik yok")
                return
            self._apply(data, source="remote")
            self._compile()
            self._save_cache(data)
        except Exception as e:
            log.warning(f"[patterns] uzak liste cekilemedi ({self.url}): {e} — mevcut liste ile devam ediliyor")

    def _save_cache(self, data):
        if not self.cache_path:
            return
        try:
            d = os.path.dirname(self.cache_path)
            if d:
                os.makedirs(d, exist_ok=True)
            tmp = self.cache_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.cache_path)
        except Exception as e:
            log.warning(f"[patterns] cache yazilamadi ({self.cache_path}): {e}")


# ── CONFIG YUKLEME ──────────────────────────────────────────────────
def _deep_merge_defaults(cfg, user_cfg):
    for k, v in user_cfg.items():
        if k in ("thresholds", "patterns") and isinstance(v, dict) and isinstance(cfg.get(k), dict):
            for kk, vv in v.items():
                if isinstance(vv, dict) and isinstance(cfg[k].get(kk), dict):
                    cfg[k][kk].update(vv)
                else:
                    cfg[k][kk] = vv
        else:
            cfg[k] = v


def load_config(path):
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    if path and os.path.isfile(path):
        try:
            with open(path, "r") as f:
                user_cfg = json.load(f)
            _deep_merge_defaults(cfg, user_cfg)
        except Exception as e:
            print(f"[config] UYARI: {path} okunamadi ({e}), varsayilan + env kullaniliyor")

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


# ── LOG TAILER (polling tabanli, rotate-aware) ──────────────────────
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
        return self._fh.readlines()


# ── COKLU SITE LOG IZLEME ────────────────────────────────────────────
def resolve_log_paths(cfg):
    """log_path + log_paths + log_path_glob'dan benzersiz path listesi uretir."""
    paths = set()
    single = cfg.get("log_path")
    if single:
        paths.add(single)
    for p in cfg.get("log_paths") or []:
        paths.add(p)
    pattern = cfg.get("log_path_glob")
    if pattern:
        paths.update(glob.glob(pattern))
    return paths


class MultiLogTailer:
    """
    Birden fazla site/vhost log dosyasini ayni anda izler (ornek: CloudPanel'de
    her site kendi /home/<site>/logs/nginx/access.log dosyasina yazar).
    log_path_glob verilmisse, discover_interval_s surede bir yeniden tarayip
    yeni eklenen siteleri de otomatik izlemeye baslar -- config'e dokunmaya
    ya da servisi restart etmeye gerek kalmaz.
    """

    def __init__(self, cfg):
        self.cfg = cfg
        self.discover_interval_s = cfg.get("log_discover_interval_s", 300)
        self._last_discover = 0.0
        self.tailers = {}  # path -> LogTailer
        self._discover(initial=True)

    def _discover(self, initial=False):
        paths = resolve_log_paths(self.cfg)
        new_paths = paths - set(self.tailers.keys())
        gone_paths = set(self.tailers.keys()) - paths
        for p in sorted(new_paths):
            if os.path.isfile(p):
                self.tailers[p] = LogTailer(p)
                log.info(f"[multilog] izlemeye baslandi: {p}")
            elif initial:
                log.warning(f"[multilog] dosya henuz yok, sonra denenecek: {p}")
        for p in gone_paths:
            del self.tailers[p]
            log.info(f"[multilog] artik yok, birakildi: {p}")
        if initial:
            log.info(f"[multilog] toplam {len(self.tailers)} log dosyasi izleniyor")

    def maybe_rediscover(self, now):
        if (now - self._last_discover) < self.discover_interval_s:
            return
        self._last_discover = now
        self._discover()

    def read_new_lines(self):
        """path -> [lines] seklinde, sadece yeni satiri olan dosyalar icin doner."""
        result = {}
        # Henuz dosyasi olusmamis (initial=True'da atlanan) path'leri de tekrar dene
        for p in resolve_log_paths(self.cfg):
            if p not in self.tailers and os.path.isfile(p):
                self.tailers[p] = LogTailer(p)
                log.info(f"[multilog] izlemeye baslandi (gecikmeli): {p}")
        for p, tailer in self.tailers.items():
            lines = tailer.read_new_lines()
            if lines:
                result[p] = lines
        return result


# ── PARSE ────────────────────────────────────────────────────────────
def parse_line(line, extended=False):
    rex = EXTENDED_LOG_LINE_RE if extended else LOG_LINE_RE
    m = rex.match(line)
    if m:
        try:
            status = int(m.group("status"))
        except (ValueError, TypeError):
            status = None
        if status is not None:
            ip = m.group("ip")
            if extended:
                xff = m.group("xff")
                if xff and xff != "-":
                    # XFF birden fazla IP icerebilir (proxy zinciri); en soldaki
                    # (istemciye en yakin) genelde gercek istemcidir.
                    ip = xff.split(",")[0].strip() or ip
            return {
                "ip": ip,
                "method": m.group("method"),
                "path": m.group("path"),
                "status": status,
                "ua": m.group("ua"),
                "malformed": False,
            }
    # Ana format eslesmedi. ONCEDEN bu satirlar sessizce atiliyordu; bozuk/
    # protokol-ihlali/binary payload iceren istekler cogu zaman tam da
    # saldiri gostergesidir. En azindan IP'yi cikarip malformed olarak isaretle.
    m2 = LOOSE_IP_RE.match(line)
    if m2:
        return {
            "ip": m2.group("ip"),
            "method": None,
            "path": None,
            "status": None,
            "ua": None,
            "malformed": True,
        }
    return None


# ── PATTERN MOTORU ───────────────────────────────────────────────────
class PatternEngine:
    def __init__(self, thresholds, cooldown_s, ignore_ips, patterns, ignore_path_prefixes=None):
        self.thresholds = thresholds
        self.cooldown_s = cooldown_s
        self.ignore_ips = set(ignore_ips or [])
        self.ignore_path_prefixes = tuple(ignore_path_prefixes or [])
        self.patterns = patterns  # PatternStore instance
        # ip -> pattern_type -> deque[timestamp]
        self.windows = collections.defaultdict(lambda: collections.defaultdict(collections.deque))
        # (ip, pattern_type) -> last_sent_epoch
        self.cooldowns = {}
        # sig_name -> deque[(ts, ip)]  (dagitik/cok-IP tespiti icin, cooldown'dan bagimsiz)
        self.global_windows = collections.defaultdict(collections.deque)
        self.global_cooldowns = {}

    def _on_cooldown(self, ip, pattern_type, now):
        last = self.cooldowns.get((ip, pattern_type))
        return last is not None and (now - last) < self.cooldown_s

    def _mark_sent(self, ip, pattern_type, now):
        self.cooldowns[(ip, pattern_type)] = now

    def _window_count(self, ip, pattern_type, now, window_s):
        """Yeni olayi pencereye ekler, penceredeki guncel olay sayisini doner."""
        dq = self.windows[ip][pattern_type]
        dq.append(now)
        while dq and (now - dq[0]) > window_s:
            dq.popleft()
        return len(dq)

    def _note_global(self, sig_name, ip, now, window_s):
        dq = self.global_windows[sig_name]
        dq.append((now, ip))
        while dq and (now - dq[0][0]) > window_s:
            dq.popleft()

    def _maybe_emit_distributed(self, sig_name, now, events):
        cfg = self.thresholds.get("distributed_signature", {})
        if not cfg.get("enabled", True):
            return
        dq = self.global_windows[sig_name]
        distinct_ips = {ip for _, ip in dq}
        if len(distinct_ips) < cfg.get("distinct_ips", 5):
            return
        key = f"distributed_{sig_name}"
        last = self.global_cooldowns.get(key)
        if last is not None and (now - last) < self.cooldown_s:
            return
        self.global_cooldowns[key] = now
        events.append(("distributed_signature", {
            "signature": sig_name,
            "distinct_ip_count": len(distinct_ips),
            "window_s": cfg.get("window_s", 300),
            "sample_ips": sorted(distinct_ips)[:20],
        }))

    def process(self, parsed, now):
        """
        parsed: parse_line() ciktisi.
        Donus: list of (pattern_type, detail_dict) -- bir satir birden fazla
        pattern tetikleyebilir. distributed_signature olaylarinda 'ip' alani
        tek bir IP degil, ornek IP listesidir (detail icinde).
        """
        ip = parsed["ip"]
        if ip in self.ignore_ips:
            return []

        events = []

        # Bozuk/parse edilemeyen satirlar: ONCEDEN tamamen atiliyordu.
        if parsed.get("malformed"):
            cfg = self.thresholds.get("malformed_request", {})
            if cfg.get("enabled", True):
                window_s = cfg.get("window_s", 60)
                count = self._window_count(ip, "malformed_request", now, window_s)
                if count >= cfg.get("count", 5) and not self._on_cooldown(ip, "malformed_request", now):
                    events.append(("malformed_request", {
                        "hit_count": count, "window_s": window_s
                    }))
                    self._mark_sent(ip, "malformed_request", now)
            return events

        status = parsed["status"]
        path = parsed["path"]
        ua = parsed["ua"]

        if path and self.ignore_path_prefixes and path.startswith(self.ignore_path_prefixes):
            return []

        # 404 flood
        cfg = self.thresholds.get("404_flood", {})
        if cfg.get("enabled") and status == 404:
            window_s = cfg.get("window_s", 60)
            count = self._window_count(ip, "404_flood", now, window_s)
            if count >= cfg.get("count", 10) and not self._on_cooldown(ip, "404_flood", now):
                events.append(("404_flood", {
                    "status": status, "path": path,
                    "hit_count": count, "window_s": window_s
                }))
                self._mark_sent(ip, "404_flood", now)

        # auth flood (401/403)
        cfg = self.thresholds.get("auth_flood", {})
        if cfg.get("enabled") and status in (401, 403):
            window_s = cfg.get("window_s", 60)
            count = self._window_count(ip, "auth_flood", now, window_s)
            if count >= cfg.get("count", 8) and not self._on_cooldown(ip, "auth_flood", now):
                events.append(("auth_flood", {
                    "status": status, "path": path,
                    "hit_count": count, "window_s": window_s
                }))
                self._mark_sent(ip, "auth_flood", now)

        # rate flood (genel istek hizi, status'tan bagimsiz)
        cfg = self.thresholds.get("rate_flood", {})
        if cfg.get("enabled"):
            window_s = cfg.get("window_s", 10)
            count = self._window_count(ip, "rate_flood", now, window_s)
            if count >= cfg.get("count", 30) and not self._on_cooldown(ip, "rate_flood", now):
                events.append(("rate_flood", {
                    "status": status, "path": path,
                    "hit_count": count, "window_s": window_s
                }))
                self._mark_sent(ip, "rate_flood", now)

        # path signature -- artik ham path'in yaninda 1x ve 2x yuzde-decode
        # edilmis halleriyle de kontrol ediliyor (double-encoding atlatmasina karsi)
        cfg = self.thresholds.get("path_signature", {})
        if cfg.get("enabled") and path:
            once = _safe_unquote(path, rounds=1)
            twice = _safe_unquote(path, rounds=2)
            candidates = {path, once, twice}
            if any(self.patterns.path_re.search(c) for c in candidates):
                dcfg = self.thresholds.get("distributed_signature", {})
                self._note_global("path_signature", ip, now, dcfg.get("window_s", 300))
                if not self._on_cooldown(ip, "path_signature", now):
                    events.append(("path_signature", {"status": status, "path": path, "hit_count": 1}))
                    self._mark_sent(ip, "path_signature", now)
                self._maybe_emit_distributed("path_signature", now, events)

        # user-agent signature
        cfg = self.thresholds.get("ua_signature", {})
        if cfg.get("enabled"):
            ua_is_empty = (not ua) or ua == "-"
            is_known_tool = bool(self.patterns.ua_re.search(ua or ""))
            should_flag = is_known_tool or (ua_is_empty and cfg.get("flag_empty_ua", False))
            if should_flag:
                dcfg = self.thresholds.get("distributed_signature", {})
                self._note_global("ua_signature", ip, now, dcfg.get("window_s", 300))
                if not self._on_cooldown(ip, "ua_signature", now):
                    events.append(("ua_signature", {"status": status, "path": path, "user_agent": ua, "hit_count": 1}))
                    self._mark_sent(ip, "ua_signature", now)
                self._maybe_emit_distributed("ua_signature", now, events)

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

        stale_gkeys = [k for k, t in self.global_cooldowns.items() if (now - t) > max(max_age_s, self.cooldown_s)]
        for k in stale_gkeys:
            del self.global_cooldowns[k]


# ── SIBERKAPAN'A GONDERIM ───────────────────────────────────────────
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
            "User-Agent": "siberkapan-nginx-watcher/2.0 (+https://siberkapan.org)",
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
        return None, f"timeout_or_os_error: {e}"
    except Exception as e:
        return None, f"unexpected_error: {e}"


# ── ANA DONGU ────────────────────────────────────────────────────────
def run(cfg, verbose=False):
    setup_logging(cfg, verbose)

    if not cfg.get("api_key"):
        log.error("api_key bos. Config dosyasina veya SIBERKAPAN_API_KEY ortam degiskenine key girilmeli.")
        sys.exit(1)

    resolved = resolve_log_paths(cfg)
    if not resolved:
        log.error("Izlenecek hicbir log_path/log_paths/log_path_glob bulunamadi.")
        sys.exit(1)

    extended = bool(cfg.get("trust_x_forwarded_for"))
    if extended:
        log.info("trust_x_forwarded_for=true — nginx log_format'in sonuna \"$http_x_forwarded_for\" eklenmis olmali")

    log.info(f"SiberKapan Nginx Watcher baslatildi. {len(resolved)} log kaynagi taniniyor, api={cfg['api_url']}")

    patterns = PatternStore(cfg.get("patterns", {}))
    tailer = MultiLogTailer(cfg)
    engine = PatternEngine(
        cfg["thresholds"], cfg["cooldown_s"], cfg.get("ignore_ips"),
        patterns, cfg.get("ignore_path_prefixes")
    )

    last_cleanup = time.time()

    while True:
        now = time.time()

        patterns.maybe_update(now)
        tailer.maybe_rediscover(now)

        for log_path, lines in tailer.read_new_lines().items():
            for raw_line in lines:
                parsed = parse_line(raw_line.rstrip("\n"), extended=extended)
                if not parsed:
                    continue

                events = engine.process(parsed, now)
                for pattern_type, detail in events:
                    send_ip = parsed["ip"]
                    if pattern_type == "distributed_signature":
                        send_ip = "distributed"  # tek IP degil, detail.sample_ips'e bakin
                    try:
                        status, body = send_to_siberkapan(cfg["api_url"], cfg["api_key"], send_ip, pattern_type, detail)
                    except Exception as e:
                        log.error(f"BEKLENMEYEN HATA gonderim sirasinda ip={send_ip} pattern={pattern_type}: {e}")
                        continue
                    if status == 200:
                        log.info(f"GONDERILDI site={log_path} ip={send_ip} pattern={pattern_type} -> {body}")
                    else:
                        log.warning(f"GONDERIM HATASI site={log_path} ip={send_ip} pattern={pattern_type} status={status} body={body}")

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

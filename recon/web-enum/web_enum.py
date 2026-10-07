#!/usr/bin/env python3
"""
Web surface enumeration: dati uno o piu' domini/host, per ognuno rileva:
  1. stack tecnologico     (whatweb, o fallback puro Python su header/body)
  2. route/path nascosti    (ffuf | gobuster | fallback puro Python, con
                             ricorsione opzionale sulle directory trovate)
  3. endpoint API nel JS    (crawl ricorsivo concorrente: pagine -> <script>,
                             poi chunk dinamici (import(), webpack/Vite/Next)
                             e source map; estrazione di path-like, URL
                             assolute, chiamate fetch/axios/XHR e possibili
                             secret — spesso le route reali di una SPA non
                             si indovinano a wordlist, sono scritte nel JS)

Non richiede che l'host sia gia' stato verificato "vivo": se l'input e' un
host semplice (non un URL completo), prova https:// poi http://, come fa
live_hosts.py. Se l'input e' gia' un URL (es. preso da live_hosts.json),
viene usato cosi' com'e'.

Controllo aggressivita':
  --profile stealth|normal|aggressive   preset di concorrenza/timing
  --recursion-depth N                   scava dir dentro dir (0 = off)
  --whatweb-args "..."                  flag grezze appese a whatweb
  --ffuf-args "..."                     flag grezze appese a ffuf
  --gobuster-args "..."                 flag grezze appese a gobuster

Input:
  -d example.com -d https://api.example.com   (ripetibile, host o URL)
  -d example.com,api.example.com              (separati da virgola)
  -iL live_hosts.txt                          (un host/URL per riga)

Output in <base>/web-enum/<label>/<timestamp>/: web_enum.json + web_enum.txt.

Uso consentito SOLO su host di tua proprieta' o per cui hai autorizzazione:
il content discovery e il crawling JS sono attivita' attive (centinaia di
richieste reali verso il target).
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import ssl
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import common  # noqa: E402

TOOL_NAME = "web-enum"

# ---------------------------------------------------------------------------
# HTTP helper condiviso (niente libreria esterna richiesta)
# ---------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Handler che NON segue i 3xx: li lascia propagare come HTTPError, cosi'
    il chiamante vede lo status grezzo (301/302) e l'header Location invece del
    200 finale. Usato dal content discovery (follow=False); resolve/stack/JS
    vogliono invece seguire il redirect per leggere la pagina reale."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


# ---------------------------------------------------------------------------
# Rate limiting: back-off su 429/503, per non aggravare un servizio sotto
# stress o gia' protetto (vedi detect_waf_builtin piu' sotto). Non e' pensato
# per "nascondersi" da un WAF: solo per non martellare un target che sta
# chiaramente chiedendo di rallentare — un dovere verso chi stiamo testando,
# non un modo per evitare i suoi controlli di sicurezza.
# ---------------------------------------------------------------------------

_THROTTLES: dict[str, "_Throttle"] = {}
_THROTTLES_LOCK = threading.Lock()


def _parse_retry_after(value: str | None) -> float | None:
    """Retry-After puo' essere un numero di secondi o una data HTTP; proviamo
    solo il caso numerico (il piu' comune), il resto ricade sul backoff."""
    if not value:
        return None
    try:
        return max(0.0, min(float(value.strip()), 60.0))
    except ValueError:
        return None


class _Throttle:
    """Un token-bucket minimale per host: un intervallo minimo costante tra
    richieste (--min-interval/profilo) piu' un penalty esponenziale quando il
    target risponde 429/503, azzerato alla prima risposta non di rate-limit."""

    def __init__(self, min_interval: float) -> None:
        self._lock = threading.Lock()
        self._min_interval = min_interval
        self._next_ok = 0.0
        self._penalty = 0.0

    def wait(self) -> None:
        with self._lock:
            delay = max(self._next_ok - time.monotonic(), 0.0)
        if delay > 0:
            time.sleep(delay)

    def note_response(self, status: int | None, retry_after: str | None) -> float:
        """Registra l'esito e ritorna il delay (secondi) applicato, se e' il
        caso di ritentare la richiesta (0.0 = nessun delay, non ritentare)."""
        with self._lock:
            now = time.monotonic()
            if status in (429, 503):
                wait = _parse_retry_after(retry_after)
                if wait is None:
                    self._penalty = min(max(self._penalty * 2, 1.0), 30.0)
                    wait = self._penalty
                self._next_ok = max(self._next_ok, now + wait)
                return wait
            self._penalty = 0.0
            self._next_ok = max(self._next_ok, now + self._min_interval)
            return 0.0


def _get_throttle(host: str, min_interval: float) -> _Throttle:
    with _THROTTLES_LOCK:
        t = _THROTTLES.get(host)
        if t is None:
            t = _Throttle(min_interval)
            _THROTTLES[host] = t
        return t


def _fetch(url: str, timeout: int, insecure: bool, max_bytes: int = 300_000,
           follow: bool = True, headers: dict[str, str] | None = None,
           min_interval: float = 0.0, max_retries: int = 4) -> dict | None:
    handlers: list = []
    if url.startswith("https://") and insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    if not follow:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    req_headers = {"User-Agent": "recon-web-enum/1.0"}
    req_headers.update(headers or {})
    host = urllib.parse.urlparse(url).hostname or url
    throttle = _get_throttle(host, min_interval)

    for attempt in range(max_retries + 1):
        throttle.wait()
        req = urllib.request.Request(url, headers=req_headers)
        try:
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read(max_bytes)
                result = {"status": resp.status, "headers": dict(resp.headers), "body": body}
        except urllib.error.HTTPError as e:
            body = e.read(max_bytes) if e.fp else b""
            result = {"status": e.code, "headers": dict(e.headers or {}), "body": body}
        except Exception:  # noqa: BLE001
            return None
        retry_after = next((v for k, v in result["headers"].items()
                            if k.lower() == "retry-after"), None)
        delay = throttle.note_response(result["status"], retry_after)
        if delay and attempt < max_retries:
            common.warn(f"{host}: status {result['status']} (rate limit?), "
                        f"attendo {delay:.1f}s prima di ritentare "
                        f"({attempt + 1}/{max_retries})...")
            continue
        return result
    return result


def resolve_base_url(entry: str, timeout: int, insecure: bool,
                     headers: dict[str, str] | None = None,
                     min_interval: float = 0.0) -> str | None:
    """Se entry e' gia' un URL, lo usa cosi' com'e'. Se e' un host semplice,
    prova https:// poi http:// (stesso approccio del probe builtin di
    live_hosts.py) e ritorna il primo schema che risponde."""
    if "://" in entry:
        return entry.rstrip("/")
    for scheme in ("https://", "http://"):
        url = f"{scheme}{entry}"
        if _fetch(url, timeout, insecure, headers=headers, min_interval=min_interval) is not None:
            return url.rstrip("/")
    return None


# ---------------------------------------------------------------------------
# 1. Stack tecnologico
# ---------------------------------------------------------------------------

# name -> (regex su header, regex su body); una delle due None se non usata.
TECH_SIGNATURES: list[tuple[str, re.Pattern | None, re.Pattern | None]] = [
    ("WordPress", None, re.compile(rb"wp-content|wp-includes", re.I)),
    ("Drupal", None, re.compile(rb"Drupal\.settings|/sites/default/", re.I)),
    ("Joomla", None, re.compile(rb"Joomla!", re.I)),
    ("Laravel", re.compile(r"laravel_session", re.I), None),
    ("Django", re.compile(r"csrftoken", re.I), None),
    ("Ruby on Rails", re.compile(r"_session_id|x-runtime", re.I), None),
    ("ASP.NET", re.compile(r"asp\.net_sessionid|x-aspnet-version", re.I), None),
    ("Express/Node.js", re.compile(r"x-powered-by:\s*express", re.I), None),
    ("PHP", re.compile(r"x-powered-by:\s*php|phpsessid", re.I), None),
    ("React", None, re.compile(rb"data-reactroot|react-dom", re.I)),
    ("Vue.js", None, re.compile(rb"data-v-app|__vue__|/js/app\.[0-9a-f]+\.js", re.I)),
    ("Angular", None, re.compile(rb"ng-version", re.I)),
    ("jQuery", None, re.compile(rb"jquery(\.min)?\.js", re.I)),
    ("Bootstrap", None, re.compile(rb"bootstrap(\.min)?\.css", re.I)),
    ("Cloudflare", re.compile(r"cf-ray|server:\s*cloudflare", re.I), None),
    ("Nginx", re.compile(r"server:\s*nginx", re.I), None),
    ("Apache", re.compile(r"server:\s*apache", re.I), None),
    ("IIS", re.compile(r"server:\s*microsoft-iis", re.I), None),
]


def detect_tech_builtin(url: str, timeout: int, insecure: bool,
                        headers: dict[str, str] | None = None,
                        min_interval: float = 0.0) -> list[str]:
    resp = _fetch(url, timeout, insecure, headers=headers, min_interval=min_interval)
    if not resp:
        return []
    header_blob = "\n".join(f"{k}: {v}" for k, v in resp["headers"].items())
    found = []
    for name, header_re, body_re in TECH_SIGNATURES:
        if header_re and header_re.search(header_blob):
            found.append(name)
        elif body_re and body_re.search(resp["body"]):
            found.append(name)
    return sorted(set(found))


# Firme di WAF/CDN su header e corpo della risposta. Lo scopo e' SOLO
# informativo: avvisare che il target e' protetto cosi' da abbassare in
# automatico l'aggressivita' (vedi _effective_profile) e non rischiare di
# aggravare un servizio gia' sotto scrutinio — non per aggirarne i controlli.
WAF_SIGNATURES: list[tuple[str, re.Pattern]] = [
    ("Cloudflare", re.compile(r"cf-ray|server:\s*cloudflare", re.I)),
    ("Akamai", re.compile(r"akamaighost|x-akamai", re.I)),
    ("Imperva/Incapsula", re.compile(r"x-iinfo|incap_ses|visid_incap", re.I)),
    ("Sucuri CloudProxy", re.compile(r"x-sucuri-id|sucuri/cloudproxy", re.I)),
    ("AWS WAF/CloudFront", re.compile(r"x-amz-cf-id|x-amzn-requestid", re.I)),
    ("F5 BIG-IP ASM", re.compile(r"big-ip|x-wa-info|tsPD_101", re.I)),
    ("Fastly", re.compile(r"x-served-by:\s*cache|fastly-io", re.I)),
    ("Barracuda", re.compile(r"barra_counter_session", re.I)),
    ("ModSecurity", re.compile(r"mod_security|this request has been blocked", re.I)),
    ("Generic WAF block page", re.compile(
        r"request blocked|access denied.*security|automated requests|"
        r"unusual (?:traffic|activity) detected", re.I)),
]


def detect_waf_builtin(url: str, timeout: int, insecure: bool,
                       headers: dict[str, str] | None = None) -> list[str]:
    """Una singola richiesta leggera, prima di qualunque scansione attiva,
    SOLO per capire se c'e' un WAF/CDN davanti al target. Il risultato guida
    _effective_profile: non e' usato per evitare il rilevamento."""
    resp = _fetch(url, timeout, insecure, headers=headers)
    if not resp:
        return []
    blob = "\n".join(f"{k}: {v}" for k, v in resp["headers"].items())
    text = resp["body"].decode("utf-8", "replace")
    found = [name for name, rx in WAF_SIGNATURES if rx.search(blob) or rx.search(text)]
    return sorted(set(found))


def detect_tech_whatweb(url: str, flags: list[str], timeout: int) -> list[str]:
    if not shutil.which("whatweb"):
        common.warn("whatweb non installato, uso il fallback builtin per lo stack.")
        return []
    cmd = ["whatweb", "--no-errors", "--log-json=-"] + flags + [url]
    rc, out, err = common.run_cmd(cmd, timeout)
    found: list[str] = []
    for line in out.splitlines():
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        for plugin in obj.get("plugins", {}):
            found.append(plugin)
    return sorted(set(found))


# ---------------------------------------------------------------------------
# 2. Route/content discovery
# ---------------------------------------------------------------------------

# Wordlist minima usata solo se non viene passato --wordlist e ne' ffuf ne'
# una wordlist di sistema nota (SecLists/dirb) sono disponibili. Copre i
# path piu' comuni per pannelli admin, file sensibili e documentazione API.
BUILTIN_WORDLIST = [
    "admin", "login", "dashboard", "api", "api/v1", "api/v2", "graphql",
    "swagger.json", "swagger-ui", "swagger-ui.html", "openapi.json",
    "wp-login.php", "wp-json", "wp-admin",
    ".env", ".git/HEAD", "backup.zip", "config.php.bak", ".DS_Store",
    "server-status", "phpinfo.php", "actuator/health", "health", "status",
    ".well-known/security.txt", "robots.txt", "sitemap.xml", "debug", "test",
]

# Wordlist di sistema comuni su Kali, provate in ordine se --wordlist non e' dato.
SYSTEM_WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
]


def pick_wordlist(user_wordlist: str | None) -> tuple[str | None, list[str]]:
    """Ritorna (path_su_disco_o_None, lista_in_memoria). Se un file esiste lo
    si usa su disco (per ffuf); altrimenti si usa la lista builtin in memoria
    (per il fallback Python)."""
    if user_wordlist and Path(user_wordlist).exists():
        return user_wordlist, []
    for path in SYSTEM_WORDLISTS:
        if Path(path).exists():
            return path, []
    return None, BUILTIN_WORDLIST


# Tetto di sicurezza sui risultati totali quando la ricorsione e' attiva
# (gobuster/builtin, dove la ricorsione la guidiamo noi): evita che un sito
# con molte directory faccia esplodere richieste e dimensione dell'output.
MAX_DISCOVERY_RESULTS = 3000

GOBUSTER_LINE_RE = re.compile(
    r"^(/\S*)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\](?:\s*\[-->\s*([^\]]+)\])?")


def _is_dir_candidate(r: dict) -> bool:
    """True se il path trovato sembra una directory in cui vale la pena
    ricorrere: niente estensione nell'ultimo segmento (non un file) e status
    che indica esistenza (200) o una dir (301/302 redirect, 403 vietata ma
    presente). I 404 non arrivano qui, sono gia' scartati a monte."""
    p = r["path"].rstrip("/")
    if not p:
        return False
    last = p.rsplit("/", 1)[-1]
    if "." in last:
        return False
    return r["status"] in (200, 301, 302, 403)


def _discover_recursive(level_fn, depth: int) -> tuple[list[dict], bool]:
    """Orchestratore di ricorsione per i motori che NON ricorrono da soli
    (builtin e gobuster). `level_fn(prefix)` esegue UN livello di fuzzing
    sotto `prefix` (stringa relativa alla radice, "" per la radice) e torna
    risultati con path gia' relativo alla radice. Ritorna (risultati, troncato)
    dove troncato=True indica che si e' raggiunto MAX_DISCOVERY_RESULTS.

    ffuf ha la sua ricorsione nativa (-recursion) e non passa di qui."""
    seen: set[str] = set()
    all_res: list[dict] = []
    frontier = [""]
    for d in range(depth + 1):
        nxt: list[str] = []
        for prefix in frontier:
            if len(all_res) >= MAX_DISCOVERY_RESULTS:
                common.warn(f"content discovery: raggiunto il cap di {MAX_DISCOVERY_RESULTS} "
                            f"risultati, ricorsione interrotta (output parziale).")
                return all_res, True
            for r in level_fn(prefix):
                if r["path"] in seen:
                    continue
                seen.add(r["path"])
                all_res.append(r)
                if d < depth and _is_dir_candidate(r):
                    cand = r["path"].rstrip("/")
                    if cand not in nxt:
                        nxt.append(cand)
        frontier = nxt
        if not frontier:
            break
    return all_res, False


def _header_flags(engine: str, headers: dict[str, str]) -> list[str]:
    """Flag '-H nome: valore' ripetute, nella sintassi condivisa da ffuf e
    gobuster (entrambi accettano -H ripetibile in questa forma)."""
    flag = "-H"
    out: list[str] = []
    for k, v in headers.items():
        out += [flag, f"{k}: {v}"]
    return out


def discover_paths_ffuf(url: str, wordlist_path: str, flags: list[str], timeout: int,
                        depth: int, headers: dict[str, str] | None = None) -> tuple[list[dict], bool]:
    """Ritorna (risultati, timed_out). timed_out=True significa che ffuf non
    ha fatto in tempo a finire la wordlist entro `timeout`: i risultati (se
    presenti) sono parziali, non vanno letti come 'scansione completa'.

    Con depth>0 usa la ricorsione NATIVA di ffuf (-recursion): piu' efficiente
    del riavvio per-directory, un solo processo scende da solo nei path trovati."""
    if not shutil.which("ffuf"):
        common.warn("ffuf non installato, uso il fallback builtin per il content discovery.")
        return [], False
    cmd = ["ffuf", "-u", f"{url}/FUZZ", "-w", wordlist_path, "-of", "json", "-o", "-", "-s"]
    if depth > 0:
        cmd += ["-recursion", "-recursion-depth", str(depth)]
    cmd += _header_flags("ffuf", headers or {})
    cmd += flags
    rc, out, err, timed_out = common.run_cmd_ext(cmd, timeout)
    results: list[dict] = []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return results, timed_out
    for r in data.get("results", []):
        # Con la ricorsione il path completo sta in 'url' (FUZZ e' solo la
        # parola dell'ultimo livello); senza ricorsione sono equivalenti.
        full = r.get("url", "")
        if full.startswith(url + "/"):
            path = full[len(url) + 1:]
        else:
            path = r.get("input", {}).get("FUZZ", "")
        entry = {"path": path, "status": r.get("status"), "length": r.get("length")}
        if r.get("redirectlocation"):
            entry["redirect"] = r["redirectlocation"]
        results.append(entry)
    return results, timed_out


def discover_paths_gobuster(url: str, wordlist_path: str, flags: list[str], timeout: int,
                            depth: int, insecure: bool,
                            headers: dict[str, str] | None = None) -> list[dict]:
    """gobuster in modalita' `dir`. gobuster NON ricorre da solo in dir mode,
    quindi la ricorsione (se richiesta) la guidiamo noi via _discover_recursive,
    riavviando gobuster sotto ogni directory trovata. `timeout` e' per singolo
    livello: con ricorsione profonda e molti host alza --tool-timeout."""
    if not shutil.which("gobuster"):
        common.warn("gobuster non installato, uso il fallback builtin per il content discovery.")
        return []

    def level(prefix: str) -> list[dict]:
        target = f"{url}/{prefix}".rstrip("/")
        cmd = ["gobuster", "dir", "-u", target, "-w", wordlist_path, "-q", "--no-error"]
        if insecure:
            cmd.append("-k")
        cmd += _header_flags("gobuster", headers or {})
        cmd += flags
        rc, out, err, timed = common.run_cmd_ext(cmd, timeout)
        if timed:
            common.warn(f"{target}: gobuster timeout dopo {timeout}s — risultati di questo "
                        f"livello parziali, NON una scansione completa.")
        res: list[dict] = []
        for line in out.splitlines():
            m = GOBUSTER_LINE_RE.match(line.strip())
            if not m:
                continue
            word = m.group(1).lstrip("/")
            path = f"{prefix}/{word}".strip("/")
            entry = {"path": path, "status": int(m.group(2)), "length": int(m.group(3))}
            if m.group(4):
                entry["redirect"] = m.group(4).strip()
            res.append(entry)
        return res

    results, _ = _discover_recursive(level, depth)
    return sorted(results, key=lambda x: x["path"])


def discover_paths_builtin(url: str, words: list[str], concurrency: int, timeout: int,
                           insecure: bool, depth: int, headers: dict[str, str] | None = None,
                           min_interval: float = 0.0) -> list[dict]:
    def level(prefix: str) -> list[dict]:
        base = f"{url}/{prefix}".rstrip("/")
        res: list[dict] = []

        def probe(word: str) -> dict | None:
            resp = _fetch(f"{base}/{word}", timeout, insecure, follow=False,
                          headers=headers, min_interval=min_interval)
            if resp and resp["status"] != 404:
                path = f"{prefix}/{word}".strip("/")
                entry = {"path": path, "status": resp["status"], "length": len(resp["body"])}
                loc = next((v for k, v in resp["headers"].items() if k.lower() == "location"), None)
                if loc:
                    entry["redirect"] = loc
                return entry
            return None

        with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
            for fut in as_completed([pool.submit(probe, w) for w in words]):
                r = fut.result()
                if r:
                    res.append(r)
        return res

    results, _ = _discover_recursive(level, depth)
    return sorted(results, key=lambda x: x["path"])


# ---------------------------------------------------------------------------
# 3. Endpoint API dai bundle JS
# ---------------------------------------------------------------------------

SCRIPT_SRC_RE = re.compile(rb'<script[^>]+src=["\']([^"\']+)["\']', re.I)
# Stringhe quotate che sembrano un path di route/API (iniziano con "/", niente
# spazi, lunghezza ragionevole). Filtriamo poi le estensioni di asset statici.
JS_PATH_RE = re.compile(rb'["\'](/[a-zA-Z0-9_\-./?=&%]{2,150})["\']')
STATIC_EXT_RE = re.compile(r"\.(png|jpe?g|gif|svg|css|woff2?|ttf|eot|ico|map)$", re.I)
# URL assolute scritte nei bundle (API di terze parti, endpoint interni, ecc.).
JS_ABS_URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{4,200}")
# Argomento stringa della prima parentesi di fetch(...)/axios.get(...)/$.get(...)
# /router.get(...): cattura le route chiamate esplicitamente, che il solo
# pattern "stringa che inizia con /" puo' perdere (es. URL assolute).
JS_CALL_RE = re.compile(
    rb"(?:fetch|axios(?:\.(?:get|post|put|patch|delete))?|\$\.(?:get|post|ajax)"
    rb"|\.(?:get|post|put|patch|delete))\s*\(\s*[`'\"]([^`'\"]{1,200})[`'\"]"
)

# (nome, regex). Applicate al testo decodificato dei soli file JS. Sono
# EURISTICHE: producono candidati da verificare a mano, non certezze. I valori
# vengono mascherati prima di finire nell'output (vedi _mask).
SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Google OAuth token", re.compile(r"ya29\.[0-9A-Za-z\-_]{20,}")),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("Stripe live secret", re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("GitHub token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Private key header", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("Firebase DB URL", re.compile(r"https://[a-z0-9.-]+\.firebaseio\.com")),
    ("assegnazione key/secret/token", re.compile(
        r"(?i)(?:api[_-]?key|secret|token|passwd|password)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9\-_./+=]{12,}[\"']")),
]


def _mask(s: str) -> str:
    """Maschera il centro di un valore sensibile: resta identificabile e
    verificabile (testa/coda) senza riversare il segreto in chiaro nei file."""
    s = s.strip()
    if len(s) <= 4:
        return "..."
    if len(s) <= 12:
        return f"{s[:2]}...{s[-2:]}"
    return f"{s[:6]}...{s[-4:]}"


# Link/asset extra per il crawl delle pagine e dei chunk.
LINK_RE = re.compile(rb'<(?:a|form|iframe|frame)\b[^>]+?(?:href|action|src)=["\']([^"\'#\s]+)', re.I)
PRELOAD_JS_RE = re.compile(rb'<link[^>]+href=["\']([^"\']+\.m?js[^"\']*)["\']', re.I)
INLINE_SCRIPT_RE = re.compile(rb"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.I | re.S)
NON_PAGE_EXT_RE = re.compile(
    r"\.(png|jpe?g|gif|svg|webp|css|woff2?|ttf|eot|ico|map|js|mjs|json|xml|pdf|zip|gz|"
    r"tgz|rar|mp[34]|avi|mov|docx?|xlsx?|pptx?|exe|dmg)$", re.I)
# Riferimenti a file .js dentro i bundle: import("./x.js"), "/_next/static/chunks/a.js",
# URL assolute su CDN/sottodomini. I nomi "nudi" (es. "vue.js") sono rumore: si
# tengono solo se hanno un "/" o sembrano un chunk con hash (name.<hash>.js).
JS_REF_RE = re.compile(
    rb"[\"'`]((?:https?:)?//[^\s\"'`<>]{4,200}?\.m?js(?:\?[\w=&.%-]*)?"
    rb"|[\w\-./@~%]{1,200}?\.m?js(?:\?[\w=&.%-]*)?)[\"'`]")
HASHED_CHUNK_RE = re.compile(r"\.[0-9a-f]{6,}\.")
# Mappa chunk di webpack: {123:"abcdef12",...}[e]+".js" / ".chunk.js" -> id.hash(.chunk).js
WEBPACK_MAP_RE = re.compile(
    rb'\{((?:(?:\d+|"?[\w~-]+"?):"[0-9a-f]{8,20}",?){2,})\}\[\w+\]\+"(\.chunk)?\.js"')
WEBPACK_PAIR_RE = re.compile(rb'("?[\w~-]+"?):"([0-9a-f]{8,20})"')
SOURCEMAP_RE = re.compile(rb"//[#@]\s*sourceMappingURL=([^\s*]+)")


def _norm(url: str) -> str:
    return urllib.parse.urldefrag(url)[0]


def _in_scope(url: str, base_host: str) -> bool:
    host = urllib.parse.urlparse(url).hostname or ""
    return host == base_host or host.endswith("." + base_host)


def _is_html(resp: dict) -> bool:
    ctype = next((v for k, v in resp["headers"].items() if k.lower() == "content-type"), "")
    return "html" in ctype.lower() or resp["body"].lstrip()[:1] == b"<"


def _js_refs(body: bytes, js_url: str, root: str) -> set[str]:
    out: set[str] = set()
    for m in JS_REF_RE.finditer(body):
        ref = m.group(1).decode("utf-8", "replace")
        if "/" not in ref and not HASHED_CHUNK_RE.search(ref):
            continue
        out.add(urllib.parse.urljoin(js_url, ref))
        # Vite/Rollup: riferimenti relativi alla base del sito, non al file corrente.
        if not ref.startswith((".", "/", "http")):
            out.add(urllib.parse.urljoin(root, ref))
    base_dir = js_url.rsplit("/", 1)[0] + "/"
    for m in WEBPACK_MAP_RE.finditer(body):
        suffix = ".chunk.js" if m.group(2) else ".js"
        for cid, h in WEBPACK_PAIR_RE.findall(m.group(1)):
            out.add(f"{base_dir}{cid.decode().strip(chr(34))}.{h.decode()}{suffix}")
    return {_norm(u) for u in out}


# jsluice (BishopFox): parsing ad AST invece di regex, risolve concatenazioni
# e template literal che i regex sopra non vedono. Presenza rilevata una sola
# volta: se assente si prosegue solo con i regex, senza warning ripetuti.
_JSLUICE_BIN = shutil.which("jsluice")
_JSLUICE_WARNED = False


def _jsluice_mine(body: bytes, source: str, acc: "_JsAcc", timeout: int) -> None:
    """Arricchisce l'estrazione con jsluice se disponibile: e' puramente
    ADDITIVO rispetto ai regex (che restano baseline/fallback). Il formato
    esatto dell'output puo' variare tra versioni di jsluice, quindi il
    parsing e' deliberatamente permissivo e non deve mai interrompere la
    scansione: qualunque problema (binario assente, JSON inatteso, timeout)
    viene inghiottito con un singolo warning."""
    global _JSLUICE_WARNED
    if not _JSLUICE_BIN:
        return
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".js", delete=False) as f:
            f.write(body)
            tmp_path = f.name
        for sub, handler in (("urls", _jsluice_handle_url), ("secrets", _jsluice_handle_secret)):
            rc, out, err = common.run_cmd([_JSLUICE_BIN, sub, tmp_path], timeout)
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict):
                    handler(obj, acc, source)
    except Exception as e:  # noqa: BLE001
        if not _JSLUICE_WARNED:
            common.warn(f"jsluice: analisi non riuscita ({e}), continuo con i soli regex "
                        f"(nessun altro warning jsluice in questa run).")
            _JSLUICE_WARNED = True
    finally:
        if tmp_path:
            try:
                Path(tmp_path).unlink(missing_ok=True)
            except OSError:
                pass


def _jsluice_handle_url(obj: dict, acc: "_JsAcc", source: str) -> None:
    u = obj.get("url") or obj.get("path") or obj.get("endpoint")
    if not isinstance(u, str) or not u:
        return
    if u.startswith(("http://", "https://")):
        acc.urls.add(u)
    elif u.startswith("/") and not STATIC_EXT_RE.search(u):
        acc._mark(u, "call")  # jsluice risolve concatenazioni: trattata come "call".


def _jsluice_handle_secret(obj: dict, acc: "_JsAcc", source: str) -> None:
    kind = obj.get("kind") or obj.get("type") or "secret"
    data = obj.get("data") if isinstance(obj.get("data"), dict) else obj
    val = next((data[k] for k in ("value", "match", "secret", "raw") if isinstance(data.get(k), str)), None)
    if not val:
        return
    key = (f"jsluice:{kind}", val)
    if key in acc._seen_secret:
        return
    acc._seen_secret.add(key)
    acc.secrets.append({"type": f"jsluice: {kind}", "match": _mask(val), "source": source})


class _JsAcc:
    """Accumulatore dei risultati del mining (usato solo dal thread principale:
    i worker fanno solo I/O di rete, quindi niente lock)."""

    def __init__(self, timeout: int = 15) -> None:
        self.endpoint_via: dict[str, str] = {}
        self.urls: set[str] = set()
        self.secrets: list[dict] = []
        self._seen_secret: set[tuple[str, str]] = set()
        self._timeout = timeout

    def _mark(self, path: str, via: str) -> None:
        # "call" (fetch/axios/..., piu' affidabile) ha priorita' su "path".
        if self.endpoint_via.get(path) != "call":
            self.endpoint_via[path] = via

    def mine(self, body: bytes, source: str) -> None:
        for m in JS_PATH_RE.finditer(body):
            p = m.group(1).decode("utf-8", "replace")
            if not STATIC_EXT_RE.search(p):
                self._mark(p, "path")
        for m in JS_CALL_RE.finditer(body):
            arg = m.group(1).decode("utf-8", "replace")
            if arg.startswith(("http://", "https://")):
                self.urls.add(arg)
            elif arg.startswith("/") and not STATIC_EXT_RE.search(arg):
                self._mark(arg, "call")
        for m in JS_ABS_URL_RE.finditer(body):
            u = m.group(0).decode("utf-8", "replace")
            if not STATIC_EXT_RE.search(u):
                self.urls.add(u)
        text = body.decode("utf-8", "replace")
        for name, rx in SECRET_PATTERNS:
            for sm in rx.finditer(text):
                val = sm.group(0)
                if (name, val) in self._seen_secret:
                    continue
                self._seen_secret.add((name, val))
                self.secrets.append({"type": name, "match": _mask(val), "source": source})
        _jsluice_mine(body, source, self, self._timeout)


def _render_pages_playwright(pages: list[str], timeout: int, insecure: bool,
                             headers: dict[str, str] | None, base_host: str) -> dict:
    """Rende le pagine con un browser headless (Chromium via Playwright) e
    intercetta il traffico di rete REALE: cattura le chiamate XHR/fetch
    effettive e gli script iniettati a runtime che un crawler statico non
    vede (SPA, route client-side, chunk caricati solo dopo un'interazione).
    Opt-in esplicito (--render playwright): richiede `pip install playwright`
    + `playwright install chromium`, assente di default.

    Ritorna {endpoints[{endpoint,via}], urls[], js_bodies[{url,body,source}]}.
    Fallisce in modo silenzioso (liste vuote, con warning) se il pacchetto o
    il browser non sono disponibili: non deve mai interrompere la scansione."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        common.warn("--render playwright richiesto ma il pacchetto 'playwright' non e' "
                    "installato (pip install playwright && playwright install chromium). "
                    "Rendering saltato, proseguo coi soli risultati statici.")
        return {"endpoints": [], "urls": [], "js_bodies": []}

    endpoints: dict[str, str] = {}
    urls: set[str] = set()
    js_bodies: list[dict] = []
    seen_req: set[str] = set()

    def on_response(resp, page_url: str) -> None:
        try:
            u = resp.url
            if u in seen_req:
                return
            seen_req.add(u)
            rtype = resp.request.resource_type
            if rtype in ("xhr", "fetch"):
                if _in_scope(u, base_host):
                    path = urllib.parse.urlparse(u).path or "/"
                    endpoints.setdefault(path, "render")
                elif u.startswith(("http://", "https://")):
                    urls.add(u)
            elif rtype == "script" and resp.status < 400 and _in_scope(u, base_host):
                body = resp.body()
                if body:
                    js_bodies.append({"url": u, "body": body, "source": f"{page_url} (rendered)"})
        except Exception:  # noqa: BLE001
            pass  # risposta chiusa/non accessibile: non deve far cadere il rendering

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            try:
                context = browser.new_context(
                    ignore_https_errors=insecure,
                    extra_http_headers=headers or {},
                    user_agent="recon-web-enum/1.0 (+playwright)",
                )
                for page_url in pages:
                    page = context.new_page()
                    page.on("response", lambda r, _u=page_url: on_response(r, _u))
                    try:
                        page.goto(page_url, wait_until="networkidle", timeout=timeout * 1000)
                    except Exception as e:  # noqa: BLE001
                        common.warn(f"{page_url}: rendering playwright non riuscito ({e}), continuo.")
                    finally:
                        page.close()
            finally:
                browser.close()
    except Exception as e:  # noqa: BLE001
        common.warn(f"playwright: errore durante il rendering ({e}), proseguo senza.")

    return {"endpoints": [{"endpoint": e, "via": v} for e, v in endpoints.items()],
            "urls": sorted(urls), "js_bodies": js_bodies}


def mine_js(url: str, timeout: int, insecure: bool, concurrency: int = 8,
            crawl_depth: int = 2, max_pages: int = 60, max_js_files: int = 200,
            max_js_bytes: int = 3_000_000, seeds: list[str] | None = None,
            headers: dict[str, str] | None = None, min_interval: float = 0.0,
            render: bool = False, max_render_pages: int = 10) -> dict:
    """Crawl ricorsivo + mining dei JS. Ritorna {endpoints, urls, secrets,
    js_files, sourcemaps, sources, pages}.

    1. Pagine: BFS fino a crawl_depth (link <a>/<form>, piu' i path trovati dal
       content discovery come seed) per raccogliere <script src>, preload e JS inline.
    2. JS: a round concorrenti, scoprendo da ogni bundle altri chunk (import(),
       mappe webpack, riferimenti Vite/Next) finche' non ne emergono di nuovi o si
       raggiunge max_js_files. Sono in scope l'host e i suoi sottodomini; i JS su
       altri host (CDN/terze parti) vengono elencati ma non scaricati.
    3. Source map: se un bundle ne dichiara una (sourceMappingURL) viene scaricata
       e se ne analizzano i sorgenti originali (sourcesContent)."""
    acc = _JsAcc(timeout)
    base_host = urllib.parse.urlparse(url).hostname or ""
    root = url.rstrip("/") + "/"
    js_found: dict[str, dict] = {}
    sourcemaps: list[dict] = []
    sources: set[str] = set()

    def add_js(u: str, origin: str) -> bool:
        """Registra un JS; True se nuovo e in scope (quindi da scaricare)."""
        u = _norm(u)
        if not u.startswith(("http://", "https://")) or u in js_found:
            return False
        js_found[u] = {"url": u, "found_in": origin, "in_scope": _in_scope(u, base_host)}
        return js_found[u]["in_scope"]

    def fetch_js(u: str) -> tuple[str, dict | None]:
        return u, _fetch(u, timeout, insecure, max_bytes=max_js_bytes,
                         headers=headers, min_interval=min_interval)

    seen_pages = {_norm(url)}
    frontier = [url] + [s for s in (seeds or []) if _norm(s) not in seen_pages]
    seen_pages.update(_norm(s) for s in frontier)
    pages_ok = 0

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        # --- 1. crawl delle pagine -------------------------------------
        for depth in range(crawl_depth + 1):
            if not frontier:
                break
            fetched = list(pool.map(
                lambda u: (u, _fetch(u, timeout, insecure, max_bytes=500_000,
                                     headers=headers, min_interval=min_interval)),
                frontier))
            frontier = []
            for page_url, resp in fetched:
                if not resp or not _is_html(resp):
                    continue
                pages_ok += 1
                body = resp["body"]
                for rx in (SCRIPT_SRC_RE, PRELOAD_JS_RE):
                    for m in rx.finditer(body):
                        add_js(urllib.parse.urljoin(page_url, m.group(1).decode("utf-8", "replace")),
                               page_url)
                for m in INLINE_SCRIPT_RE.finditer(body):
                    if m.group(1).strip():
                        acc.mine(m.group(1), f"{page_url} (inline)")
                if depth == crawl_depth:
                    continue
                for m in LINK_RE.finditer(body):
                    link = _norm(urllib.parse.urljoin(page_url, m.group(1).decode("utf-8", "replace")))
                    if (link.startswith(("http://", "https://")) and link not in seen_pages
                            and _in_scope(link, base_host)
                            and not NON_PAGE_EXT_RE.search(urllib.parse.urlparse(link).path)
                            and len(seen_pages) < max_pages):
                        seen_pages.add(link)
                        frontier.append(link)

        # --- 2./3. JS ricorsivi + source map --------------------------
        pending = [u for u, m in js_found.items() if m["in_scope"]]
        n_fetched = 0
        while pending and n_fetched < max_js_files:
            batch = pending[:max_js_files - n_fetched]
            n_fetched += len(batch)
            pending = []
            map_jobs: list[tuple[str, str]] = []  # (js_url, map_url)
            for ju, resp in pool.map(fetch_js, batch):
                meta = js_found[ju]
                if not resp or resp["status"] >= 400:
                    meta["status"] = resp["status"] if resp else None
                    continue
                body = resp["body"]
                meta.update(status=resp["status"], bytes=len(body),
                            truncated=len(body) >= max_js_bytes)
                acc.mine(body, ju)
                for ref in _js_refs(body, ju, root):
                    if add_js(ref, ju):
                        pending.append(ref)
                sm = SOURCEMAP_RE.search(body[-2000:])
                if sm:
                    ref = sm.group(1).decode("utf-8", "replace")
                    if not ref.startswith("data:"):
                        map_jobs.append((ju, _norm(urllib.parse.urljoin(ju, ref))))
            if not map_jobs:
                continue
            for (ju, mu), (_, resp) in zip(map_jobs, pool.map(fetch_js, [m for _, m in map_jobs])):
                if not resp or resp["status"] >= 400:
                    continue
                try:
                    smap = json.loads(resp["body"])
                except ValueError:
                    continue
                srcs = smap.get("sources") or []
                contents = smap.get("sourcesContent") or []
                js_found[ju]["sourcemap"] = mu
                sourcemaps.append({"url": mu, "js": ju, "sources": len(srcs),
                                   "has_content": bool(contents)})
                for i, name in enumerate(srcs):
                    if "node_modules" in name:
                        continue
                    sources.add(name)
                    if i < len(contents) and isinstance(contents[i], str):
                        acc.mine(contents[i].encode("utf-8", "replace"), f"{mu} :: {name}")

    rendered = 0
    if render:
        render_pages = list(dict.fromkeys([url] + list(seeds or [])))[:max_render_pages]
        common.log(f"{url}: rendering {len(render_pages)} pagine con playwright...")
        rr = _render_pages_playwright(render_pages, timeout, insecure, headers, base_host)
        for e in rr["endpoints"]:
            acc._mark(e["endpoint"], e["via"])
        acc.urls.update(rr["urls"])
        for jb in rr["js_bodies"]:
            ju = _norm(jb["url"])
            if ju not in js_found:
                js_found[ju] = {"url": ju, "found_in": jb["source"], "in_scope": True}
            js_found[ju].update(status=200, bytes=len(jb["body"]), rendered=True)
            acc.mine(jb["body"], jb["source"])
            rendered += 1

    return {
        "endpoints": [{"endpoint": e, "via": acc.endpoint_via[e]} for e in sorted(acc.endpoint_via)][:500],
        "urls": sorted(acc.urls)[:300],
        "secrets": acc.secrets[:50],
        "js_files": sorted(js_found.values(), key=lambda m: m["url"]),
        "sourcemaps": sourcemaps,
        "sources": sorted(sources)[:300],
        "pages": pages_ok,
        "rendered_js": rendered,
    }


PROFILES: dict[str, dict] = {
    # min_interval: secondi minimi tra due richieste builtin allo stesso host
    # (vedi _Throttle). ffuf/gobuster hanno il proprio -p/--delay, gia' nelle
    # flag qui sotto; min_interval vale per i fetch Python (stack/content
    # discovery fallback/mining JS).
    "stealth": {"whatweb": ["-a", "1"], "ffuf": ["-t", "5", "-p", "0.3"],
                "gobuster": ["-t", "5", "--delay", "300ms"],
                "builtin_concurrency": 5, "js_concurrency": 3, "min_interval": 0.3},
    "normal": {"whatweb": ["-a", "3"], "ffuf": ["-t", "40"],
               "gobuster": ["-t", "40"],
               "builtin_concurrency": 20, "js_concurrency": 8, "min_interval": 0.0},
    "aggressive": {"whatweb": ["-a", "4"], "ffuf": ["-t", "100"],
                   "gobuster": ["-t", "100"],
                   "builtin_concurrency": 50, "js_concurrency": 15, "min_interval": 0.0},
}

# Se detect_waf_builtin trova un WAF/CDN, l'aggressivita' effettiva viene
# riportata ad almeno questo livello (indipendentemente dal --profile scelto),
# salvo --ignore-waf-detection: lo scopo e' non martellare un servizio che sta
# gia' segnalando una protezione attiva, non eludere quella protezione.
WAF_SAFE_CAP = {"builtin_concurrency": 5, "js_concurrency": 3, "min_interval": 0.3}


def _effective_profile(profile: dict, waf: list[str], ignore_waf: bool) -> dict:
    if not waf or ignore_waf:
        return profile
    return {
        **profile,
        "builtin_concurrency": min(profile["builtin_concurrency"], WAF_SAFE_CAP["builtin_concurrency"]),
        "js_concurrency": min(profile["js_concurrency"], WAF_SAFE_CAP["js_concurrency"]),
        "min_interval": max(profile["min_interval"], WAF_SAFE_CAP["min_interval"]),
    }


# ---------------------------------------------------------------------------
# Input
# ---------------------------------------------------------------------------


def label_source(entry: str) -> str:
    """Estrae solo l'host da un URL per il calcolo del label di default:
    l'URL intero (schema + porta, es. 'http://127.0.0.1:8911') contiene
    caratteri non validi in un nome di cartella (i ':' soprattutto su
    Windows, ma e' comunque piu' pulito evitarli ovunque)."""
    if "://" in entry:
        netloc = urllib.parse.urlparse(entry).netloc
        return netloc.split(":")[0] or entry
    return entry


def collect_inputs(domains: list[str], input_list: str | None) -> list[str]:
    items: list[str] = []
    for d in domains:
        items.extend(x.strip() for x in d.split(",") if x.strip())
    if input_list:
        p = Path(input_list)
        if not p.exists():
            common.warn(f"file input non trovato: {input_list}")
        else:
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    items.append(line)
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        key = it.lower().rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


EMPTY_JS = {"endpoints": [], "urls": [], "secrets": [], "js_files": [],
            "sourcemaps": [], "sources": [], "pages": 0, "rendered_js": 0}


def enum_one(entry: str, args, flags_whatweb: list[str], flags_ffuf: list[str],
             flags_gobuster: list[str], wordlist_path: str | None,
             wordlist_mem: list[str], profile: dict, extra_headers: dict[str, str]) -> dict:
    url = resolve_base_url(entry, args.timeout, args.insecure, extra_headers)
    if not url:
        common.warn(f"nessuna risposta da {entry}, salto.")
        return {"input": entry, "url": None, "tech": [], "waf": [], "paths": [], "js": dict(EMPTY_JS)}

    waf = [] if args.ignore_waf_detection else detect_waf_builtin(url, args.timeout, args.insecure, extra_headers)
    eff_profile = _effective_profile(profile, waf, args.ignore_waf_detection)
    if waf:
        note = ("" if eff_profile is not profile else " (gia' al livello piu' prudente)")
        common.warn(f"{url}: rilevato/i {', '.join(waf)} — scansione riportata al livello "
                    f"'stealth' per non aggravare un servizio protetto{note}. "
                    f"Usa --ignore-waf-detection per forzare il profilo scelto.")
    min_interval = eff_profile["min_interval"]

    common.log(f"{url}: stack...")
    tech = (detect_tech_whatweb(url, flags_whatweb, args.tool_timeout) if args.stack != "builtin" else [])
    if not tech:
        tech = detect_tech_builtin(url, args.timeout, args.insecure, extra_headers, min_interval)

    common.log(f"{url}: route discovery ({args.routes}"
               f"{', ricorsione ' + str(args.recursion_depth) if args.recursion_depth else ''})...")
    paths: list[dict] = []
    if args.routes == "ffuf" and wordlist_path:
        paths, ffuf_timed_out = discover_paths_ffuf(
            url, wordlist_path, flags_ffuf, args.tool_timeout, args.recursion_depth, extra_headers)
        if ffuf_timed_out:
            common.warn(f"{url}: ffuf non ha finito in {args.tool_timeout}s con la wordlist "
                        f"completa ({wordlist_path}) — risultati parziali o nulli, NON e' una "
                        f"scansione completa. Alza --tool-timeout o usa una wordlist piu' corta.")
    elif args.routes == "gobuster" and wordlist_path:
        paths = discover_paths_gobuster(
            url, wordlist_path, flags_gobuster, args.tool_timeout, args.recursion_depth,
            args.insecure, extra_headers)
    if not paths:
        words = wordlist_mem or BUILTIN_WORDLIST
        paths = discover_paths_builtin(
            url, words, eff_profile["builtin_concurrency"], args.timeout, args.insecure,
            args.recursion_depth, extra_headers, min_interval)

    js = dict(EMPTY_JS)
    if not args.skip_js:
        common.log(f"{url}: mining endpoint/secret da JS...")
        seeds = [f"{url}/{p['path']}" for p in paths if p["status"] == 200][:30]
        js = mine_js(url, args.timeout, args.insecure, eff_profile["js_concurrency"],
                     args.crawl_depth, args.max_pages, args.max_js, args.max_js_bytes, seeds,
                     extra_headers, min_interval, args.render == "playwright", args.max_render_pages)

    return {"input": entry, "url": url, "tech": tech, "waf": waf, "paths": paths, "js": js}


def render_text(results: list[dict]) -> str:
    lines = []
    for r in results:
        if not r["url"]:
            lines.append(f"{r['input']}: nessuna risposta\n")
            continue
        js = r["js"]
        lines.append(f"## {r['url']}")
        lines.append(f"  stack: {', '.join(r['tech']) or '(nessuno rilevato)'}")
        if r.get("waf"):
            lines.append(f"  [!] WAF/CDN rilevato: {', '.join(r['waf'])} "
                         f"— scansione rallentata automaticamente")
        if r["paths"]:
            lines.append(f"  path trovati ({len(r['paths'])}):")
            for p in r["paths"]:
                line = f"    {p['status']}\t/{p['path']}\t({p['length']} byte)"
                if p.get("redirect"):
                    line += f"  ->  {p['redirect']}"
                lines.append(line)
        if js["js_files"]:
            fetched = [f for f in js["js_files"] if f.get("bytes") is not None]
            ext = [f for f in js["js_files"] if not f["in_scope"]]
            render_note = f", {js['rendered_js']} via rendering" if js.get("rendered_js") else ""
            lines.append(f"  JS: {len(js['js_files'])} trovati ({len(fetched)} analizzati{render_note}, "
                         f"{len(ext)} esterni non scaricati) da {js['pages']} pagine crawlate")
            for f in js["js_files"][:60]:
                tag = "" if f["in_scope"] else "  [esterno]"
                if f.get("sourcemap"):
                    tag += "  [source map]"
                if f.get("truncated"):
                    tag += "  [troncato]"
                if f.get("rendered"):
                    tag += "  [solo via rendering]"
                lines.append(f"    {f['url']}{tag}")
            if len(js["js_files"]) > 60:
                lines.append(f"    ... e altri {len(js['js_files']) - 60} (vedi web_enum.json)")
        if js["sources"]:
            lines.append(f"  sorgenti originali da source map ({len(js['sources'])}):")
            for src in js["sources"][:40]:
                lines.append(f"    {src}")
            if len(js["sources"]) > 40:
                lines.append(f"    ... e altri {len(js['sources']) - 40} (vedi web_enum.json)")
        if js["endpoints"]:
            lines.append(f"  endpoint da JS ({len(js['endpoints'])}):")
            for e in js["endpoints"][:50]:
                tag = "fetch/axios" if e["via"] == "call" else "stringa"
                lines.append(f"    {e['endpoint']}\t({tag})")
            if len(js["endpoints"]) > 50:
                lines.append(f"    ... e altri {len(js['endpoints']) - 50} (vedi web_enum.json)")
        if js["urls"]:
            lines.append(f"  URL assolute nei JS ({len(js['urls'])}):")
            for u in js["urls"][:30]:
                lines.append(f"    {u}")
            if len(js["urls"]) > 30:
                lines.append(f"    ... e altre {len(js['urls']) - 30} (vedi web_enum.json)")
        if js["secrets"]:
            lines.append(f"  [!] possibili secret nei JS ({len(js['secrets'])}) — DA VERIFICARE a mano:")
            for s in js["secrets"]:
                lines.append(f"    [{s['type']}] {s['match']}  ({s['source']})")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Stack tecnologico, route discovery ed endpoint API dai JS.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-d", "--domain", action="append", default=[],
                        help="Host o URL (ripetibile, o separati da virgola)")
    parser.add_argument("-iL", "--input-list", default=None,
                        help="File con un host/URL per riga (es. live_hosts.txt)")
    parser.add_argument("-o", "--output", default=None,
                        help="Cartella base output: relativo risolto dalla radice del repo, "
                             "assoluto usato cosi'. Default <radice>/output")
    parser.add_argument("--label", default=None, help="Nome sotto-cartella output")
    parser.add_argument("--profile", choices=list(PROFILES), default="normal",
                        help="Livello di aggressivita' (default normal)")
    parser.add_argument("--stack", choices=["whatweb", "builtin"], default="whatweb",
                        help="Motore per il rilevamento stack (default whatweb, fallback automatico)")
    parser.add_argument("--routes", choices=["ffuf", "gobuster", "builtin"], default="ffuf",
                        help="Motore per il content discovery (default ffuf, fallback builtin automatico)")
    parser.add_argument("--recursion-depth", type=int, default=0,
                        help="Profondita' di ricorsione sulle directory trovate (0 = off, default). "
                             "ffuf usa la ricorsione nativa; gobuster e builtin la ottengono "
                             "riavviando la scansione sotto ogni dir trovata.")
    parser.add_argument("--wordlist", default=None, help="Wordlist custom per il content discovery")
    parser.add_argument("--skip-js", action="store_true", help="Salta il mining di endpoint dai JS")
    parser.add_argument("--crawl-depth", type=int, default=2,
                        help="Profondita' del crawl HTML per trovare i <script> (default 2)")
    parser.add_argument("--max-pages", type=int, default=60,
                        help="Max pagine HTML crawlate per host (default 60)")
    parser.add_argument("--max-js", type=int, default=200,
                        help="Max file JS scaricati per host, chunk inclusi (default 200)")
    parser.add_argument("--max-js-bytes", type=int, default=3_000_000,
                        help="Max byte letti per singolo JS/source map (default 3MB)")
    parser.add_argument("--render", choices=["off", "playwright"], default="off",
                        help="Rendering con browser headless (Chromium via Playwright) per catturare "
                             "script iniettati a runtime e le chiamate XHR/fetch reali che il crawler "
                             "statico non vede. Opt-in: richiede 'pip install playwright && "
                             "playwright install chromium'. Default off (nessun browser lanciato).")
    parser.add_argument("--max-render-pages", type=int, default=10,
                        help="Max pagine renderizzate per host con --render playwright (default 10, "
                             "costoso: un browser headless per pagina)")
    parser.add_argument("--whatweb-args", default="", help="Flag grezze appese a whatweb")
    parser.add_argument("--ffuf-args", default="", help="Flag grezze appese a ffuf")
    parser.add_argument("--gobuster-args", default="", help="Flag grezze appese a gobuster")
    parser.add_argument("--header", action="append", default=[], metavar="'Nome: valore'",
                        help="Header custom (ripetibile), es. --header 'Authorization: Bearer ...'. "
                             "Passato a fetch builtin, ffuf e gobuster (non a whatweb).")
    parser.add_argument("--cookie", default=None,
                        help="Cookie di sessione, es. 'session=abc; csrftoken=xyz'")
    parser.add_argument("--ignore-waf-detection", action="store_true",
                        help="Non riportare automaticamente il profilo a 'stealth' quando viene "
                             "rilevato un WAF/CDN davanti al target. Di default, per non aggravare "
                             "un servizio gia' protetto, la scansione si auto-limita in questi casi.")
    parser.add_argument("--insecure", action="store_true", help="Non verificare i certificati TLS")
    parser.add_argument("--timeout", type=int, default=15,
                        help="Timeout per singola richiesta HTTP: resolve, fetch builtin, "
                             "mining JS (default 15s)")
    parser.add_argument("--tool-timeout", type=int, default=180,
                        help="Timeout per l'intera invocazione di ffuf/whatweb (default 180s). "
                             "Una wordlist grande (es. dirb common.txt, ~4600 parole) puo' "
                             "richiedere piu' di qualche secondo: un valore troppo basso qui "
                             "tronca ffuf a meta' e fa scattare il fallback builtin, molto "
                             "piu' limitato, senza che sia ovvio dal solo output finale.")
    parser.add_argument("--json", action="store_true", help="Stampa il JSON completo su stdout")
    args = parser.parse_args()

    inputs = collect_inputs(args.domain, args.input_list)
    if not inputs:
        common.warn("Nessun input valido. Usa -d e/o -iL.")
        return 2

    try:
        flags_whatweb = common.effective_flags(PROFILES, args.profile, "whatweb", args.whatweb_args)
        flags_ffuf = common.effective_flags(PROFILES, args.profile, "ffuf", args.ffuf_args)
        flags_gobuster = common.effective_flags(PROFILES, args.profile, "gobuster", args.gobuster_args)
    except ValueError as e:
        common.warn(f"Errore nel parsing delle flag passthrough: {e}")
        return 2

    extra_headers: dict[str, str] = {}
    for h in args.header:
        if ":" not in h:
            common.warn(f"--header ignorato (manca ':'): {h!r}")
            continue
        k, v = h.split(":", 1)
        extra_headers[k.strip()] = v.strip()
    if args.cookie:
        extra_headers["Cookie"] = args.cookie

    wordlist_path, wordlist_mem = pick_wordlist(args.wordlist)
    common.log(f"Input: {len(inputs)}  |  Profilo: {args.profile}  |  "
               f"Stack: {args.stack}  |  Routes: {args.routes}  |  "
               f"Wordlist: {wordlist_path or f'builtin ({len(BUILTIN_WORDLIST)} path)'}"
               f"{'  |  Auth: si' if extra_headers else ''}")

    profile = PROFILES[args.profile]
    results = []
    with ThreadPoolExecutor(max_workers=min(5, len(inputs))) as pool:
        futs = {
            pool.submit(enum_one, entry, args, flags_whatweb, flags_ffuf, flags_gobuster,
                        wordlist_path, wordlist_mem, profile, extra_headers): entry
            for entry in inputs
        }
        for fut in as_completed(futs):
            entry = futs[fut]
            try:
                results.append(fut.result())
            except Exception as e:  # noqa: BLE001
                common.warn(f"{entry} eccezione: {e}")

    results.sort(key=lambda r: r["input"])

    domains_all = [label_source(r["input"]) for r in results] or [label_source(i) for i in inputs]
    base = common.resolve_output_base(args.output)
    label = args.label or common.default_label(domains_all)
    outdir = common.make_outdir(base, TOOL_NAME, label)

    totals = {
        "hosts": len(results),
        "hosts_responsive": sum(1 for r in results if r["url"]),
        "hosts_waf": sum(1 for r in results if r.get("waf")),
        "paths": sum(len(r["paths"]) for r in results),
        "js_endpoints": sum(len(r["js"]["endpoints"]) for r in results),
        "js_urls": sum(len(r["js"]["urls"]) for r in results),
        "js_files": sum(len(r["js"]["js_files"]) for r in results),
        "js_sourcemaps": sum(len(r["js"]["sourcemaps"]) for r in results),
        "js_secrets": sum(len(r["js"]["secrets"]) for r in results),
    }
    report = {
        "generated_utc": common.now_iso(),
        "profile": args.profile,
        "stack_engine": args.stack,
        "routes_engine": args.routes,
        "recursion_depth": args.recursion_depth,
        "wordlist": wordlist_path or "builtin",
        "inputs": inputs,
        "totals": totals,
        "results": results,
    }
    (outdir / "web_enum.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    text = render_text(results)
    (outdir / "web_enum.txt").write_text(text, encoding="utf-8")

    common.log(f"Host che rispondono: {totals['hosts_responsive']}/{totals['hosts']}  |  "
               f"Path trovati: {totals['paths']}  |  File JS: {totals['js_files']}  |  Endpoint da JS: {totals['js_endpoints']}  |  "
               f"URL da JS: {totals['js_urls']}  |  Possibili secret: {totals['js_secrets']}")
    common.log(f"Salvato: {outdir / 'web_enum.json'}")
    common.log(f"Salvato: {outdir / 'web_enum.txt'}")

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(text)

    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Web surface enumeration: dati uno o piu' domini/host, per ognuno rileva:
  1. stack tecnologico     (whatweb, o fallback puro Python su header/body)
  2. route/path nascosti    (ffuf | gobuster | fallback puro Python, con
                             ricorsione opzionale sulle directory trovate)
  3. endpoint API nel JS    (crawling leggero dei <script src> + estrazione
                             dai bundle di: path-like, URL assolute, argomenti
                             di chiamate fetch/axios/XHR e possibili secret
                             trapelati — spesso le route reali di una SPA non
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


def _fetch(url: str, timeout: int, insecure: bool, max_bytes: int = 300_000,
           follow: bool = True) -> dict | None:
    handlers: list = []
    if url.startswith("https://") and insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    if not follow:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={"User-Agent": "recon-web-enum/1.0"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(max_bytes)
            return {"status": resp.status, "headers": dict(resp.headers), "body": body}
    except urllib.error.HTTPError as e:
        body = e.read(max_bytes) if e.fp else b""
        return {"status": e.code, "headers": dict(e.headers or {}), "body": body}
    except Exception:  # noqa: BLE001
        return None


def resolve_base_url(entry: str, timeout: int, insecure: bool) -> str | None:
    """Se entry e' gia' un URL, lo usa cosi' com'e'. Se e' un host semplice,
    prova https:// poi http:// (stesso approccio del probe builtin di
    live_hosts.py) e ritorna il primo schema che risponde."""
    if "://" in entry:
        return entry.rstrip("/")
    for scheme in ("https://", "http://"):
        url = f"{scheme}{entry}"
        if _fetch(url, timeout, insecure) is not None:
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


def detect_tech_builtin(url: str, timeout: int, insecure: bool) -> list[str]:
    resp = _fetch(url, timeout, insecure)
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


def discover_paths_ffuf(url: str, wordlist_path: str, flags: list[str], timeout: int,
                        depth: int) -> tuple[list[dict], bool]:
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
                            depth: int, insecure: bool) -> list[dict]:
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
                           insecure: bool, depth: int) -> list[dict]:
    def level(prefix: str) -> list[dict]:
        base = f"{url}/{prefix}".rstrip("/")
        res: list[dict] = []

        def probe(word: str) -> dict | None:
            resp = _fetch(f"{base}/{word}", timeout, insecure, follow=False)
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


def mine_js(url: str, timeout: int, insecure: bool,
            max_js_files: int = 15, max_js_bytes: int = 500_000) -> dict:
    """Ritorna {endpoints, urls, secrets}. Analizza solo i file JS same-origin
    referenziati dalla pagina (non l'HTML inline, ne' host esterni): tiene il
    rumore basso e rispetta il limite gia' documentato."""
    out: dict = {"endpoints": [], "urls": [], "secrets": []}
    main = _fetch(url, timeout, insecure, max_bytes=300_000)
    if not main:
        return out

    base_netloc = urllib.parse.urlparse(url).netloc
    js_urls: list[str] = []
    for m in SCRIPT_SRC_RE.finditer(main["body"]):
        src = m.group(1).decode("utf-8", "replace")
        full = urllib.parse.urljoin(url + "/", src)
        if urllib.parse.urlparse(full).netloc == base_netloc:
            js_urls.append(full)

    # path -> provenienza: "call" (da fetch/axios/..., piu' affidabile) ha
    # priorita' su "path" (stringa path-like trovata nel bundle).
    endpoint_via: dict[str, str] = {}
    urls: set[str] = set()
    secrets: list[dict] = []
    seen_secret: set[tuple[str, str]] = set()

    def mark(path: str, via: str) -> None:
        if endpoint_via.get(path) != "call":
            endpoint_via[path] = via

    for js_url in js_urls[:max_js_files]:
        resp = _fetch(js_url, timeout, insecure, max_bytes=max_js_bytes)
        if not resp:
            continue
        body = resp["body"]
        for m in JS_PATH_RE.finditer(body):
            p = m.group(1).decode("utf-8", "replace")
            if not STATIC_EXT_RE.search(p):
                mark(p, "path")
        for m in JS_CALL_RE.finditer(body):
            arg = m.group(1).decode("utf-8", "replace")
            if arg.startswith(("http://", "https://")):
                urls.add(arg)
            elif arg.startswith("/") and not STATIC_EXT_RE.search(arg):
                mark(arg, "call")
        for m in JS_ABS_URL_RE.finditer(body):
            u = m.group(0).decode("utf-8", "replace")
            if not STATIC_EXT_RE.search(u):
                urls.add(u)
        text = body.decode("utf-8", "replace")
        for name, rx in SECRET_PATTERNS:
            for sm in rx.finditer(text):
                val = sm.group(0)
                key = (name, val)
                if key in seen_secret:
                    continue
                seen_secret.add(key)
                secrets.append({"type": name, "match": _mask(val), "source": js_url})

    out["endpoints"] = [{"endpoint": e, "via": endpoint_via[e]} for e in sorted(endpoint_via)][:300]
    out["urls"] = sorted(urls)[:150]
    out["secrets"] = secrets[:50]
    return out


PROFILES: dict[str, dict] = {
    "stealth": {"whatweb": ["-a", "1"], "ffuf": ["-t", "5", "-p", "0.3"],
                "gobuster": ["-t", "5", "--delay", "300ms"],
                "builtin_concurrency": 5, "js_concurrency": 3},
    "normal": {"whatweb": ["-a", "3"], "ffuf": ["-t", "40"],
               "gobuster": ["-t", "40"],
               "builtin_concurrency": 20, "js_concurrency": 8},
    "aggressive": {"whatweb": ["-a", "4"], "ffuf": ["-t", "100"],
                   "gobuster": ["-t", "100"],
                   "builtin_concurrency": 50, "js_concurrency": 15},
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


EMPTY_JS = {"endpoints": [], "urls": [], "secrets": []}


def enum_one(entry: str, args, flags_whatweb: list[str], flags_ffuf: list[str],
             flags_gobuster: list[str], wordlist_path: str | None,
             wordlist_mem: list[str], profile: dict) -> dict:
    url = resolve_base_url(entry, args.timeout, args.insecure)
    if not url:
        common.warn(f"nessuna risposta da {entry}, salto.")
        return {"input": entry, "url": None, "tech": [], "paths": [], "js": dict(EMPTY_JS)}

    common.log(f"{url}: stack...")
    tech = (detect_tech_whatweb(url, flags_whatweb, args.tool_timeout) if args.stack != "builtin" else [])
    if not tech:
        tech = detect_tech_builtin(url, args.timeout, args.insecure)

    common.log(f"{url}: route discovery ({args.routes}"
               f"{', ricorsione ' + str(args.recursion_depth) if args.recursion_depth else ''})...")
    paths: list[dict] = []
    if args.routes == "ffuf" and wordlist_path:
        paths, ffuf_timed_out = discover_paths_ffuf(
            url, wordlist_path, flags_ffuf, args.tool_timeout, args.recursion_depth)
        if ffuf_timed_out:
            common.warn(f"{url}: ffuf non ha finito in {args.tool_timeout}s con la wordlist "
                        f"completa ({wordlist_path}) — risultati parziali o nulli, NON e' una "
                        f"scansione completa. Alza --tool-timeout o usa una wordlist piu' corta.")
    elif args.routes == "gobuster" and wordlist_path:
        paths = discover_paths_gobuster(
            url, wordlist_path, flags_gobuster, args.tool_timeout, args.recursion_depth, args.insecure)
    if not paths:
        words = wordlist_mem or BUILTIN_WORDLIST
        paths = discover_paths_builtin(
            url, words, profile["builtin_concurrency"], args.timeout, args.insecure, args.recursion_depth)

    js = dict(EMPTY_JS)
    if not args.skip_js:
        common.log(f"{url}: mining endpoint/secret da JS...")
        js = mine_js(url, args.timeout, args.insecure)

    return {"input": entry, "url": url, "tech": tech, "paths": paths, "js": js}


def render_text(results: list[dict]) -> str:
    lines = []
    for r in results:
        if not r["url"]:
            lines.append(f"{r['input']}: nessuna risposta\n")
            continue
        js = r["js"]
        lines.append(f"## {r['url']}")
        lines.append(f"  stack: {', '.join(r['tech']) or '(nessuno rilevato)'}")
        if r["paths"]:
            lines.append(f"  path trovati ({len(r['paths'])}):")
            for p in r["paths"]:
                line = f"    {p['status']}\t/{p['path']}\t({p['length']} byte)"
                if p.get("redirect"):
                    line += f"  ->  {p['redirect']}"
                lines.append(line)
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
    parser.add_argument("--whatweb-args", default="", help="Flag grezze appese a whatweb")
    parser.add_argument("--ffuf-args", default="", help="Flag grezze appese a ffuf")
    parser.add_argument("--gobuster-args", default="", help="Flag grezze appese a gobuster")
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

    wordlist_path, wordlist_mem = pick_wordlist(args.wordlist)
    common.log(f"Input: {len(inputs)}  |  Profilo: {args.profile}  |  "
               f"Stack: {args.stack}  |  Routes: {args.routes}  |  "
               f"Wordlist: {wordlist_path or f'builtin ({len(BUILTIN_WORDLIST)} path)'}")

    profile = PROFILES[args.profile]
    results = []
    with ThreadPoolExecutor(max_workers=min(5, len(inputs))) as pool:
        futs = {
            pool.submit(enum_one, entry, args, flags_whatweb, flags_ffuf, flags_gobuster,
                        wordlist_path, wordlist_mem, profile): entry
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
        "paths": sum(len(r["paths"]) for r in results),
        "js_endpoints": sum(len(r["js"]["endpoints"]) for r in results),
        "js_urls": sum(len(r["js"]["urls"]) for r in results),
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
               f"Path trovati: {totals['paths']}  |  Endpoint da JS: {totals['js_endpoints']}  |  "
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

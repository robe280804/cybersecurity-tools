#!/usr/bin/env python3
"""
Web surface enumeration: dati uno o piu' domini/host, per ognuno rileva:
  1. stack tecnologico     (whatweb, o fallback puro Python su header/body)
  2. route/path nascosti    (ffuf, o fallback puro Python con wordlist ridotta)
  3. endpoint API nel JS    (crawling leggero dei <script src> + estrazione
                             di stringhe path-like dai bundle — spesso le
                             route reali di una SPA non si indovinano a
                             wordlist, sono scritte nel JS lato client)

Non richiede che l'host sia gia' stato verificato "vivo": se l'input e' un
host semplice (non un URL completo), prova https:// poi http://, come fa
live_hosts.py. Se l'input e' gia' un URL (es. preso da live_hosts.json),
viene usato cosi' com'e'.

Controllo aggressivita':
  --profile stealth|normal|aggressive   preset di concorrenza/timing
  --whatweb-args "..."                  flag grezze appese a whatweb
  --ffuf-args "..."                     flag grezze appese a ffuf

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


def _fetch(url: str, timeout: int, insecure: bool, max_bytes: int = 300_000) -> dict | None:
    ctx = None
    if url.startswith("https://") and insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "recon-web-enum/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
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


def discover_paths_ffuf(url: str, wordlist_path: str, flags: list[str], timeout: int) -> list[dict]:
    if not shutil.which("ffuf"):
        common.warn("ffuf non installato, uso il fallback builtin per il content discovery.")
        return []
    cmd = ["ffuf", "-u", f"{url}/FUZZ", "-w", wordlist_path, "-of", "json", "-o", "-",
           "-s"] + flags
    rc, out, err = common.run_cmd(cmd, timeout)
    results: list[dict] = []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return results
    for r in data.get("results", []):
        results.append({
            "path": r.get("input", {}).get("FUZZ", ""),
            "status": r.get("status"),
            "length": r.get("length"),
        })
    return results


def discover_paths_builtin(url: str, words: list[str], concurrency: int, timeout: int, insecure: bool) -> list[dict]:
    results: list[dict] = []

    def probe(word: str) -> dict | None:
        resp = _fetch(f"{url}/{word}", timeout, insecure)
        if resp and resp["status"] != 404:
            return {"path": word, "status": resp["status"], "length": len(resp["body"])}
        return None

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futs = [pool.submit(probe, w) for w in words]
        for fut in as_completed(futs):
            r = fut.result()
            if r:
                results.append(r)
    return sorted(results, key=lambda x: x["path"])


# ---------------------------------------------------------------------------
# 3. Endpoint API dai bundle JS
# ---------------------------------------------------------------------------

SCRIPT_SRC_RE = re.compile(rb'<script[^>]+src=["\']([^"\']+)["\']', re.I)
# Stringhe quotate che sembrano un path di route/API (iniziano con "/", niente
# spazi, lunghezza ragionevole). Filtriamo poi le estensioni di asset statici.
JS_PATH_RE = re.compile(rb'["\'](/[a-zA-Z0-9_\-./?=&%]{2,150})["\']')
STATIC_EXT_RE = re.compile(r"\.(png|jpe?g|gif|svg|css|woff2?|ttf|eot|ico|map)$", re.I)


def mine_js_endpoints(url: str, timeout: int, insecure: bool,
                       max_js_files: int = 15, max_js_bytes: int = 500_000) -> list[str]:
    main = _fetch(url, timeout, insecure, max_bytes=300_000)
    if not main:
        return []
    js_urls = []
    for m in SCRIPT_SRC_RE.finditer(main["body"]):
        src = m.group(1).decode("utf-8", "replace")
        full = urllib.parse.urljoin(url + "/", src)
        if urllib.parse.urlparse(full).netloc == urllib.parse.urlparse(url).netloc:
            js_urls.append(full)
    js_urls = js_urls[:max_js_files]

    endpoints: set[str] = set()
    for js_url in js_urls:
        resp = _fetch(js_url, timeout, insecure, max_bytes=max_js_bytes)
        if not resp:
            continue
        for m in JS_PATH_RE.finditer(resp["body"]):
            path = m.group(1).decode("utf-8", "replace")
            if not STATIC_EXT_RE.search(path):
                endpoints.add(path)
    return sorted(endpoints)[:300]  # cap per non esplodere l'output


PROFILES: dict[str, dict] = {
    "stealth": {"whatweb": ["-a", "1"], "ffuf": ["-t", "5", "-p", "0.3"],
                "builtin_concurrency": 5, "js_concurrency": 3},
    "normal": {"whatweb": ["-a", "3"], "ffuf": ["-t", "40"],
               "builtin_concurrency": 20, "js_concurrency": 8},
    "aggressive": {"whatweb": ["-a", "4"], "ffuf": ["-t", "100"],
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


def enum_one(entry: str, args, flags_whatweb: list[str], flags_ffuf: list[str],
             wordlist_path: str | None, wordlist_mem: list[str], profile: dict) -> dict:
    url = resolve_base_url(entry, args.timeout, args.insecure)
    if not url:
        common.warn(f"nessuna risposta da {entry}, salto.")
        return {"input": entry, "url": None, "tech": [], "paths": [], "js_endpoints": []}

    common.log(f"{url}: stack...")
    tech = (detect_tech_whatweb(url, flags_whatweb, args.timeout) if args.stack != "builtin" else [])
    if not tech:
        tech = detect_tech_builtin(url, args.timeout, args.insecure)

    common.log(f"{url}: route discovery...")
    paths = []
    if args.routes != "builtin" and wordlist_path:
        paths = discover_paths_ffuf(url, wordlist_path, flags_ffuf, args.timeout)
    if not paths:
        words = wordlist_mem or BUILTIN_WORDLIST
        paths = discover_paths_builtin(url, words, profile["builtin_concurrency"], args.timeout, args.insecure)

    js_endpoints = []
    if not args.skip_js:
        common.log(f"{url}: mining endpoint da JS...")
        js_endpoints = mine_js_endpoints(url, args.timeout, args.insecure)

    return {"input": entry, "url": url, "tech": tech, "paths": paths, "js_endpoints": js_endpoints}


def render_text(results: list[dict]) -> str:
    lines = []
    for r in results:
        if not r["url"]:
            lines.append(f"{r['input']}: nessuna risposta\n")
            continue
        lines.append(f"## {r['url']}")
        lines.append(f"  stack: {', '.join(r['tech']) or '(nessuno rilevato)'}")
        if r["paths"]:
            lines.append("  path trovati:")
            for p in r["paths"]:
                lines.append(f"    {p['status']}\t/{p['path']}\t({p['length']} byte)")
        if r["js_endpoints"]:
            lines.append(f"  endpoint da JS ({len(r['js_endpoints'])}):")
            for e in r["js_endpoints"][:50]:
                lines.append(f"    {e}")
            if len(r["js_endpoints"]) > 50:
                lines.append(f"    ... e altri {len(r['js_endpoints']) - 50} (vedi web_enum.json)")
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
    parser.add_argument("--routes", choices=["ffuf", "builtin"], default="ffuf",
                        help="Motore per il content discovery (default ffuf, fallback automatico)")
    parser.add_argument("--wordlist", default=None, help="Wordlist custom per il content discovery")
    parser.add_argument("--skip-js", action="store_true", help="Salta il mining di endpoint dai JS")
    parser.add_argument("--whatweb-args", default="", help="Flag grezze appese a whatweb")
    parser.add_argument("--ffuf-args", default="", help="Flag grezze appese a ffuf")
    parser.add_argument("--insecure", action="store_true", help="Non verificare i certificati TLS")
    parser.add_argument("--timeout", type=int, default=15, help="Timeout per richiesta/esecuzione (default 15s)")
    parser.add_argument("--json", action="store_true", help="Stampa il JSON completo su stdout")
    args = parser.parse_args()

    inputs = collect_inputs(args.domain, args.input_list)
    if not inputs:
        common.warn("Nessun input valido. Usa -d e/o -iL.")
        return 2

    try:
        flags_whatweb = common.effective_flags(PROFILES, args.profile, "whatweb", args.whatweb_args)
        flags_ffuf = common.effective_flags(PROFILES, args.profile, "ffuf", args.ffuf_args)
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
            pool.submit(enum_one, entry, args, flags_whatweb, flags_ffuf,
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

    report = {
        "generated_utc": common.now_iso(),
        "profile": args.profile,
        "stack_engine": args.stack,
        "routes_engine": args.routes,
        "wordlist": wordlist_path or "builtin",
        "inputs": inputs,
        "results": results,
    }
    (outdir / "web_enum.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    text = render_text(results)
    (outdir / "web_enum.txt").write_text(text, encoding="utf-8")

    total_paths = sum(len(r["paths"]) for r in results)
    total_js = sum(len(r["js_endpoints"]) for r in results)
    common.log(f"Path trovati: {total_paths}  |  Endpoint da JS: {total_js}")
    common.log(f"Salvato: {outdir / 'web_enum.json'}")
    common.log(f"Salvato: {outdir / 'web_enum.txt'}")

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(text)

    return 0


if __name__ == "__main__":
    sys.exit(main())

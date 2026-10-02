#!/usr/bin/env python3
"""
Live host discovery (HTTP/HTTPS probing).

Dati sottodomini/host (tipicamente l'output di subdomains_passive.py), trova
quali rispondono su HTTP/HTTPS e con quali metadati (status code, titolo,
server/tech). E' il passo intermedio tra la recon passiva e il port scan:
restringe la lista a cio' che e' effettivamente vivo prima di scansionare.

Probing:
  httpx    (ProjectDiscovery, se installato; status-code, titolo, tech-detect)
  builtin  (fallback puro Python via urllib; prova https:// poi http://)

Controllo aggressivita':
  --profile stealth|normal|aggressive   preset di flag/concorrenza
  --httpx-args "..."                    flag grezze appese a httpx

Input host:
  -d example.com -d sub.example.com      (ripetibile)
  -d example.com,sub.example.com         (separati da virgola)
  -iL subdomains.txt                     (un host per riga)

Output in <base>/<label>/<timestamp>/ : live_hosts.txt + live_hosts.json.

Nota: e' gia' un probe HTTP attivo verso il target (richieste reali), quindi
va usato solo su host di tua proprieta' o per cui hai autorizzazione.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import ssl
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import common  # noqa: E402

TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


# ---------------------------------------------------------------------------
# Probing: httpx (ProjectDiscovery)
# ---------------------------------------------------------------------------


def is_projectdiscovery_httpx() -> bool:
    """shutil.which('httpx') puo' trovare anche la CLI del package Python
    'httpx' (basata su click), che non c'entra nulla con il tool Go di
    ProjectDiscovery e usa flag incompatibili. Il tool Go riconosce -version
    (singolo trattino) e stampa un numero di versione; il click-tool invece
    rifiuta il flag e stampa il proprio usage. Distinguiamo su questo."""
    if not shutil.which("httpx"):
        return False
    rc, out, err = common.run_cmd(["httpx", "-version"], timeout=10)
    if "usage: httpx [options] url" in (out + err).lower():
        return False  # e' il click-tool del package Python httpx
    return rc == 0 or "version" in (out + err).lower()


def probe_httpx(hosts: list[str], flags: list[str], timeout: int) -> list[dict]:
    if not is_projectdiscovery_httpx():
        common.warn("httpx di ProjectDiscovery non trovato (potrebbe essere "
                     "installato un 'httpx' diverso, es. il package Python), "
                     "uso il probe builtin.")
        return []
    cmd = ["httpx", "-silent", "-json", "-status-code", "-title",
           "-tech-detect", "-follow-redirects"] + flags
    common.log(f"httpx: {' '.join(cmd)} (host via stdin)")
    rc, out, err = common.run_cmd(cmd, timeout, input_text="\n".join(hosts))
    if err.strip():
        common.warn(f"httpx stderr: {err.strip()[:200]}")
    results: list[dict] = []
    for line in out.splitlines():
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        results.append({
            "host": obj.get("input") or obj.get("host"),
            "url": obj.get("url"),
            "status_code": obj.get("status_code"),
            "title": obj.get("title"),
            "tech": obj.get("tech", []),
            "webserver": obj.get("webserver"),
            "content_length": obj.get("content_length"),
        })
    return results


# ---------------------------------------------------------------------------
# Probing: builtin (fallback puro Python)
# ---------------------------------------------------------------------------


def _fetch(url: str, timeout: int, insecure: bool) -> dict | None:
    ctx = None
    if url.startswith("https://") and insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "recon-livehosts/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(65536)  # basta per il <title>
            title_match = TITLE_RE.search(body)
            title = (
                title_match.group(1).decode("utf-8", "replace").strip()
                if title_match else None
            )
            return {
                "host": None,  # riempito dal chiamante
                "url": url,
                "status_code": resp.status,
                "title": title,
                "tech": [],
                "webserver": resp.headers.get("Server"),
                "content_length": resp.headers.get("Content-Length"),
            }
    except urllib.error.HTTPError as e:
        # Risponde comunque (es. 403/404): host vivo.
        return {
            "host": None, "url": url, "status_code": e.code, "title": None,
            "tech": [], "webserver": e.headers.get("Server") if e.headers else None,
            "content_length": None,
        }
    except Exception:  # noqa: BLE001  (timeout, DNS, TLS, connessione rifiutata...)
        return None


def probe_builtin_host(host: str, timeout: int, insecure: bool) -> dict | None:
    for scheme in ("https://", "http://"):
        result = _fetch(f"{scheme}{host}", timeout, insecure)
        if result:
            result["host"] = host
            return result
    return None


def probe_builtin(hosts: list[str], concurrency: int, timeout: int, insecure: bool) -> list[dict]:
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futs = {pool.submit(probe_builtin_host, h, timeout, insecure): h for h in hosts}
        for fut in as_completed(futs):
            h = futs[fut]
            try:
                r = fut.result()
            except Exception as e:  # noqa: BLE001
                common.warn(f"probe {h}: {e}")
                r = None
            if r:
                results.append(r)
    return results


# Preset di aggressivita': per httpx = flag CLI; per builtin = concorrenza/timeout.
PROFILES: dict[str, dict] = {
    "stealth": {
        "httpx": ["-rate-limit", "10", "-threads", "5"],
        "builtin_concurrency": 5,
    },
    "normal": {
        "httpx": ["-threads", "25"],
        "builtin_concurrency": 20,
    },
    "aggressive": {
        "httpx": ["-rate-limit", "300", "-threads", "100"],
        "builtin_concurrency": 50,
    },
}


# ---------------------------------------------------------------------------
# Input
# ---------------------------------------------------------------------------


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
        low = it.lower().rstrip(".")
        if low in seen:
            continue
        if common.is_ip(low) or common.valid_domain(low):
            seen.add(low)
            out.append(low)
        else:
            common.warn(f"input ignorato (non host valido): {it!r}")
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Live host discovery via probing HTTP/HTTPS.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-d", "--domain", action="append", default=[],
                        help="Host (ripetibile, o separati da virgola)")
    parser.add_argument("-iL", "--input-list", default=None,
                        help="File con un host per riga (es. subdomains.txt)")
    parser.add_argument("-o", "--output", default=None,
                        help="Cartella base output: path relativo risolto dalla "
                             "radice del repo, assoluto usato cosi'. Default <radice>/output")
    parser.add_argument("--label", default=None,
                        help="Nome sotto-cartella output (default: primo input)")
    parser.add_argument("--prober", choices=["httpx", "builtin"], default="httpx",
                        help="Motore di probing (default httpx, fallback automatico a builtin)")
    parser.add_argument("--profile", choices=list(PROFILES), default="normal",
                        help="Livello di aggressivita' (default normal)")
    parser.add_argument("--httpx-args", default="",
                        help="Flag grezze appese a httpx")
    parser.add_argument("--insecure", action="store_true",
                        help="Non verificare i certificati TLS (solo probe builtin)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Timeout per singola richiesta/esecuzione (default 10s; "
                             "per httpx e' il timeout dell'intera invocazione se >60")
    parser.add_argument("--json", action="store_true", help="Stampa il JSON completo su stdout")
    args = parser.parse_args()

    inputs = collect_inputs(args.domain, args.input_list)
    if not inputs:
        common.warn("Nessun input valido. Usa -d e/o -iL.")
        return 2

    profile = PROFILES[args.profile]
    try:
        httpx_flags = common.effective_flags(PROFILES, args.profile, "httpx", args.httpx_args)
    except ValueError as e:
        common.warn(f"Errore nel parsing di --httpx-args: {e}")
        return 2

    common.log(f"Input: {len(inputs)}  |  Prober: {args.prober}  |  Profilo: {args.profile}")

    prober = args.prober
    if prober == "httpx" and not is_projectdiscovery_httpx():
        prober = "builtin"

    # Timeout per-invocazione (httpx scansiona tutta la lista in un colpo solo).
    invocation_timeout = max(args.timeout * len(inputs), 60)

    if prober == "httpx":
        common.log(f"  flag httpx: {' '.join(httpx_flags)}")
        live = probe_httpx(inputs, httpx_flags, invocation_timeout)
    else:
        common.log(f"  concorrenza builtin: {profile['builtin_concurrency']}")
        live = probe_builtin(inputs, profile["builtin_concurrency"], args.timeout, args.insecure)

    live.sort(key=lambda r: (r.get("host") or "", r.get("url") or ""))

    base = common.resolve_output_base(args.output)
    label = args.label or inputs[0]
    outdir = common.make_outdir(base, label)

    txt_path = outdir / "live_hosts.txt"
    txt_path.write_text(
        "\n".join(r["url"] for r in live if r.get("url")) + ("\n" if live else ""),
        encoding="utf-8",
    )

    json_path = outdir / "live_hosts.json"
    result = {
        "generated_utc": common.now_iso(),
        "prober": prober,
        "profile": args.profile,
        "effective_flags": {"httpx": httpx_flags} if prober == "httpx" else {},
        "inputs": inputs,
        "total_inputs": len(inputs),
        "total_live": len(live),
        "live_hosts": live,
    }
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    common.log(f"Host vivi: {len(live)}/{len(inputs)}")
    common.log(f"Salvato: {txt_path}")
    common.log(f"Salvato: {json_path}")

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for r in live:
            title = f" | {r['title']}" if r.get("title") else ""
            print(f"{r.get('url')}\t{r.get('status_code')}{title}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

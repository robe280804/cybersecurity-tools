#!/usr/bin/env python3
"""
Passive subdomain enumeration.

Orchestra piu' sorgenti passive (nessun pacchetto diretto verso il target
oltre alle normali query a servizi OSINT pubblici), deduplica e salva.

Sorgenti:
  - crt.sh           (pura Python, sempre disponibile)
  - subfinder        (se installato su Kali)
  - assetfinder      (se installato su Kali)
  - amass (passive)  (se installato su Kali)

Controllo aggressivita':
  --profile stealth|normal|aggressive   preset di flag per ogni tool
  --subfinder-args "..."                flag grezze appese a subfinder
  --amass-args "..."                    flag grezze appese ad amass
  --assetfinder-args "..."              flag grezze appese ad assetfinder
Le flag di --profile e quelle grezze si sommano (le grezze vincono, essendo
appese dopo). Es: --profile aggressive --subfinder-args "-rate-limit 20"

Esempi:
  python3 subdomains_passive.py -d example.com
  python3 subdomains_passive.py -d example.com --profile aggressive
  python3 subdomains_passive.py -d example.com --profile stealth --only crtsh,subfinder
  python3 subdomains_passive.py -d example.com --subfinder-args "-all -recursive" --json

Uso consentito solo su domini di tua proprieta' o per cui hai autorizzazione.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import common  # noqa: E402

# ---------------------------------------------------------------------------
# Sorgenti
# ---------------------------------------------------------------------------


def normalize(host: str, root: str) -> str | None:
    """Pulisce un host e lo tiene solo se appartiene al dominio radice."""
    host = host.strip().lower().rstrip(".")
    host = host.lstrip("*.")  # wildcard dai certificati
    if not host or "@" in host or " " in host:
        return None
    if host == root or host.endswith("." + root):
        return host if common.valid_domain(host) else None
    return None


def source_crtsh(domain: str, timeout: int, extra: list[str]) -> set[str]:
    """Certificate transparency via crt.sh (nessun tool richiesto; ignora extra)."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "recon-passive/1.0"})
    found: set[str] = set()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as e:  # noqa: BLE001
        common.warn(f"crt.sh errore: {e}")
        return found
    for entry in data:
        for field in ("name_value", "common_name"):
            val = entry.get(field, "")
            for line in str(val).splitlines():
                h = normalize(line, domain)
                if h:
                    found.add(h)
    return found


def source_subfinder(domain: str, timeout: int, extra: list[str]) -> set[str]:
    if not shutil.which("subfinder"):
        common.warn("subfinder non installato, salto.")
        return set()
    cmd = ["subfinder", "-silent", "-d", domain] + extra
    lines = common.run_cmd_lines(cmd, timeout)
    return {h for line in lines if (h := normalize(line, domain))}


def source_assetfinder(domain: str, timeout: int, extra: list[str]) -> set[str]:
    if not shutil.which("assetfinder"):
        common.warn("assetfinder non installato, salto.")
        return set()
    # assetfinder vuole il dominio come ultimo argomento posizionale.
    cmd = ["assetfinder", "--subs-only"] + extra + [domain]
    lines = common.run_cmd_lines(cmd, timeout)
    return {h for line in lines if (h := normalize(line, domain))}


def source_amass(domain: str, timeout: int, extra: list[str]) -> set[str]:
    if not shutil.which("amass"):
        common.warn("amass non installato, salto.")
        return set()
    cmd = ["amass", "enum", "-passive", "-d", domain] + extra
    lines = common.run_cmd_lines(cmd, timeout)
    return {h for line in lines if (h := normalize(line, domain))}


# Identifica questo script nella struttura di output: output/<TOOL_NAME>/<label>/<timestamp>/
TOOL_NAME = "subdomain-enum"

SOURCES = {
    "crtsh": source_crtsh,
    "subfinder": source_subfinder,
    "assetfinder": source_assetfinder,
    "amass": source_amass,
}

# Preset di flag per livello di aggressivita'. Le flag utente (--<tool>-args)
# vengono appese DOPO queste, quindi possono sovrascriverle.
PROFILES: dict[str, dict[str, list[str]]] = {
    "stealth": {
        "subfinder": ["-rate-limit", "10", "-t", "5"],
        "amass": ["-norecursive"],
        "assetfinder": [],
    },
    "normal": {
        "subfinder": [],
        "amass": ["-norecursive"],
        "assetfinder": [],
    },
    "aggressive": {
        "subfinder": ["-all", "-recursive", "-t", "50"],
        "amass": [],  # niente -norecursive: lascia ricorsione passiva
        "assetfinder": [],
    },
}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Enumerazione passiva di sottodomini.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-d", "--domain", required=True, help="Dominio radice (es. example.com)")
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Cartella base output. Path relativo = risolto dalla radice del "
             "repo; path assoluto = usato cosi' com'e'. Default: <radice>/output",
    )
    parser.add_argument(
        "--only",
        default=None,
        help="Sorgenti da usare, separate da virgola: " + ",".join(SOURCES),
    )
    parser.add_argument("--timeout", type=int, default=120, help="Timeout per sorgente in secondi (default 120)")
    parser.add_argument(
        "--profile",
        choices=list(PROFILES),
        default="normal",
        help="Livello di aggressivita' (default: normal)",
    )
    parser.add_argument("--subfinder-args", default="", help="Flag grezze appese a subfinder (es. \"-all -recursive\")")
    parser.add_argument("--amass-args", default="", help="Flag grezze appese ad amass")
    parser.add_argument("--assetfinder-args", default="", help="Flag grezze appese ad assetfinder")
    parser.add_argument("--json", action="store_true", help="Stampa anche risultato JSON su stdout")
    args = parser.parse_args()

    domain = args.domain.strip().lower().rstrip(".")
    if not common.valid_domain(domain):
        common.warn(f"Dominio non valido: {domain!r}")
        return 2

    # Selezione sorgenti
    if args.only:
        chosen = [s.strip() for s in args.only.split(",") if s.strip()]
        unknown = [s for s in chosen if s not in SOURCES]
        if unknown:
            common.warn(f"Sorgenti sconosciute: {unknown}. Disponibili: {list(SOURCES)}")
            return 2
    else:
        chosen = list(SOURCES)

    # Flag effettive per tool = preset del profilo + passthrough utente.
    # crtsh non ha flag (ignora extra), ma deve comunque comparire nel dict.
    raw_args_by_tool = {
        "subfinder": args.subfinder_args,
        "amass": args.amass_args,
        "assetfinder": args.assetfinder_args,
    }
    try:
        extra_for = {
            name: common.effective_flags(PROFILES, args.profile, name, raw_args_by_tool.get(name, ""))
            for name in chosen
        }
    except ValueError as e:
        common.warn(f"Errore nel parsing delle flag passthrough: {e}")
        return 2

    common.log(f"Target: {domain}  |  Profilo: {args.profile}  |  Sorgenti: {chosen}")
    for name in chosen:
        if extra_for[name]:
            common.log(f"  {name} flag: {' '.join(extra_for[name])}")

    # Output: <base>/<dominio>/<timestamp>/
    base = common.resolve_output_base(args.output)
    outdir = common.make_outdir(base, TOOL_NAME, domain)

    # Esecuzione parallela delle sorgenti
    per_source: dict[str, set[str]] = {}
    all_hosts: set[str] = set()
    with ThreadPoolExecutor(max_workers=len(chosen)) as pool:
        futures = {
            pool.submit(SOURCES[name], domain, args.timeout, extra_for[name]): name
            for name in chosen
        }
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                hosts = fut.result()
            except Exception as e:  # noqa: BLE001
                common.warn(f"{name} eccezione: {e}")
                hosts = set()
            per_source[name] = hosts
            all_hosts |= hosts
            common.log(f"{name}: {len(hosts)} sottodomini")

    sorted_hosts = sorted(all_hosts)

    # Salvataggio
    txt_path = outdir / "subdomains.txt"
    txt_path.write_text("\n".join(sorted_hosts) + ("\n" if sorted_hosts else ""), encoding="utf-8")

    json_path = outdir / "subdomains.json"
    result = {
        "domain": domain,
        "generated_utc": common.now_iso(),
        "profile": args.profile,
        "sources": chosen,
        "effective_flags": {name: extra_for[name] for name in chosen},
        "total": len(sorted_hosts),
        "per_source_counts": {k: len(v) for k, v in per_source.items()},
        "subdomains": sorted_hosts,
    }
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    common.log(f"Totale unici: {len(sorted_hosts)}")
    common.log(f"Salvato: {txt_path}")
    common.log(f"Salvato: {json_path}")

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for h in sorted_hosts:
            print(h)

    return 0


if __name__ == "__main__":
    sys.exit(main())

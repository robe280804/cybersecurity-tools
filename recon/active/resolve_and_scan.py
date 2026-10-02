#!/usr/bin/env python3
"""
Resolve + port scan.

Dati uno o piu' domini:
  1. li risolve in indirizzi IP (A/AAAA)
  2. deduplica gli IP e lancia un port scan sulle porte aperte

Fase 1 - risoluzione:
  builtin  (socket di Python, sempre disponibile)
  dnsx     (ProjectDiscovery, se installato)

Fase 2 - port scan:
  nmap     (default; service/version detection, timing -T0..-T5)
  naabu    (ProjectDiscovery; veloce, solo scoperta porte)
  masscan  (velocissimo su range ampi; richiede root, solo scoperta porte)

Controllo aggressivita':
  --profile stealth|normal|aggressive   preset di flag per lo scanner
  --scanner-args "..."                  flag grezze appese allo scanner scelto

Input domini:
  -d example.com -d sub.example.com      (ripetibile)
  -d example.com,sub.example.com         (separati da virgola)
  -iL subdomains.txt                     (un dominio/host per riga)
  (si puo' combinare -d con -iL; es. l'output di subdomains_passive.py)

Output in <base>/<label>/<timestamp>/ : results.json + output grezzo dello scanner.

Uso consentito SOLO su host di tua proprieta' o per cui hai autorizzazione:
il port scan e' attivita' attiva e genera traffico verso il target.
"""
from __future__ import annotations

import argparse
import json
import shutil
import socket
import sys
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import common  # noqa: E402

# Alias locali per brevita' nel resto del file.
log = common.log
warn = common.warn
valid_domain = common.valid_domain
is_ip = common.is_ip
run_cmd = common.run_cmd


# ---------------------------------------------------------------------------
# Fase 1 - risoluzione dominio -> IP
# ---------------------------------------------------------------------------


def resolve_builtin(host: str, want_ipv6: bool) -> set[str]:
    ips: set[str] = set()
    families = [socket.AF_INET] + ([socket.AF_INET6] if want_ipv6 else [])
    for fam in families:
        try:
            for info in socket.getaddrinfo(host, None, fam):
                ips.add(info[4][0])
        except socket.gaierror:
            pass
        except Exception as e:  # noqa: BLE001
            warn(f"risoluzione {host}: {e}")
    return ips


def resolve_dnsx_stdin(hosts: list[str], want_ipv6: bool, timeout: int) -> dict[str, set[str]]:
    if not shutil.which("dnsx"):
        warn("dnsx non installato, uso il resolver builtin.")
        return {}
    cmd = ["dnsx", "-silent", "-json", "-a"]
    if want_ipv6:
        cmd.append("-aaaa")
    rc, out, err = run_cmd(cmd, timeout, input_text="\n".join(hosts))
    mapping: dict[str, set[str]] = {}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = obj.get("host", "")
        a = obj.get("a", []) or []
        aaaa = obj.get("aaaa", []) or []
        if host:
            mapping.setdefault(host, set()).update(a)
            if want_ipv6:
                mapping[host].update(aaaa)
    return mapping


def resolve_all(hosts: list[str], resolver: str, want_ipv6: bool, timeout: int) -> dict[str, set[str]]:
    mapping: dict[str, set[str]] = {}
    # Host gia' in forma di IP: passano cosi' come sono.
    plain_ips = [h for h in hosts if is_ip(h)]
    names = [h for h in hosts if not is_ip(h)]
    for ip in plain_ips:
        mapping.setdefault(ip, set()).add(ip)

    if resolver == "dnsx":
        mapping.update({k: v for k, v in resolve_dnsx_stdin(names, want_ipv6, timeout).items()})
        # host non risolti da dnsx -> fallback builtin
        unresolved = [h for h in names if h not in mapping or not mapping[h]]
        names = unresolved

    # builtin (default, o fallback)
    with ThreadPoolExecutor(max_workers=min(20, max(1, len(names)))) as pool:
        futs = {pool.submit(resolve_builtin, h, want_ipv6): h for h in names}
        for fut in as_completed(futs):
            h = futs[fut]
            try:
                mapping.setdefault(h, set()).update(fut.result())
            except Exception as e:  # noqa: BLE001
                warn(f"risoluzione {h}: {e}")
    return mapping


# ---------------------------------------------------------------------------
# Fase 2 - port scan
# ---------------------------------------------------------------------------


def scan_nmap(ips: list[str], flags: list[str], outdir: Path, timeout: int) -> dict[str, list[dict]]:
    if not shutil.which("nmap"):
        warn("nmap non installato, salto lo scan.")
        return {}
    xml_path = outdir / "nmap.xml"
    txt_path = outdir / "nmap.txt"
    cmd = ["nmap"] + flags + ["-oX", str(xml_path), "-oN", str(txt_path)] + ips
    log(f"nmap: {' '.join(cmd)}")
    rc, out, err = run_cmd(cmd, timeout)
    if err.strip():
        warn(f"nmap stderr: {err.strip()[:200]}")
    if not xml_path.exists():
        return {}
    return parse_nmap_xml(xml_path)


def parse_nmap_xml(xml_path: Path) -> dict[str, dict]:
    """Ritorna {ip: {"ports": [...], "ptr": str|None}}.

    Il PTR (reverse DNS, es. 'clients.your-server.de' = Hetzner,
    'bc.googleusercontent.com' = GCP) e' spesso un buon indizio sul
    provider di hosting, quindi lo conserviamo invece di scartarlo."""
    results: dict[str, dict] = {}
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as e:
        warn(f"parsing nmap XML: {e}")
        return results
    for host in tree.getroot().findall("host"):
        addr = None
        for a in host.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr")
                break
        if not addr:
            continue
        ptr = None
        hn = host.find("./hostnames/hostname[@type='PTR']")
        if hn is not None:
            ptr = hn.get("name")
        ports: list[dict] = []
        for p in host.findall("./ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = p.find("service")
            ports.append({
                "port": int(p.get("portid")),
                "proto": p.get("protocol"),
                "state": "open",
                "service": (svc.get("name") if svc is not None else None),
                "product": (svc.get("product") if svc is not None else None),
                "version": (svc.get("version") if svc is not None else None),
            })
        results[addr] = {"ports": sorted(ports, key=lambda x: x["port"]), "ptr": ptr}
    return results


def scan_naabu(ips: list[str], flags: list[str], outdir: Path, timeout: int) -> dict[str, dict]:
    if not shutil.which("naabu"):
        warn("naabu non installato, salto lo scan.")
        return {}
    cmd = ["naabu", "-silent", "-json"] + flags
    log(f"naabu: {' '.join(cmd)} (host via stdin)")
    rc, out, err = run_cmd(cmd, timeout, input_text="\n".join(ips))
    (outdir / "naabu.jsonl").write_text(out, encoding="utf-8")
    ports_by_ip: dict[str, list[dict]] = {}
    for line in out.splitlines():
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        ip = obj.get("ip") or obj.get("host")
        port = obj.get("port")
        if ip and port:
            ports_by_ip.setdefault(ip, []).append(
                {"port": int(port), "proto": "tcp", "state": "open",
                 "service": None, "product": None, "version": None}
            )
    results: dict[str, dict] = {}
    for ip, ports in ports_by_ip.items():
        ports.sort(key=lambda x: x["port"])
        results[ip] = {"ports": ports, "ptr": None}  # naabu non fornisce il PTR
    return results


def scan_masscan(ips: list[str], flags: list[str], outdir: Path, timeout: int) -> dict[str, dict]:
    if not shutil.which("masscan"):
        warn("masscan non installato, salto lo scan.")
        return {}
    json_path = outdir / "masscan.json"
    cmd = ["masscan"] + flags + ["-oJ", str(json_path)] + ips
    log(f"masscan: {' '.join(cmd)}")
    rc, out, err = run_cmd(cmd, timeout)
    if err.strip():
        warn(f"masscan stderr: {err.strip()[:200]}")
    ports_by_ip: dict[str, list[dict]] = {}
    if not json_path.exists():
        return {}
    try:
        data = json.loads(json_path.read_text(encoding="utf-8") or "[]")
    except json.JSONDecodeError:
        # masscan a volte lascia una virgola finale: proviamo a sanare
        raw = json_path.read_text(encoding="utf-8").strip().rstrip(",")
        try:
            data = json.loads("[" + raw + "]") if not raw.startswith("[") else json.loads(raw)
        except json.JSONDecodeError as e:
            warn(f"parsing masscan JSON: {e}")
            return {}
    for entry in data:
        ip = entry.get("ip")
        for pr in entry.get("ports", []):
            if ip and pr.get("port"):
                ports_by_ip.setdefault(ip, []).append(
                    {"port": int(pr["port"]), "proto": pr.get("proto", "tcp"),
                     "state": pr.get("status", "open"),
                     "service": None, "product": None, "version": None}
                )
    results: dict[str, dict] = {}
    for ip, ports in ports_by_ip.items():
        ports.sort(key=lambda x: x["port"])
        results[ip] = {"ports": ports, "ptr": None}  # masscan non fornisce il PTR
    return results


SCANNERS = {"nmap": scan_nmap, "naabu": scan_naabu, "masscan": scan_masscan}

# Preset di flag per scanner e profilo.
# -Pn su nmap: disabilita l'host discovery (il ping preliminare) e tratta ogni
# IP come "up". Senza questo flag, un host che blocca ICMP (comunissimo per
# server web dietro firewall) risulta "0 hosts up" e nmap SALTA del tutto il
# port scan su quell'IP, anche se ha porte aperte e raggiungibili via TCP.
PROFILES: dict[str, dict[str, list[str]]] = {
    "stealth": {
        "nmap": ["-Pn", "-T2", "--top-ports", "100"],
        "naabu": ["-rate", "100", "-top-ports", "100"],
        "masscan": ["--rate", "100", "-p", "1-1000"],
    },
    "normal": {
        "nmap": ["-Pn", "-T3", "--top-ports", "1000"],
        "naabu": ["-top-ports", "1000"],
        "masscan": ["--rate", "1000", "-p", "1-1000"],
    },
    "aggressive": {
        "nmap": ["-Pn", "-T4", "--top-ports", "1000", "-sV"],
        "naabu": ["-rate", "1000", "-top-ports", "1000"],
        "masscan": ["--rate", "5000", "-p", "1-65535"],
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
            warn(f"file input non trovato: {input_list}")
        else:
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    items.append(line)
    # dedup mantenendo l'ordine
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        low = it.lower().rstrip(".")
        if low in seen:
            continue
        if is_ip(low) or valid_domain(low):
            seen.add(low)
            out.append(low)
        else:
            warn(f"input ignorato (non dominio/IP valido): {it!r}")
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Risoluzione domini -> IP e port scan delle porte aperte.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-d", "--domain", action="append", default=[],
                        help="Dominio o IP (ripetibile, o separati da virgola)")
    parser.add_argument("-iL", "--input-list", default=None,
                        help="File con un dominio/host per riga (es. subdomains.txt)")
    parser.add_argument("-o", "--output", default=None,
                        help="Cartella base output: path relativo risolto dalla "
                             "radice del repo, assoluto usato cosi'. Default <radice>/output")
    parser.add_argument("--label", default=None,
                        help="Nome sotto-cartella output (default: primo input)")
    parser.add_argument("--resolver", choices=["builtin", "dnsx"], default="builtin",
                        help="Resolver DNS (default builtin)")
    parser.add_argument("--scanner", choices=list(SCANNERS), default="nmap",
                        help="Port scanner (default nmap)")
    parser.add_argument("--profile", choices=list(PROFILES), default="normal",
                        help="Livello di aggressivita' (default normal)")
    parser.add_argument("--scanner-args", default="",
                        help="Flag grezze appese allo scanner scelto")
    parser.add_argument("--ipv6", action="store_true", help="Includi anche indirizzi IPv6")
    parser.add_argument("--timeout", type=int, default=600,
                        help="Timeout per lo scan in secondi (default 600)")
    parser.add_argument("--json", action="store_true", help="Stampa il JSON completo su stdout")
    args = parser.parse_args()

    inputs = collect_inputs(args.domain, args.input_list)
    if not inputs:
        warn("Nessun input valido. Usa -d e/o -iL.")
        return 2

    # Flag effettive = preset profilo + passthrough utente.
    try:
        flags = common.effective_flags(PROFILES, args.profile, args.scanner, args.scanner_args)
    except ValueError as e:
        warn(f"Errore nel parsing di --scanner-args: {e}")
        return 2

    log(f"Input: {len(inputs)}  |  Resolver: {args.resolver}  |  "
        f"Scanner: {args.scanner}  |  Profilo: {args.profile}")
    if flags:
        log(f"  flag {args.scanner}: {' '.join(flags)}")

    # --- Fase 1: risoluzione ---
    resolution = resolve_all(inputs, args.resolver, args.ipv6, args.timeout)
    ip_to_hosts: dict[str, set[str]] = {}
    for host, ips in resolution.items():
        for ip in ips:
            ip_to_hosts.setdefault(ip, set()).add(host)
    unique_ips = sorted(ip_to_hosts)

    # Input che non hanno prodotto nemmeno un IP (NXDOMAIN, nessun record
    # A/AAAA, timeout DNS...). Senza questo controllo sparivano in silenzio
    # dal risultato finale, senza nessun avviso.
    unresolved = sorted(h for h in inputs if not resolution.get(h))
    if unresolved:
        warn(f"Non risolti ({len(unresolved)}/{len(inputs)}): {', '.join(unresolved)}")

    log(f"IP unici risolti: {len(unique_ips)}")
    if not unique_ips:
        warn("Nessun IP risolto, niente da scansionare.")
        return 1

    # --- Output dir ---
    base = common.resolve_output_base(args.output)
    label = args.label or common.default_label(inputs)
    outdir = common.make_outdir(base, label)

    # --- Fase 2: scan ---
    port_results = SCANNERS[args.scanner](unique_ips, flags, outdir, args.timeout)

    # --- Assemble ---
    hosts_out = []
    for ip in unique_ips:
        entry = port_results.get(ip, {})
        hosts_out.append({
            "ip": ip,
            "ptr": entry.get("ptr"),
            "domains": sorted(ip_to_hosts.get(ip, set())),
            "ports": entry.get("ports", []),
        })
    total_open = sum(len(h["ports"]) for h in hosts_out)

    result = {
        "generated_utc": common.now_iso(),
        "resolver": args.resolver,
        "scanner": args.scanner,
        "profile": args.profile,
        "effective_flags": {args.scanner: flags},
        "inputs": inputs,
        "resolution": {h: sorted(ips) for h, ips in resolution.items()},
        "unresolved": unresolved,
        "unique_ips": unique_ips,
        "total_open_ports": total_open,
        "hosts": hosts_out,
    }
    json_path = outdir / "results.json"
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    log(f"Porte aperte totali: {total_open}")
    log(f"Salvato: {json_path}")

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for h in hosts_out:
            doms = ",".join(h["domains"])
            if h["ports"]:
                plist = ",".join(str(p["port"]) for p in h["ports"])
                print(f"{h['ip']}\t{plist}\t{doms}")
            else:
                print(f"{h['ip']}\t-\t{doms}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

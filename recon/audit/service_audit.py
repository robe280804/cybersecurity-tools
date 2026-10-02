#!/usr/bin/env python3
"""
Audit mirato dei servizi non-web gia' trovati da resolve_and_scan.py
(FTP, MySQL, PostgreSQL, SMTP/IMAP/POP3): usa gli NSE script di nmap per
verificare misconfigurazioni comuni — SOLO check passivi/non distruttivi
(login anonimo, password vuota, open relay, versione vulnerabile nota).
Nessun bruteforce di credenziali, nessun DoS.

Input: --active results.json (da recon/active/resolve_and_scan.py).
Per ogni host, individua le porte con servizi noti e lancia solo gli NSE
script pertinenti a quelle porte (non uno scan a tappeto).

Copertura per servizio:
  ftp                -> ftp-anon, ftp-syst, ftp-bounce
  mysql              -> mysql-info, mysql-empty-password, mysql-enum
  smtp/smtps/submission -> smtp-commands, smtp-open-relay, smtp-vuln-cve2010-4344
  imap/imaps         -> imap-capabilities
  pop3/pop3s         -> pop3-capabilities
  postgresql         -> nessun NSE sicuro integrato in nmap di serie:
                        segnalato come "verifica manuale", non simulato.

Controllo aggressivita':
  --profile stealth|normal|aggressive   preset di timing/version-intensity
  --nmap-args "..."                     flag grezze appese a nmap

Output in <base>/<label>/<timestamp>/: audit.json + audit.txt + nmap.xml per host.

Uso consentito SOLO su host di tua proprieta' o per cui hai autorizzazione:
anche se gli script sono non-distruttivi, restano probe attivi verso servizi
reali (tentativi di login anonimo/vuoto inclusi).
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import common  # noqa: E402

# service (come riportato da nmap -sV) -> lista NSE script da lanciare
SERVICE_SCRIPTS: dict[str, list[str]] = {
    "ftp": ["ftp-anon", "ftp-syst", "ftp-bounce"],
    "mysql": ["mysql-info", "mysql-empty-password", "mysql-enum"],
    "smtp": ["smtp-commands", "smtp-open-relay", "smtp-vuln-cve2010-4344"],
    "smtps": ["smtp-commands", "smtp-open-relay", "smtp-vuln-cve2010-4344"],
    "submission": ["smtp-commands", "smtp-open-relay", "smtp-vuln-cve2010-4344"],
    "imap": ["imap-capabilities"],
    "imaps": ["imap-capabilities"],
    "pop3": ["pop3-capabilities"],
    "pop3s": ["pop3-capabilities"],
}
# Servizi noti ma senza NSE sicuro integrato in nmap: segnaliamo, non fingiamo.
NO_SAFE_NSE = {"postgresql", "postgres"}

# Classificatori per output NSE -> finding degno di nota (non solo
# informativo). Sono euristiche sul testo, non parsing strutturato: nmap non
# espone questi script con un formato machine-readable uniforme. Funzioni
# (non semplici regex "contiene la parola X") per evitare falsi positivi su
# frasi negative tipo "NOT VULNERABLE" o "doesn't seem to be an open relay".


def _is_vulnerable(output: str) -> bool:
    up = output.upper()
    return "VULNERABLE" in up and "NOT VULNERABLE" not in up


def _is_open_relay(output: str) -> bool:
    return bool(output.strip()) and "doesn't seem to be an open relay" not in output.lower()


def _ftp_anon_allowed(output: str) -> bool:
    return "anonymous ftp login allowed" in output.lower()


def _mysql_empty_password(output: str) -> bool:
    return "account has empty password" in output.lower()


FINDING_RULES: list[tuple[str, object, str]] = [
    ("ftp-anon", _ftp_anon_allowed, "HIGH: login FTP anonimo consentito"),
    ("mysql-empty-password", _mysql_empty_password, "HIGH: account MySQL con password vuota"),
    ("smtp-vuln-cve2010-4344", _is_vulnerable, "HIGH: smtp-vuln-cve2010-4344 segnala vulnerabilita'"),
    ("smtp-open-relay", _is_open_relay,
     "MEDIUM: smtp-open-relay ha prodotto output anomalo (verificare manualmente: possibile relay aperto)"),
]

PROFILES: dict[str, dict[str, list[str]]] = {
    "stealth": {"nmap": ["-T2", "--version-intensity", "2"]},
    "normal": {"nmap": ["-T3", "--version-intensity", "5"]},
    "aggressive": {"nmap": ["-T4", "--version-intensity", "9"]},
}


def collect_targets(active: dict) -> dict[str, list[dict]]:
    """ip -> lista di {port, service} per i soli servizi che sappiamo auditare
    (coperti da NSE o segnalati come 'verifica manuale')."""
    targets: dict[str, list[dict]] = {}
    for h in active.get("hosts", []):
        ip = h.get("ip")
        for p in h.get("ports", []):
            svc = (p.get("service") or "").lower()
            if svc in SERVICE_SCRIPTS or svc in NO_SAFE_NSE:
                targets.setdefault(ip, []).append({"port": p["port"], "service": svc})
    return targets


def audit_host(ip: str, ports: list[dict], flags: list[str], outdir: Path, timeout: int) -> dict:
    auditable = [p for p in ports if p["service"] in SERVICE_SCRIPTS]
    manual_only = [p for p in ports if p["service"] in NO_SAFE_NSE]

    result: dict = {"ip": ip, "ports": [], "manual_review": manual_only}

    if not auditable:
        return result
    if not shutil.which("nmap"):
        common.warn("nmap non installato, salto l'audit.")
        return result

    scripts = sorted({s for p in auditable for s in SERVICE_SCRIPTS[p["service"]]})
    port_list = ",".join(str(p["port"]) for p in auditable)
    xml_path = outdir / f"nmap-audit-{ip.replace(':', '_')}.xml"

    cmd = (["nmap", "-Pn", "-sV"] + flags
           + ["--script", ",".join(scripts), "-p", port_list, "-oX", str(xml_path), ip])
    common.log(f"nmap audit {ip}: {' '.join(cmd)}")
    rc, out, err = common.run_cmd(cmd, timeout)
    if err.strip():
        common.warn(f"nmap stderr ({ip}): {err.strip()[:200]}")
    if not xml_path.exists():
        return result

    result["ports"] = parse_audit_xml(xml_path)
    return result


def parse_audit_xml(xml_path: Path) -> list[dict]:
    out: list[dict] = []
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as e:
        common.warn(f"parsing XML audit: {e}")
        return out
    for port_el in tree.getroot().findall(".//ports/port"):
        portid = int(port_el.get("portid"))
        proto = port_el.get("protocol")
        scripts_out = []
        findings = []
        for script in port_el.findall("script"):
            sid = script.get("id")
            output = script.get("output", "")
            scripts_out.append({"script": sid, "output": output})
            for rule_script, classifier, label in FINDING_RULES:
                if sid == rule_script and classifier(output):
                    findings.append(label)
        out.append({"port": portid, "proto": proto, "scripts": scripts_out, "findings": findings})
    return out


def render_text(label: str, audits: list[dict]) -> str:
    lines = [f"Audit servizi — {label}", ""]
    any_finding = False
    for h in audits:
        if not h["ports"] and not h["manual_review"]:
            continue
        lines.append(f"## {h['ip']}")
        for p in h["ports"]:
            lines.append(f"  porta {p['port']}/{p['proto']}:")
            for f in p["findings"]:
                lines.append(f"    [!] {f}")
                any_finding = True
            for s in p["scripts"]:
                if s["output"].strip():
                    indented = "\n".join("      " + l for l in s["output"].splitlines())
                    lines.append(f"    -- {s['script']} --\n{indented}")
        for m in h["manual_review"]:
            lines.append(f"  porta {m['port']} ({m['service']}): nessun NSE sicuro integrato "
                         f"in nmap — verifica manuale consigliata (es. client nativo con utenza "
                         f"di test, mai credenziali reali in uno script automatico).")
        lines.append("")
    if not any_finding:
        lines.append("Nessun finding automatico rilevato dai pattern noti. "
                      "Questo NON significa 'sicuro': leggi comunque l'output raw sopra "
                      "e verifica a mano i servizi in 'manual_review'.")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit mirato (NSE) dei servizi non-web gia' scoperti.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--active", required=True, help="results.json di resolve_and_scan.py")
    parser.add_argument("-o", "--output", default=None,
                        help="Cartella base output: relativo risolto dalla radice del repo, "
                             "assoluto usato cosi'. Default <radice>/output")
    parser.add_argument("--label", default=None, help="Nome sotto-cartella output")
    parser.add_argument("--profile", choices=list(PROFILES), default="normal",
                        help="Livello di aggressivita' (default normal)")
    parser.add_argument("--nmap-args", default="", help="Flag grezze appese a nmap")
    parser.add_argument("--timeout", type=int, default=300,
                        help="Timeout per host in secondi (default 300)")
    parser.add_argument("--json", action="store_true", help="Stampa il JSON completo su stdout")
    args = parser.parse_args()

    active_path = Path(args.active)
    if not active_path.exists():
        common.warn(f"file non trovato: {args.active}")
        return 2
    try:
        active = json.loads(active_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        common.warn(f"JSON non valido in {args.active}: {e}")
        return 2

    try:
        flags = common.effective_flags(PROFILES, args.profile, "nmap", args.nmap_args)
    except ValueError as e:
        common.warn(f"Errore nel parsing di --nmap-args: {e}")
        return 2

    targets = collect_targets(active)
    if not targets:
        common.log("Nessun servizio auditabile (ftp/mysql/postgresql/smtp/imap/pop3) trovato in input.")
        return 0

    common.log(f"Host con servizi da auditare: {len(targets)}  |  Profilo: {args.profile}")

    domains_all = [d for h in active.get("hosts", []) for d in h.get("domains", [])] or list(targets)
    base = common.resolve_output_base(args.output)
    label = args.label or common.default_label(domains_all)
    outdir = common.make_outdir(base, label)

    audits: list[dict] = []
    with ThreadPoolExecutor(max_workers=min(8, len(targets))) as pool:
        futs = {
            pool.submit(audit_host, ip, ports, flags, outdir, args.timeout): ip
            for ip, ports in targets.items()
        }
        for fut in as_completed(futs):
            ip = futs[fut]
            try:
                audits.append(fut.result())
            except Exception as e:  # noqa: BLE001
                common.warn(f"audit {ip} eccezione: {e}")

    audits.sort(key=lambda a: a["ip"] or "")
    total_findings = sum(len(p["findings"]) for h in audits for p in h["ports"])

    report = {
        "generated_utc": common.now_iso(),
        "profile": args.profile,
        "effective_flags": {"nmap": flags},
        "total_hosts_audited": len(audits),
        "total_findings": total_findings,
        "hosts": audits,
    }

    (outdir / "audit.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    text = render_text(label, audits)
    (outdir / "audit.txt").write_text(text, encoding="utf-8")

    common.log(f"Findings automatici: {total_findings}")
    common.log(f"Salvato: {outdir / 'audit.json'}")
    common.log(f"Salvato: {outdir / 'audit.txt'}")

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(text)

    return 0


if __name__ == "__main__":
    sys.exit(main())

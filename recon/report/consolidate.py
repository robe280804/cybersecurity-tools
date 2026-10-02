#!/usr/bin/env python3
"""
Consolida i risultati di una campagna di recon in un'unica vista leggibile:

    IP -> porte/servizi (+ PTR) -> domini che ci puntano -> stato HTTP

Prende in input i JSON prodotti dagli step precedenti:
  --active  results.json      (da recon/active/resolve_and_scan.py, obbligatorio)
  --live    live_hosts.json   (da recon/discovery/live_hosts.py, opzionale)

Il collegamento domini<->HTTP live si fa sul nome host (non sullo scheme),
quindi un dominio con sia http:// che https:// vivi compare con entrambe le
voci. Un dominio senza nessuna voce in live_hosts.json e' segnato "unknown"
(non e' stato controllato), non "dead".

Output in <base>/<label>/<timestamp>/ : report.json + report.md + report.txt

Esempi:
  python3 consolidate.py --active ../active/output/.../results.json
  python3 consolidate.py --active results.json --live ../discovery/output/.../live_hosts.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import common  # noqa: E402


def load_json(path: str, required: bool) -> dict | None:
    p = Path(path)
    if not p.exists():
        if required:
            common.warn(f"file non trovato: {path}")
            sys.exit(2)
        common.warn(f"file opzionale non trovato, salto: {path}")
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        common.warn(f"JSON non valido in {path}: {e}")
        if required:
            sys.exit(2)
        return None


def build_report(active: dict, live: dict | None) -> dict:
    # host (senza scheme) -> lista di voci live (http/https possono coesistere)
    live_by_host: dict[str, list[dict]] = {}
    dead_hosts: set[str] = set()
    if live:
        for entry in live.get("live_hosts", []):
            host = entry.get("host")
            if host:
                live_by_host.setdefault(host, []).append({
                    "url": entry.get("url"),
                    "status_code": entry.get("status_code"),
                    "title": entry.get("title"),
                    "tech": entry.get("tech", []),
                    "webserver": entry.get("webserver"),
                })
        dead_hosts = set(live.get("dead_hosts", []))

    hosts_out = []
    for h in active.get("hosts", []):
        domains_out = []
        for dom in h.get("domains", []):
            live_entries = live_by_host.get(dom)
            if live_entries:
                http_status = live_entries
            elif dom in dead_hosts:
                http_status = "dead"  # controllato, non risponde
            elif live is None:
                http_status = "unknown"  # nessun live_hosts.json fornito
            else:
                http_status = "unknown"  # presente in active ma non in live (liste diverse)
            domains_out.append({"domain": dom, "http": http_status})

        hosts_out.append({
            "ip": h.get("ip"),
            "ptr": h.get("ptr"),
            "ports": h.get("ports", []),
            "domains": domains_out,
        })

    # ordina per IP, poi per numero di porte aperte decrescente (gli host piu'
    # "interessanti" prima)
    hosts_out.sort(key=lambda x: (-len(x["ports"]), x["ip"] or ""))

    total_ports = sum(len(h["ports"]) for h in hosts_out)
    total_domains = sum(len(h["domains"]) for h in hosts_out)

    return {
        "generated_utc": common.now_iso(),
        "source_active": active.get("generated_utc"),
        "source_live": live.get("generated_utc") if live else None,
        "total_ips": len(hosts_out),
        "total_open_ports": total_ports,
        "total_domains_mapped": total_domains,
        "hosts": hosts_out,
    }


def render_markdown(report: dict) -> str:
    lines = ["# Report consolidato — IP -> porte -> domini -> HTTP", ""]
    lines.append(f"Generato: {report['generated_utc']}")
    lines.append(f"IP totali: {report['total_ips']} | "
                  f"Porte aperte totali: {report['total_open_ports']} | "
                  f"Domini mappati: {report['total_domains_mapped']}")
    lines.append("")
    for h in report["hosts"]:
        ptr = f"  _(PTR: {h['ptr']})_" if h.get("ptr") else ""
        lines.append(f"## {h['ip']}{ptr}")
        if h["ports"]:
            lines.append("")
            lines.append("| Porta | Servizio | Prodotto/Versione |")
            lines.append("|---|---|---|")
            for p in h["ports"]:
                prod = " ".join(x for x in [p.get("product"), p.get("version")] if x) or "-"
                lines.append(f"| {p['port']}/{p['proto']} | {p.get('service') or '-'} | {prod} |")
        else:
            lines.append("")
            lines.append("_Nessuna porta aperta rilevata._")
        lines.append("")
        lines.append("| Dominio | HTTP |")
        lines.append("|---|---|")
        for d in h["domains"]:
            http = d["http"]
            if isinstance(http, list):
                cell = "<br>".join(
                    f"{e['url']} → {e['status_code']}" + (f" _{e['title']}_" if e.get("title") else "")
                    for e in http
                )
            else:
                cell = {"dead": "❌ nessuna risposta", "unknown": "❔ non controllato"}.get(http, str(http))
            lines.append(f"| {d['domain']} | {cell} |")
        lines.append("")
    return "\n".join(lines)


def render_text(report: dict) -> str:
    lines = []
    for h in report["hosts"]:
        ptr = f" ({h['ptr']})" if h.get("ptr") else ""
        lines.append(f"{h['ip']}{ptr}")
        for p in h["ports"]:
            svc = p.get("service") or "?"
            prod = " ".join(x for x in [p.get("product"), p.get("version")] if x)
            lines.append(f"  {p['port']}/{p['proto']}\t{svc}" + (f"\t{prod}" if prod else ""))
        for d in h["domains"]:
            http = d["http"]
            if isinstance(http, list):
                for e in http:
                    title = f" | {e['title']}" if e.get("title") else ""
                    lines.append(f"  -> {d['domain']}\t{e['url']}\t{e['status_code']}{title}")
            else:
                tag = {"dead": "DEAD", "unknown": "UNKNOWN"}.get(http, http)
                lines.append(f"  -> {d['domain']}\t{tag}")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Consolida active+discovery in un report IP->porte->domini->HTTP.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--active", required=True, help="results.json di resolve_and_scan.py")
    parser.add_argument("--live", default=None, help="live_hosts.json di live_hosts.py (opzionale)")
    parser.add_argument("-o", "--output", default=None,
                        help="Cartella base output: relativo risolto dalla radice del repo, "
                             "assoluto usato cosi'. Default <radice>/output")
    parser.add_argument("--label", default=None, help="Nome sotto-cartella output")
    parser.add_argument("--json", action="store_true", help="Stampa il JSON completo su stdout")
    args = parser.parse_args()

    active = load_json(args.active, required=True)
    live = load_json(args.live, required=False) if args.live else None

    report = build_report(active, live)

    domains_all = [d["domain"] for h in report["hosts"] for d in h["domains"]] or ["report"]
    base = common.resolve_output_base(args.output)
    label = args.label or common.default_label(domains_all)
    outdir = common.make_outdir(base, label)

    (outdir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (outdir / "report.md").write_text(render_markdown(report), encoding="utf-8")
    (outdir / "report.txt").write_text(render_text(report), encoding="utf-8")

    common.log(f"IP: {report['total_ips']}  |  Porte aperte: {report['total_open_ports']}  |  "
               f"Domini mappati: {report['total_domains_mapped']}")
    common.log(f"Salvato: {outdir / 'report.json'}")
    common.log(f"Salvato: {outdir / 'report.md'}")
    common.log(f"Salvato: {outdir / 'report.txt'}")

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(render_text(report))

    return 0


if __name__ == "__main__":
    sys.exit(main())

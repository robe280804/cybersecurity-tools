#!/usr/bin/env python3
"""
Vulnerability scan con nuclei.

Passo successivo della pipeline dopo `live-host-probe`/`web-enum`: non si limita
a mappare la superficie, ma la *qualifica*, cercando CVE note, misconfigurazioni,
pannelli esposti, security header mancanti e subdomain takeover sugli URL/host
gia' individuati come vivi.

Input URL/host (combinabili):
  -u https://a.example.com            (ripetibile, o separati da virgola)
  -iL live_hosts.txt                  (un URL/host per riga)
  --live live_hosts.json              (output di live-host-probe: usa i campi url)

Controllo aggressivita':
  --profile stealth|normal|aggressive   preset -rate-limit/-c per nuclei
  --nuclei-args "..."                    flag grezze appese a nuclei

Gating severita' (nuclei invia payload reali):
  default           template info,low,medium
  --include-high    aggiunge high,critical (opt-in esplicito)

Output in <base>/vuln-scan/<label>/<timestamp>/:
  findings.json  schema normalizzato (id, severity, target, evidence,
                 technique_id, tool, timestamp) coerente con docker-configuration
  findings.txt   stesso contenuto, leggibile
  nuclei.jsonl   output grezzo di nuclei, per ispezione manuale

Uso consentito SOLO su host di tua proprieta' o per cui hai autorizzazione
scritta: nuclei genera traffico reale e invia payload verso il target.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import common  # noqa: E402

log = common.log
warn = common.warn
valid_domain = common.valid_domain
is_ip = common.is_ip
run_cmd_ext = common.run_cmd_ext

# Identifica questo script nella struttura di output: output/<TOOL_NAME>/<label>/<timestamp>/
TOOL_NAME = "vuln-scan"

# Allineata a docker-configuration: stesso ordine/ranking per un report unico.
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Severita' spedite a nuclei. high/critical inviano i payload piu' invasivi:
# restano fuori dal default e si abilitano con --include-high (vedi roadmap).
DEFAULT_SEVERITIES = ["info", "low", "medium"]
HIGH_SEVERITIES = ["high", "critical"]

# Tecnica ATT&CK di default per un finding di nuclei: scansione di
# vulnerabilita' in fase di ricognizione.
DEFAULT_TECHNIQUE = "T1595.002"
# Alcuni tag qualificano meglio la tecnica difensiva associata.
TAG_TECHNIQUE = {
    "takeover": "T1584",   # subdomain takeover -> difesa su Compromise Infrastructure
}

# Preset per profilo. nuclei accetta -rate-limit (richieste/s globali) e
# -c (concorrenza dei template): piu' bassi = piu' lento ma meno rumoroso e
# meno aggressivo verso target fragili dietro WAF/rate-limit.
PROFILES: dict[str, dict[str, list[str]]] = {
    "stealth":    {"nuclei": ["-rate-limit", "20", "-c", "10", "-timeout", "10"]},
    "normal":     {"nuclei": ["-rate-limit", "150", "-c", "25"]},
    "aggressive": {"nuclei": ["-rate-limit", "500", "-c", "50"]},
}


# ---------------------------------------------------------------------------
# Input
# ---------------------------------------------------------------------------


def _norm_target(raw: str) -> str | None:
    """Normalizza una riga di input in un target accettabile da nuclei.

    Accetta URL completi (restituiti cosi' come sono) e bare host/IP
    (dominio o IP valido). Scarta il resto avvisando."""
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None
    if raw.startswith(("http://", "https://")):
        host = urlparse(raw).hostname or ""
        if host and (is_ip(host) or valid_domain(host)):
            return raw
        warn(f"input ignorato (URL senza host valido): {raw!r}")
        return None
    low = raw.lower().rstrip(".")
    if is_ip(low) or valid_domain(low):
        return low
    warn(f"input ignorato (non URL/dominio/IP valido): {raw!r}")
    return None


def _from_live_json(path: Path) -> list[str]:
    """Estrae gli URL vivi da un live_hosts.json di live-host-probe."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        warn(f"impossibile leggere --live {path}: {e}")
        return []
    urls = []
    for h in data.get("live_hosts", []):
        url = h.get("url")
        if url:
            urls.append(url)
    return urls


def collect_targets(urls: list[str], input_list: str | None, live_json: str | None) -> list[str]:
    items: list[str] = []
    for u in urls:
        items.extend(x for x in u.split(",") if x.strip())
    if input_list:
        p = Path(input_list)
        if not p.exists():
            warn(f"file input non trovato: {input_list}")
        else:
            items.extend(p.read_text(encoding="utf-8").splitlines())
    if live_json:
        p = Path(live_json)
        if not p.exists():
            warn(f"file --live non trovato: {live_json}")
        else:
            items.extend(_from_live_json(p))

    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        t = _norm_target(it)
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


# ---------------------------------------------------------------------------
# nuclei
# ---------------------------------------------------------------------------


def _technique_for(tags: list[str]) -> str:
    for tag in tags:
        if tag in TAG_TECHNIQUE:
            return TAG_TECHNIQUE[tag]
    return DEFAULT_TECHNIQUE


def parse_nuclei_line(line: str) -> dict | None:
    """Converte una riga JSONL di nuclei in un finding dello schema normalizzato.

    Campi nuclei rilevanti: template-id, info.{name,severity,tags,description,
    reference}, info.classification.{cve-id,cwe-id}, host, matched-at,
    matcher-name, extracted-results."""
    line = line.strip()
    if not line:
        return None
    try:
        o = json.loads(line)
    except json.JSONDecodeError:
        return None

    info = o.get("info") or {}
    severity = (info.get("severity") or "info").upper()
    if severity not in SEV_RANK:
        severity = "INFO"
    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]

    classification = info.get("classification") or {}
    cve = classification.get("cve-id") or []
    cwe = classification.get("cwe-id") or []
    if isinstance(cve, str):
        cve = [cve]
    if isinstance(cwe, str):
        cwe = [cwe]

    # "evidence": dove e come il template ha matchato, senza duplicare il raw.
    evidence: dict = {}
    if o.get("matched-at"):
        evidence["matched_at"] = o["matched-at"]
    if o.get("matcher-name"):
        evidence["matcher"] = o["matcher-name"]
    if o.get("extracted-results"):
        evidence["extracted"] = o["extracted-results"]

    target = o.get("host") or o.get("matched-at") or ""

    f = {
        "id": o.get("template-id", ""),
        "severity": severity,
        "target": target,
        "title": info.get("name", ""),
        "technique_id": _technique_for(tags),
        "tool": "nuclei",
        "timestamp": o.get("timestamp") or common.now_iso(),
        "tags": tags,
        "type": o.get("type", ""),
        "evidence": evidence,
    }
    if cve:
        f["cve"] = cve
    if cwe:
        f["cwe"] = cwe
    desc = (info.get("description") or "").strip()
    if desc:
        f["description"] = desc
    ref = info.get("reference") or []
    if isinstance(ref, str):
        ref = [ref]
    if ref:
        f["references"] = ref
    return f


def run_nuclei(targets_file: Path, severities: list[str], flags: list[str],
               outdir: Path, timeout: int) -> tuple[list[dict], bool]:
    """Esegue nuclei e ritorna (findings, truncated).

    truncated=True se nuclei e' andato in timeout: in quel caso il risultato
    e' parziale, non uno zero-findings da interpretare come 'pulito'."""
    raw_path = outdir / "nuclei.jsonl"
    cmd = [
        "nuclei",
        "-list", str(targets_file),
        "-severity", ",".join(severities),
        "-jsonl", "-silent",
        "-jsonl-export", str(raw_path),
        "-disable-update-check",
    ] + flags
    log(f"nuclei: {' '.join(cmd)}")
    rc, out, err, timed_out = run_cmd_ext(cmd, timeout)
    if err.strip():
        warn(f"nuclei stderr: {err.strip()[:300]}")

    # Fonte primaria: il file -jsonl-export (una riga per match). Se mancante
    # (versioni vecchie o errore), ripieghiamo su stdout.
    lines: list[str] = []
    if raw_path.exists():
        lines = raw_path.read_text(encoding="utf-8").splitlines()
    else:
        lines = out.splitlines()
        if lines:
            raw_path.write_text(out, encoding="utf-8")

    findings = [f for ln in lines if (f := parse_nuclei_line(ln))]
    return findings, timed_out


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------


def dedupe(findings: list[dict]) -> list[dict]:
    """Stesso template sullo stesso punto esatto = un solo finding."""
    seen: set[tuple] = set()
    out: list[dict] = []
    for f in findings:
        key = (f["id"], f["target"], f.get("evidence", {}).get("matched_at", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: (SEV_RANK.get(f["severity"], 9),
                                           f["target"], f["id"]))


def render_text(label: str, findings: list[dict], meta: dict) -> str:
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    summary = "  ".join(f"{s}:{counts[s]}" for s in SEVERITIES if counts[s])
    lines = [
        f"# vuln-scan — {label}",
        f"Target: {meta['total_targets']}  |  Profilo: {meta['profile']}  |  "
        f"Severita': {','.join(meta['severities'])}",
        f"Findings: {summary or 'nessuno'}",
        "",
    ]
    if meta.get("truncated"):
        lines += ["⚠️  Scan TRONCATO per timeout: risultato parziale.", ""]
    if not findings:
        lines += ["Nessun finding dalle severita' selezionate. "
                  "NON significa 'sicuro': solo che i template scelti non hanno "
                  "trovato nulla. Valuta --include-high e la lettura di nuclei.jsonl."]
        return "\n".join(lines) + "\n"

    for f in findings:
        head = f"[{f['severity']}] {f['id']}  ->  {f['target']}"
        lines.append(head)
        if f.get("title"):
            lines.append(f"    {f['title']}")
        meta_bits = [f"ATT&CK {f['technique_id']}"]
        if f.get("cve"):
            meta_bits.append(",".join(f["cve"]))
        if f.get("tags"):
            meta_bits.append("tags: " + ",".join(f["tags"][:6]))
        lines.append("    " + "  |  ".join(meta_bits))
        ev = f.get("evidence", {})
        if ev.get("matched_at"):
            lines.append(f"    matched-at: {ev['matched_at']}")
        if ev.get("extracted"):
            lines.append(f"    extracted: {', '.join(map(str, ev['extracted'][:5]))}")
        lines.append("")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Vulnerability scan con nuclei su host/URL vivi.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-u", "--url", action="append", default=[],
                        help="URL o host (ripetibile, o separati da virgola)")
    parser.add_argument("-iL", "--input-list", default=None,
                        help="File con un URL/host per riga (es. live_hosts.txt)")
    parser.add_argument("--live", default=None,
                        help="live_hosts.json di live-host-probe (usa i campi url)")
    parser.add_argument("-o", "--output", default=None,
                        help="Cartella base output: path relativo risolto dalla "
                             "radice del repo, assoluto usato cosi'. Default <radice>/output")
    parser.add_argument("--label", default=None,
                        help="Nome sotto-cartella output (default: suffisso di dominio comune)")
    parser.add_argument("--profile", choices=list(PROFILES), default="normal",
                        help="Livello di aggressivita' (default normal)")
    parser.add_argument("--include-high", action="store_true",
                        help="Includi template high+critical (default: solo info,low,medium)")
    parser.add_argument("--severity", default=None,
                        help="Override esplicito delle severita' nuclei (es. 'medium,high'). "
                             "Ha precedenza su --include-high.")
    parser.add_argument("--nuclei-args", default="",
                        help="Flag grezze appese a nuclei (es. '-tags cve,takeover')")
    parser.add_argument("--timeout", type=int, default=1800,
                        help="Timeout totale dello scan in secondi (default 1800)")
    parser.add_argument("--fail-on", choices=SEVERITIES, default=None,
                        help="Exit code 3 se esiste un finding >= a questa severita'")
    parser.add_argument("--json", action="store_true",
                        help="Stampa il JSON completo su stdout")
    args = parser.parse_args()

    targets = collect_targets(args.url, args.input_list, args.live)
    if not targets:
        warn("Nessun target valido. Usa -u, -iL e/o --live.")
        return 2

    if not shutil.which("nuclei"):
        warn("nuclei non installato nel PATH. Installa con ./install-tools.sh --all "
             "(o: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest).")
        return 1

    # Severita' da inviare a nuclei.
    if args.severity:
        severities = [s.strip().lower() for s in args.severity.split(",") if s.strip()]
    else:
        severities = list(DEFAULT_SEVERITIES)
        if args.include_high:
            severities += HIGH_SEVERITIES

    try:
        flags = common.effective_flags(PROFILES, args.profile, "nuclei", args.nuclei_args)
    except ValueError as e:
        warn(f"Errore nel parsing di --nuclei-args: {e}")
        return 2

    log(f"Target: {len(targets)}  |  Profilo: {args.profile}  |  "
        f"Severita': {','.join(severities)}")
    if flags:
        log(f"  flag nuclei: {' '.join(flags)}")

    base = common.resolve_output_base(args.output)
    label = args.label or common.default_label(
        [urlparse(t).hostname or t if t.startswith(("http://", "https://")) else t
         for t in targets]
    )
    outdir = common.make_outdir(base, TOOL_NAME, label)

    targets_file = outdir / "targets.txt"
    targets_file.write_text("\n".join(targets) + "\n", encoding="utf-8")

    findings, truncated = run_nuclei(targets_file, severities, flags, outdir, args.timeout)
    findings = sort_findings(dedupe(findings))

    meta = {
        "generated_utc": common.now_iso(),
        "tool": "nuclei",
        "profile": args.profile,
        "severities": severities,
        "effective_flags": {"nuclei": flags},
        "total_targets": len(targets),
        "truncated": truncated,
    }
    summary = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    report = {
        **meta,
        "targets": targets,
        "summary": summary,
        "total_findings": len(findings),
        "findings": findings,
    }

    (outdir / "findings.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (outdir / "findings.txt").write_text(render_text(label, findings, meta), encoding="utf-8")

    log(f"Findings: {summary}")
    log(f"Salvato: {outdir / 'findings.json'}")

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(render_text(label, findings, meta), end="")

    # Exit code dedicato per la CI/gating.
    if args.fail_on:
        threshold = SEV_RANK[args.fail_on]
        if any(SEV_RANK[f["severity"]] <= threshold for f in findings):
            warn(f"Trovati finding >= {args.fail_on}: exit 3 (--fail-on).")
            return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())

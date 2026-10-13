#!/usr/bin/env python3
"""
Audit delle misconfigurazioni di sicurezza di uno stack Docker, in due
modalita' combinabili:

  STATICA  (--path)   analizza i file del progetto: Dockerfile e
                      docker-compose. Vede l'INTENZIONE (cosa e' scritto),
                      utile anche prima del deploy / in CI.
  LIVE     (--live)   interroga il daemon Docker (locale, oppure remoto via
                      SSH con --docker-host ssh://user@host) e legge la
                      configurazione EFFETTIVA dei container in esecuzione
                      con `docker inspect`. Vede cosa sta girando davvero,
                      compresi override, `docker run` manuali e drift
                      rispetto ai file del repo.

Le due modalita' passano per lo stesso set di regole: compose e inspect
vengono normalizzati in una "spec" comune (privileged, capability, mount,
porte, env, limiti...), cosi' un finding ha lo stesso significato da
qualunque parte arrivi.

Regole integrate (nessuna dipendenza esterna):
  privileged, docker.sock montato, mount sensibili dell'host, capability
  pericolose, network/pid/ipc host, seccomp/apparmor disattivati, porte
  pubblicate su tutte le interfacce (Docker scavalca UFW/firewalld!),
  secret in chiaro nelle variabili d'ambiente, utente root, assenza di
  read_only / limiti memoria e pids / no-new-privileges, tag :latest.
  In live anche: opzioni di sicurezza e warning del daemon (`docker info`).

Tool esterni opzionali (saltati con un warning se assenti):
  hadolint       lint dei Dockerfile                     (statica)
  trivy config   misconfigurazioni dei Dockerfile        (statica)
  trivy image    CVE + secret + config delle immagini    (live, --scan-images)
  docker compose `config` risolve merge override + .env  (statica; fallback PyYAML)

Correlazione con port-scan (--active results.json): una porta pubblicata su
0.0.0.0 che risulta aperta anche dallo scan esterno viene marcata come
esposizione CONFERMATA.

Output in <base>/docker-configuration/<label>/<timestamp>/:
  findings.json, findings.txt, raw/ (inspect, docker info, output dei tool).
I valori delle variabili d'ambiente che sembrano secret sono SEMPRE
mascherati, anche nei file raw.

La modalita' live e' read-only verso il daemon (ps/inspect/info), tranne
--scan-images su host remoto, che esegue `docker save` per scaricare
l'immagine in locale. Usare SOLO su host di tua proprieta' o autorizzati.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import common  # noqa: E402

# Identifica questo script nella struttura di output: output/<TOOL_NAME>/<label>/<timestamp>/
TOOL_NAME = "docker-configuration"

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

COMPOSE_BASE_NAMES = ["compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"]
COMPOSE_RE = re.compile(r"^(docker-)?compose([.-][\w.-]+)?\.ya?ml$", re.IGNORECASE)
DOCKERFILE_RE = re.compile(r"^(Dockerfile([.-][\w.-]+)?|[\w.-]+\.Dockerfile)$", re.IGNORECASE)
SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "output"}

# Path dell'host che non dovrebbero mai finire montati in un container.
SENSITIVE_MOUNTS = ["/", "/etc", "/proc", "/sys", "/root", "/boot", "/dev",
                    "/var/lib/docker", "/run", "/var/run", "/home"]
# Per questi anche le sottocartelle sono sensibili (es. /etc/ssl, /root/.ssh)
SENSITIVE_SUBTREES = {"/etc", "/proc", "/sys", "/root", "/boot"}
DOCKER_SOCKETS = {"/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock"}

DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_RAWIO", "DAC_READ_SEARCH",
                  "DAC_OVERRIDE", "NET_ADMIN", "SYS_BOOT", "SYS_TIME", "BPF", "PERFMON"}

# Porte che, se pubblicate su tutte le interfacce, sono quasi sempre un errore.
SENSITIVE_PORTS = {
    22: "ssh", 2375: "docker API (no TLS)", 2376: "docker API", 3306: "mysql", 5432: "postgresql",
    6379: "redis", 27017: "mongodb", 9200: "elasticsearch", 9300: "elasticsearch",
    11211: "memcached", 5984: "couchdb", 8086: "influxdb", 5672: "rabbitmq", 15672: "rabbitmq admin",
    9000: "php-fpm / portainer", 9090: "prometheus", 3000: "grafana", 8025: "mailhog", 1025: "smtp dev",
}

SECRET_KEY_RE = re.compile(
    r"(PASS(WORD|WD)?|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?|AUTH|SALT|DSN)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Finding helpers
# ---------------------------------------------------------------------------


def finding(severity: str, rule: str, target: str, message: str, source: str = "builtin",
            detail: str | None = None) -> dict:
    f = {"severity": severity, "rule": rule, "target": target, "message": message, "source": source}
    if detail:
        f["detail"] = detail
    return f


def is_secret_key(key: str) -> bool:
    # VAR_FILE punta a un file (pattern docker secrets), non contiene il secret
    return bool(SECRET_KEY_RE.search(key)) and not key.upper().endswith("_FILE")


def mask(value: str) -> str:
    return f"***({len(value)} char)" if value else ""


def mask_env_list(env: list[str]) -> list[str]:
    out = []
    for item in env or []:
        k, sep, v = item.partition("=")
        out.append(f"{k}={mask(v)}" if sep and is_secret_key(k) else item)
    return out


def mask_env_dict(env: dict) -> dict:
    return {k: (mask(str(v)) if v is not None and is_secret_key(k) else v) for k, v in (env or {}).items()}


# ---------------------------------------------------------------------------
# Normalizzazione: compose service / docker inspect -> spec comune
# ---------------------------------------------------------------------------
#
# spec = {
#   image, privileged, cap_add[], security_opt[], network_mode, pid_mode, ipc_mode,
#   user (None = non specificato), read_only, mem_limit, pids_limit, no_new_privs,
#   devices[], env{k: v}, mounts[{source, target, rw, type}],
#   ports[{host_ip, host_port, container_port, proto}]
# }


def parse_short_port(raw: str) -> dict:
    s, _, proto = str(raw).partition("/")
    host_ip = ""
    if s.startswith("["):
        host_ip, _, s = s[1:].partition("]:")
    parts = s.split(":")
    if len(parts) == 3:
        host_ip, host_port, cont = parts
    elif len(parts) == 2:
        host_port, cont = parts
    else:
        host_port, cont = "", parts[0]
    # host_port vuoto = Docker sceglie una porta effimera, sempre su tutte le interfacce
    return {"host_ip": host_ip, "host_port": host_port or "random", "container_port": cont,
            "proto": proto or "tcp"}


def parse_compose_ports(ports: list) -> list[dict]:
    out = []
    for p in ports or []:
        if isinstance(p, dict):
            out.append({"host_ip": p.get("host_ip", ""), "host_port": str(p.get("published") or "random"),
                        "container_port": str(p.get("target", "")), "proto": p.get("protocol", "tcp")})
        else:
            out.append(parse_short_port(p))
    return out


def parse_compose_volumes(vols: list) -> list[dict]:
    out = []
    for v in vols or []:
        if isinstance(v, dict):
            out.append({"type": v.get("type", "volume"), "source": v.get("source", ""),
                        "target": v.get("target", ""), "rw": not v.get("read_only", False)})
            continue
        parts = str(v).split(":")
        if len(parts) == 1:  # volume anonimo
            out.append({"type": "volume", "source": "", "target": parts[0], "rw": True})
            continue
        src, tgt = parts[0], parts[1]
        mode = parts[2] if len(parts) > 2 else "rw"
        kind = "bind" if src.startswith(("/", ".", "~")) else "volume"
        out.append({"type": kind, "source": src, "target": tgt, "rw": "ro" not in mode.split(",")})
    return out


def compose_env(env) -> dict:
    if isinstance(env, dict):
        return {k: ("" if v is None else str(v)) for k, v in env.items()}
    out = {}
    for item in env or []:
        k, _, v = str(item).partition("=")
        out[k] = v
    return out


def spec_from_compose(svc: dict) -> dict:
    limits = ((svc.get("deploy") or {}).get("resources") or {}).get("limits") or {}
    sec_opt = [str(s) for s in svc.get("security_opt") or []]
    return {
        "image": svc.get("image") or ("(build locale)" if svc.get("build") else ""),
        "privileged": bool(svc.get("privileged")),
        "cap_add": [str(c).upper().removeprefix("CAP_") for c in svc.get("cap_add") or []],
        "security_opt": sec_opt,
        "network_mode": str(svc.get("network_mode") or ""),
        "pid_mode": str(svc.get("pid") or ""),
        "ipc_mode": str(svc.get("ipc") or ""),
        "user": str(svc["user"]) if svc.get("user") is not None else None,
        "read_only": bool(svc.get("read_only")),
        "mem_limit": bool(svc.get("mem_limit") or limits.get("memory")),
        "pids_limit": bool(svc.get("pids_limit") or limits.get("pids")),
        "no_new_privs": any("no-new-privileges" in s and not s.endswith("false") for s in sec_opt),
        "devices": [str(d) if not isinstance(d, dict) else d.get("source", "") for d in svc.get("devices") or []],
        "env": compose_env(svc.get("environment")),
        "mounts": parse_compose_volumes(svc.get("volumes")),
        "ports": parse_compose_ports(svc.get("ports")),
    }


def spec_from_inspect(c: dict) -> dict:
    hc = c.get("HostConfig") or {}
    cfg = c.get("Config") or {}
    ports = []
    seen: set[tuple] = set()
    for key, bindings in ((c.get("NetworkSettings") or {}).get("Ports") or {}).items():
        cont, _, proto = key.partition("/")
        for b in bindings or []:  # None = esposta ma non pubblicata sull'host
            host_ip = b.get("HostIp", "")
            # Docker crea un binding per 0.0.0.0 e uno per ::, e' la stessa esposizione
            k = ("*" if all_interfaces(host_ip) else host_ip, b.get("HostPort", ""), cont, proto)
            if k in seen:
                continue
            seen.add(k)
            ports.append({"host_ip": host_ip, "host_port": b.get("HostPort", ""),
                          "container_port": cont, "proto": proto or "tcp"})
    sec_opt = hc.get("SecurityOpt") or []
    env = {}
    for item in cfg.get("Env") or []:
        k, _, v = item.partition("=")
        env[k] = v
    return {
        "image": cfg.get("Image", ""),
        "privileged": bool(hc.get("Privileged")),
        "cap_add": [str(x).upper().removeprefix("CAP_") for x in hc.get("CapAdd") or []],
        "security_opt": sec_opt,
        "network_mode": hc.get("NetworkMode", ""),
        "pid_mode": hc.get("PidMode", ""),
        "ipc_mode": hc.get("IpcMode", ""),
        # In inspect Config.User include gia' l'USER dell'immagine: vuoto = root
        "user": cfg.get("User") or "",
        "read_only": bool(hc.get("ReadonlyRootfs")),
        "mem_limit": bool(hc.get("Memory")),
        "pids_limit": bool(hc.get("PidsLimit") and hc["PidsLimit"] > 0),
        "no_new_privs": any("no-new-privileges" in s and not s.endswith("false") for s in sec_opt),
        "devices": [d.get("PathOnHost", "") for d in hc.get("Devices") or []],
        "env": env,
        "mounts": [{"type": m.get("Type", ""), "source": m.get("Source", ""),
                    "target": m.get("Destination", ""), "rw": bool(m.get("RW"))}
                   for m in c.get("Mounts") or []],
        "ports": ports,
    }


# ---------------------------------------------------------------------------
# Regole sulla spec
# ---------------------------------------------------------------------------


def all_interfaces(host_ip: str) -> bool:
    return host_ip in ("", "0.0.0.0", "::")


def first_port(p: str) -> int | None:
    m = re.match(r"\d+", p or "")
    return int(m.group()) if m else None


def check_spec(target: str, spec: dict, live: bool) -> list[dict]:
    f: list[dict] = []

    if spec["privileged"]:
        f.append(finding("CRITICAL", "privileged", target,
                         "Container privileged: accesso completo ai device dell'host, escape banale."))

    for m in spec["mounts"]:
        src = (m["source"] or "").rstrip("/") or ("/" if m["source"] else "")
        if src in DOCKER_SOCKETS or m["target"] in DOCKER_SOCKETS:
            f.append(finding("CRITICAL", "docker-socket", target,
                             f"Socket Docker montato ({m['source']} -> {m['target']}): "
                             "chi controlla il container controlla l'host (root).",
                             detail="Anche in read-only il socket permette di creare container privilegiati."))
            continue
        if m["type"] != "bind" or not src:
            continue
        for s in SENSITIVE_MOUNTS:
            if src == s or (s in SENSITIVE_SUBTREES and src.startswith(s + "/")):
                sev = "HIGH" if m["rw"] else "MEDIUM"
                f.append(finding(sev, "sensitive-mount", target,
                                 f"Path sensibile dell'host montato {'in scrittura' if m['rw'] else 'read-only'}: "
                                 f"{m['source']} -> {m['target']}"))
                break

    caps = sorted(set(spec["cap_add"]) & DANGEROUS_CAPS)
    if caps:
        f.append(finding("HIGH", "dangerous-capabilities", target,
                         f"Capability pericolose aggiunte: {', '.join(caps)}"))

    for field, label, sev in (("network_mode", "network", "HIGH"), ("pid_mode", "pid", "HIGH"),
                              ("ipc_mode", "ipc", "MEDIUM")):
        if spec[field] == "host":
            f.append(finding(sev, f"{label}-host", target,
                             f"Namespace {label} condiviso con l'host ({label}: host)."))

    for s in spec["security_opt"]:
        sl = s.lower().replace("=", ":")
        if sl in ("seccomp:unconfined", "apparmor:unconfined", "label:disable"):
            f.append(finding("HIGH", "security-profile-disabled", target, f"Profilo di sicurezza disattivato: {s}"))

    for d in spec["devices"]:
        f.append(finding("MEDIUM", "host-device", target, f"Device dell'host esposto al container: {d}"))

    for p in spec["ports"]:
        if not all_interfaces(p["host_ip"]):
            continue
        cport = first_port(p["container_port"])
        hport = first_port(p["host_port"])
        svc = SENSITIVE_PORTS.get(cport) or SENSITIVE_PORTS.get(hport)
        where = f"{p['host_port']}->{p['container_port']}/{p['proto']}"
        if svc:
            f.append(finding("HIGH", "sensitive-port-public", target,
                             f"Porta {where} ({svc}) pubblicata su TUTTE le interfacce.",
                             detail="Docker scrive regole iptables proprie e scavalca UFW/firewalld: "
                                    "la porta e' raggiungibile anche se il firewall la blocca. "
                                    "Usare '127.0.0.1:PORTA:PORTA' o una rete interna."))
        else:
            f.append(finding("LOW", "port-public", target,
                             f"Porta {where} pubblicata su tutte le interfacce (verifica che sia voluto; "
                             "Docker scavalca UFW/firewalld)."))

    for k, v in spec["env"].items():
        if not is_secret_key(k) or not v or v.startswith("${"):
            continue
        f.append(finding("MEDIUM", "env-secret", target,
                         f"Secret in chiaro nella variabile d'ambiente {k}={mask(v)}",
                         detail="Visibile a chiunque possa fare `docker inspect` e nei log di debug. "
                                "Preferire docker secrets / file montati (VAR_FILE)."))

    user = spec["user"]
    if live and (user in ("", "root", "0") or user.startswith(("root:", "0:"))):
        f.append(finding("MEDIUM", "root-user", target, "Il container gira come root."))
    elif not live and user is not None and (user in ("root", "0") or user.startswith(("root:", "0:"))):
        f.append(finding("MEDIUM", "root-user", target, f"user: {user} esplicito nel compose."))

    if not spec["no_new_privs"] and not spec["privileged"]:
        f.append(finding("LOW", "no-new-privileges", target,
                         "Manca security_opt no-new-privileges:true (blocca escalation via setuid)."))
    if not spec["read_only"]:
        f.append(finding("LOW", "writable-rootfs", target, "Filesystem root del container scrivibile (read_only: false)."))
    if not spec["mem_limit"]:
        f.append(finding("LOW", "no-memory-limit", target, "Nessun limite di memoria."))
    if not spec["pids_limit"]:
        f.append(finding("LOW", "no-pids-limit", target, "Nessun pids_limit (fork bomb possibile)."))

    img = spec["image"]
    if img and not img.startswith("(") and not img.startswith("sha256:"):
        name = img.split("@")[0]
        if "@" not in img and (":" not in name.rsplit("/", 1)[-1] or name.endswith(":latest")):
            f.append(finding("LOW", "image-latest", target, f"Immagine senza tag fisso: {img}"))

    return f


# ---------------------------------------------------------------------------
# Modalita' STATICA
# ---------------------------------------------------------------------------


def discover(paths: list[str]) -> tuple[list[Path], list[Path]]:
    dockerfiles: list[Path] = []
    composes: list[Path] = []
    for raw in paths:
        p = Path(raw).expanduser().resolve()
        if p.is_file():
            candidates = [p]
        elif p.is_dir():
            candidates = [c for c in p.rglob("*")
                          if c.is_file() and not (set(c.relative_to(p).parts[:-1]) & SKIP_DIRS)]
        else:
            common.warn(f"path non trovato, salto: {raw}")
            continue
        for c in candidates:
            if COMPOSE_RE.match(c.name):
                composes.append(c)
            elif DOCKERFILE_RE.match(c.name):
                dockerfiles.append(c)
    return sorted(set(dockerfiles)), sorted(set(composes))


def group_compose(files: list[Path]) -> list[list[Path]]:
    """Raggruppa i compose come li unirebbe `docker compose` lanciato nella
    cartella: file base + suo .override. Gli altri (es. docker-compose.prod.yml)
    vengono analizzati da soli."""
    by_dir: dict[Path, list[Path]] = {}
    for f in files:
        by_dir.setdefault(f.parent, []).append(f)
    groups: list[list[Path]] = []
    for d, fs in by_dir.items():
        names = {f.name: f for f in fs}
        base = next((names[n] for n in COMPOSE_BASE_NAMES if n in names), None)
        used: set[Path] = set()
        if base:
            stem = base.name.rsplit(".", 1)[0]
            overrides = [f for f in fs if f.name.startswith(stem + ".override.")]
            groups.append([base] + overrides)
            used.update([base, *overrides])
        groups.extend([f] for f in fs if f not in used)
    return groups


def load_compose(group: list[Path], timeout: int) -> tuple[dict | None, str]:
    """Prima prova `docker compose config` (risolve merge override, .env,
    extends, normalizza la sintassi). Se docker non c'e' o il file non e'
    valido da solo, ripiega su PyYAML (sintassi grezza, niente interpolazione)."""
    if shutil.which("docker"):
        cmd = ["docker", "compose", "--project-directory", str(group[0].parent)]
        for f in group:
            cmd += ["-f", str(f)]
        rc, out, err = common.run_cmd(cmd + ["config", "--format", "json"], timeout)
        if rc == 0 and out.strip():
            try:
                return json.loads(out), "docker compose config"
            except json.JSONDecodeError:
                pass
        elif err.strip():
            common.warn(f"docker compose config {group[0].name}: {err.strip().splitlines()[-1][:200]}")
    try:
        import yaml  # noqa: PLC0415
    except ImportError:
        common.warn("ne' docker compose ne' PyYAML disponibili: compose non analizzabili.")
        return None, ""
    merged: dict = {"services": {}}
    for f in group:
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        except (yaml.YAMLError, OSError) as e:
            common.warn(f"YAML non valido {f}: {e}")
            continue
        for name, svc in (data.get("services") or {}).items():
            merged["services"].setdefault(name, {}).update(svc or {})
    return merged, "PyYAML (raw, override fusi solo a livello di chiave)"


def dockerfile_builtin(path: Path) -> list[dict]:
    """Pochi check essenziali, utili quando hadolint/trivy non sono installati."""
    target = f"Dockerfile {path}"
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        common.warn(f"lettura {path}: {e}")
        return []
    f: list[dict] = []
    last_user = None
    for n, line in enumerate(lines, 1):
        s = line.strip()
        instr, _, rest = s.partition(" ")
        instr = instr.upper()
        if instr == "USER":
            last_user = rest.strip()
        elif instr == "FROM":
            img = rest.split()[0] if rest.split() else ""
            if img and img.lower() != "scratch" and "$" not in img and "@" not in img and (
                    ":" not in img.rsplit("/", 1)[-1] or img.endswith(":latest")):
                f.append(finding("LOW", "image-latest", target, f"riga {n}: FROM senza tag fisso ({img})"))
        elif instr in ("ENV", "ARG"):
            key = re.split(r"[=\s]", rest.strip(), maxsplit=1)[0]
            if key and is_secret_key(key) and ("=" in rest or instr == "ENV"):
                f.append(finding("MEDIUM", "dockerfile-secret", target,
                                 f"riga {n}: {instr} {key} — i secret in ENV/ARG restano nei layer dell'immagine "
                                 "(`docker history`). Usare RUN --mount=type=secret."))
        elif instr == "ADD" and re.search(r"https?://", rest):
            f.append(finding("LOW", "add-remote-url", target, f"riga {n}: ADD da URL remoto senza verifica checksum."))
    if last_user is None or last_user.split(":")[0] in ("root", "0"):
        f.append(finding("MEDIUM", "dockerfile-root", target, "Nessun USER non-root: l'immagine gira come root."))
    return f


def run_hadolint(path: Path, rawdir: Path, timeout: int) -> list[dict]:
    if not shutil.which("hadolint"):
        return []
    rc, out, err = common.run_cmd(["hadolint", "-f", "json", "--no-fail", str(path)], timeout)
    try:
        items = json.loads(out or "[]")
    except json.JSONDecodeError:
        common.warn(f"hadolint output non JSON per {path}: {err.strip()[:200]}")
        return []
    (rawdir / f"hadolint-{file_tag(path)}.json").write_text(json.dumps(items, indent=2), encoding="utf-8")
    sev = {"error": "MEDIUM", "warning": "LOW", "info": "INFO", "style": "INFO"}
    return [finding(sev.get(i.get("level"), "INFO"), i.get("code", "hadolint"), f"Dockerfile {path}",
                    f"riga {i.get('line')}: {i.get('message')}", source="hadolint")
            for i in items]


def parse_trivy(data: dict, target_prefix: str) -> tuple[list[dict], dict]:
    """Ritorna (findings misconfig+secret, riepilogo vulnerabilita')."""
    f: list[dict] = []
    vulns: list[dict] = []
    for res in data.get("Results") or []:
        tgt = f"{target_prefix} [{res.get('Target', '')}]"
        for m in res.get("Misconfigurations") or []:
            if m.get("Status", "FAIL") != "FAIL":
                continue
            f.append(finding(m.get("Severity", "INFO"), m.get("AVDID") or m.get("ID", "trivy"), tgt,
                             m.get("Title") or m.get("Message", ""), source="trivy",
                             detail=m.get("Message")))
        for s in res.get("Secrets") or []:
            f.append(finding("HIGH", s.get("RuleID", "secret"), tgt,
                             f"Secret nell'immagine: {s.get('Title', '')} (riga {s.get('StartLine')})",
                             source="trivy"))
        for v in res.get("Vulnerabilities") or []:
            vulns.append({"id": v.get("VulnerabilityID"), "pkg": v.get("PkgName"),
                          "installed": v.get("InstalledVersion"), "fixed": v.get("FixedVersion", ""),
                          "severity": v.get("Severity"), "title": v.get("Title", "")})
    counts: dict[str, int] = {}
    for v in vulns:
        counts[v["severity"]] = counts.get(v["severity"], 0) + 1
    return f, {"counts": counts, "vulnerabilities": vulns}


def run_trivy_config(path: Path, rawdir: Path, timeout: int) -> list[dict]:
    if not shutil.which("trivy"):
        return []
    rc, out, err = common.run_cmd(["trivy", "config", "--quiet", "--format", "json", str(path)], timeout)
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        common.warn(f"trivy config fallito su {path}: {err.strip()[:200]}")
        return []
    (rawdir / f"trivy-config-{file_tag(path)}.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    f, _ = parse_trivy(data, "trivy config")
    return f


def static_audit(paths: list[str], rawdir: Path, timeout: int) -> tuple[list[dict], dict]:
    dockerfiles, composes = discover(paths)
    common.log(f"Statica: {len(dockerfiles)} Dockerfile, {len(composes)} file compose")
    findings: list[dict] = []
    meta = {"dockerfiles": [str(d) for d in dockerfiles], "compose_groups": []}

    for group in group_compose(composes):
        data, how = load_compose(group, timeout)
        meta["compose_groups"].append({"files": [str(f) for f in group], "parsed_with": how})
        if not data:
            continue
        label = " + ".join(f.name for f in group)
        masked = {"services": {n: {**(s or {}), "environment": mask_env_dict(compose_env((s or {}).get("environment")))}
                               for n, s in (data.get("services") or {}).items()}}
        (rawdir / f"compose-{file_tag(group[0])}.json").write_text(json.dumps(masked, indent=2), encoding="utf-8")
        for name, svc in (data.get("services") or {}).items():
            findings += check_spec(f"service {name} ({group[0].parent.name}/{label})", spec_from_compose(svc or {}),
                                   live=False)

    for d in dockerfiles:
        findings += dockerfile_builtin(d)
        findings += run_hadolint(d, rawdir, timeout)
    # trivy config una volta per directory radice passata (scansiona ricorsivamente)
    if dockerfiles:
        for raw in paths:
            p = Path(raw).expanduser().resolve()
            if p.exists():
                findings += run_trivy_config(p, rawdir, timeout)
    if not shutil.which("hadolint"):
        common.warn("hadolint non installato: solo check integrati sui Dockerfile.")
    if not shutil.which("trivy"):
        common.warn("trivy non installato: salto trivy config.")
    return findings, meta


# ---------------------------------------------------------------------------
# Modalita' LIVE
# ---------------------------------------------------------------------------


def docker_base(host: str | None, context: str | None) -> list[str]:
    cmd = ["docker"]
    if host:
        cmd += ["-H", host]
    if context:
        cmd += ["--context", context]
    return cmd


def check_daemon(info: dict) -> list[dict]:
    f: list[dict] = []
    target = f"daemon {info.get('Name', '')} (Docker {info.get('ServerVersion', '?')})"
    opts = " ".join(info.get("SecurityOptions") or [])
    if "seccomp" not in opts:
        f.append(finding("HIGH", "daemon-no-seccomp", target, "Seccomp non attivo sul daemon."))
    if "rootless" not in opts and "userns" not in opts:
        f.append(finding("LOW", "daemon-rootful", target,
                         "Daemon rootful senza userns-remap: root nel container = root sull'host in caso di escape."))
    if not info.get("LiveRestoreEnabled"):
        f.append(finding("INFO", "daemon-no-live-restore", target, "live-restore disattivato."))
    for w in info.get("Warnings") or []:
        sev = "CRITICAL" if "without encryption" in w or "2375" in w else "INFO"
        f.append(finding(sev, "daemon-warning", target, w.strip()))
    return f


def scan_image(docker: list[str], image: str, remote: bool, rawdir: Path, timeout: int) -> tuple[list[dict], dict]:
    cmd = ["trivy", "image", "--quiet", "--format", "json", "--severity", "HIGH,CRITICAL",
           "--scanners", "vuln,secret", "--image-config-scanners", "misconfig,secret"]
    with tempfile.TemporaryDirectory() as tmp:
        if remote:
            # trivy non parla col daemon via ssh://: scarichiamo l'immagine in locale
            tar = Path(tmp) / "image.tar"
            common.log(f"docker save {image} (remoto -> locale)")
            rc, _, err = common.run_cmd(docker + ["save", "-o", str(tar), image], timeout)
            if rc != 0 or not tar.exists():
                common.warn(f"docker save {image} fallito: {err.strip()[:200]}")
                return [], {}
            cmd += ["--input", str(tar)]
        else:
            cmd.append(image)
        common.log(f"trivy image {image}")
        rc, out, err = common.run_cmd(cmd, timeout)
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        common.warn(f"trivy image {image} fallito: {err.strip()[:200]}")
        return [], {}
    (rawdir / f"trivy-image-{safe_name(image)}.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    f, summary = parse_trivy(data, f"image {image}")
    counts = summary["counts"]
    if counts:
        sev = "CRITICAL" if counts.get("CRITICAL") else "HIGH"
        top = sorted(summary["vulnerabilities"], key=lambda v: SEV_RANK.get(v["severity"], 9))[:5]
        f.append(finding(sev, "image-vulnerabilities", f"image {image}",
                         f"CVE: {counts.get('CRITICAL', 0)} CRITICAL, {counts.get('HIGH', 0)} HIGH",
                         source="trivy",
                         detail="; ".join(f"{v['id']} {v['pkg']} {v['installed']}"
                                          f"{' -> ' + v['fixed'] if v['fixed'] else ' (no fix)'}" for v in top)))
    return f, summary


def live_audit(host: str | None, context: str | None, include_stopped: bool, scan_images: bool,
               rawdir: Path, timeout: int) -> tuple[list[dict], dict, list[dict]]:
    """Ritorna (findings, meta, porte pubblicate per la correlazione)."""
    if not shutil.which("docker"):
        common.warn("docker CLI non trovata: la modalita' live richiede il client docker.")
        return [], {}, []
    docker = docker_base(host, context)
    findings: list[dict] = []
    meta: dict = {"docker_host": host or "locale", "daemon_reachable": False, "containers": [], "images": {}}

    rc, out, err = common.run_cmd(docker + ["info", "--format", "{{json .}}"], timeout)
    if rc != 0:
        common.warn(f"docker info fallito (daemon raggiungibile? permessi sul socket?): {err.strip()[:300]}")
        return [], meta, []
    meta["daemon_reachable"] = True
    try:
        info = json.loads(out)
        (rawdir / "docker-info.json").write_text(json.dumps(info, indent=2), encoding="utf-8")
        findings += check_daemon(info)
    except json.JSONDecodeError:
        common.warn("docker info: output non JSON.")

    ids = common.run_cmd_lines(docker + ["ps", "-q"] + (["-a"] if include_stopped else []), timeout)
    ids = [i.strip() for i in ids if i.strip()]
    common.log(f"Live: {len(ids)} container {'(inclusi fermi)' if include_stopped else 'in esecuzione'}")
    if not ids:
        return findings, meta, []

    rc, out, err = common.run_cmd(docker + ["inspect"] + ids, timeout)
    try:
        containers = json.loads(out)
    except json.JSONDecodeError:
        common.warn(f"docker inspect fallito: {err.strip()[:200]}")
        return findings, meta, []

    published: list[dict] = []
    images: set[str] = set()
    for c in containers:
        name = c.get("Name", "").lstrip("/")
        labels = (c.get("Config") or {}).get("Labels") or {}
        project = labels.get("com.docker.compose.project")
        target = f"container {name}" + (f" (compose: {project}/{labels.get('com.docker.compose.service')})"
                                        if project else "")
        spec = spec_from_inspect(c)
        findings += check_spec(target, spec, live=True)
        images.add(spec["image"])
        for p in spec["ports"]:
            if all_interfaces(p["host_ip"]):
                published.append({**p, "target": target})
        meta["containers"].append({
            "name": name, "image": spec["image"], "state": (c.get("State") or {}).get("Status"),
            "compose_project": project,
            # dove stanno i file compose sull'host: utili per un successivo --path
            "compose_files": labels.get("com.docker.compose.project.config_files"),
            "compose_workdir": labels.get("com.docker.compose.project.working_dir"),
        })
        cfg = c.get("Config") or {}
        cfg["Env"] = mask_env_list(cfg.get("Env"))
    (rawdir / "docker-inspect.json").write_text(json.dumps(containers, indent=2), encoding="utf-8")

    if scan_images:
        if not shutil.which("trivy"):
            common.warn("--scan-images richiesto ma trivy non installato.")
        else:
            remote = bool(host and not host.startswith("unix://")) or bool(context)
            for img in sorted(i for i in images if i):
                f, summary = scan_image(docker, img, remote, rawdir, timeout)
                findings += f
                meta["images"][img] = summary.get("counts", {})
    return findings, meta, published


def correlate(published: list[dict], active: dict) -> list[dict]:
    """Porta pubblicata su 0.0.0.0 + aperta nello scan esterno = esposizione confermata."""
    open_ports: dict[int, list[str]] = {}
    for h in active.get("hosts", []):
        for p in h.get("ports", []):
            open_ports.setdefault(int(p["port"]), []).append(h.get("ip", "?"))
    f: list[dict] = []
    for p in published:
        hp = first_port(p["host_port"])
        if hp in open_ports:
            svc = SENSITIVE_PORTS.get(first_port(p["container_port"])) or SENSITIVE_PORTS.get(hp)
            f.append(finding("CRITICAL" if svc else "HIGH", "exposure-confirmed", p["target"],
                             f"Porta {hp}/{p['proto']}{' (' + svc + ')' if svc else ''} pubblicata da Docker "
                             f"E aperta dall'esterno su {', '.join(sorted(set(open_ports[hp])))}.",
                             source="correlation"))
    for port in (2375, 2376):
        if port in open_ports:
            f.append(finding("CRITICAL", "docker-api-exposed", ", ".join(open_ports[port]),
                             f"API Docker raggiungibile dall'esterno sulla porta {port}.", source="correlation"))
    return f


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def safe_name(s: str) -> str:
    return re.sub(r"[^\w.-]+", "_", s).strip("_")[-60:]


def file_tag(path: Path) -> str:
    """Nome breve per i file raw: <cartella>_<file>, non il path completo
    (su Windows i path lunghi superano il limite di 260 caratteri)."""
    return safe_name(f"{path.parent.name}_{path.name}")


def render_text(label: str, findings: list[dict], meta: dict) -> str:
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    lines = [f"Docker configuration audit — {label}",
             "  " + "  ".join(f"{s}: {n}" for s, n in counts.items()), ""]
    by_target: dict[str, list[dict]] = {}
    for f in findings:
        by_target.setdefault(f["target"], []).append(f)
    order = sorted(by_target, key=lambda t: (min(SEV_RANK.get(x["severity"], 9) for x in by_target[t]), t))
    for t in order:
        lines.append(f"## {t}")
        for f in sorted(by_target[t], key=lambda x: SEV_RANK.get(x["severity"], 9)):
            src = "" if f["source"] == "builtin" else f" [{f['source']}]"
            lines.append(f"  [{f['severity']}] {f['rule']}{src}: {f['message']}")
            if f.get("detail") and SEV_RANK.get(f["severity"], 9) <= SEV_RANK["MEDIUM"]:
                lines.append(f"      -> {f['detail']}")
        lines.append("")
    live = meta.get("live") or {}
    hints = [c for c in live.get("containers", []) if c.get("compose_files")]
    if hints:
        lines.append("File compose usati dai container (sull'host) — utili per un'analisi statica con --path:")
        for c in hints:
            lines.append(f"  {c['name']}: {c['compose_files']}")
        lines.append("")
    if not findings:
        lines.append("Nessun finding. Verifica che l'input contenesse davvero Dockerfile/compose o container.")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit misconfigurazioni di sicurezza di uno stack Docker (statico e/o live).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--path", action="append", default=[],
                        help="File o cartella con Dockerfile / docker-compose (ripetibile)")
    parser.add_argument("--live", action="store_true",
                        help="Analizza i container in esecuzione via `docker inspect`")
    parser.add_argument("--docker-host", default=None,
                        help="Daemon remoto, es. ssh://deploy@staging.example.com (implica --live)")
    parser.add_argument("--context", default=None, help="docker context da usare (implica --live)")
    parser.add_argument("--all", action="store_true", help="Live: includi anche i container fermi")
    parser.add_argument("--scan-images", action="store_true",
                        help="Live: trivy image su ogni immagine in uso (su host remoto fa docker save)")
    parser.add_argument("--active", default=None,
                        help="results.json di port-scan per confermare l'esposizione delle porte pubblicate")
    parser.add_argument("--min-severity", choices=SEVERITIES, default="INFO",
                        help="Mostra solo finding da questa severita' in su (default INFO = tutti)")
    parser.add_argument("-o", "--output", default=None,
                        help="Cartella base output: relativo risolto dalla radice del repo, "
                             "assoluto usato cosi'. Default <radice>/output")
    parser.add_argument("--label", default=None, help="Nome sotto-cartella output")
    parser.add_argument("--timeout", type=int, default=600, help="Timeout per singolo comando (default 600)")
    parser.add_argument("--json", action="store_true", help="Stampa il JSON completo su stdout")
    args = parser.parse_args()

    live = args.live or bool(args.docker_host) or bool(args.context)
    if not args.path and not live:
        parser.error("serve almeno --path e/o --live (o --docker-host)")

    active = None
    if args.active:
        try:
            active = json.loads(Path(args.active).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            common.warn(f"--active non leggibile: {e}")
            return 2

    if args.label:
        label = args.label
    elif args.docker_host and args.docker_host.startswith("ssh://"):
        label = args.docker_host.removeprefix("ssh://").split("@")[-1].split(":")[0]
        label = common.default_label([label]) if common.valid_domain(label) else label
    elif live:
        label = args.context or "localhost"
    else:
        label = safe_name(Path(args.path[0]).expanduser().resolve().name) or "local"

    outdir = common.make_outdir(common.resolve_output_base(args.output), TOOL_NAME, label)
    rawdir = outdir / "raw"
    rawdir.mkdir(exist_ok=True)

    findings: list[dict] = []
    meta: dict = {}
    if args.path:
        f, meta["static"] = static_audit(args.path, rawdir, args.timeout)
        findings += f
    if live:
        f, meta["live"], published = live_audit(args.docker_host, args.context, args.all,
                                                args.scan_images, rawdir, args.timeout)
        findings += f
        if active is not None:
            findings += correlate(published, active)
    elif active is not None:
        common.warn("--active serve solo in modalita' live (porte pubblicate reali): ignorato.")

    threshold = SEV_RANK[args.min_severity]
    findings = [f for f in findings if SEV_RANK.get(f["severity"], 9) <= threshold]
    findings.sort(key=lambda f: (SEV_RANK.get(f["severity"], 9), f["target"], f["rule"]))

    report = {
        "generated_utc": common.now_iso(),
        "modes": [m for m, on in (("static", bool(args.path)), ("live", live)) if on],
        "summary": {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES},
        "findings": findings,
        "meta": meta,
    }
    (outdir / "findings.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    text = render_text(label, findings, meta)
    (outdir / "findings.txt").write_text(text, encoding="utf-8")

    common.log(f"Findings: {report['summary']}")
    common.log(f"Salvato: {outdir / 'findings.json'}")
    common.log(f"Salvato: {outdir / 'findings.txt'}")

    print(json.dumps(report, indent=2) if args.json else text)
    if live and not meta["live"].get("daemon_reachable"):
        common.warn("Modalita' live NON eseguita: il report non copre i container in esecuzione.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

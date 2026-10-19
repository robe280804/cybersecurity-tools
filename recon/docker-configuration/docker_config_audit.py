#!/usr/bin/env python3
"""
Audit di sicurezza di uno stack Docker, in due modalita' combinabili:

  STATICA  (--path)   analizza i file del progetto: Dockerfile e
                      docker-compose. Vede l'INTENZIONE (cosa e' scritto),
                      utile anche prima del deploy / in CI.
  LIVE     (--live)   interroga il daemon Docker (locale, oppure remoto via
                      SSH con --docker-host ssh://user@host) e legge la
                      configurazione EFFETTIVA dei container in esecuzione.
                      Vede cosa sta girando davvero, compresi override,
                      `docker run` manuali e drift rispetto ai file del repo.

Le due modalita' passano per lo stesso set di regole: compose e inspect
vengono normalizzati in una "spec" comune (privileged, capability, mount,
porte, env, limiti...), cosi' un finding ha lo stesso significato da
qualunque parte arrivi. Ogni regola ha categoria, riferimento CIS Docker
Benchmark v1.6.0 (dove esiste) e remediation.

Cosa raccoglie in live (tutto read-only verso il daemon):
  docker version / info     versione engine, runc (CVE di escape note),
                            opzioni di sicurezza e warning del daemon
  docker inspect            configurazione effettiva di ogni container
  docker image inspect      eta' dell'immagine, healthcheck, drift del tag
  docker network inspect    bridge di default con ICC, overlay in chiaro
  docker top                processi nel container (sshd, miner, reverse shell)
  docker diff               modifiche al filesystem dall'avvio (binari
                            alterati, persistenza, file nascosti in /tmp)

Check sull'host (solo lettura, via la stessa connessione SSH del daemon, o
in locale su Linux): daemon.json, ExecStart di dockerd (API TCP senza TLS),
permessi del socket, membri del gruppo docker, porte 2375/2376 in ascolto.
Nessun tool viene installato sull'host.

Tool esterni, usati SOLO se gia' presenti (rilevati in locale e, via SSH,
sul server; mancanti = saltati con un warning):
  hadolint, trivy config, kics           Dockerfile / compose   (statica)
  trivy image, grype, dockle,             CVE, secret e best practice
  docker scout                            delle immagini         (--scan-images)
  docker-bench-security                   CIS Docker Benchmark sull'host
Se un tool e' presente sul server viene eseguito li' (niente trasferimento
delle immagini); altrimenti l'immagine viene esportata con `docker save` e
analizzata in locale.

Il report raggruppa i finding per categoria e per regola (un problema
ripetuto su 20 container e' UNA riga con 20 target), calcola un punteggio di
rischio per container e correla i finding in catene di attacco (es. porta
esposta + docker.sock montato).

Output in <base>/docker-configuration/<label>/<timestamp>/:
  findings.txt (raggruppato), by-target.txt, findings.json, findings.csv,
  raw/ (inspect, docker info, output dei tool).
I valori che sembrano secret (per nome della variabile o per formato del
valore) sono SEMPRE mascherati, anche nei file raw.

Usare SOLO su host di tua proprieta' o autorizzati.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import common  # noqa: E402

# Identifica questo script nella struttura di output: output/<TOOL_NAME>/<label>/<timestamp>/
TOOL_NAME = "docker-configuration"

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
# Peso per il punteggio di rischio per target (cap a 100)
SEV_WEIGHT = {"CRITICAL": 40, "HIGH": 15, "MEDIUM": 5, "LOW": 1, "INFO": 0}

COMPOSE_BASE_NAMES = ["compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"]
COMPOSE_RE = re.compile(r"^(docker-)?compose([.-][\w.-]+)?\.ya?ml$", re.IGNORECASE)
DOCKERFILE_RE = re.compile(r"^(Dockerfile([.-][\w.-]+)?|[\w.-]+\.Dockerfile)$", re.IGNORECASE)
SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "output"}

# Path dell'host che non dovrebbero mai finire montati in un container.
SENSITIVE_MOUNTS = ["/", "/etc", "/proc", "/sys", "/root", "/boot", "/dev",
                    "/var/lib/docker", "/run", "/var/run", "/home", "/var/log", "/usr", "/lib"]
# Per questi anche le sottocartelle sono sensibili (es. /etc/ssl, /root/.ssh)
SENSITIVE_SUBTREES = {"/etc", "/proc", "/sys", "/root", "/boot", "/var/lib/docker", "/usr", "/lib"}
CONTAINER_SOCKETS = {"/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock",
                     "/var/run/containerd/containerd.sock", "/run/podman/podman.sock", "/var/run/crio/crio.sock",
                     "/run/crio/crio.sock", "/var/run/cri-dockerd.sock", "/run/k3s/containerd/containerd.sock"}

DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_RAWIO", "DAC_READ_SEARCH",
                  "DAC_OVERRIDE", "NET_ADMIN", "SYS_BOOT", "SYS_TIME", "BPF", "PERFMON", "SYSLOG",
                  "MAC_ADMIN", "MAC_OVERRIDE", "NET_RAW", "SETFCAP"}
# Sottoinsieme che da solo e' una primitiva di escape (usato per le catene di attacco)
ESCAPE_CAPS = {"ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_RAWIO", "DAC_READ_SEARCH", "BPF"}

# Porte che, se pubblicate su tutte le interfacce, sono quasi sempre un errore.
SENSITIVE_PORTS = {
    22: "ssh", 2375: "docker API (no TLS)", 2376: "docker API", 2379: "etcd", 3306: "mysql", 5432: "postgresql",
    6379: "redis", 27017: "mongodb", 9200: "elasticsearch", 9300: "elasticsearch", 1433: "mssql",
    1521: "oracle", 11211: "memcached", 5984: "couchdb", 8086: "influxdb", 5672: "rabbitmq",
    15672: "rabbitmq admin", 9000: "php-fpm / portainer", 9443: "portainer", 9090: "prometheus",
    9093: "alertmanager", 9100: "node-exporter", 3000: "grafana", 8025: "mailhog", 1025: "smtp dev",
    8080: "admin/proxy dashboard", 8500: "consul", 8200: "vault", 5601: "kibana", 9042: "cassandra",
    7474: "neo4j", 8888: "jupyter", 4444: "selenium", 10250: "kubelet", 6443: "kubernetes API",
}
# Porte la cui esposizione equivale (o quasi) a controllo totale
CRITICAL_EXPOSED = {2375, 2376, 2379, 6379, 11211, 27017, 9200, 10250, 6443, 8888}

SECRET_KEY_RE = re.compile(
    r"(PASS(WORD|WD)?|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?|AUTH(?![A-Za-z])|SALT|DSN)",
    re.IGNORECASE,
)
STANDARD_LABEL_PREFIXES = ("org.opencontainers.", "org.label-schema.", "com.docker.compose.", "com.docker.desktop.",
                           "maintainer", "desktop.docker.io")
NON_SECRET_SUFFIX_RE = re.compile(
    r"_(FILE|PATH|DIR|TIME|TTL|TIMEOUT|LIFETIME|EXPIRATION|EXPIRES?|EXPIRY|ENABLED?|DISABLED?|MODE|TYPE|DRIVER"
    r"|ALGO(RITHM)?|HOST|PORT|USER(NAME)?|NAME|URL_?PATH|LENGTH|ROUNDS|CACHE|PROVIDER|GUARD|METHOD|HEADER)$",
    re.IGNORECASE)
TRIVIAL_VALUE_RE = re.compile(r"^(\d+[smhd]?|true|false|yes|no|on|off|null|none|-)$", re.IGNORECASE)
# Immagini infrastrutturali: i secret applicativi qui dentro sono sovra-esposti
# (tipico env_file condiviso tra app e DB). Valore = prefissi delle variabili legittime.
INFRA_IMAGES = {
    "mysql": ("MYSQL_",), "mariadb": ("MARIADB_", "MYSQL_"), "postgres": ("POSTGRES_", "PG"),
    "redis": ("REDIS_",), "valkey": ("VALKEY_", "REDIS_"), "mongo": ("MONGO_",), "nginx": ("NGINX_",),
    "traefik": ("TRAEFIK_",), "caddy": ("CADDY_",), "memcached": (), "rabbitmq": ("RABBITMQ_",),
    "certbot": (), "elasticsearch": ("ELASTIC",), "httpd": (), "haproxy": (),
}
# Secret riconoscibili dal formato del valore, indipendentemente dal nome della variabile
SECRET_VALUE_PATTERNS = [
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("chiave privata", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("token GitHub", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("token GitLab", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("token Slack", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("chiave Stripe live", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}\b")),
    ("API key Google", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("API key LLM", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,}")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("credenziali in URL", re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@'\"]+:([^/\s@'\"$]+)@", re.IGNORECASE)),
]
CMDLINE_SECRET_RE = re.compile(
    r"(?:^|\s)--?[\w-]*(?:pass(?:word|wd)?|secret|token|api[-_]?key)[\w-]*(?:=|\s+)(?!\$)(\S+)", re.IGNORECASE)

SUSPICIOUS_PROC_RE = re.compile(
    r"(xmrig|kinsing|kdevtmpfsi|minerd|cpuminer|nbminer|t-rex|lolminer|\bncat\b|\bsocat\b|\bnc\s+-\w*[ec]"
    r"|/dev/tcp/|bash\s+-i\b|sh\s+-i\b|python[0-9.]*\s+-c\s+.*socket|perl\s+-e\s+.*socket|\bchisel\b|\bfrpc\b"
    r"|\bngrok\b|\bgsocket\b|\bgs-netcat\b|stratum\+tcp)", re.IGNORECASE)

# docker diff: path il cui cambiamento a runtime e' un indicatore di persistenza/compromissione
PERSISTENCE_PATHS = re.compile(
    r"^/(etc/(passwd|shadow|group|sudoers(\.d/.*)?|crontab|cron\.\w+/.*|ld\.so\.preload|profile\.d/.*|rc\.local"
    r"|ssh/sshd_config|pam\.d/.*|systemd/system/.*)|var/spool/cron/.*|root/\.ssh(/.*)?|home/[^/]+/\.ssh(/.*)?"
    r"|root/\.bashrc|root/\.profile)$")
BINARY_DIRS = re.compile(r"^/(bin|sbin|usr/bin|usr/sbin|usr/local/bin|usr/local/sbin|lib|lib64|usr/lib|usr/lib64)/")
TMP_DIRS = re.compile(r"^/(tmp|var/tmp|dev/shm|run/lock)/")
TMP_SUSPICIOUS = re.compile(r"(/\.[^/]+$|\.(sh|so|elf|bin|x86|x86_64|arm|arm7|mips|pl|py)$)")
# file temporanei legittimi di runtime noti (JVM/JNA, Elasticsearch, X11, PHP, Postgres)
TMP_BENIGN = re.compile(
    r"(/tmp/elasticsearch-\d+/|/jna[-\w]*/|jansi|libnetty|snappy|sqlite-|/hsperfdata_|\.com_ibm_tools_attach"
    r"|/\.(X11|ICE|font|XIM|Test)-unix|/\.java_pid\d+|/\.htaccess$|/\.s\.PGSQL|/\.lock$|/\.keep$|/\.gitkeep$)")

# runc: escape noti risolti in queste versioni (per branch)
RUNC_CVES = [
    # (cve, descrizione, funzione vulnerabile(version_tuple) -> bool)
    ("CVE-2024-21626", "Leaky Vessels: fd leak -> accesso al filesystem dell'host", lambda v: v < (1, 1, 12)),
    ("CVE-2025-31133/52565/52881", "bypass di maskedPaths/procfs -> container escape",
     lambda v: v < (1, 2, 8) or (1, 3, 0) <= v < (1, 3, 3)),
]

# ---------------------------------------------------------------------------
# Catalogo regole: categoria, riferimento CIS, titolo, remediation
# ---------------------------------------------------------------------------

CAT_ESCAPE = "Isolamento e container escape"
CAT_NETWORK = "Esposizione di rete"
CAT_SECRETS = "Secret e credenziali"
CAT_HARDEN = "Hardening runtime"
CAT_RESOURCES = "Risorse e disponibilita'"
CAT_IMAGE = "Immagini e supply chain"
CAT_VULN = "Vulnerabilita' (CVE)"
CAT_DAEMON = "Daemon e host Docker"
CAT_ANOMALY = "Anomalie, drift e indicatori di compromissione"
CAT_CHAIN = "Catene di attacco (rischio composto)"
CATEGORY_ORDER = [CAT_CHAIN, CAT_ESCAPE, CAT_NETWORK, CAT_SECRETS, CAT_ANOMALY, CAT_DAEMON, CAT_VULN,
                  CAT_IMAGE, CAT_HARDEN, CAT_RESOURCES]

RULES: dict[str, tuple[str, str, str, str]] = {
    # rule: (categoria, CIS, titolo, remediation)
    "privileged": (CAT_ESCAPE, "5.5", "Container privileged",
                   "Rimuovere privileged; aggiungere solo le capability necessarie con cap_add."),
    "docker-socket": (CAT_ESCAPE, "5.32", "Socket del runtime montato nel container",
                      "Non montare il socket; se serve (reverse proxy, CI) usare un socket-proxy in sola lettura "
                      "che espone solo le API necessarie (es. tecnativa/docker-socket-proxy)."),
    "sensitive-mount": (CAT_ESCAPE, "5.6", "Path sensibile dell'host montato",
                        "Montare solo directory dedicate all'applicazione, in read-only quando possibile."),
    "dangerous-capabilities": (CAT_ESCAPE, "5.4", "Capability pericolose aggiunte",
                               "Rimuovere le capability non indispensabili; partire da cap_drop: [ALL]."),
    "network-host": (CAT_ESCAPE, "5.10", "Namespace di rete dell'host condiviso",
                     "Usare una rete bridge dedicata e pubblicare solo le porte necessarie."),
    "pid-host": (CAT_ESCAPE, "5.16", "Namespace PID dell'host condiviso",
                 "Rimuovere pid: host (permette di vedere e segnalare i processi dell'host)."),
    "ipc-host": (CAT_ESCAPE, "5.17", "Namespace IPC dell'host condiviso", "Rimuovere ipc: host."),
    "uts-host": (CAT_ESCAPE, "5.21", "Namespace UTS dell'host condiviso", "Rimuovere uts: host."),
    "userns-host": (CAT_ESCAPE, "5.31", "User namespace dell'host condiviso",
                    "Rimuovere userns_mode: host per beneficiare di userns-remap."),
    "cgroupns-host": (CAT_ESCAPE, "", "Cgroup namespace dell'host condiviso", "Usare cgroup: private."),
    "security-profile-disabled": (CAT_ESCAPE, "5.22", "Profilo seccomp/AppArmor/SELinux disattivato",
                                  "Rimuovere *:unconfined / label:disable; se serve, usare un profilo dedicato."),
    "no-apparmor": (CAT_ESCAPE, "5.2", "Nessun profilo AppArmor applicato",
                    "Il daemon supporta AppArmor ma il container gira senza profilo: usare docker-default o uno custom."),
    "systempaths-unconfined": (CAT_ESCAPE, "", "Masked/readonly paths del kernel disattivati",
                               "Rimuovere security_opt systempaths=unconfined (espone /proc/kcore, /sys/firmware...)."),
    "mount-propagation": (CAT_ESCAPE, "5.20", "Mount propagation condivisa con l'host",
                          "Usare propagation private/rprivate (default)."),
    "host-device": (CAT_ESCAPE, "5.18", "Device dell'host esposti", "Esporre solo i device indispensabili, con permessi minimi."),
    "device-cgroup-rule": (CAT_ESCAPE, "", "Regole cgroup sui device permissive",
                           "Restringere device_cgroup_rules al singolo major:minor necessario."),
    "unsafe-sysctl": (CAT_ESCAPE, "", "Sysctl del kernel modificate dal container",
                      "Evitare sysctl kernel.*: sono condivise con l'host."),
    "sensitive-port-public": (CAT_NETWORK, "5.14", "Servizio sensibile pubblicato su tutte le interfacce",
                              "Pubblicare su 127.0.0.1 (127.0.0.1:PORTA:PORTA) o usare solo la rete interna: "
                              "Docker scrive regole iptables proprie e scavalca UFW/firewalld."),
    "port-public": (CAT_NETWORK, "5.14", "Porta pubblicata su tutte le interfacce",
                    "Se non deve essere pubblica, legarla a 127.0.0.1 o a un'interfaccia specifica."),
    "exposure-confirmed": (CAT_NETWORK, "5.14", "Porta pubblicata da Docker e raggiungibile dall'esterno",
                           "Chiudere la pubblicazione o filtrare nella chain DOCKER-USER di iptables."),
    "docker-api-exposed": (CAT_NETWORK, "2.7", "API Docker raggiungibile dall'esterno",
                           "Chiudere la porta; se serve l'accesso remoto usare SSH o TLS con client cert."),
    "default-bridge": (CAT_NETWORK, "5.30", "Container sulla rete bridge di default",
                       "Usare reti user-defined: isolamento tra stack e DNS interno."),
    "default-bridge-icc": (CAT_NETWORK, "2.2", "Comunicazione libera tra container sul bridge di default",
                           "Impostare \"icc\": false in daemon.json e usare reti dedicate."),
    "overlay-unencrypted": (CAT_NETWORK, "", "Rete overlay senza cifratura",
                            "Creare la rete con --opt encrypted se attraversa reti non fidate."),
    "host-lan-network": (CAT_NETWORK, "", "Container direttamente sulla LAN (macvlan/ipvlan)",
                         "Verificare che sia voluto: il container ha un IP sulla rete fisica."),
    "env-secret": (CAT_SECRETS, "", "Secret in chiaro nelle variabili d'ambiente",
                   "Usare docker secrets o file montati (VAR_FILE): l'env e' leggibile con docker inspect, "
                   "/proc/<pid>/environ e finisce nei crash dump."),
    "env-overshare": (CAT_SECRETS, "", "Secret applicativi in container che non li usano",
                      "Non condividere lo stesso env_file tra app e servizi infrastrutturali (DB, cache, proxy): "
                      "passare a ciascun servizio solo le sue variabili. Una compromissione del DB non deve "
                      "consegnare le chiavi Stripe/LLM/SMTP."),
    "secret-pattern": (CAT_SECRETS, "", "Credenziale riconoscibile in chiaro",
                       "Ruotare la credenziale e spostarla in un secret manager / docker secrets."),
    "cmdline-secret": (CAT_SECRETS, "", "Secret passato come argomento del comando",
                       "Gli argomenti sono visibili con ps a tutti gli utenti dell'host: usare file o secrets."),
    "label-secret": (CAT_SECRETS, "", "Secret o hash di password nelle label",
                     "Spostare credenziali/hash in file montati (es. traefik usersFile)."),
    "dockerfile-secret": (CAT_SECRETS, "4.10", "Secret in ENV/ARG del Dockerfile",
                          "Usare RUN --mount=type=secret: ENV e ARG restano nei layer (docker history)."),
    "root-user": (CAT_HARDEN, "4.1", "Container eseguito come root",
                  "Impostare USER non-root nel Dockerfile o user: nel compose."),
    "dockerfile-root": (CAT_HARDEN, "4.1", "Immagine senza USER non-root", "Aggiungere USER non-root nello stage finale."),
    "no-new-privileges": (CAT_HARDEN, "5.26", "no-new-privileges non impostato",
                          "security_opt: [no-new-privileges:true] (o default nel daemon)."),
    "cap-drop-missing": (CAT_HARDEN, "5.4", "Capability di default non rimosse",
                         "cap_drop: [ALL] e cap_add solo per quelle necessarie."),
    "writable-rootfs": (CAT_HARDEN, "5.13", "Filesystem root scrivibile",
                        "read_only: true con tmpfs per le directory che l'app deve scrivere."),
    "no-healthcheck": (CAT_HARDEN, "5.27", "Nessun healthcheck", "Definire HEALTHCHECK nell'immagine o healthcheck nel compose."),
    "sshd-in-container": (CAT_HARDEN, "5.7", "Demone SSH in esecuzione nel container",
                          "Rimuovere sshd: per accedere usare docker exec dall'host."),
    "no-memory-limit": (CAT_RESOURCES, "5.11", "Nessun limite di memoria", "Impostare mem_limit / deploy.resources.limits.memory."),
    "no-pids-limit": (CAT_RESOURCES, "5.29", "Nessun limite di PID", "Impostare pids_limit (es. 200)."),
    "no-cpu-limit": (CAT_RESOURCES, "5.12", "Nessun limite di CPU", "Impostare cpus / deploy.resources.limits.cpus."),
    "oom-kill-disabled": (CAT_RESOURCES, "", "OOM killer disattivato senza limite di memoria",
                          "Rimuovere oom_kill_disable o impostare un limite di memoria."),
    "no-logging": (CAT_RESOURCES, "", "Logging disattivato", "Senza log non c'e' traccia di un incidente: usare un driver di log."),
    "log-no-rotation": (CAT_RESOURCES, "", "Log json-file senza rotazione",
                        "Impostare max-size/max-file (o il driver local): i log possono riempire il disco."),
    "image-latest": (CAT_IMAGE, "", "Immagine senza tag fisso",
                     "Usare un tag di versione o, meglio, il digest (@sha256:...)."),
    "image-old": (CAT_IMAGE, "", "Immagine non ricostruita da molto tempo",
                  "Ricostruire periodicamente per incorporare le patch dell'immagine base."),
    "add-remote-url": (CAT_IMAGE, "4.9", "ADD da URL remoto", "Usare RUN curl con verifica del checksum, o COPY."),
    "pipe-to-shell": (CAT_IMAGE, "", "Script remoto eseguito senza verifica (curl | sh)",
                      "Scaricare, verificare checksum/firma, poi eseguire."),
    "tls-verification-disabled": (CAT_IMAGE, "", "Verifica TLS disattivata durante la build",
                                  "Rimuovere --insecure / -k / --no-check-certificate / trusted-host."),
    "dockerfile-expose-ssh": (CAT_IMAGE, "5.7", "Porta SSH esposta dall'immagine", "Rimuovere EXPOSE 22 e sshd."),
    "dockerfile-chmod-777": (CAT_IMAGE, "", "Permessi 777 nell'immagine", "Assegnare permessi minimi e owner corretto."),
    "dockerfile-sudo": (CAT_IMAGE, "", "sudo installato nell'immagine", "Non installare sudo: il container non deve elevare privilegi."),
    "dockerfile-no-healthcheck": (CAT_IMAGE, "4.6", "HEALTHCHECK assente nel Dockerfile",
                                  "Aggiungere HEALTHCHECK (o definirlo nel compose)."),
    "image-vulnerabilities": (CAT_VULN, "4.4", "CVE HIGH/CRITICAL nell'immagine",
                              "Aggiornare l'immagine base / i pacchetti alle versioni con fix e ricostruire."),
    "runc-vulnerable": (CAT_DAEMON, "1.2.2", "runc vulnerabile a container escape noti",
                        "Aggiornare docker/containerd.io (runc) all'ultima versione del proprio branch."),
    "docker-version-old": (CAT_DAEMON, "1.2.2", "Docker Engine datato", "Aggiornare Docker Engine a una release supportata."),
    "daemon-no-seccomp": (CAT_DAEMON, "2.16", "Seccomp non attivo sul daemon", "Abilitare seccomp nel kernel/daemon."),
    "daemon-rootful": (CAT_DAEMON, "2.9", "Daemon rootful senza userns-remap",
                       "Valutare rootless mode o \"userns-remap\": \"default\": root nel container != root sull'host."),
    "daemon-no-live-restore": (CAT_DAEMON, "2.14", "live-restore disattivato", "\"live-restore\": true in daemon.json."),
    "daemon-warning": (CAT_DAEMON, "", "Warning del daemon", "Vedi il messaggio del daemon."),
    "daemon-insecure-registry": (CAT_DAEMON, "2.5", "Registry insicuri configurati",
                                 "Rimuovere insecure-registries: le immagini viaggiano senza TLS (MITM)."),
    "daemon-experimental": (CAT_DAEMON, "2.17", "Funzionalita' sperimentali attive", "Disattivare experimental in produzione."),
    "daemon-debug": (CAT_DAEMON, "2.3", "Daemon in modalita' debug", "Disattivare debug in produzione."),
    "daemon-no-authz": (CAT_DAEMON, "2.12", "Nessun authorization plugin",
                        "Chiunque acceda al socket ha pieno controllo: limitare il gruppo docker / valutare un authz plugin."),
    "daemon-icc": (CAT_DAEMON, "2.2", "ICC abilitata di default", "\"icc\": false in daemon.json."),
    "daemon-no-new-privileges": (CAT_DAEMON, "2.18", "no-new-privileges non impostato a livello daemon",
                                 "\"no-new-privileges\": true in daemon.json."),
    "daemon-userland-proxy": (CAT_DAEMON, "2.15", "userland-proxy attivo", "\"userland-proxy\": false in daemon.json."),
    "daemon-log-rotation": (CAT_DAEMON, "", "Log dei container senza rotazione di default",
                            "\"log-opts\": {\"max-size\": \"10m\", \"max-file\": \"3\"} in daemon.json."),
    "daemon-tcp-no-tls": (CAT_DAEMON, "2.7", "API del daemon su TCP senza TLS",
                          "Rimuovere -H tcp:// o abilitare --tlsverify con certificati client: oggi chiunque "
                          "raggiunga la porta e' root sull'host."),
    "daemon-tcp-tls": (CAT_DAEMON, "2.7", "API del daemon su TCP con TLS", "Verificare che la porta non sia esposta a Internet."),
    "docker-api-listening": (CAT_DAEMON, "2.7", "Porta API Docker in ascolto sull'host",
                             "Verificare chi la raggiunge; senza TLS e' root remoto."),
    "socket-permissions": (CAT_DAEMON, "3.15/3.16", "Permessi del socket Docker troppo larghi",
                           "Il socket deve essere root:docker 660."),
    "docker-group-members": (CAT_DAEMON, "1.1.2", "Utenti nel gruppo docker (equivalente a root)",
                             "Lasciare nel gruppo docker solo gli account che ne hanno bisogno."),
    "swarm-manager": (CAT_DAEMON, "", "Nodo Swarm manager attivo", "Verificare che Swarm serva; altrimenti docker swarm leave."),
    "chain-exposed-escape": (CAT_CHAIN, "", "Servizio esposto + primitiva di escape",
                             "Rimuovere la primitiva di escape o togliere l'esposizione: una RCE nell'app diventa root sull'host."),
    "chain-exposed-vulnerable-root": (CAT_CHAIN, "", "Servizio esposto, eseguito come root, con CVE critiche",
                                      "Aggiornare l'immagine e passare a un utente non-root."),
    "chain-exposed-secrets": (CAT_CHAIN, "", "Servizio esposto con secret in chiaro e socket/host mount",
                              "Rimuovere i secret dall'env: una lettura arbitraria di file/env li espone."),
    "suspicious-process": (CAT_ANOMALY, "", "Processo sospetto nel container",
                           "Indagare subito: pattern tipico di miner, reverse shell o tunnel."),
    "persistence-fs-change": (CAT_ANOMALY, "", "File di persistenza/autenticazione modificati a runtime",
                              "Indagare: modifiche a passwd/shadow/cron/.ssh/ld.so.preload dopo l'avvio sono un IoC."),
    "runtime-binary-change": (CAT_ANOMALY, "", "Binari o librerie di sistema modificati a runtime",
                              "Il container non e' immutabile: pacchetti installati a mano o compromissione. Ricreare "
                              "dall'immagine e indagare."),
    "suspicious-fs-change": (CAT_ANOMALY, "", "File eseguibili o nascosti nelle directory temporanee",
                             "Verificare l'origine dei file: posizione tipica di payload scaricati."),
    "fs-drift": (CAT_ANOMALY, "", "Filesystem del container molto modificato dall'avvio",
                 "Valutare read_only: true e volumi espliciti per i dati."),
    "stale-container-image": (CAT_ANOMALY, "", "Container in esecuzione su un'immagine superata",
                              "Il tag e' stato aggiornato ma il container non e' stato ricreato: docker compose up -d."),
    "manual-container": (CAT_ANOMALY, "", "Container non gestito da compose",
                         "Avviato con docker run: configurazione non versionata, verificare che sia voluto."),
    "restart-loop": (CAT_ANOMALY, "", "Container in restart continuo", "Analizzare i log: crash ripetuti."),
    "unhealthy": (CAT_ANOMALY, "", "Healthcheck fallito", "Analizzare lo stato del servizio."),
    "oom-killed": (CAT_ANOMALY, "", "Container terminato per OOM", "Rivedere i limiti di memoria."),
}


# ---------------------------------------------------------------------------
# Finding helpers
# ---------------------------------------------------------------------------


def finding(severity: str, rule: str, target: str, message: str, source: str = "builtin",
            detail: str | None = None, category: str | None = None) -> dict:
    cat, cis, title, remediation = RULES.get(rule, (category or CAT_IMAGE, "", "", ""))
    f = {"severity": severity, "category": category or cat, "rule": rule, "target": target,
         "message": message, "source": source}
    if title:
        f["title"] = title
    if cis:
        f["cis"] = cis
    if remediation:
        f["remediation"] = remediation
    if detail:
        f["detail"] = detail
    return f


def is_secret_key(key: str) -> bool:
    # VAR_FILE punta a un file (pattern docker secrets), non contiene il secret;
    # *_TOKEN_EXPIRATION_TIME, *_AUTH_ENABLED ecc. sono configurazione, non credenziali
    return bool(SECRET_KEY_RE.search(key)) and not NON_SECRET_SUFFIX_RE.search(key)


def looks_like_secret_value(v: str) -> bool:
    return bool(v) and not v.startswith("${") and not TRIVIAL_VALUE_RE.match(v)


def mask(value: str) -> str:
    return f"***({len(value)} char)" if value else ""


def secret_patterns_in(value: str) -> list[str]:
    return [name for name, rx in SECRET_VALUE_PATTERNS if rx.search(value or "")]


def mask_patterns(value: str) -> str:
    """Maschera nel testo i soli match dei pattern di secret (il resto resta leggibile)."""
    if not value:
        return value
    for name, rx in SECRET_VALUE_PATTERNS:
        if name == "credenziali in URL":
            value = rx.sub(lambda m: m.group(0).replace(m.group(1), mask(m.group(1))), value)
        else:
            value = rx.sub(lambda m: mask(m.group(0)), value)
    return CMDLINE_SECRET_RE.sub(lambda m: m.group(0).replace(m.group(1), mask(m.group(1))), value)


def mask_kv(k: str, v) -> object:
    if v is None:
        return v
    return mask(str(v)) if is_secret_key(k) else mask_patterns(str(v))


def mask_env_list(env: list[str]) -> list[str]:
    out = []
    for item in env or []:
        k, sep, v = item.partition("=")
        out.append(f"{k}={mask_kv(k, v)}" if sep else item)
    return out


def mask_env_dict(env: dict) -> dict:
    return {k: mask_kv(k, v) for k, v in (env or {}).items()}


def as_list(v) -> list:
    if v is None:
        return []
    if isinstance(v, str):
        return shlex.split(v) if v.strip() else []
    return [str(x) for x in v]


def kv_map(v) -> dict:
    """compose accetta sia dict sia lista "K=V" per environment/labels/sysctls."""
    if isinstance(v, dict):
        return {str(k): ("" if x is None else str(x)) for k, x in v.items()}
    out = {}
    for item in v or []:
        k, _, x = str(item).partition("=")
        out[k] = x
    return out


# ---------------------------------------------------------------------------
# Normalizzazione: compose service / docker inspect -> spec comune
# ---------------------------------------------------------------------------
#
# spec = {
#   image, privileged, cap_add[], cap_drop[], security_opt[], network_mode, pid_mode, ipc_mode,
#   uts_mode, userns_mode, cgroupns_mode, user (None = non specificato), read_only,
#   mem_limit, pids_limit, cpu_limit, no_new_privs, oom_kill_disable, devices[],
#   device_cgroup_rules[], sysctls{}, env{k: v}, labels{}, command, healthcheck (True/False/None),
#   log_driver, log_opts{}, networks[], masked_paths_off,
#   mounts[{source, target, rw, type, propagation}], ports[{host_ip, host_port, container_port, proto}]
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
                        "target": v.get("target", ""), "rw": not v.get("read_only", False),
                        "propagation": ((v.get("bind") or {}).get("propagation") or "")})
            continue
        parts = str(v).split(":")
        if len(parts) == 1:  # volume anonimo
            out.append({"type": "volume", "source": "", "target": parts[0], "rw": True, "propagation": ""})
            continue
        src, tgt = parts[0], parts[1]
        mode = parts[2].split(",") if len(parts) > 2 else []
        kind = "bind" if src.startswith(("/", ".", "~")) else "volume"
        prop = next((m for m in mode if m in ("shared", "rshared", "slave", "rslave", "private", "rprivate")), "")
        out.append({"type": kind, "source": src, "target": tgt, "rw": "ro" not in mode, "propagation": prop})
    return out


def compose_healthcheck(hc) -> bool | None:
    if hc is None:
        return None  # puo' arrivare dall'immagine: non lo sappiamo staticamente
    if hc.get("disable") or as_list(hc.get("test"))[:1] == ["NONE"]:
        return False
    return True


def spec_from_compose(svc: dict) -> dict:
    limits = ((svc.get("deploy") or {}).get("resources") or {}).get("limits") or {}
    sec_opt = [str(s) for s in svc.get("security_opt") or []]
    logging = svc.get("logging") or {}
    return {
        "image": svc.get("image") or ("(build locale)" if svc.get("build") else ""),
        "privileged": bool(svc.get("privileged")),
        "cap_add": [str(c).upper().removeprefix("CAP_") for c in svc.get("cap_add") or []],
        "cap_drop": [str(c).upper().removeprefix("CAP_") for c in svc.get("cap_drop") or []],
        "security_opt": sec_opt,
        "network_mode": str(svc.get("network_mode") or ""),
        "pid_mode": str(svc.get("pid") or ""),
        "ipc_mode": str(svc.get("ipc") or ""),
        "uts_mode": str(svc.get("uts") or ""),
        "userns_mode": str(svc.get("userns_mode") or ""),
        "cgroupns_mode": str(svc.get("cgroup") or ""),
        "user": str(svc["user"]) if svc.get("user") is not None else None,
        "read_only": bool(svc.get("read_only")),
        "mem_limit": bool(svc.get("mem_limit") or limits.get("memory")),
        "pids_limit": bool(svc.get("pids_limit") or limits.get("pids")),
        "cpu_limit": bool(svc.get("cpus") or svc.get("cpu_quota") or svc.get("cpuset") or limits.get("cpus")),
        "no_new_privs": any("no-new-privileges" in s and not s.endswith("false") for s in sec_opt),
        "oom_kill_disable": bool(svc.get("oom_kill_disable")),
        "devices": [str(d) if not isinstance(d, dict) else d.get("source", "") for d in svc.get("devices") or []],
        "device_cgroup_rules": [str(r) for r in svc.get("device_cgroup_rules") or []],
        "sysctls": kv_map(svc.get("sysctls")),
        "env": kv_map(svc.get("environment")),
        "labels": kv_map(svc.get("labels")),
        "command": " ".join(as_list(svc.get("entrypoint")) + as_list(svc.get("command"))),
        "healthcheck": compose_healthcheck(svc.get("healthcheck")),
        "log_driver": logging.get("driver"),  # None = default del daemon, sconosciuto in statico
        "log_opts": logging.get("options") or {},
        "networks": list((svc.get("networks") or {}) if isinstance(svc.get("networks"), dict)
                         else svc.get("networks") or []),
        "masked_paths_off": any(s.replace(":", "=") == "systempaths=unconfined" for s in sec_opt),
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
    health = cfg.get("Healthcheck") or {}
    log_cfg = hc.get("LogConfig") or {}
    masked = hc.get("MaskedPaths")
    return {
        "image": cfg.get("Image", ""),
        "privileged": bool(hc.get("Privileged")),
        "cap_add": [str(x).upper().removeprefix("CAP_") for x in hc.get("CapAdd") or []],
        "cap_drop": [str(x).upper().removeprefix("CAP_") for x in hc.get("CapDrop") or []],
        "security_opt": sec_opt,
        "network_mode": hc.get("NetworkMode", ""),
        "pid_mode": hc.get("PidMode", ""),
        "ipc_mode": hc.get("IpcMode", ""),
        "uts_mode": hc.get("UTSMode", ""),
        "userns_mode": hc.get("UsernsMode", ""),
        "cgroupns_mode": hc.get("CgroupnsMode", ""),
        # In inspect Config.User include gia' l'USER dell'immagine: vuoto = root
        "user": cfg.get("User") or "",
        "read_only": bool(hc.get("ReadonlyRootfs")),
        "mem_limit": bool(hc.get("Memory")),
        "pids_limit": bool(hc.get("PidsLimit") and hc["PidsLimit"] > 0),
        "cpu_limit": bool(hc.get("NanoCpus") or (hc.get("CpuQuota") or 0) > 0 or hc.get("CpusetCpus")),
        "no_new_privs": any("no-new-privileges" in s and not s.endswith("false") for s in sec_opt),
        "oom_kill_disable": bool(hc.get("OomKillDisable")),
        "devices": [d.get("PathOnHost", "") for d in hc.get("Devices") or []],
        "device_cgroup_rules": hc.get("DeviceCgroupRules") or [],
        "sysctls": hc.get("Sysctls") or {},
        "env": kv_map(cfg.get("Env")),
        "labels": cfg.get("Labels") or {},
        "command": " ".join(as_list(cfg.get("Entrypoint")) + as_list(cfg.get("Cmd"))),
        "healthcheck": bool(health.get("Test")) and health.get("Test")[:1] != ["NONE"],
        "log_driver": log_cfg.get("Type", ""),
        "log_opts": log_cfg.get("Config") or {},
        "networks": list(((c.get("NetworkSettings") or {}).get("Networks") or {}).keys()),
        "masked_paths_off": (any(s.replace(":", "=") == "systempaths=unconfined" for s in sec_opt)
                             or (masked is not None and len(masked) == 0 and not hc.get("Privileged"))),
        "mounts": [{"type": m.get("Type", ""), "source": m.get("Source", ""), "target": m.get("Destination", ""),
                    "rw": bool(m.get("RW")), "propagation": m.get("Propagation", "")}
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


def check_secrets(target: str, spec: dict) -> list[dict]:
    f: list[dict] = []
    by_name: list[str] = []
    for k, v in spec["env"].items():
        if not looks_like_secret_value(v):
            continue
        pats = secret_patterns_in(v)
        if pats:
            f.append(finding("HIGH", "secret-pattern", target,
                             f"Variabile {k}: contiene {', '.join(pats)} in chiaro ({mask_patterns(v)[:80]})"))
        elif is_secret_key(k):
            by_name.append(k)
    if by_name:
        # una riga per container, non una per variabile: il problema (e il fix) e' lo stesso
        f.append(finding("MEDIUM", "env-secret", target,
                         f"{len(by_name)} secret in chiaro nell'env: {', '.join(sorted(by_name))}"))
    base = re.split(r"[:@]", (spec["image"] or "").rsplit("/", 1)[-1])[0].lower()
    if base in INFRA_IMAGES:
        allowed = INFRA_IMAGES[base]
        foreign = sorted(k for k, v in spec["env"].items()
                         if looks_like_secret_value(v) and (is_secret_key(k) or secret_patterns_in(v))
                         and not k.upper().startswith(allowed))
        if foreign:
            f.append(finding("MEDIUM", "env-overshare", target,
                             f"Container {base} con {len(foreign)} secret che non gli servono: "
                             f"{', '.join(foreign[:12])}{' ...' if len(foreign) > 12 else ''}"))
    for k, v in (spec["labels"] or {}).items():
        v = str(v or "")
        if not v or k.startswith(STANDARD_LABEL_PREFIXES):
            continue
        if "basicauth.users" in k.lower() or "digestauth.users" in k.lower():
            f.append(finding("MEDIUM", "label-secret", target,
                             f"Label {k}: hash di password nelle label (leggibili con docker inspect)."))
        elif secret_patterns_in(v):
            f.append(finding("HIGH", "secret-pattern", target,
                             f"Label {k}: contiene {', '.join(secret_patterns_in(v))} in chiaro."))
        elif is_secret_key(k.rsplit(".", 1)[-1]) and not v.startswith("${") and len(v) >= 6:
            f.append(finding("MEDIUM", "label-secret", target, f"Label {k}={mask(v)} sembra un secret."))
    cmd = spec.get("command") or ""
    if cmd:
        pats = secret_patterns_in(cmd)
        m = CMDLINE_SECRET_RE.search(cmd)
        if pats or m:
            f.append(finding("MEDIUM" if not pats else "HIGH", "cmdline-secret", target,
                             f"Secret nella riga di comando: {mask_patterns(cmd)[:160]}"))
    return f


def check_spec(target: str, spec: dict, live: bool) -> list[dict]:
    f: list[dict] = []

    if spec["privileged"]:
        f.append(finding("CRITICAL", "privileged", target,
                         "Container privileged: accesso completo ai device dell'host, escape banale."))

    for m in spec["mounts"]:
        src = (m["source"] or "").rstrip("/") or ("/" if m["source"] else "")
        if src in CONTAINER_SOCKETS or m["target"] in CONTAINER_SOCKETS:
            f.append(finding("CRITICAL", "docker-socket", target,
                             f"Socket del runtime montato ({m['source']} -> {m['target']}"
                             f"{', read-only' if not m['rw'] else ''}): chi controlla il container controlla l'host.",
                             detail="Anche in read-only il socket permette di creare container privilegiati."))
            continue
        if m.get("propagation") in ("shared", "rshared"):
            f.append(finding("MEDIUM", "mount-propagation", target,
                             f"Mount {m['source']} -> {m['target']} con propagation {m['propagation']}."))
        if m["type"] != "bind" or not src:
            continue
        for s in SENSITIVE_MOUNTS:
            if src == s or (s in SENSITIVE_SUBTREES and src.startswith(s + "/")):
                sev = "HIGH" if m["rw"] else "MEDIUM"
                if src == "/" or src in ("/proc", "/sys", "/var/lib/docker", "/dev"):
                    sev = "CRITICAL" if m["rw"] else "HIGH"
                f.append(finding(sev, "sensitive-mount", target,
                                 f"Path sensibile dell'host montato {'in scrittura' if m['rw'] else 'read-only'}: "
                                 f"{m['source']} -> {m['target']}"))
                break

    caps = sorted(set(spec["cap_add"]) & DANGEROUS_CAPS)
    if caps:
        sev = "CRITICAL" if set(caps) & {"ALL", "SYS_ADMIN", "SYS_MODULE"} else "HIGH"
        f.append(finding(sev, "dangerous-capabilities", target, f"Capability pericolose aggiunte: {', '.join(caps)}"))

    for field, label, sev in (("network_mode", "network", "HIGH"), ("pid_mode", "pid", "HIGH"),
                              ("ipc_mode", "ipc", "MEDIUM"), ("uts_mode", "uts", "MEDIUM"),
                              ("userns_mode", "userns", "MEDIUM"), ("cgroupns_mode", "cgroupns", "LOW")):
        if spec[field] == "host":
            f.append(finding(sev, f"{label}-host", target, f"Namespace {label} condiviso con l'host ({label}: host)."))

    # Docker aggiunge da solo label=disable ai container privileged / pid|ipc host:
    # in quel caso e' una conseguenza gia' segnalata, non una scelta esplicita
    implied_label = live and (spec["privileged"] or "host" in (spec["pid_mode"], spec["ipc_mode"]))
    for s in spec["security_opt"]:
        sl = s.lower().replace("=", ":")
        if sl == "label:disable" and implied_label:
            continue
        if sl in ("seccomp:unconfined", "apparmor:unconfined", "label:disable", "label:type:unconfined_t"):
            f.append(finding("HIGH", "security-profile-disabled", target, f"Profilo di sicurezza disattivato: {s}"))
    if spec["masked_paths_off"]:
        f.append(finding("HIGH", "systempaths-unconfined", target,
                         "Masked/readonly paths disattivati: /proc e /sys dell'host esposti al container."))

    for d in spec["devices"]:
        f.append(finding("MEDIUM", "host-device", target, f"Device dell'host esposto al container: {d}"))
    for r in spec["device_cgroup_rules"]:
        broad = re.match(r"^[abc]\s+\*:\*", r.strip()) or r.strip() == "a"
        f.append(finding("HIGH" if broad else "MEDIUM", "device-cgroup-rule", target, f"device_cgroup_rule: {r}"))
    for k, v in spec["sysctls"].items():
        if k.startswith("kernel.") or k.startswith("vm."):
            f.append(finding("MEDIUM", "unsafe-sysctl", target, f"sysctl {k}={v} (condivisa con l'host)."))

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
                                    "la porta e' raggiungibile anche se il firewall la blocca."))
        else:
            f.append(finding("LOW", "port-public", target, f"Porta {where} pubblicata su tutte le interfacce."))

    if live and spec["network_mode"] in ("default", "bridge"):
        f.append(finding("LOW", "default-bridge", target, "Container sulla rete bridge di default (docker0)."))

    f += check_secrets(target, spec)

    user = spec["user"]
    if live and (user in ("", "root", "0") or user.startswith(("root:", "0:"))):
        f.append(finding("MEDIUM", "root-user", target, "Il container gira come root."))
    elif not live and user is not None and (user in ("root", "0") or user.startswith(("root:", "0:"))):
        f.append(finding("MEDIUM", "root-user", target, f"user: {user} esplicito nel compose."))

    if not spec["privileged"]:
        if not spec["no_new_privs"]:
            f.append(finding("LOW", "no-new-privileges", target,
                             "Manca security_opt no-new-privileges:true (blocca escalation via setuid)."))
        if "ALL" not in spec["cap_drop"]:
            f.append(finding("LOW", "cap-drop-missing", target,
                             "Capability di default (es. NET_RAW, CHOWN, SETUID) non rimosse con cap_drop: [ALL]."))
    if not spec["read_only"]:
        f.append(finding("LOW", "writable-rootfs", target, "Filesystem root del container scrivibile."))
    if spec["healthcheck"] is False:
        f.append(finding("LOW", "no-healthcheck", target, "Nessun healthcheck definito."))
    if not spec["mem_limit"]:
        f.append(finding("LOW", "no-memory-limit", target, "Nessun limite di memoria."))
        if spec["oom_kill_disable"]:
            f.append(finding("MEDIUM", "oom-kill-disabled", target,
                             "OOM killer disattivato senza limite di memoria: puo' esaurire la RAM dell'host."))
    if not spec["pids_limit"]:
        f.append(finding("LOW", "no-pids-limit", target, "Nessun pids_limit (fork bomb possibile)."))
    if not spec["cpu_limit"]:
        f.append(finding("LOW", "no-cpu-limit", target, "Nessun limite di CPU."))
    if spec["log_driver"] == "none":
        f.append(finding("MEDIUM", "no-logging", target, "Log driver 'none': nessun log del container."))
    elif spec["log_driver"] == "json-file" and not (spec["log_opts"] or {}).get("max-size"):
        f.append(finding("LOW", "log-no-rotation", target, "Log json-file senza max-size."))

    img = spec["image"]
    if img and not img.startswith("(") and not img.startswith("sha256:"):
        name = img.split("@")[0]
        if "@" not in img and (":" not in name.rsplit("/", 1)[-1] or name.endswith(":latest")):
            f.append(finding("LOW", "image-latest", target, f"Immagine senza tag fisso: {img}"))

    return f


# ---------------------------------------------------------------------------
# Tool esterni: rilevamento ed esecuzione
# ---------------------------------------------------------------------------

LOCAL_TOOLS = ["docker", "hadolint", "trivy", "grype", "dockle", "kics", "docker-bench-security"]


def detect_local_tools(timeout: int) -> dict[str, str]:
    found = {t: p for t in LOCAL_TOOLS if (p := shutil.which(t))}
    if "docker" in found:
        # docker scout e' un plugin della CLI (incluso in Docker Desktop)
        rc, out, _ = common.run_cmd(["docker", "scout", "version"], min(timeout, 30))
        if rc == 0:
            found["docker-scout"] = "docker scout"
    return found


class HostShell:
    """Esegue script sh di sola lettura sull'host del daemon: via ssh se il
    daemon e' remoto, con sh in locale su Linux. Nessun file viene installato:
    lo script passa su stdin (`sh -s`)."""

    def __init__(self, argv: list[str], where: str, remote: bool):
        self.argv = argv
        self.where = where
        self.remote = remote

    def run(self, script: str, timeout: int) -> tuple[int, str, str]:
        # stdin in binario: in text mode su Windows "\n" diventa "\r\n" e sh rompe ogni riga
        try:
            p = subprocess.run(self.argv, input=script.encode(), capture_output=True, timeout=timeout, check=False)
        except FileNotFoundError:
            common.warn(f"{self.argv[0]} non trovato nel PATH: salto i check sull'host.")
            return 1, "", ""
        except subprocess.TimeoutExpired:
            common.warn(f"{self.where}: timeout dopo {timeout}s.")
            return 1, "", ""
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def resolve_endpoint(host: str | None, context: str | None, timeout: int) -> str:
    if host:
        return host
    if context:
        rc, out, _ = common.run_cmd(["docker", "context", "inspect", context, "--format",
                                     "{{.Endpoints.docker.Host}}"], timeout)
        if rc == 0:
            return out.strip()
    return ""


def build_host_shell(endpoint: str, info: dict) -> HostShell | None:
    if endpoint.startswith("ssh://"):
        u = urlsplit(endpoint)
        dest = f"{u.username}@{u.hostname}" if u.username else (u.hostname or "")
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15"]
        if u.port:
            argv += ["-p", str(u.port)]
        return HostShell(argv + [dest, "sh -s"], f"ssh {dest}", remote=True)
    if endpoint and not endpoint.startswith(("unix://", "npipe://")):
        common.warn(f"daemon su {endpoint}: niente accesso shell all'host, salto i check sull'host.")
        return None
    if not sys.platform.startswith("linux") or "Docker Desktop" in (info.get("OperatingSystem") or ""):
        common.warn("daemon in una VM (Docker Desktop) o host non Linux: salto i check sull'host.")
        return None
    return HostShell(["sh", "-s"], "locale", remote=False)


HOST_SCRIPT = r"""
echo '=====os====='; (grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null; uname -r)
echo '=====daemon_json====='; cat /etc/docker/daemon.json 2>/dev/null
echo '=====unit====='; systemctl cat docker.service 2>/dev/null | grep -E '^[[:space:]]*ExecStart='
echo '=====dockerd====='; ps -eo args 2>/dev/null | grep -E '[d]ockerd'
echo '=====sock====='; stat -c '%U:%G %a %n' /var/run/docker.sock /run/docker.sock 2>/dev/null
echo '=====group====='; getent group docker 2>/dev/null
echo '=====listen====='; (ss -ltnH 2>/dev/null || netstat -ltn 2>/dev/null)
echo '=====tools====='
for t in trivy grype dockle docker-bench-security; do p=$(command -v "$t" 2>/dev/null) && echo "$t=$p"; done
for d in /opt/docker-bench-security /usr/local/docker-bench-security /usr/share/docker-bench-security \
         /usr/local/share/docker-bench-security "$HOME/docker-bench-security" /root/docker-bench-security; do
  [ -f "$d/docker-bench-security.sh" ] && echo "docker-bench-dir=$d"
done
echo '=====sudo====='; (sudo -n true 2>/dev/null && echo yes) || echo no
echo '=====end====='
"""


def split_sections(out: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    cur = None
    for line in out.splitlines():
        m = re.fullmatch(r"=====([\w.-]+)=====", line.strip())
        if m:
            cur = m.group(1)
            sections[cur] = []
        elif cur:
            sections[cur].append(line)
    return {k: "\n".join(v).strip() for k, v in sections.items()}


def check_host(sections: dict[str, str], where: str) -> list[dict]:
    """Check sull'host da output testuale (daemon.json, unit, socket, gruppo, porte)."""
    f: list[dict] = []
    target = f"host {where}"
    dj: dict = {}
    if sections.get("daemon_json"):
        try:
            dj = json.loads(sections["daemon_json"])
        except json.JSONDecodeError:
            f.append(finding("LOW", "daemon-warning", target, "/etc/docker/daemon.json non e' JSON valido."))
    if "daemon_json" in sections:
        if not sections["daemon_json"]:
            target = f"host {where} (daemon.json assente: valori di default)"
        if dj.get("icc", True) is not False:
            f.append(finding("LOW", "daemon-icc", target, "icc non impostato a false in daemon.json."))
        if not dj.get("no-new-privileges"):
            f.append(finding("LOW", "daemon-no-new-privileges", target, "no-new-privileges non abilitato nel daemon."))
        if dj.get("userland-proxy", True) is not False:
            f.append(finding("INFO", "daemon-userland-proxy", target, "userland-proxy non disattivato."))
        log_opts = dj.get("log-opts") or {}
        if dj.get("log-driver", "json-file") == "json-file" and not log_opts.get("max-size"):
            f.append(finding("LOW", "daemon-log-rotation", target, "log-opts max-size non impostato in daemon.json."))
        if dj.get("ip") in ("127.0.0.1", "::1"):
            f.append(finding("INFO", "daemon-warning", target,
                             f"daemon.json \"ip\": {dj['ip']}: le porte pubblicate senza IP esplicito sono locali."))

    target = f"host {where}"
    args = " ".join([sections.get("unit", ""), sections.get("dockerd", "")])
    hosts = re.findall(r"(?:-H|--host)[=\s]+(tcp://\S+)", args) + [h for h in dj.get("hosts") or []
                                                                    if str(h).startswith("tcp://")]
    tls = "--tlsverify" in args or dj.get("tlsverify") is True
    for h in sorted(set(hosts)):
        if tls:
            f.append(finding("INFO", "daemon-tcp-tls", target, f"Daemon in ascolto su {h} con --tlsverify."))
        else:
            sev = "HIGH" if re.search(r"tcp://(127\.0\.0\.1|localhost)", h) else "CRITICAL"
            f.append(finding(sev, "daemon-tcp-no-tls", target, f"Daemon in ascolto su {h} SENZA --tlsverify."))

    for line in (sections.get("sock") or "").splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        owner, mode, path = parts[0], parts[1], parts[2]
        world = len(mode) >= 1 and mode[-1] not in ("0",)
        if world:
            f.append(finding("CRITICAL", "socket-permissions", target,
                             f"{path} {owner} {mode}: socket accessibile a tutti gli utenti locali = root per chiunque."))
        elif owner.split(":")[0] != "root" or mode not in ("660", "600"):
            f.append(finding("MEDIUM", "socket-permissions", target, f"{path} {owner} {mode} (atteso root:docker 660)."))

    grp = sections.get("group") or ""
    if grp:
        members = [m for m in grp.split(":")[-1].split(",") if m]
        if members:
            f.append(finding("MEDIUM" if len(members) > 2 else "INFO", "docker-group-members", target,
                             f"{len(members)} utenti nel gruppo docker (= root sull'host): {', '.join(members)}"))

    for line in (sections.get("listen") or "").splitlines():
        m = re.search(r"(\S+):(2375|2376)\s", line + " ")
        if m:
            addr, port = m.group(1), m.group(2)
            local = addr in ("127.0.0.1", "[::1]", "::1")
            sev = "INFO" if port == "2376" or local else "CRITICAL"
            f.append(finding(sev, "docker-api-listening", target, f"Porta {port} in ascolto su {addr}."))
    return f


def parse_host_tools(sections: dict[str, str]) -> dict[str, str]:
    tools: dict[str, str] = {}
    for line in (sections.get("tools") or "").splitlines():
        k, _, v = line.partition("=")
        if k and v:
            tools.setdefault(k, v)
    return tools


def bench_script(tools: dict[str, str], sudo: bool) -> str | None:
    """docker-bench-security, se gia' presente: log in una tmp dir rimossa a fine run."""
    s = "sudo -n " if sudo else ""
    if "docker-bench-dir" in tools:
        run = f"cd {shlex.quote(tools['docker-bench-dir'])} && {s}sh docker-bench-security.sh"
    elif "docker-bench-security" in tools:
        run = f"{s}{shlex.quote(tools['docker-bench-security'])}"
    else:
        return None
    return (f'T=$(mktemp -d) || exit 1\n'
            f'({run} -b -l "$T/bench.log") >/dev/null 2>&1\n'
            f'{s}cat "$T/bench.log.json" 2>/dev/null\n'
            f'{s}rm -rf "$T"\n')


BENCH_CATEGORY = {"1": CAT_DAEMON, "2": CAT_DAEMON, "3": CAT_DAEMON, "4": CAT_IMAGE, "5": CAT_HARDEN,
                  "6": CAT_ANOMALY, "7": CAT_DAEMON, "8": CAT_DAEMON}


def parse_bench(data: dict, where: str) -> list[dict]:
    f: list[dict] = []
    for section in data.get("tests") or []:
        for r in section.get("results") or []:
            if r.get("result") != "WARN":
                continue
            rid = str(r.get("id", ""))
            items = r.get("items") or []
            detail = ", ".join(str(i) for i in items[:10]) + (f" (+{len(items) - 10})" if len(items) > 10 else "")
            f.append(finding("MEDIUM", f"CIS-{rid}", f"host {where}", r.get("desc", ""), source="docker-bench",
                             detail=detail or r.get("details") or None,
                             category=BENCH_CATEGORY.get(rid.split(".")[0], CAT_DAEMON)))
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


def logical_lines(text: str) -> list[tuple[int, str]]:
    """Righe del Dockerfile con le continuazioni (\\) unite, con il numero della prima riga."""
    out: list[tuple[int, str]] = []
    buf, start = "", 0
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not buf and (not s or s.startswith("#")):
            continue
        if s.startswith("#"):
            continue
        if not buf:
            start = n
        if s.endswith("\\"):
            buf += s[:-1] + " "
            continue
        out.append((start, buf + s))
        buf = ""
    if buf:
        out.append((start, buf))
    return out


def dockerfile_builtin(path: Path) -> list[dict]:
    """Check integrati, utili anche quando hadolint/trivy non sono installati."""
    target = f"Dockerfile {path}"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        common.warn(f"lettura {path}: {e}")
        return []
    f: list[dict] = []
    last_user = None
    stage = ""
    stage_users: dict[str, str | None] = {}
    healthcheck = False
    for n, s in logical_lines(text):
        instr, _, rest = s.partition(" ")
        instr = instr.upper()
        if instr == "FROM":
            if stage:
                stage_users[stage] = last_user
            words = [w for w in rest.split() if not w.startswith("--")]
            img = words[0] if words else ""
            stage = words[2].lower() if len(words) >= 3 and words[1].upper() == "AS" else ""
            # FROM <stage precedente> eredita il suo USER; un'immagine esterna riparte da root
            # (salvo il suo USER, che staticamente non conosciamo)
            internal = img.lower() in stage_users
            last_user = stage_users[img.lower()] if internal else None
            if img and not internal and img.lower() != "scratch" and "$" not in img and "@" not in img and (
                    ":" not in img.rsplit("/", 1)[-1] or img.endswith(":latest")):
                f.append(finding("LOW", "image-latest", target, f"riga {n}: FROM senza tag fisso ({img})"))
        elif instr == "USER":
            last_user = rest.strip()
        elif instr == "HEALTHCHECK":
            healthcheck = "NONE" not in rest.upper().split()
        elif instr in ("ENV", "ARG"):
            key = re.split(r"[=\s]", rest.strip(), maxsplit=1)[0]
            if key and is_secret_key(key) and ("=" in rest or instr == "ENV"):
                f.append(finding("MEDIUM", "dockerfile-secret", target,
                                 f"riga {n}: {instr} {key} — i secret in ENV/ARG restano nei layer dell'immagine."))
            elif secret_patterns_in(rest):
                f.append(finding("HIGH", "secret-pattern", target,
                                 f"riga {n}: {instr} con {', '.join(secret_patterns_in(rest))} in chiaro."))
        elif instr == "ADD" and re.search(r"https?://", rest):
            f.append(finding("LOW", "add-remote-url", target, f"riga {n}: ADD da URL remoto senza verifica checksum."))
        elif instr == "EXPOSE" and re.search(r"(^|\s)22(/tcp)?(\s|$)", rest):
            f.append(finding("MEDIUM", "dockerfile-expose-ssh", target, f"riga {n}: EXPOSE 22."))
        elif instr == "RUN":
            if re.search(r"(curl|wget)[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", rest):
                f.append(finding("MEDIUM", "pipe-to-shell", target, f"riga {n}: download eseguito direttamente in una shell."))
            if re.search(r"(curl\s[^|;&]*(\s-k\b|--insecure)|--no-check-certificate|--trusted-host|"
                         r"sslverify\s*=\s*(0|false)|strict-ssl\s+false|GIT_SSL_NO_VERIFY)", rest, re.IGNORECASE):
                f.append(finding("MEDIUM", "tls-verification-disabled", target, f"riga {n}: verifica TLS disattivata."))
            if re.search(r"chmod\s+(-R\s+)?0?777\b", rest):
                f.append(finding("LOW", "dockerfile-chmod-777", target, f"riga {n}: chmod 777."))
            if re.search(r"(apt-get|apt|apk|yum|dnf)\s+(install|add)\b[^;&|]*\bsudo\b", rest):
                f.append(finding("LOW", "dockerfile-sudo", target, f"riga {n}: installazione di sudo."))
            if secret_patterns_in(rest):
                f.append(finding("HIGH", "secret-pattern", target,
                                 f"riga {n}: RUN con {', '.join(secret_patterns_in(rest))} in chiaro."))
    if last_user is None or last_user.split(":")[0] in ("root", "0"):
        f.append(finding("MEDIUM", "dockerfile-root", target, "Nessun USER non-root nello stage finale."))
    if not healthcheck:
        f.append(finding("LOW", "dockerfile-no-healthcheck", target, "Nessuna istruzione HEALTHCHECK."))
    return f


def run_hadolint(path: Path, rawdir: Path, timeout: int) -> list[dict]:
    rc, out, err = common.run_cmd(["hadolint", "-f", "json", "--no-fail", str(path)], timeout)
    try:
        items = json.loads(out or "[]")
    except json.JSONDecodeError:
        common.warn(f"hadolint output non JSON per {path}: {err.strip()[:200]}")
        return []
    (rawdir / f"hadolint-{file_tag(path)}.json").write_text(json.dumps(items, indent=2), encoding="utf-8")
    sev = {"error": "MEDIUM", "warning": "LOW", "info": "INFO", "style": "INFO"}
    return [finding(sev.get(i.get("level"), "INFO"), i.get("code", "hadolint"), f"Dockerfile {path}",
                    f"riga {i.get('line')}: {i.get('message')}", source="hadolint", category=CAT_IMAGE)
            for i in items]


def parse_trivy(data: dict, target_prefix: str) -> tuple[list[dict], list[dict]]:
    """Ritorna (findings misconfig+secret, lista vulnerabilita')."""
    f: list[dict] = []
    vulns: list[dict] = []
    for res in data.get("Results") or []:
        tgt = f"{target_prefix} [{res.get('Target', '')}]"
        for m in res.get("Misconfigurations") or []:
            if m.get("Status", "FAIL") != "FAIL":
                continue
            f.append(finding(m.get("Severity", "INFO"), m.get("AVDID") or m.get("ID", "trivy"), tgt,
                             m.get("Title") or m.get("Message", ""), source="trivy",
                             detail=m.get("Message"), category=CAT_IMAGE))
        for s in res.get("Secrets") or []:
            f.append(finding("HIGH", s.get("RuleID", "secret"), tgt,
                             f"Secret nell'immagine: {s.get('Title', '')} (riga {s.get('StartLine')})",
                             source="trivy", category=CAT_SECRETS))
        for v in res.get("Vulnerabilities") or []:
            vulns.append({"id": v.get("VulnerabilityID"), "pkg": v.get("PkgName"),
                          "installed": v.get("InstalledVersion"), "fixed": v.get("FixedVersion", ""),
                          "severity": (v.get("Severity") or "").upper(), "title": v.get("Title", "")})
    return f, vulns


def run_trivy_config(path: Path, rawdir: Path, timeout: int) -> list[dict]:
    rc, out, err = common.run_cmd(["trivy", "config", "--quiet", "--format", "json", str(path)], timeout)
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        common.warn(f"trivy config fallito su {path}: {err.strip()[:200]}")
        return []
    (rawdir / f"trivy-config-{file_tag(path)}.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    f, _ = parse_trivy(data, "trivy config")
    return f


def run_kics(path: Path, rawdir: Path, timeout: int) -> list[dict]:
    """KICS copre anche docker-compose (trivy config no)."""
    with tempfile.TemporaryDirectory() as tmp:
        common.run_cmd(["kics", "scan", "-p", str(path), "-o", tmp, "--report-formats", "json",
                        "--output-name", "kics", "--type", "Dockerfile,DockerCompose",
                        "--no-progress", "--silent", "--disable-secrets"], timeout)
        rep = Path(tmp) / "kics.json"
        if not rep.exists():
            common.warn(f"kics non ha prodotto output per {path}.")
            return []
        data = json.loads(rep.read_text(encoding="utf-8"))
    (rawdir / f"kics-{file_tag(path)}.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    f: list[dict] = []
    for q in data.get("queries") or []:
        sev = (q.get("severity") or "INFO").upper()
        sev = sev if sev in SEV_RANK else "INFO"
        for loc in q.get("files") or []:
            f.append(finding(sev, f"kics:{q.get('query_name', q.get('query_id', ''))}",
                             f"file {loc.get('file_name', '')}",
                             f"riga {loc.get('line')}: {q.get('query_name', '')} — "
                             f"atteso {loc.get('expected_value', '')}", source="kics", category=CAT_HARDEN))
    return f


def static_audit(paths: list[str], rawdir: Path, timeout: int, tools: dict) -> tuple[list[dict], dict]:
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
        masked = {"services": {n: {**(s or {}), "environment": mask_env_dict(kv_map((s or {}).get("environment")))}
                               for n, s in (data.get("services") or {}).items()}}
        (rawdir / f"compose-{file_tag(group[0])}.json").write_text(json.dumps(masked, indent=2), encoding="utf-8")
        for name, svc in (data.get("services") or {}).items():
            findings += check_spec(f"service {name} ({group[0].parent.name}/{label})", spec_from_compose(svc or {}),
                                   live=False)

    for d in dockerfiles:
        findings += dockerfile_builtin(d)
        if "hadolint" in tools:
            findings += run_hadolint(d, rawdir, timeout)
    roots = [Path(raw).expanduser().resolve() for raw in paths if Path(raw).expanduser().exists()]
    if dockerfiles and "trivy" in tools:
        # trivy config una volta per path passato (scansiona ricorsivamente)
        for p in roots:
            findings += run_trivy_config(p, rawdir, timeout)
    if (dockerfiles or composes) and "kics" in tools:
        for p in roots:
            findings += run_kics(p, rawdir, timeout)
    for t, why in (("hadolint", "solo check integrati sui Dockerfile"), ("trivy", "salto trivy config"),
                   ("kics", "salto kics (compose + Dockerfile)")):
        if t not in tools:
            common.warn(f"{t} non disponibile: {why}.")
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


def docker_json(docker: list[str], args: list[str], timeout: int):
    rc, out, err = common.run_cmd(docker + args, timeout)
    try:
        return json.loads(out) if out.strip() else None
    except json.JSONDecodeError:
        if err.strip():
            common.warn(f"docker {' '.join(args[:2])}: {err.strip()[:200]}")
        return None


def version_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:3]) or (0,)


def check_versions(version: dict, target: str) -> list[dict]:
    f: list[dict] = []
    server = version.get("Server") or {}
    comps = {c.get("Name"): c.get("Version", "") for c in server.get("Components") or []}
    runc = comps.get("runc", "")
    if runc:
        v = version_tuple(runc)
        for cve, desc, vulnerable in RUNC_CVES:
            if vulnerable(v):
                f.append(finding("CRITICAL", "runc-vulnerable", target, f"runc {runc}: {cve} — {desc}"))
    engine = server.get("Version", "")
    if engine and version_tuple(engine)[0] < 25:
        f.append(finding("MEDIUM", "docker-version-old", target,
                         f"Docker Engine {engine}: release datata, probabilmente senza patch di sicurezza."))
    return f


def check_daemon(info: dict, target: str) -> list[dict]:
    f: list[dict] = []
    opts = " ".join(info.get("SecurityOptions") or [])
    if "seccomp" not in opts:
        f.append(finding("HIGH", "daemon-no-seccomp", target, "Seccomp non attivo sul daemon."))
    if "rootless" not in opts and "userns" not in opts:
        f.append(finding("LOW", "daemon-rootful", target,
                         "Daemon rootful senza userns-remap: root nel container = root sull'host in caso di escape."))
    if not info.get("LiveRestoreEnabled"):
        f.append(finding("INFO", "daemon-no-live-restore", target, "live-restore disattivato."))
    if info.get("ExperimentalBuild"):
        f.append(finding("LOW", "daemon-experimental", target, "Funzionalita' sperimentali abilitate."))
    if info.get("Debug"):
        f.append(finding("LOW", "daemon-debug", target, "Daemon in modalita' debug."))
    if info.get("LoggingDriver") == "none":
        f.append(finding("MEDIUM", "no-logging", target, "Logging driver di default 'none'."))
    plugins = (info.get("Plugins") or {}).get("Authorization") or []
    if not plugins:
        f.append(finding("INFO", "daemon-no-authz", target, "Nessun authorization plugin: il socket e' all-or-nothing."))
    insecure = [c for c in ((info.get("RegistryConfig") or {}).get("InsecureRegistryCIDRs") or [])
                if c not in ("127.0.0.0/8", "::1/128")]
    insecure += [n for n, v in ((info.get("RegistryConfig") or {}).get("IndexConfigs") or {}).items()
                 if not v.get("Secure", True)]
    if insecure:
        f.append(finding("HIGH", "daemon-insecure-registry", target, f"Registry insicuri: {', '.join(insecure)}"))
    swarm = info.get("Swarm") or {}
    if swarm.get("LocalNodeState") == "active" and swarm.get("ControlAvailable"):
        f.append(finding("INFO", "swarm-manager", target, "Il nodo e' uno Swarm manager."))
    for w in info.get("Warnings") or []:
        sev = "CRITICAL" if "without encryption" in w or "2375" in w else "INFO"
        f.append(finding(sev, "daemon-warning", target, w.strip()))
    return f


def check_networks(networks: list[dict]) -> list[dict]:
    f: list[dict] = []
    for n in networks or []:
        name = n.get("Name", "")
        opts = n.get("Options") or {}
        members = len(n.get("Containers") or {})
        if name == "bridge" and opts.get("com.docker.network.bridge.enable_icc", "true") != "false" and members >= 2:
            f.append(finding("LOW", "default-bridge-icc", f"network {name}",
                             f"{members} container sul bridge di default con ICC attiva: si raggiungono tutti tra loro."))
        if n.get("Driver") == "overlay" and "encrypted" not in opts and not n.get("Ingress"):
            f.append(finding("MEDIUM", "overlay-unencrypted", f"network {name}", "Overlay senza --opt encrypted."))
        if n.get("Driver") in ("macvlan", "ipvlan") and members:
            f.append(finding("INFO", "host-lan-network", f"network {name}",
                             f"{members} container con IP diretto sulla LAN ({n.get('Driver')})."))
    return f


def parse_docker_date(s: str) -> datetime | None:
    m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", s or "")
    if not m:
        return None
    return datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)


def check_state(target: str, c: dict, labels: dict) -> list[dict]:
    f: list[dict] = []
    st = c.get("State") or {}
    if c.get("RestartCount", 0) >= 5:
        if st.get("ExitCode", 0) != 0:
            f.append(finding("MEDIUM", "restart-loop", target,
                             f"{c['RestartCount']} restart dall'ultimo avvio, ultimo exit code {st.get('ExitCode')}."))
        else:
            # es. worker Laravel/Celery con --max-time/--max-jobs: escono puliti e Docker li riavvia
            f.append(finding("INFO", "restart-loop", target,
                             f"{c['RestartCount']} restart con exit code 0 (probabile worker a ciclo di vita limitato)."))
    if (st.get("Health") or {}).get("Status") == "unhealthy":
        f.append(finding("MEDIUM", "unhealthy", target, "Stato healthcheck: unhealthy."))
    if st.get("OOMKilled"):
        f.append(finding("LOW", "oom-killed", target, "Ultima terminazione per OOM."))
    if not labels.get("com.docker.compose.project") and not labels.get("com.docker.stack.namespace") \
            and not labels.get("io.kubernetes.pod.name"):
        f.append(finding("INFO", "manual-container", target, "Container avviato fuori da compose/stack."))
    return f


def check_image(target: str, spec: dict, c: dict, images: dict[str, dict]) -> list[dict]:
    f: list[dict] = []
    img = images.get(c.get("Image", ""))
    if img:
        created = parse_docker_date(img.get("Created", ""))
        if created:
            age = (datetime.now(timezone.utc) - created).days
            if age > 365:
                f.append(finding("MEDIUM", "image-old", target, f"Immagine {spec['image']} creata {age} giorni fa."))
            elif age > 180:
                f.append(finding("LOW", "image-old", target, f"Immagine {spec['image']} creata {age} giorni fa."))
    tagged = images.get(spec["image"])
    if tagged and tagged.get("Id") and c.get("Image") and tagged["Id"] != c["Image"]:
        f.append(finding("LOW", "stale-container-image", target,
                         f"Il tag {spec['image']} punta a {tagged['Id'][7:19]}, il container usa {c['Image'][7:19]}."))
    return f


def process_users(top: dict | None) -> set[str]:
    if not top:
        return set()
    titles = [t.upper() for t in top.get("Titles") or []]
    col = next((titles.index(c) for c in ("USER", "UID") if c in titles), None)
    return {p[col] for p in top.get("Processes") or [] if col is not None and len(p) > col}


def check_processes(target: str, top: dict | None) -> list[dict]:
    f: list[dict] = []
    if not top:
        return f
    titles = [t.upper() for t in top.get("Titles") or []]
    for proc in top.get("Processes") or []:
        row = dict(zip(titles, proc))
        args = row.get("COMMAND") or row.get("ARGS") or row.get("CMD") or " ".join(proc)
        user = row.get("USER") or row.get("UID") or ""
        if re.search(r"(^|/)sshd(\s|$|:)", args):
            f.append(finding("MEDIUM", "sshd-in-container", target, f"sshd in esecuzione ({user}): {args[:120]}"))
        m = SUSPICIOUS_PROC_RE.search(args)
        if m:
            f.append(finding("HIGH", "suspicious-process", target,
                             f"Processo sospetto ({m.group(0)}), utente {user}: {mask_patterns(args)[:160]}"))
    return f


def check_diff(target: str, changes: list[str]) -> list[dict]:
    f: list[dict] = []
    persistence, binaries, tmp = [], [], []
    for line in changes:
        kind, _, path = line.partition(" ")
        if kind not in ("A", "C"):
            continue
        if PERSISTENCE_PATHS.match(path):
            persistence.append(f"{kind} {path}")
        elif BINARY_DIRS.match(path) and not path.endswith((".pyc", ".cache")) and "__pycache__" not in path:
            binaries.append(f"{kind} {path}")
        elif TMP_DIRS.match(path) and TMP_SUSPICIOUS.search(path) and not TMP_BENIGN.search(path):
            tmp.append(f"{kind} {path}")

    def sample(xs: list[str]) -> str:
        return ", ".join(xs[:8]) + (f" (+{len(xs) - 8})" if len(xs) > 8 else "")

    accounts = [x for x in persistence if re.search(r" /etc/(passwd|group|shadow|gshadow)$", x)]
    strong = [x for x in persistence if x not in accounts]
    if strong:
        sev = "HIGH" if any(re.search(r"(\.ssh|sudoers|ld\.so\.preload|pam\.d|sshd_config)", x) for x in strong)             else "MEDIUM"
        f.append(finding(sev, "persistence-fs-change", target, f"{len(strong)} file di persistenza modificati: "
                                                               f"{sample(strong)}"))
    if accounts:
        f.append(finding("MEDIUM", "persistence-fs-change", target,
                         f"Account modificati a runtime ({sample(accounts)}): spesso usermod/groupmod "
                         "nell'entrypoint, verificare (vedi anche extra-uid0)."))
    if binaries:
        only_scripts = len(binaries) <= 3 and all(b.endswith(".sh") for b in binaries)
        f.append(finding("LOW" if only_scripts else "MEDIUM", "runtime-binary-change", target, f"{len(binaries)} file in directory di sistema: "
                                                                    f"{sample(binaries)}"))
    if tmp:
        f.append(finding("MEDIUM", "suspicious-fs-change", target, f"{len(tmp)} file eseguibili/nascosti in tmp: "
                                                                   f"{sample(tmp)}"))
    if len(changes) >= 200:
        f.append(finding("INFO", "fs-drift", target, f"{len(changes)} modifiche al filesystem dall'avvio."))
    return f


def probe_container(docker: list[str], cid: str, running: bool, timeout: int) -> tuple[dict | None, list[str]]:
    """docker top + docker diff: entrambi read-only, eseguiti dal daemon sull'host."""
    top = None
    if running:
        # ps lato host filtrato sui PID del container; -e serve, altrimenti ps vede solo la propria sessione
        rc, out, _ = common.run_cmd(docker + ["top", cid, "-eo", "user,pid,args"], timeout)
        if rc == 0 and out.strip():
            lines = out.splitlines()
            titles = lines[0].split()
            procs = [ln.split(None, len(titles) - 1) for ln in lines[1:] if ln.strip()]
            top = {"Titles": titles, "Processes": procs}
    rc, out, _ = common.run_cmd(docker + ["diff", cid], timeout)
    changes = out.splitlines() if rc == 0 else []
    return top, changes


# ---------------------------------------------------------------------------
# Scansione immagini (trivy / grype / dockle / docker scout)
# ---------------------------------------------------------------------------


def parse_grype(data: dict) -> list[dict]:
    out = []
    for m in data.get("matches") or []:
        v = m.get("vulnerability") or {}
        a = m.get("artifact") or {}
        out.append({"id": v.get("id"), "pkg": a.get("name"), "installed": a.get("version"),
                    "fixed": ", ".join((v.get("fix") or {}).get("versions") or []),
                    "severity": (v.get("severity") or "").upper(), "title": v.get("description", "")[:120]})
    return out


def parse_scout_sarif(data: dict) -> list[dict]:
    out = []
    for run in data.get("runs") or []:
        rules = {r.get("id"): r for r in ((run.get("tool") or {}).get("driver") or {}).get("rules") or []}
        for res in run.get("results") or []:
            props = (rules.get(res.get("ruleId")) or {}).get("properties") or {}
            sev = str(props.get("cvssV3_severity") or "").upper()
            if not sev:
                try:
                    score = float(props.get("security-severity", 0))
                except (TypeError, ValueError):
                    score = 0
                sev = "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
            purls = props.get("purls") or []
            out.append({"id": res.get("ruleId"), "pkg": purls[0] if purls else "",
                        "installed": props.get("affected_version", ""), "fixed": props.get("fixed_version", ""),
                        "severity": sev, "title": ""})
    return out


def parse_dockle(data: dict, image: str) -> list[dict]:
    sev = {"FATAL": "HIGH", "WARN": "MEDIUM", "INFO": "LOW"}
    f = []
    for d in data.get("details") or []:
        level = d.get("level", "")
        if level not in sev:
            continue
        cat = CAT_SECRETS if d.get("code") in ("CIS-DI-0010", "DKL-DI-0005") else CAT_IMAGE
        f.append(finding(sev[level], d.get("code", "dockle"), f"image {image}", d.get("title", ""),
                         source="dockle", detail="; ".join((d.get("alerts") or [])[:5]) or None, category=cat))
    return f


class ImageScanner:
    def __init__(self, docker: list[str], local_daemon: bool, local_tools: dict, shell: HostShell | None,
                 host_tools: dict, only: set[str] | None, rawdir: Path, timeout: int):
        self.docker = docker
        self.local_daemon = local_daemon
        self.shell = shell if shell and shell.remote else None
        self.rawdir = rawdir
        self.timeout = timeout
        self.disabled: set[str] = set()
        want = only or {"trivy", "grype", "dockle", "docker-scout"}
        # dove gira ogni scanner: "remote" (sul server, se gia' installato) o "local"
        self.plan: dict[str, str] = {}
        for t in ("trivy", "grype", "dockle"):
            if t not in want:
                continue
            if self.shell and t in host_tools:
                self.plan[t] = "remote"
            elif t in local_tools:
                self.plan[t] = "local"
        # docker scout richiede login a Docker Hub: solo se mancano trivy e grype
        if "docker-scout" in want and "docker-scout" in local_tools and not ({"trivy", "grype"} & set(self.plan)):
            self.plan["docker-scout"] = "local"

    def _run(self, tool: str, where: str, image: str, tar: Path | None) -> tuple[int, str, str]:
        q = shlex.quote(image)
        if where == "remote":
            cmds = {
                "trivy": f"trivy image --quiet --format json --severity HIGH,CRITICAL --scanners vuln,secret "
                         f"--image-config-scanners misconfig,secret {q}",
                "grype": f"grype docker:{q} -o json -q",
                "dockle": f"dockle -f json {q}",
            }
            return self.shell.run(cmds[tool], self.timeout)
        src_trivy = ["--input", str(tar)] if tar else [image]
        cmds = {
            "trivy": ["trivy", "image", "--quiet", "--format", "json", "--severity", "HIGH,CRITICAL",
                      "--scanners", "vuln,secret", "--image-config-scanners", "misconfig,secret", *src_trivy],
            "grype": ["grype", f"docker-archive:{tar}" if tar else f"docker:{image}", "-o", "json", "-q"],
            "dockle": ["dockle", "-f", "json", *(["--input", str(tar)] if tar else [image])],
            "docker-scout": ["docker", "scout", "cves", "--format", "sarif", "--only-severity", "critical,high",
                             f"archive://{tar}" if tar else image],
        }
        return common.run_cmd(cmds[tool], self.timeout)

    def scan(self, image: str) -> tuple[list[dict], dict]:
        findings: list[dict] = []
        vulns: dict[tuple, dict] = {}
        used: list[str] = []
        need_tar = not self.local_daemon and any(w == "local" for w in self.plan.values())
        with tempfile.TemporaryDirectory() as tmp:
            tar = None
            if need_tar:
                # i tool locali non parlano col daemon remoto via ssh://: esportiamo l'immagine una volta
                tar = Path(tmp) / "image.tar"
                common.log(f"docker save {image} (remoto -> locale)")
                rc, _, err = common.run_cmd(self.docker + ["save", "-o", str(tar), image], self.timeout)
                if rc != 0 or not tar.exists():
                    common.warn(f"docker save {image} fallito: {err.strip()[:200]}")
                    tar = None
            for tool, where in self.plan.items():
                if tool in self.disabled or (where == "local" and need_tar and tar is None):
                    continue
                common.log(f"{tool} ({'server' if where == 'remote' else 'locale'}) {image}")
                rc, out, err = self._run(tool, where, image, tar)
                try:
                    data = json.loads(out)
                except json.JSONDecodeError:
                    msg = (err.strip() or out.strip())
                    if tool == "docker-scout" and "Log in" in msg:
                        common.warn("docker scout richiede `docker login` (account Docker Hub): lo disattivo.")
                        self.disabled.add(tool)
                    else:
                        common.warn(f"{tool} su {image} fallito: {msg.splitlines()[-1][:200] if msg else 'nessun output'}")
                    continue
                used.append(f"{tool}@{'server' if where == 'remote' else 'locale'}")
                (self.rawdir / f"{tool}-image-{safe_name(image)}.json").write_text(
                    json.dumps(data, indent=2), encoding="utf-8")
                if tool == "trivy":
                    f, vs = parse_trivy(data, f"image {image}")
                    findings += f
                elif tool == "grype":
                    vs = parse_grype(data)
                elif tool == "docker-scout":
                    vs = parse_scout_sarif(data)
                else:
                    findings += parse_dockle(data, image)
                    vs = []
                for v in vs:
                    if v["severity"] in ("HIGH", "CRITICAL"):
                        vulns.setdefault((v["id"], v["pkg"]), {**v, "sources": []})["sources"].append(tool)
        vl = sorted(vulns.values(), key=lambda v: (SEV_RANK.get(v["severity"], 9), v["id"] or ""))
        counts = {s: sum(1 for v in vl if v["severity"] == s) for s in ("CRITICAL", "HIGH")}
        fixable = sum(1 for v in vl if v.get("fixed"))
        if vl:
            findings.append(finding("CRITICAL" if counts["CRITICAL"] else "HIGH", "image-vulnerabilities",
                                    f"image {image}",
                                    f"CVE: {counts['CRITICAL']} CRITICAL, {counts['HIGH']} HIGH "
                                    f"({fixable} con fix disponibile)", source="+".join(sorted({u.split('@')[0] for u in used})),
                                    detail="; ".join(f"{v['id']} {v['pkg']} {v['installed']}"
                                                     f"{' -> ' + v['fixed'] if v['fixed'] else ' (no fix)'}"
                                                     for v in vl[:8])))
        return findings, {"counts": counts, "fixable": fixable, "scanners": used, "vulnerabilities": vl}


# ---------------------------------------------------------------------------
# Orchestrazione live
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Analisi integrata approfondita (nessun tool esterno, tutto read-only)
# ---------------------------------------------------------------------------
#
# Senza trivy/grype non abbiamo il database delle CVE, ma un sistema operativo
# o un runtime fuori supporto e' il miglior indicatore disponibile: non riceve
# piu' patch di sicurezza, quindi accumula CVE note senza fix.

# fine supporto (date ufficiali; per Debian/Ubuntu si considera la fine LTS/standard)
OS_EOL = {
    "alpine": {"3.15": "2023-11-01", "3.16": "2024-05-23", "3.17": "2024-11-22", "3.18": "2025-05-09",
               "3.19": "2025-11-01", "3.20": "2026-04-01", "3.21": "2026-11-01", "3.22": "2027-05-01"},
    "debian": {"8": "2020-06-30", "9": "2022-06-30", "10": "2024-06-30", "11": "2026-08-31", "12": "2028-06-30"},
    "ubuntu": {"14.04": "2019-04-30", "16.04": "2021-04-30", "18.04": "2023-05-31", "20.04": "2025-05-31",
               "22.04": "2027-06-01", "24.04": "2029-05-31"},
    "centos": {"7": "2024-06-30", "8": "2021-12-31"},
    "rhel": {"7": "2024-06-30"},
    "amzn": {"2": "2026-06-30"},
}
RUNTIME_EOL = {
    # variabile d'ambiente delle immagini ufficiali -> (nome, {major: data fine supporto})
    "PHP_VERSION": ("PHP", {"7.4": "2022-11-28", "8.0": "2023-11-26", "8.1": "2025-12-31", "8.2": "2026-12-31",
                            "8.3": "2027-12-31", "8.4": "2028-12-31"}),
    "NODE_VERSION": ("Node.js", {"14": "2023-04-30", "16": "2023-09-11", "18": "2025-04-30", "20": "2026-04-30",
                                 "22": "2027-04-30", "24": "2028-04-30"}),
    "PYTHON_VERSION": ("Python", {"3.7": "2023-06-27", "3.8": "2024-10-07", "3.9": "2025-10-31",
                                  "3.10": "2026-10-31", "3.11": "2027-10-31", "3.12": "2028-10-31"}),
    "MYSQL_VERSION": ("MySQL", {"5.7": "2023-10-31", "8.0": "2026-04-30"}),
    "MYSQL_MAJOR": ("MySQL", {"5.7": "2023-10-31", "8.0": "2026-04-30"}),
    "PG_MAJOR": ("PostgreSQL", {"11": "2023-11-09", "12": "2024-11-21", "13": "2025-11-13", "14": "2026-11-12",
                                "15": "2027-11-11"}),
}
EOL_SOON_DAYS = 90

CAP_NAMES = ["CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID", "KILL", "SETGID", "SETUID", "SETPCAP",
             "LINUX_IMMUTABLE", "NET_BIND_SERVICE", "NET_BROADCAST", "NET_ADMIN", "NET_RAW", "IPC_LOCK", "IPC_OWNER",
             "SYS_MODULE", "SYS_RAWIO", "SYS_CHROOT", "SYS_PTRACE", "SYS_PACCT", "SYS_ADMIN", "SYS_BOOT", "SYS_NICE",
             "SYS_RESOURCE", "SYS_TIME", "SYS_TTY_CONFIG", "MKNOD", "LEASE", "AUDIT_WRITE", "AUDIT_CONTROL",
             "SETFCAP", "MAC_OVERRIDE", "MAC_ADMIN", "SYSLOG", "WAKE_ALARM", "BLOCK_SUSPEND", "AUDIT_READ",
             "PERFMON", "BPF", "CHECKPOINT_RESTORE"]

RULES.update({
    "os-eol": (CAT_VULN, "4.3", "Sistema operativo dell'immagine fuori supporto",
               "Ricostruire su una release supportata: senza patch le CVE note restano aperte per sempre."),
    "runtime-eol": (CAT_VULN, "4.3", "Runtime/servizio fuori supporto",
                    "Aggiornare a una versione con supporto di sicurezza attivo."),
    "eol-soon": (CAT_VULN, "", "Fine supporto imminente", "Pianificare l'aggiornamento prima della fine supporto."),
    "extra-uid0": (CAT_ANOMALY, "", "Account con UID 0 oltre a root nell'immagine/container",
                   "Indagare: un secondo account root e' una tecnica classica di persistenza."),
    "image-history-secret": (CAT_SECRETS, "4.10", "Secret nella history di build dell'immagine",
                             "Chiunque possa fare docker pull/history lo legge: ruotare il secret e usare "
                             "RUN --mount=type=secret invece di ARG/ENV."),
    "image-history-risky": (CAT_IMAGE, "", "Pratica di build rischiosa nella history dell'immagine",
                            "Verificare checksum/firme dei download in fase di build."),
    "runtime-seccomp-off": (CAT_ESCAPE, "5.22", "Seccomp non attivo sul processo (verificato a runtime)",
                            "Il processo del container gira senza filtro seccomp: rimuovere l'override."),
    "runtime-capabilities": (CAT_ESCAPE, "5.4", "Capability pericolose effettive (verificato a runtime)",
                             "Il bounding set reale del processo include capability pericolose: rimuoverle."),
    "runtime-no-userns": (CAT_DAEMON, "2.9", "Root nel container e' root sull'host (verificato a runtime)",
                          "Valutare userns-remap o rootless per i container che devono girare come root."),
    "bind-world-writable": (CAT_ESCAPE, "", "Sorgente di un bind mount scrivibile da tutti sull'host",
                            "Qualunque utente locale puo' piantare file letti/eseguiti dal container: chmod o-w."),
    "bind-missing": (CAT_ANOMALY, "", "Sorgente di un bind mount inesistente sull'host",
                     "Docker crea una directory vuota di root: verificare la configurazione."),
    "env-file-permissions": (CAT_SECRETS, "", "File .env del progetto leggibile da tutti gli utenti dell'host",
                             "chmod 600 (o 640 con gruppo dedicato) sui file .env con credenziali."),
    "registry-creds-plaintext": (CAT_SECRETS, "", "Credenziali dei registry in chiaro in ~/.docker/config.json",
                                 "Usare un credential helper (credsStore): oggi sono base64 leggibili."),
    "firewall-bypass": (CAT_NETWORK, "5.14", "Firewall attivo ma scavalcato dalle porte pubblicate da Docker",
                        "Le regole UFW/firewalld non filtrano il traffico verso i container: usare la chain "
                        "DOCKER-USER o pubblicare solo su 127.0.0.1."),
    "docker-path-permissions": (CAT_DAEMON, "3.x", "Permessi dei file/directory di Docker sull'host",
                                "Owner root e niente scrittura per gruppo/altri (CIS sezione 3)."),
    "cross-project-network": (CAT_NETWORK, "", "Rete condivisa tra progetti compose diversi",
                              "Progetti diversi sulla stessa rete si raggiungono tra loro: separare le reti."),
    "dangling-volumes": (CAT_ANOMALY, "", "Volumi orfani",
                         "Volumi non usati da nessun container: possono contenere dati/secret vecchi. Verificare e rimuovere."),
})


def days_until(date_s: str) -> int:
    return (datetime.strptime(date_s, "%Y-%m-%d").replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days


def eol_finding(target: str, rule: str, what: str, eol: str) -> dict | None:
    left = days_until(eol)
    if left < 0:
        return finding("HIGH", rule, target, f"{what}: fuori supporto dal {eol} ({-left} giorni).")
    if left <= EOL_SOON_DAYS:
        return finding("LOW", "eol-soon", target, f"{what}: fine supporto il {eol} (tra {left} giorni).")
    return None


def parse_os_release(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip().strip('"')
    return out


def check_os_eol(target: str, osr: dict) -> list[dict]:
    dist = (osr.get("ID") or "").lower()
    ver = osr.get("VERSION_ID") or ""
    table = OS_EOL.get(dist)
    if not table or not ver:
        return []
    key = ".".join(ver.split(".")[:2]) if dist in ("alpine", "ubuntu") else ver.split(".")[0]
    if key in table:
        label = osr.get("PRETTY_NAME") or f"{dist} {ver}"
        if dist not in label.lower():
            label += f" (base {dist} {ver})"
        f = eol_finding(target, "os-eol", label, table[key])
        return [f] if f else []
    # versione piu' vecchia della piu' vecchia in tabella = sicuramente EOL
    if version_tuple(key) < min(version_tuple(k) for k in table):
        return [finding("HIGH", "os-eol", target, f"{osr.get('PRETTY_NAME') or dist + ' ' + ver}: fuori supporto.")]
    return []


def check_runtime_eol(target: str, env: dict) -> list[dict]:
    f = []
    seen: set[str] = set()
    for var, (name, table) in RUNTIME_EOL.items():
        v = env.get(var)
        if not v or name in seen:
            continue
        seen.add(name)
        parts = re.findall(r"\d+", v)
        if not parts:
            continue
        key = parts[0] if name in ("Node.js", "PostgreSQL") else ".".join(parts[:2])
        if key in table:
            x = eol_finding(target, "runtime-eol", f"{name} {v}", table[key])
            if x:
                f.append(x)
        elif version_tuple(key) < min(version_tuple(k) for k in table):
            f.append(finding("HIGH", "runtime-eol", target, f"{name} {v}: fuori supporto."))
    return f


def check_passwd(target: str, text: str) -> list[dict]:
    extra = [ln.split(":")[0] for ln in text.splitlines()
             if ln.count(":") >= 6 and ln.split(":")[2] == "0" and ln.split(":")[0] != "root"]
    return [finding("HIGH", "extra-uid0", target, f"Account con UID 0: {', '.join(extra)}")] if extra else []


def docker_cp_text(docker: list[str], cid: str, path: str, timeout: int) -> str | None:
    """Legge un file del container con `docker cp <id>:<path> -` (archivio tar su stdout):
    lettura dal filesystem tramite il daemon, nessun processo eseguito nel container."""
    try:
        p = subprocess.run(docker + ["cp", f"{cid}:{path}", "-"], capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if p.returncode != 0 or not p.stdout:
        return None
    try:
        with tarfile.open(fileobj=io.BytesIO(p.stdout)) as tar:
            for m in tar.getmembers():
                if m.issym() or m.islnk():
                    # /etc/os-release e' spesso un link a /usr/lib/os-release
                    target = m.linkname if m.linkname.startswith("/") else str(Path(path).parent / m.linkname)
                    return docker_cp_text(docker, cid, target, timeout) if target != path else None
                if m.isfile() and m.size < 1_000_000:
                    return tar.extractfile(m).read().decode("utf-8", "replace")
    except tarfile.TarError:
        return None
    return None


HISTORY_ARG_RE = re.compile(r"^\|\d+\s+(.*?)\s+/bin/sh -c")


def check_history(target: str, history: list[dict]) -> list[dict]:
    f: list[dict] = []
    secret_hits: list[str] = []
    risky: list[str] = []
    for layer in history:
        cmd = layer.get("CreatedBy") or ""
        # build-arg passati a RUN: "|2 NPM_TOKEN=xxx FOO=bar /bin/sh -c ..."
        m = HISTORY_ARG_RE.match(cmd)
        if m:
            for kv in shlex.split(m.group(1)) if m.group(1) else []:
                k, _, v = kv.partition("=")
                if is_secret_key(k) and looks_like_secret_value(v):
                    secret_hits.append(f"build-arg {k}={mask(v)}")
        em = re.match(r"(?:/bin/sh -c #\(nop\)\s+)?(ENV|ARG)\s+(\S+?)=(\S+)", cmd)
        if em and is_secret_key(em.group(2)) and looks_like_secret_value(em.group(3)):
            secret_hits.append(f"{em.group(1)} {em.group(2)}={mask(em.group(3))}")
        pats = secret_patterns_in(cmd)
        if pats:
            secret_hits.append(f"{', '.join(pats)} in: {mask_patterns(cmd)[:100]}")
        if re.search(r"(curl|wget)[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", cmd):
            risky.append("download eseguito in shell (curl | sh)")
        if re.search(r"(--no-check-certificate|curl\s[^|;&]*\s-k\b|--insecure|--trusted-host)", cmd):
            risky.append("verifica TLS disattivata")
        if re.search(r"chmod\s+(-R\s+)?0?777\b", cmd):
            risky.append("chmod 777")
    if secret_hits:
        f.append(finding("HIGH", "image-history-secret", target,
                         f"{len(secret_hits)} secret nei layer: {'; '.join(sorted(set(secret_hits))[:5])}"))
    if risky:
        f.append(finding("LOW", "image-history-risky", target, ", ".join(sorted(set(risky)))))
    return f


def image_deep_checks(docker: list[str], image_id: str, image_name: str, cid: str, env: dict,
                      timeout: int) -> tuple[list[dict], dict]:
    target = f"image {image_name}"
    f: list[dict] = []
    info: dict = {}
    osr_text = docker_cp_text(docker, cid, "/etc/os-release", timeout)
    if osr_text:
        osr = parse_os_release(osr_text)
        info["os"] = osr.get("PRETTY_NAME")
        f += check_os_eol(target, osr)
    passwd = docker_cp_text(docker, cid, "/etc/passwd", timeout)
    if passwd:
        f += check_passwd(target, passwd)
    f += check_runtime_eol(target, env)
    info["runtimes"] = {k: env[k] for k in RUNTIME_EOL if env.get(k)}
    hist = []
    rc, out, _ = common.run_cmd(docker + ["history", "--no-trunc", "--format", "{{json .}}", image_id], timeout)
    for line in out.splitlines() if rc == 0 else []:
        try:
            hist.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    f += check_history(target, hist)
    info["layers"] = len(hist)
    return f, info


def decode_caps(hexmask: str) -> set[str]:
    try:
        v = int(hexmask, 16)
    except ValueError:
        return set()
    return {name for i, name in enumerate(CAP_NAMES) if v >> i & 1}


def runtime_script(pids: dict[str, int], binds: list[str], workdirs: list[str]) -> str:
    """Seconda passata sull'host, dopo l'inspect: stato reale dei processi dei
    container e permessi dei path coinvolti. Solo letture (/proc, stat)."""
    q = shlex.quote
    lines = []
    for name, pid in pids.items():
        lines.append(f"echo '=====pid_{safe_name(name)}====='; "
                     f"grep -E '^(Uid|CapEff|CapBnd|NoNewPrivs|Seccomp):' /proc/{pid}/status 2>/dev/null; "
                     f"echo \"AppArmor: $(cat /proc/{pid}/attr/current 2>/dev/null)\"; "
                     f"echo \"UidMap: $(head -1 /proc/{pid}/uid_map 2>/dev/null)\"")
    lines.append("echo '=====binds====='")
    for b in binds:
        lines.append(f"stat -c '%a %U:%G %F|%n' -- {q(b)} 2>/dev/null || echo 'MISSING|'{q(b)}")
    lines.append("echo '=====envfiles====='")
    for d in workdirs:
        lines.append(f"for f in {q(d)}/.env {q(d)}/*.env {q(d)}/.env.*; do [ -f \"$f\" ] && "
                     f"stat -c '%a %U:%G|%n' -- \"$f\"; done 2>/dev/null")
    lines += [
        "echo '=====dockercfg====='",
        'f="$HOME/.docker/config.json"; if [ -r "$f" ]; then echo "auths=$(grep -c \'"auth"[[:space:]]*:\' "$f")"; '
        'grep -q credsStore "$f" && echo credsStore=yes; fi',
        "echo '=====firewall====='",
        "for s in ufw firewalld; do echo \"$s=$(systemctl is-active $s 2>/dev/null)\"; done",
        "echo '=====paths====='",
        "stat -c '%a %U:%G|%n' /var/lib/docker /etc/docker /etc/docker/daemon.json /etc/default/docker "
        "/lib/systemd/system/docker.service /lib/systemd/system/docker.socket "
        "/usr/lib/systemd/system/docker.service /usr/lib/systemd/system/docker.socket "
        "/etc/systemd/system/docker.service.d /run/containerd/containerd.sock 2>/dev/null",
        "echo '=====end====='",
    ]
    return "\n".join(lines) + "\n"


def world_writable(mode: str) -> bool:
    return bool(mode) and mode[-1] in "2367"


def world_readable(mode: str) -> bool:
    return bool(mode) and mode[-1] in "4567"


def check_runtime(sections: dict[str, str], targets: dict[str, str], specs: dict[str, dict],
                  bind_users: dict[str, list[str]], published: list[dict], where: str) -> list[dict]:
    f: list[dict] = []
    for name, target in targets.items():
        sec = sections.get(f"pid_{safe_name(name)}")
        if not sec:
            continue
        kv = {}
        for line in sec.splitlines():
            k, _, v = line.partition(":")
            kv[k.strip()] = v.strip()
        spec = specs[name]
        if kv.get("Seccomp") == "0" and not spec["privileged"] \
                and not any("seccomp" in s and "unconfined" in s for s in spec["security_opt"]):
            f.append(finding("HIGH", "runtime-seccomp-off", target, "Seccomp: 0 su PID 1 del container."))
        caps = decode_caps(kv.get("CapBnd", "")) & DANGEROUS_CAPS
        undeclared = caps - set(spec["cap_add"]) - {"NET_RAW", "SETFCAP", "DAC_OVERRIDE"}  # default di Docker
        if undeclared and not spec["privileged"]:
            f.append(finding("HIGH", "runtime-capabilities", target,
                             f"Bounding set con capability non dichiarate nell'inspect: {', '.join(sorted(undeclared))}"))
        uid = (kv.get("Uid") or "").split()
        umap = kv.get("UidMap", "").split()
        if uid and uid[0] == "0" and len(umap) == 3 and umap[1] == "0":
            f.append(finding("LOW", "runtime-no-userns", target,
                             "PID 1 con UID 0 senza user namespace: UID 0 anche sull'host."))
    for line in (sections.get("binds") or "").splitlines():
        meta_s, _, path = line.partition("|")
        if meta_s == "MISSING":
            f.append(finding("LOW", "bind-missing", f"host {where}",
                             f"{path} (montato da: {', '.join(bind_users.get(path, []))})"))
            continue
        parts = meta_s.split(" ", 2)
        if len(parts) >= 2 and world_writable(parts[0]) and "socket" not in meta_s:
            sticky = len(parts[0]) == 4 and parts[0][0] in "1357"
            f.append(finding("LOW" if sticky else "MEDIUM", "bind-world-writable", f"host {where}",
                             f"{path} {parts[1]} {parts[0]}{' (sticky)' if sticky else ''}, montato in: "
                             f"{', '.join(bind_users.get(path, []))}"))
    for line in (sections.get("envfiles") or "").splitlines():
        meta_s, _, path = line.partition("|")
        parts = meta_s.split()
        if parts and world_readable(parts[0]):
            f.append(finding("MEDIUM", "env-file-permissions", f"host {where}", f"{path} {parts[1]} {parts[0]}"))
    cfg = dict(ln.split("=", 1) for ln in (sections.get("dockercfg") or "").splitlines() if "=" in ln)
    if cfg.get("auths", "0") not in ("", "0") and cfg.get("credsStore") != "yes":
        f.append(finding("MEDIUM", "registry-creds-plaintext", f"host {where}",
                         f"{cfg['auths']} credenziali di registry in ~/.docker/config.json senza credential helper."))
    fw = dict(ln.split("=", 1) for ln in (sections.get("firewall") or "").splitlines() if "=" in ln)
    active = [k for k, v in fw.items() if v == "active"]
    if active:
        bypass = sorted({f"{p['host_port']}/{p['proto']} ({p['target'].split(' (')[0]})" for p in published
                         if first_port(p["host_port"]) not in (80, 443)})
        if bypass:
            f.append(finding("MEDIUM", "firewall-bypass", f"host {where}",
                             f"{'/'.join(active)} attivo, ma queste porte pubblicate lo scavalcano: {', '.join(bypass)}"))
    for line in (sections.get("paths") or "").splitlines():
        meta_s, _, path = line.partition("|")
        parts = meta_s.split()
        if len(parts) < 2:
            continue
        mode, owner = parts[0], parts[1]
        bad_owner = owner.split(":")[0] != "root"
        group_w = len(mode) >= 2 and mode[-2] in "2367" and not path.endswith(".sock")
        if bad_owner or world_writable(mode) or group_w:
            f.append(finding("HIGH" if world_writable(mode) else "MEDIUM", "docker-path-permissions",
                             f"host {where}", f"{path} {owner} {mode}"))
        elif path == "/var/lib/docker" and world_readable(mode):
            f.append(finding("LOW", "docker-path-permissions", f"host {where}",
                             f"{path} {owner} {mode}: leggibile da tutti (atteso 710)"))
    return f


def check_cross_project(networks: list[dict], project_of: dict[str, str]) -> list[dict]:
    f = []
    for n in networks or []:
        if n.get("Name") in ("bridge", "host", "none"):
            continue
        members = [(c.get("Name", ""), project_of.get(c.get("Name", ""), "-")) for c in (n.get("Containers") or {}).values()]
        projects = {p for _, p in members}
        if len(projects) > 1:
            f.append(finding("LOW", "cross-project-network", f"network {n.get('Name')}",
                             f"Progetti {', '.join(sorted(projects))} sulla stessa rete: "
                             f"{', '.join(sorted(m for m, _ in members))}"))
    return f


def live_audit(args, rawdir: Path, local_tools: dict) -> tuple[list[dict], dict, list[dict]]:
    """Ritorna (findings, meta, porte pubblicate per la correlazione)."""
    meta: dict = {"docker_host": args.docker_host or args.context or "locale", "daemon_reachable": False,
                  "containers": [], "images": {}, "host_tools": {}, "host_checks": None}
    if "docker" not in local_tools:
        common.warn("docker CLI non trovata: la modalita' live richiede il client docker.")
        return [], meta, []
    timeout = args.timeout
    skip = set(args.skip)
    docker = docker_base(args.docker_host, args.context)
    findings: list[dict] = []

    info = docker_json(docker, ["info", "--format", "{{json .}}"], timeout)
    if not isinstance(info, dict):
        common.warn("docker info fallito (daemon raggiungibile? permessi sul socket?)")
        return [], meta, []
    meta["daemon_reachable"] = True
    (rawdir / "docker-info.json").write_text(json.dumps(info, indent=2), encoding="utf-8")
    version = docker_json(docker, ["version", "--format", "{{json .}}"], timeout) or {}
    (rawdir / "docker-version.json").write_text(json.dumps(version, indent=2), encoding="utf-8")
    daemon_target = f"daemon {info.get('Name', '')} (Docker {info.get('ServerVersion', '?')})"
    findings += check_daemon(info, daemon_target)
    findings += check_versions(version, daemon_target)
    comps = {c.get("Name"): c.get("Version") for c in (version.get("Server") or {}).get("Components") or []}
    meta["daemon"] = {"name": info.get("Name"), "os": info.get("OperatingSystem"), "kernel": info.get("KernelVersion"),
                      "engine": info.get("ServerVersion"), "runc": comps.get("runc"),
                      "containerd": comps.get("containerd"), "security_options": info.get("SecurityOptions")}

    # --- host: check read-only + tool gia' presenti sul server ---
    endpoint = resolve_endpoint(args.docker_host, args.context, timeout)
    shell = None if "host" in skip and "bench" in skip and not args.scan_images else build_host_shell(endpoint, info)
    host_tools: dict[str, str] = {}
    if shell:
        rc, out, err = shell.run(HOST_SCRIPT, timeout)
        sections = split_sections(out)
        if "end" not in sections:
            common.warn(f"check sull'host ({shell.where}) non riusciti: {err.strip()[:200]}")
        else:
            host_tools = parse_host_tools(sections)
            meta["host_tools"] = host_tools
            meta["host_checks"] = {"where": shell.where, "os": sections.get("os")}
            (rawdir / "host-checks.txt").write_text(out, encoding="utf-8")
            if "host" not in skip:
                findings += check_host(sections, shell.where)
            if "bench" not in skip:
                script = bench_script(host_tools, sections.get("sudo") == "yes")
                if script:
                    common.log(f"docker-bench-security sull'host ({shell.where}), puo' richiedere qualche minuto")
                    rc, out, err = shell.run(script, max(timeout, 900))
                    try:
                        bench = json.loads(out)
                        (rawdir / "docker-bench.json").write_text(json.dumps(bench, indent=2), encoding="utf-8")
                        findings += parse_bench(bench, shell.where)
                        meta["docker_bench"] = {"score": bench.get("score"), "checks": bench.get("checks")}
                    except json.JSONDecodeError:
                        common.warn(f"docker-bench-security senza output JSON: {err.strip()[:200]}")
                else:
                    common.warn("docker-bench-security non presente sull'host: salto il CIS benchmark completo.")

    # --- container ---
    ids = [i.strip() for i in common.run_cmd_lines(docker + ["ps", "-q"] + (["-a"] if args.all else []), timeout)
           if i.strip()]
    common.log(f"Live: {len(ids)} container {'(inclusi fermi)' if args.all else 'in esecuzione'}")
    published: list[dict] = []
    if not ids:
        return findings, meta, published
    containers = docker_json(docker, ["inspect"] + ids, timeout)
    if not isinstance(containers, list):
        common.warn("docker inspect fallito.")
        return findings, meta, published

    # immagini: per id (eta', config) e per tag (drift: il tag punta a un'immagine piu' nuova?)
    refs = sorted({c.get("Image", "") for c in containers} | {(c.get("Config") or {}).get("Image", "")
                                                              for c in containers} - {""})
    images: dict[str, dict] = {}
    for img in docker_json(docker, ["image", "inspect"] + refs, timeout) or []:
        images[img.get("Id", "")] = img
        for t in img.get("RepoTags") or []:
            images[t] = img
            if t.startswith("docker.io/library/"):
                images[t.removeprefix("docker.io/library/")] = img

    if "networks" not in skip:
        net_ids = [n for n in common.run_cmd_lines(docker + ["network", "ls", "-q"], timeout) if n.strip()]
        nets = docker_json(docker, ["network", "inspect"] + net_ids, timeout) if net_ids else []
        (rawdir / "docker-networks.json").write_text(json.dumps(nets or [], indent=2), encoding="utf-8")
        findings += check_networks(nets or [])
        project_of = {c.get("Name", "").lstrip("/"): ((c.get("Config") or {}).get("Labels") or {})
                      .get("com.docker.compose.project", "(nessun progetto)") for c in containers}
        findings += check_cross_project(nets or [], project_of)
        dangling = [v for v in common.run_cmd_lines(docker + ["volume", "ls", "-q", "-f", "dangling=true"], timeout)
                    if v.strip()]
        if dangling:
            findings.append(finding("INFO", "dangling-volumes", daemon_target,
                                    f"{len(dangling)} volumi non usati: {', '.join(dangling[:10])}"
                                    f"{' ...' if len(dangling) > 10 else ''}"))

    probes: dict[str, tuple] = {}
    if "probes" not in skip:
        common.log(f"docker top + docker diff su {len(containers)} container ({args.workers} in parallelo)")
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            futs = {c["Id"]: pool.submit(probe_container, docker, c["Id"],
                                         bool((c.get("State") or {}).get("Running")), timeout) for c in containers}
            probes = {k: fut.result() for k, fut in futs.items()}

    apparmor = "apparmor" in " ".join(info.get("SecurityOptions") or [])
    used_images: dict[str, list[str]] = {}
    runtime_targets: dict[str, str] = {}
    runtime_pids: dict[str, int] = {}
    specs: dict[str, dict] = {}
    bind_users: dict[str, list[str]] = {}
    workdirs: set[str] = set()
    image_probe: dict[str, tuple] = {}  # image id -> (nome, container id, env)
    for c in containers:
        name = c.get("Name", "").lstrip("/")
        labels = (c.get("Config") or {}).get("Labels") or {}
        project = labels.get("com.docker.compose.project")
        target = f"container {name}" + (f" (compose: {project}/{labels.get('com.docker.compose.service')})"
                                        if project else "")
        if not (c.get("State") or {}).get("Running"):
            # con --all: il rischio si materializza solo se viene riavviato (restart policy, compose up)
            target += f" [fermo: {(c.get('State') or {}).get('Status', '?')}]"
        spec = spec_from_inspect(c)
        cf = check_spec(target, spec, live=True)
        top = probes.get(c["Id"], (None, []))[0]
        users = process_users(top)
        if users and not users & {"root", "0"}:
            # Config.User vuoto ma l'entrypoint scala i privilegi (gosu/su-exec, es. redis, postgres)
            for f in cf:
                if f["rule"] == "root-user":
                    f["severity"] = "LOW"
                    f["message"] = (f"Avviato come root, ma i processi girano come {', '.join(sorted(users))} "
                                    "(drop dei privilegi nell'entrypoint).")
        findings += cf
        findings += check_state(target, c, labels)
        findings += check_image(target, spec, c, images)
        if apparmor and not spec["privileged"] and c.get("AppArmorProfile", "") in ("", "unconfined") \
                and not any("apparmor" in s for s in spec["security_opt"]):
            findings.append(finding("MEDIUM", "no-apparmor", target, "Nessun profilo AppArmor applicato."))
        if c["Id"] in probes:
            top, changes = probes[c["Id"]]
            findings += check_processes(target, top)
            findings += check_diff(target, changes)
            (rawdir / f"diff-{safe_name(name)}.txt").write_text("\n".join(changes), encoding="utf-8")
            if top:
                rows = [[mask_patterns(x) for x in p] for p in top["Processes"]]
                (rawdir / f"top-{safe_name(name)}.json").write_text(json.dumps({**top, "Processes": rows}, indent=2),
                                                                     encoding="utf-8")
        used_images.setdefault(spec["image"], []).append(target)
        specs[name] = spec
        runtime_targets[name] = target
        if (c.get("State") or {}).get("Running") and (c.get("State") or {}).get("Pid"):
            runtime_pids[name] = int(c["State"]["Pid"])
        for m in spec["mounts"]:
            if m["type"] == "bind" and m["source"] and m["source"].rstrip("/") not in CONTAINER_SOCKETS:
                bind_users.setdefault(m["source"], []).append(name)
        if labels.get("com.docker.compose.project.working_dir"):
            workdirs.add(labels["com.docker.compose.project.working_dir"])
        image_probe.setdefault(c.get("Image", ""), (spec["image"], c["Id"], spec["env"]))
        for p in spec["ports"]:
            if all_interfaces(p["host_ip"]):
                published.append({**p, "target": target})
        meta["containers"].append({
            "name": name, "target": target, "image": spec["image"], "state": (c.get("State") or {}).get("Status"),
            "user": spec["user"] or "root", "ports": [f"{p['host_ip'] or '0.0.0.0'}:{p['host_port']}->"
                                                      f"{p['container_port']}/{p['proto']}" for p in spec["ports"]],
            "compose_project": project,
            # dove stanno i file compose sull'host: utili per un successivo --path
            "compose_files": labels.get("com.docker.compose.project.config_files"),
            "compose_workdir": labels.get("com.docker.compose.project.working_dir"),
        })
        cfg = c.get("Config") or {}
        cfg["Env"] = mask_env_list(cfg.get("Env"))
        cfg["Labels"] = {k: mask_kv(k.rsplit(".", 1)[-1], v) if "auth.users" not in k.lower() else mask(str(v))
                         for k, v in (cfg.get("Labels") or {}).items()}
        for key in ("Cmd", "Entrypoint"):
            if isinstance(cfg.get(key), list):
                cfg[key] = [mask_patterns(x) for x in cfg[key]]
        c["Args"] = [mask_patterns(x) for x in c.get("Args") or []]
    (rawdir / "docker-inspect.json").write_text(json.dumps(containers, indent=2), encoding="utf-8")
    meta["image_usage"] = used_images

    # --- analisi integrata delle immagini: OS/runtime EOL, UID 0 extra, secret nella history ---
    if "deep" not in skip:
        common.log(f"Analisi immagini integrata su {len(image_probe)} immagini (os-release, passwd, history)")
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            futs = {iid: pool.submit(image_deep_checks, docker, iid, nm, cid, env, timeout)
                    for iid, (nm, cid, env) in image_probe.items() if iid}
            meta["image_details"] = {}
            for iid, fut in futs.items():
                f, det = fut.result()
                findings += f
                meta["image_details"][image_probe[iid][0]] = det

    # --- seconda passata sull'host: stato reale dei processi e permessi dei path ---
    if shell and "host" not in skip and meta.get("host_checks"):
        rc, out, err = shell.run(runtime_script(runtime_pids, sorted(bind_users), sorted(workdirs)), timeout)
        sections = split_sections(out)
        if "end" in sections:
            (rawdir / "host-runtime.txt").write_text(out, encoding="utf-8")
            findings += check_runtime(sections, runtime_targets, specs, bind_users, published, shell.where)
        else:
            common.warn(f"check runtime sull'host non riusciti: {err.strip()[:200]}")

    if args.scan_images:
        local_daemon = not (endpoint.startswith(("ssh://", "tcp://")))
        scanner = ImageScanner(docker, local_daemon, local_tools, shell, host_tools,
                               set(args.scanners) if args.scanners else None, rawdir, timeout)
        if not scanner.plan:
            common.warn("--scan-images: nessuno scanner disponibile (trivy, grype, dockle, docker scout) "
                        "ne' in locale ne' sul server.")
        else:
            common.log(f"Scanner immagini: {', '.join(f'{t}@{w}' for t, w in scanner.plan.items())}")
            for img in sorted(i for i in used_images if i):
                f, summary = scanner.scan(img)
                findings += f
                meta["images"][img] = summary
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
            cp = first_port(p["container_port"])
            svc = SENSITIVE_PORTS.get(cp) or SENSITIVE_PORTS.get(hp)
            f.append(finding("CRITICAL" if svc else "HIGH", "exposure-confirmed", p["target"],
                             f"Porta {hp}/{p['proto']}{' (' + svc + ')' if svc else ''} pubblicata da Docker "
                             f"E aperta dall'esterno su {', '.join(sorted(set(open_ports[hp])))}.",
                             source="correlation"))
    for port in (2375, 2376):
        if port in open_ports:
            f.append(finding("CRITICAL", "docker-api-exposed", ", ".join(open_ports[port]),
                             f"API Docker raggiungibile dall'esterno sulla porta {port}.", source="correlation"))
    return f


ESCAPE_RULES = {"privileged", "docker-socket", "pid-host", "security-profile-disabled", "systempaths-unconfined",
                "device-cgroup-rule"}
EXPOSURE_RULES = {"port-public", "sensitive-port-public", "exposure-confirmed", "network-host"}


def attack_chains(findings: list[dict], image_usage: dict[str, list[str]]) -> list[dict]:
    """Combina finding dello stesso target in rischi composti."""
    by_target: dict[str, list[dict]] = {}
    for f in findings:
        by_target.setdefault(f["target"], []).append(f)
    vulnerable_targets: set[str] = set()
    for f in findings:
        if f["rule"] == "image-vulnerabilities" and f["severity"] == "CRITICAL":
            img = f["target"].removeprefix("image ")
            vulnerable_targets.update(image_usage.get(img, []))
    out: list[dict] = []
    for t, fs in by_target.items():
        rules = {f["rule"] for f in fs}
        exposure = [f for f in fs if f["rule"] in EXPOSURE_RULES]
        if not exposure:
            continue
        escapes = [f for f in fs if f["rule"] in ESCAPE_RULES
                   or (f["rule"] == "sensitive-mount" and f["severity"] in ("CRITICAL", "HIGH"))
                   or (f["rule"] == "dangerous-capabilities" and f["severity"] == "CRITICAL")]
        exp = "; ".join(sorted({e["message"].split(" pubblicata")[0] if e["rule"] != "network-host" else "network: host"
                                for e in exposure}))[:160]
        if escapes:
            out.append(finding("CRITICAL", "chain-exposed-escape", t,
                               f"Esposto in rete ({exp}) e con primitiva di escape "
                               f"({', '.join(sorted({e['rule'] for e in escapes}))}).", source="correlation"))
        if t in vulnerable_targets and "root-user" in rules:
            out.append(finding("HIGH", "chain-exposed-vulnerable-root", t,
                               f"Esposto in rete ({exp}), gira come root, immagine con CVE CRITICAL.",
                               source="correlation"))
        if rules & {"env-secret", "secret-pattern"} and (escapes or rules & {"sensitive-mount"}):
            out.append(finding("HIGH", "chain-exposed-secrets", t,
                               "Esposto in rete, con secret in chiaro e accesso a risorse dell'host.",
                               source="correlation"))
    return out


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def safe_name(s: str) -> str:
    return re.sub(r"[^\w.-]+", "_", s).strip("_")[-60:]


def file_tag(path: Path) -> str:
    """Nome breve per i file raw: <cartella>_<file>, non il path completo
    (su Windows i path lunghi superano il limite di 260 caratteri)."""
    return safe_name(f"{path.parent.name}_{path.name}")


def dedupe(findings: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    out = []
    for f in findings:
        k = (f["rule"], f["target"], f["message"])
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def risk_scores(findings: list[dict]) -> list[dict]:
    by_target: dict[str, dict] = {}
    for f in findings:
        t = by_target.setdefault(f["target"], {"target": f["target"], "score": 0,
                                               **{s: 0 for s in SEVERITIES}})
        t[f["severity"]] = t.get(f["severity"], 0) + 1
        t["score"] += SEV_WEIGHT.get(f["severity"], 0)
    for t in by_target.values():
        t["score"] = min(100, t["score"])
        t["rating"] = ("CRITICAL" if t["CRITICAL"] else "HIGH" if t["score"] >= 30 or t["HIGH"]
                       else "MEDIUM" if t["score"] >= 10 else "LOW")
    return sorted(by_target.values(), key=lambda t: (-t["score"], t["target"]))


def sev_counts(fs: list[dict]) -> str:
    return " ".join(f"{s[0]}{n}" for s in SEVERITIES if (n := sum(1 for f in fs if f["severity"] == s)))


def render_grouped(label: str, findings: list[dict], meta: dict, scores: list[dict], tools_line: str) -> str:
    W = 100
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    live = meta.get("live") or {}
    daemon = live.get("daemon") or {}
    lines = ["=" * W, f" DOCKER SECURITY AUDIT — {label}", f" Generato: {common.now_iso()}"
             f"   Modalita': {' + '.join(meta.get('modes', []))}"]
    if daemon:
        lines.append(f" Daemon: {live.get('docker_host')} — Docker {daemon.get('engine')}, runc {daemon.get('runc')}, "
                     f"containerd {daemon.get('containerd')} — {daemon.get('os')} (kernel {daemon.get('kernel')})")
        lines.append(f" Container: {len(live.get('containers', []))}   Immagini: {len(live.get('image_usage', {}))}"
                     f"   Check host: {(live.get('host_checks') or {}).get('where', 'no')}")
    st = meta.get("static") or {}
    if st:
        lines.append(f" Statica: {len(st.get('dockerfiles', []))} Dockerfile, "
                     f"{len(st.get('compose_groups', []))} gruppi compose")
    lines += [f" Tool: {tools_line}", "=" * W, "",
              "RIEPILOGO", "  " + "   ".join(f"{s}: {n}" for s, n in counts.items()), ""]

    by_cat: dict[str, list[dict]] = {}
    for f in findings:
        by_cat.setdefault(f["category"], []).append(f)
    cats = [c for c in CATEGORY_ORDER if c in by_cat] + sorted(c for c in by_cat if c not in CATEGORY_ORDER)
    lines.append("  Per categoria:")
    for c in cats:
        lines.append(f"    {c:<52} {sev_counts(by_cat[c])}")
    lines.append("")

    ranked = [s for s in scores if s["score"] > 0]
    if ranked:
        lines.append("TARGET PIU' A RISCHIO (punteggio 0-100: CRITICAL 40, HIGH 15, MEDIUM 5, LOW 1)")
        lines.append(f"  {'score':>5}  {'rating':<8}  {'C/H/M/L':<11}  target")
        for s in ranked[:15]:
            lines.append(f"  {s['score']:>5}  {s['rating']:<8}  "
                         f"{s['CRITICAL']}/{s['HIGH']}/{s['MEDIUM']}/{s['LOW']:<5}  {s['target']}")
        if len(ranked) > 15:
            lines.append(f"  ... altri {len(ranked) - 15} target in findings.json")
        lines.append("")

    lines.append("FINDING RAGGRUPPATI PER CATEGORIA E REGOLA")
    for c in cats:
        lines += ["", "-" * W, f" {c.upper()}   [{sev_counts(by_cat[c])}]", "-" * W]
        by_rule: dict[tuple, list[dict]] = {}
        for f in by_cat[c]:
            by_rule.setdefault((f["rule"], f["source"]), []).append(f)
        order = sorted(by_rule, key=lambda k: (min(SEV_RANK[x["severity"]] for x in by_rule[k]),
                                               -len(by_rule[k]), k[0]))
        for key in order:
            fs = sorted(by_rule[key], key=lambda x: (SEV_RANK[x["severity"]], x["target"]))
            head = fs[0]
            src = "" if head["source"] == "builtin" else f" [{head['source']}]"
            cis = f" (CIS {head['cis']})" if head.get("cis") else ""
            title = head.get("title") or head["message"][:80]
            ntarget = len({x["target"] for x in fs})
            lines.append(f"\n[{head['severity']}] {head['rule']}{cis}{src} — {title} — {ntarget} target")
            if head.get("remediation"):
                lines.append(f"    Fix: {head['remediation']}")
            limit = 12 if SEV_RANK[head["severity"]] >= SEV_RANK["LOW"] else 50
            for x in fs[:limit]:
                sev = f"[{x['severity']}] " if x["severity"] != head["severity"] else ""
                lines.append(f"    - {sev}{x['target']}: {x['message']}")
                if x.get("detail") and SEV_RANK[x["severity"]] <= SEV_RANK["MEDIUM"]:
                    lines.append(f"        -> {x['detail']}")
            if len(fs) > limit:
                rest = sorted({x["target"] for x in fs[limit:]})
                lines.append(f"    ... e altri {len(fs) - limit}: {', '.join(rest)[:400]}")

    imgs = live.get("images") or {}
    if imgs:
        lines += ["", "-" * W, " VULNERABILITA' PER IMMAGINE (HIGH/CRITICAL)", "-" * W]
        for img, s in sorted(imgs.items(), key=lambda kv: (-(kv[1].get("counts") or {}).get("CRITICAL", 0),
                                                            -(kv[1].get("counts") or {}).get("HIGH", 0))):
            c = s.get("counts") or {}
            lines.append(f"  C{c.get('CRITICAL', 0):<4} H{c.get('HIGH', 0):<4} fix:{s.get('fixable', 0):<4} "
                         f"{img}   [{', '.join(s.get('scanners') or []) or 'scan fallito'}]")

    hints = [c for c in live.get("containers", []) if c.get("compose_files")]
    if hints:
        lines += ["", "File compose usati dai container (sull'host) — utili per un'analisi statica con --path:"]
        for c in sorted({(h["compose_project"], h["compose_files"]) for h in hints}):
            lines.append(f"  {c[0]}: {c[1]}")
    if not findings:
        lines.append("\nNessun finding. Verifica che l'input contenesse davvero Dockerfile/compose o container.")
    return "\n".join(lines) + "\n"


def render_by_target(label: str, findings: list[dict], scores: list[dict]) -> str:
    lines = [f"Docker security audit — {label} — dettaglio per target", ""]
    by_target: dict[str, list[dict]] = {}
    for f in findings:
        by_target.setdefault(f["target"], []).append(f)
    for s in scores:
        t = s["target"]
        lines.append(f"## {t}   [score {s['score']}, {s['rating']}]")
        for f in sorted(by_target[t], key=lambda x: (SEV_RANK[x["severity"]], x["category"], x["rule"])):
            src = "" if f["source"] == "builtin" else f" [{f['source']}]"
            lines.append(f"  [{f['severity']}] {f['rule']}{src}: {f['message']}")
        lines.append("")
    return "\n".join(lines)


def write_csv(path: Path, findings: list[dict]) -> None:
    cols = ["severity", "category", "rule", "cis", "target", "message", "source", "detail", "remediation"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(findings)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit di sicurezza di uno stack Docker (statico e/o live).",
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
                        help="Live: CVE/secret/best practice delle immagini in uso con gli scanner presenti")
    parser.add_argument("--scanners", type=lambda s: [x.strip() for x in s.split(",") if x.strip()], default=None,
                        help="Limita gli scanner immagini: trivy,grype,dockle,docker-scout (default: tutti quelli presenti)")
    parser.add_argument("--skip", type=lambda s: [x.strip() for x in s.split(",") if x.strip()], default=[],
                        help="Salta fasi live: host (check sull'host), bench (docker-bench-security), "
                             "probes (docker top/diff), networks, deep (os-release/passwd/history immagini)")
    parser.add_argument("--workers", type=int, default=4, help="Container sondati in parallelo (default 4)")
    parser.add_argument("--active", default=None,
                        help="results.json di port-scan per confermare l'esposizione delle porte pubblicate")
    parser.add_argument("--min-severity", choices=SEVERITIES, default="INFO",
                        help="Mostra solo finding da questa severita' in su (default INFO = tutti)")
    parser.add_argument("--fail-on", choices=SEVERITIES, default=None,
                        help="Exit code 3 se ci sono finding da questa severita' in su (per CI)")
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
    bad = set(args.skip) - {"host", "bench", "probes", "networks", "deep"}
    if bad:
        parser.error(f"--skip: valori non validi {sorted(bad)}")

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
        label = urlsplit(args.docker_host).hostname or "remote"
        label = common.default_label([label]) if common.valid_domain(label) else label
    elif live:
        label = args.context or "localhost"
    else:
        label = safe_name(Path(args.path[0]).expanduser().resolve().name) or "local"

    outdir = common.make_outdir(common.resolve_output_base(args.output), TOOL_NAME, label)
    rawdir = outdir / "raw"
    rawdir.mkdir(exist_ok=True)

    local_tools = detect_local_tools(args.timeout)
    common.log(f"Tool locali rilevati: {', '.join(sorted(local_tools)) or 'nessuno'}")

    findings: list[dict] = []
    meta: dict = {"modes": [m for m, on in (("static", bool(args.path)), ("live", live)) if on],
                  "local_tools": local_tools}
    if args.path:
        f, meta["static"] = static_audit(args.path, rawdir, args.timeout, local_tools)
        findings += f
    published: list[dict] = []
    if live:
        f, meta["live"], published = live_audit(args, rawdir, local_tools)
        findings += f
        if active is not None:
            findings += correlate(published, active)
    elif active is not None:
        common.warn("--active serve solo in modalita' live (porte pubblicate reali): ignorato.")

    findings = dedupe(findings)
    findings += attack_chains(findings, (meta.get("live") or {}).get("image_usage") or {})

    threshold = SEV_RANK[args.min_severity]
    findings = [f for f in findings if SEV_RANK.get(f["severity"], 9) <= threshold]
    for f in findings:
        if f["severity"] not in SEV_RANK:
            f["severity"] = "INFO"
    findings.sort(key=lambda f: (SEV_RANK[f["severity"]], f["category"], f["rule"], f["target"]))
    scores = risk_scores(findings)

    host_tools = (meta.get("live") or {}).get("host_tools") or {}
    tools_line = ("locali: " + (", ".join(sorted(local_tools)) or "-") +
                  ("; sul server: " + ", ".join(sorted(k for k in host_tools if k != "docker-bench-dir"
                                                       ) + (["docker-bench-security"] if "docker-bench-dir"
                                                            in host_tools else [])) if host_tools else ""))

    report = {
        "generated_utc": common.now_iso(),
        "label": label,
        "modes": meta["modes"],
        "summary": {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES},
        "summary_by_category": {c: {s: sum(1 for f in findings if f["category"] == c and f["severity"] == s)
                                    for s in SEVERITIES} for c in sorted({f["category"] for f in findings})},
        "risk_scores": scores,
        "findings": findings,
        "meta": meta,
    }
    (outdir / "findings.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    text = render_grouped(label, findings, meta, scores, tools_line)
    (outdir / "findings.txt").write_text(text, encoding="utf-8")
    (outdir / "by-target.txt").write_text(render_by_target(label, findings, scores), encoding="utf-8")
    write_csv(outdir / "findings.csv", findings)

    common.log(f"Findings: {report['summary']}")
    for name in ("findings.txt", "by-target.txt", "findings.json", "findings.csv"):
        common.log(f"Salvato: {outdir / name}")

    print(json.dumps(report, indent=2) if args.json else text)
    if live and not meta["live"].get("daemon_reachable"):
        common.warn("Modalita' live NON eseguita: il report non copre i container in esecuzione.")
        return 1
    if args.fail_on and any(SEV_RANK[f["severity"]] <= SEV_RANK[args.fail_on] for f in findings):
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())

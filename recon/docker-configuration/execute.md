# execute.md — `docker_config_audit.py`

**Tool:** `docker-configuration` → output sempre in `output/docker-configuration/<label>/<timestamp>/`

Audit di sicurezza di uno **stack Docker**: configurazione dei container,
immagini, daemon e host. A differenza degli altri step non guarda il target
dall'esterno, ma la sua configurazione: i file del progetto e/o i container
in esecuzione.

> ⚠️ La modalita' live e' read-only verso il daemon (`info`, `version`,
> `ps`, `inspect`, `top`, `diff`, `network inspect`). Sull'host non viene
> installato nulla: i check passano come script `sh` su stdin della stessa
> connessione SSH. Eccezioni: `--scan-images` con scanner solo in locale fa
> `docker save` per scaricare l'immagine; se docker-bench-security e' gia'
> sul server viene eseguito con log in una cartella temporanea rimossa a
> fine run. Usa SOLO su host di tua proprieta' o per cui hai autorizzazione.

## Due modalita': file o container in esecuzione?

| | Statica `--path` | Live `--live` / `--docker-host` |
|---|---|---|
| Input | cartella/file con `Dockerfile`, `docker-compose*.yml`, `compose*.yaml` | il daemon Docker (locale o remoto via SSH) |
| Cosa vede | l'**intenzione**: cosa c'e' scritto nei file | la configurazione **effettiva**: cosa sta girando davvero |
| Trova anche | problemi nei Dockerfile (USER, secret nei layer, curl \| sh, ADD da URL) | `docker run` manuali, override non versionati, drift dal repo, processi e file sospetti, daemon e host |
| Serve accesso al server | no (basta il repo) | si': utente nel gruppo `docker` (equivale a root!) |

**Conviene usarle entrambe**: si completano. In live il report elenca anche
dove stanno i file compose sull'host (label `com.docker.compose.project.config_files`),
cosi' sai cosa passare a `--path`.

Nota su `docker config`: e' un comando di **Swarm** (gestisce oggetti
"config"), non mostra la configurazione dei container. Il comando giusto per
i container e' `docker inspect`, ed e' quello che usa lo script. Per i file
compose usa `docker compose config`, che risolve merge con
`docker-compose.override.yml`, variabili `.env` ed `extends`. Senza
`docker` sulla macchina ripiega su PyYAML, con la sintassi grezza.

## Come passare i file

```bash
# una cartella: cerca ricorsivamente Dockerfile e compose (salta .git, node_modules, vendor)
python3 recon/docker-configuration/docker_config_audit.py --path ~/progetti/mio-stack

# file singoli o piu' cartelle: --path e' ripetibile
python3 recon/docker-configuration/docker_config_audit.py \
  --path ~/progetti/mio-stack/docker-compose.yml \
  --path ~/progetti/mio-stack/docker/php/Dockerfile
```

I compose nella stessa cartella vengono uniti come farebbe `docker compose`:
`docker-compose.yml` + `docker-compose.override.yml`. Gli altri (es.
`docker-compose.prod.yml`) sono analizzati da soli.

Se i file sono solo sul server, copiali in locale prima di lanciare lo script:
```bash
scp -r deploy@staging.example.com:/srv/mio-stack ./stack-staging
python3 recon/docker-configuration/docker_config_audit.py --path ./stack-staging
```

## Container in esecuzione

```bash
# sul server stesso (o in locale)
python3 recon/docker-configuration/docker_config_audit.py --live

# da Kali verso un server remoto: niente da installare sul server,
# il client docker locale parla col daemon remoto via SSH
python3 recon/docker-configuration/docker_config_audit.py --docker-host ssh://deploy@staging.example.com

# con un docker context gia' configurato
python3 recon/docker-configuration/docker_config_audit.py --context staging

# includi anche i container fermi
python3 recon/docker-configuration/docker_config_audit.py --docker-host ssh://deploy@staging.example.com --all

# run veloce: niente docker top/diff, niente docker-bench
python3 recon/docker-configuration/docker_config_audit.py --docker-host ssh://deploy@staging.example.com --skip probes,bench
```

Requisiti per il remoto: `docker` CLI su Kali, accesso SSH con chiave
all'host (`BatchMode`: niente prompt di password), utente remoto nel gruppo `docker`.

### Scansione delle immagini in uso (`--scan-images`)
```bash
python3 recon/docker-configuration/docker_config_audit.py --docker-host ssh://deploy@staging.example.com --scan-images
```
Usa tutti gli scanner gia' presenti (vedi sotto). Le CVE HIGH/CRITICAL
trovate da piu' scanner vengono unite e deduplicate per CVE + pacchetto.
Con `--scanners trivy,dockle` limiti quali usare. Alza `--timeout` per
immagini grandi.

### Correlazione con port-scan (`--active`)
```bash
python3 recon/docker-configuration/docker_config_audit.py \
  --docker-host ssh://deploy@staging.example.com \
  --active output/port-scan/example.com/latest/results.json
```
Docker scrive regole iptables proprie e **scavalca UFW/firewalld**. Una porta
pubblicata su `0.0.0.0` che risulta aperta anche nello scan esterno diventa
`exposure-confirmed`: HIGH, oppure CRITICAL se e' un DB, Redis, l'API Docker
e simili.

### In CI
```bash
python3 recon/docker-configuration/docker_config_audit.py --path . --min-severity MEDIUM --fail-on HIGH
```
Exit code `3` se c'e' almeno un finding HIGH o CRITICAL.

### Tutto insieme
```bash
python3 recon/docker-configuration/docker_config_audit.py \
  --path ./stack-staging \
  --docker-host ssh://deploy@staging.example.com \
  --scan-images \
  --active output/port-scan/example.com/latest/results.json \
  --label example.com
```

## Cosa raccoglie in live (tutto read-only)

| Fonte | Per cosa |
|---|---|
| `docker version` / `docker info` | versione engine e **runc** (escape noti: CVE-2024-21626, CVE-2025-31133/52565/52881), opzioni di sicurezza, registry insicuri, warning del daemon |
| `docker inspect` | configurazione effettiva di ogni container |
| `docker image inspect` | eta' dell'immagine, drift del tag (container non ricreato dopo l'aggiornamento) |
| `docker network inspect` | bridge di default con ICC, overlay non cifrati, macvlan/ipvlan |
| `docker top` | processi nel container: sshd, miner, reverse shell, tunnel; utente reale dei processi |
| `docker diff` | modifiche al filesystem dall'avvio: `/etc/passwd`, cron, `.ssh`, `ld.so.preload`, binari di sistema, file eseguibili/nascosti in `/tmp` |

### Analisi integrata (senza scanner esterni)
Quasi nessun server ha trivy/grype/dockle: lo script copre il piu' possibile da solo.

| Fonte | Per cosa |
|---|---|
| `docker cp <id>:/etc/os-release -` | distribuzione dell'immagine → **OS fuori supporto** (Alpine, Debian, Ubuntu, CentOS...) o in scadenza entro 90 giorni. Legge il file tramite il daemon: nessun processo eseguito nel container |
| `docker cp <id>:/etc/passwd -` | account con UID 0 oltre a root (`extra-uid0`) |
| env dell'immagine (`PHP_VERSION`, `NODE_VERSION`, `PYTHON_VERSION`, `MYSQL_VERSION`, `PG_MAJOR`) | **runtime fuori supporto** |
| `docker history --no-trunc` | secret nei layer: build-arg (`RUN \|1 TOKEN=...`), `ENV`/`ARG` con valore, token riconoscibili; `curl \| sh`, TLS disattivato |
| `/proc/<pid>/status` dei container (lato host, leggibile da qualsiasi utente) | stato **effettivo**: seccomp attivo, capability nel bounding set, UID reale, user namespace |
| `stat` sui sorgenti dei bind mount e sui `.env` dei progetti compose | directory montate scrivibili da tutti, `.env` leggibili da tutti (mai letto il contenuto) |
| `~/.docker/config.json` dell'utente SSH | credenziali di registry in chiaro (conta solo le voci) |
| `systemctl is-active ufw firewalld` | firewall attivo ma scavalcato dalle porte pubblicate da Docker |
| `stat` su `/var/lib/docker`, `/etc/docker`, unit systemd, socket containerd | permessi (CIS sezione 3) |
| `docker network inspect`, `docker volume ls -f dangling=true` | reti condivise tra progetti compose diversi, volumi orfani |

Senza scanner non c'e' il database delle CVE: un OS o un runtime fuori
supporto e' l'indicatore piu' affidabile disponibile, perche' accumula CVE
che non verranno mai corrette.

### Check sull'host
Con `--docker-host ssh://...` (o un `--context` ssh, o `--live` su Linux)
sulla **stessa connessione SSH** viene eseguito uno script `sh` di sola
lettura passato su stdin. Legge:
- `/etc/docker/daemon.json` (icc, no-new-privileges, userland-proxy, log-opts, `hosts`)
- `ExecStart` di `docker.service` e riga di comando di `dockerd` → API `tcp://` senza `--tlsverify`
- permessi del socket (atteso `root:docker 660`) e membri del gruppo `docker`
- porte 2375/2376 in ascolto
- quali tool sono gia' installati sul server e se `sudo -n` e' disponibile

Con Docker Desktop (daemon in una VM) o un daemon `tcp://` questi check
vengono saltati.

### Tool gia' presenti: rilevati e usati in automatico
Lo script **non installa nulla**: cerca i tool in locale (PATH) e sul server
(via SSH) e usa quelli che trova. L'intestazione del report dice quali.

| Tool | Dove | Cosa aggiunge |
|---|---|---|
| `docker-bench-security` | server (PATH, `/opt`, `/usr/local`, `/usr/share`, `~`) | CIS Docker Benchmark completo (file del daemon, auditd...). Usa `sudo -n` se disponibile senza password |
| `trivy image` | server se presente, altrimenti locale | CVE HIGH/CRITICAL, secret nei layer, misconfig della config immagine |
| `grype` | server se presente, altrimenti locale | CVE, unite a quelle di trivy |
| `dockle` | server se presente, altrimenti locale | best practice CIS sulle immagini (`CIS-DI-*`) |
| `docker scout` | locale (plugin di Docker Desktop) | CVE, solo se mancano trivy e grype; richiede `docker login` |
| `hadolint`, `trivy config`, `kics` | locale | statica: Dockerfile (+ compose con kics) |

Se uno scanner e' sul server l'immagine viene analizzata li' (niente
trasferimento); se c'e' solo in locale e il daemon e' remoto, l'immagine
viene esportata **una volta** con `docker save` e passata a tutti gli
scanner locali. Se un tool manca, lo script lo salta con un warning.

## Cosa controlla

Ogni finding ha **categoria**, riferimento **CIS Docker Benchmark v1.6.0**
(dove esiste) e **remediation**.

| Categoria | Regole principali |
|---|---|
| Catene di attacco | `chain-exposed-escape` (porta esposta + privileged / docker.sock / mount dell'host / SYS_ADMIN / pid host), `chain-exposed-vulnerable-root` (esposto + root + CVE CRITICAL), `chain-exposed-secrets` |
| Isolamento e container escape | `privileged`, `docker-socket` (anche containerd/podman/crio), `sensitive-mount`, `dangerous-capabilities`, namespace `network/pid/ipc/uts/userns/cgroupns: host`, `security-profile-disabled`, `no-apparmor`, `systempaths-unconfined`, `mount-propagation`, `host-device`, `device-cgroup-rule`, `unsafe-sysctl` |
| Esposizione di rete | `sensitive-port-public` (DB, Redis, API Docker, kubelet, pannelli admin...), `port-public`, `default-bridge`, `default-bridge-icc`, `overlay-unencrypted`, `exposure-confirmed` / `docker-api-exposed` (con `--active`) |
| Secret e credenziali | `env-secret` (per nome, una riga per container; esclusi `*_TIME`, `*_PATH`, `*_ENABLED`...), `env-overshare` (secret applicativi dentro DB/cache/proxy: tipico `env_file` condiviso), `secret-pattern` (per formato: AWS key, token GitHub/GitLab/Slack, JWT, chiavi private, `scheme://user:pass@`), `cmdline-secret`, `label-secret` (es. basicauth di traefik), `dockerfile-secret` |
| Anomalie e indicatori di compromissione | `suspicious-process`, `persistence-fs-change`, `runtime-binary-change`, `suspicious-fs-change`, `fs-drift`, `stale-container-image`, `manual-container`, `restart-loop`, `unhealthy`, `oom-killed` |
| Daemon e host | `runc-vulnerable`, `docker-version-old`, `daemon-tcp-no-tls`, `docker-api-listening`, `socket-permissions`, `docker-group-members`, `daemon-insecure-registry`, `daemon-no-seccomp`, `daemon-rootful`, `daemon-icc`, `daemon-log-rotation`... + `CIS-x.y` da docker-bench |
| Vulnerabilita' | `image-vulnerabilities` per immagine (conteggi, quante con fix, CVE principali) |
| Immagini e supply chain | `image-latest`, `image-old`; Dockerfile: `pipe-to-shell`, `tls-verification-disabled`, `add-remote-url`, `dockerfile-expose-ssh`, `dockerfile-chmod-777`, `dockerfile-sudo`, `dockerfile-no-healthcheck`, `dockerfile-root`; + hadolint / trivy / dockle |
| Hardening runtime | `root-user`, `no-new-privileges`, `cap-drop-missing`, `writable-rootfs`, `no-healthcheck`, `sshd-in-container` |
| Risorse | `no-memory-limit`, `no-pids-limit`, `no-cpu-limit`, `oom-kill-disabled`, `no-logging`, `log-no-rotation` |

Per ridurre i falsi positivi:
- `root-user` scende a LOW se `docker top` mostra che i processi girano come
  utente non-root (entrypoint con gosu/su-exec, es. redis, postgres);
- `restart-loop` e' MEDIUM solo se l'ultimo exit code e' diverso da 0; restart puliti
  (worker con `--max-time`) sono INFO;
- con `--all` i container non in esecuzione sono marcati `[fermo: exited]` nel target;
- in un Dockerfile multi-stage `FROM <stage>` non e' un'immagine senza tag ed eredita l'`USER` dello stage;
- Docker aggiunge da solo `label=disable` ai container privileged o con
  `pid: host`: in quel caso non viene segnalato una seconda volta.

## Output

- `findings.txt` (anche su stdout): intestazione con versioni e tool usati,
  riepilogo per severita' e categoria, **classifica dei target per
  punteggio di rischio** (0-100: CRITICAL 40, HIGH 15, MEDIUM 5, LOW 1),
  poi i finding **raggruppati per categoria e per regola**: un problema
  ripetuto su 20 container e' un blocco solo, con fix e lista dei target.
  In coda: vulnerabilita' per immagine e file compose usati sull'host.
- `by-target.txt`: gli stessi finding visti per container/servizio
- `findings.json`: findings completi, `risk_scores`, `summary_by_category`, metadati (container, immagini, tool)
- `findings.csv`: una riga per finding, per Excel / ticketing
- `raw/`: `docker-inspect.json`, `docker-info.json`, `docker-version.json`,
  `docker-networks.json`, `top-*.json`, `diff-*.txt`, `host-checks.txt`,
  `docker-bench.json`, compose risolti e output JSON dei tool

I valori che sembrano secret (per nome della variabile **o per formato del
valore**) sono **mascherati anche nei file raw** (`***(N char)`): env,
label, Cmd/Entrypoint, argomenti, processi. `output/` e' in `.gitignore`,
ma tratta comunque la cartella come materiale riservato.

Exit code: `0` run completo, `1` modalita' live chiesta ma daemon non
raggiungibile (report parziale), `2` input non valido, `3` con `--fail-on`
se ci sono finding di quella severita' o superiore.

---

## Tutte le opzioni

| Flag | Default | Descrizione |
|---|---|---|
| `--path` | — | File o cartella da analizzare staticamente (ripetibile) |
| `--live` | off | Analizza i container del daemon locale |
| `--docker-host` | — | Daemon remoto, es. `ssh://user@host` (implica `--live`) |
| `--context` | — | `docker context` da usare (implica `--live`; se e' ssh:// abilita i check sull'host) |
| `--all` | off | Live: includi anche i container fermi |
| `--scan-images` | off | Live: CVE / secret / best practice delle immagini con gli scanner presenti |
| `--scanners` | tutti i presenti | Limita gli scanner: `trivy,grype,dockle,docker-scout` |
| `--skip` | — | Salta fasi live: `host`, `bench`, `probes` (top/diff), `networks`, `deep` (os-release/passwd/history) |
| `--workers` | `4` | Container sondati in parallelo con top/diff |
| `--active` | — | `results.json` di port-scan per confermare l'esposizione |
| `--min-severity` | `INFO` | Mostra solo da questa severita' in su |
| `--fail-on` | — | Exit code 3 se ci sono finding da questa severita' in su |
| `-o, --output` | `<radice>/output` | Cartella base (relativa alla radice o assoluta) |
| `--label` | host di `--docker-host`, context, `localhost` o nome della cartella | Nome sotto-cartella output |
| `--timeout` | `600` | Timeout per singolo comando (secondi; docker-bench almeno 900) |
| `--json` | off | Stampa il JSON completo su stdout |

Serve almeno uno tra `--path` e `--live`/`--docker-host`/`--context`.

## Prossimi passi suggeriti

- Se `docker-bench-security` non e' sul server, i check che richiedono root
  sull'host (permessi dei file del daemon, auditd) restano scoperti:
  valuta di lanciarlo a mano da un account amministratore.
- Per i finding `docker-socket` / `privileged` / `sensitive-mount`:
  verifica dall'interno del container cosa ottiene un attaccante (`deepce`).
- Per i finding *Anomalie e indicatori di compromissione*
  (`suspicious-process`, `persistence-fs-change`): non ricreare subito il
  container, prima conserva le evidenze (`docker export`, `docker logs`,
  `raw/diff-*.txt`).

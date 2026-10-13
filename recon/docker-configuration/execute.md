# execute.md — `docker_config_audit.py`

**Tool:** `docker-configuration` → output sempre in `output/docker-configuration/<label>/<timestamp>/`

Audit delle **misconfigurazioni di sicurezza di uno stack Docker**. A
differenza degli altri step non guarda il target dall'esterno, ma la sua
configurazione: i file del progetto e/o i container in esecuzione.

> ⚠️ La modalita' live e' read-only verso il daemon (`docker info`, `ps`,
> `inspect`), con l'eccezione di `--scan-images` su host remoto, che fa
> `docker save` per scaricare le immagini. Usa SOLO su host di tua
> proprieta' o per cui hai autorizzazione.

## Due modalita': file o container in esecuzione?

| | Statica `--path` | Live `--live` / `--docker-host` |
|---|---|---|
| Input | cartella/file con `Dockerfile`, `docker-compose*.yml`, `compose*.yaml` | il daemon Docker (locale o remoto via SSH) |
| Cosa vede | l'**intenzione**: cosa c'e' scritto nei file | la configurazione **effettiva**: cosa sta girando davvero |
| Trova anche | problemi nei Dockerfile (USER, secret nei layer, ADD da URL) | `docker run` manuali, override non versionati, drift dal repo, opzioni del daemon |
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
```

Requisiti per il remoto: `docker` CLI su Kali, accesso SSH con chiave
all'host, utente remoto nel gruppo `docker`.

### Scansione delle immagini in uso (`--scan-images`)
```bash
python3 recon/docker-configuration/docker_config_audit.py --docker-host ssh://deploy@staging.example.com --scan-images
```
Lancia `trivy image` su ogni immagine usata dai container: CVE
HIGH/CRITICAL, secret rimasti nei layer, misconfigurazioni della config
dell'immagine. Su host remoto l'immagine viene prima scaricata con
`docker save`, quindi puo' richiedere tempo e banda. Alza `--timeout` per
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

### Tutto insieme
```bash
python3 recon/docker-configuration/docker_config_audit.py \
  --path ./stack-staging \
  --docker-host ssh://deploy@staging.example.com \
  --scan-images \
  --active output/port-scan/example.com/latest/results.json \
  --label example.com
```

## Cosa controlla

### Regole integrate (compose + container live)
| Regola | Severita' | Condizione |
|---|---|---|
| `privileged` | CRITICAL | `privileged: true` |
| `docker-socket` | CRITICAL | `/var/run/docker.sock` montato, anche in read-only |
| `sensitive-mount` | HIGH (rw) / MEDIUM (ro) | bind di `/`, `/etc`, `/proc`, `/sys`, `/root`, `/boot`, `/dev`, `/var/lib/docker`, `/run`, `/home` |
| `dangerous-capabilities` | HIGH | `cap_add` con `SYS_ADMIN`, `SYS_PTRACE`, `NET_ADMIN`, `ALL`... |
| `network-host` / `pid-host` / `ipc-host` | HIGH / HIGH / MEDIUM | namespace condivisi con l'host |
| `security-profile-disabled` | HIGH | `seccomp:unconfined`, `apparmor:unconfined`, `label:disable` |
| `sensitive-port-public` | HIGH | DB, cache, API Docker o pannelli admin pubblicati su tutte le interfacce |
| `port-public` | LOW | altre porte pubblicate su tutte le interfacce |
| `env-secret` | MEDIUM | `*PASSWORD*`, `*SECRET*`, `*TOKEN*`, `*API_KEY*`... valorizzate in chiaro. Il valore viene mascherato |
| `root-user` | MEDIUM | live: il container gira come root; compose: `user: root` esplicito |
| `host-device` | MEDIUM | device dell'host esposti |
| `no-new-privileges`, `writable-rootfs`, `no-memory-limit`, `no-pids-limit`, `image-latest` | LOW | hardening mancante |

### Solo live
| Regola | Severita' |
|---|---|
| `daemon-no-seccomp` | HIGH |
| `daemon-warning` (es. API su 2375 senza TLS) | CRITICAL / INFO |
| `daemon-rootful` (no rootless, no userns-remap) | LOW |
| `exposure-confirmed`, `docker-api-exposed` (con `--active`) | CRITICAL / HIGH |

### Dockerfile
Check integrati: nessun `USER` non-root, secret in `ENV`/`ARG`, `ADD` da
URL, `FROM` senza tag. Se installati si aggiungono **hadolint** e
**trivy config**, con finding marcati `[hadolint]` / `[trivy]`.

Docker Compose **non** e' tra i formati supportati da `trivy config`: per i
compose valgono le regole integrate sopra.

## Tool esterni (opzionali)

| Tool | Usato per | Installazione su Kali |
|---|---|---|
| `docker` (CLI + compose plugin) | modalita' live; `docker compose config` | `sudo apt install docker.io docker-compose` |
| `hadolint` | lint dei Dockerfile | binario da GitHub releases |
| `trivy` | `trivy config`, `trivy image` | `sudo apt install trivy` |

Se un tool manca, lo script lo salta con un warning e non si blocca.

## Output

- `findings.txt`: riepilogo per target, ordinato per severita' (anche su stdout)
- `findings.json`: findings completi + metadati (file analizzati, container, conteggi CVE per immagine)
- `raw/`: `docker-inspect.json`, `docker-info.json`, compose risolti e output JSON di hadolint/trivy

I valori delle variabili che sembrano secret sono **mascherati anche nei
file raw** (`***(N char)`). Il resto dell'inspect (mount, label, comandi)
resta integro: `output/` e' in `.gitignore`, ma tratta comunque la cartella
come materiale riservato.

Exit code: `0` se il run e' completo, `1` se e' stata chiesta la modalita'
live ma il daemon non era raggiungibile (report parziale), `2` per input non
valido.

---

## Tutte le opzioni

| Flag | Default | Descrizione |
|---|---|---|
| `--path` | — | File o cartella da analizzare staticamente (ripetibile) |
| `--live` | off | Analizza i container del daemon locale |
| `--docker-host` | — | Daemon remoto, es. `ssh://user@host` (implica `--live`) |
| `--context` | — | `docker context` da usare (implica `--live`) |
| `--all` | off | Live: includi anche i container fermi |
| `--scan-images` | off | Live: `trivy image` sulle immagini in uso |
| `--active` | — | `results.json` di port-scan per confermare l'esposizione |
| `--min-severity` | `INFO` | Mostra solo da questa severita' in su |
| `-o, --output` | `<radice>/output` | Cartella base (relativa alla radice o assoluta) |
| `--label` | host di `--docker-host`, context, `localhost` o nome della cartella | Nome sotto-cartella output |
| `--timeout` | `600` | Timeout per singolo comando (secondi) |
| `--json` | off | Stampa il JSON completo su stdout |

Serve almeno uno tra `--path` e `--live`/`--docker-host`/`--context`.

## Prossimi passi suggeriti

- **docker-bench-security** (CIS Docker Benchmark) direttamente sul server,
  per i controlli che richiedono root sull'host: permessi dei file del
  daemon, auditd, configurazione di `daemon.json`.
- Per i finding `docker-socket` / `privileged` / `sensitive-mount`:
  verifica dall'interno del container cosa ottiene un attaccante (`deepce`).

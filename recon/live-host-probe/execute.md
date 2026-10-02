# execute.md — `live_hosts.py`

**Tool:** `live-host-probe` → output sempre in `output/live-host-probe/<label>/<timestamp>/`

Dati **host/sottodomini**, trova quali rispondono su **HTTP/HTTPS** e con
quali metadati (status code, titolo, tech-stack, web server). E' lo step
intermedio tra la recon passiva (`subdomains_passive.py`) e il port scan
(`resolve_and_scan.py`): restringe la lista a cio' che e' effettivamente
vivo prima di spendere tempo a scansionare porte.

Output in `<base>/live-host-probe/<label>/<timestamp>/` (`live_hosts.txt` + `live_hosts.json`).

> ⚠️ E' gia' un probe HTTP **attivo**: invia richieste reali al target.
> Usalo solo su host di tua proprieta' o per cui hai autorizzazione.

## Prober (`--prober`)

| Prober | Richiede tool | Dettagli raccolti |
|---|---|---|
| `httpx` (default) | sì (ProjectDiscovery) | status code, titolo, tech-detect, web server, redirect |
| `builtin` | no (fallback automatico se httpx assente) | status code, titolo, web server (via header `Server`) |

Se `httpx` non e' installato, lo script passa **automaticamente** a `builtin`
(nessun crash, solo un warning). Attenzione: esiste anche una CLI chiamata
`httpx` fornita dal **package Python** `httpx` (diversa dal tool Go di
ProjectDiscovery) — se finisce nel PATH prima di quella giusta, lo script
se ne accorge (verifica `-version`) e fa comunque fallback a `builtin`
invece di invocare il tool sbagliato.

## Profili di aggressivita' (`--profile`)

| | httpx | builtin |
|---|---|---|
| `stealth` | `-rate-limit 10 -threads 5` | concorrenza 5 |
| `normal` | `-threads 25` | concorrenza 20 |
| `aggressive` | `-rate-limit 300 -threads 100` | concorrenza 50 |

`--httpx-args` appende flag grezze dopo il profilo (vincono in caso di conflitto).

## Input

- `-d example.com` — ripetibile o separati da virgola
- `-iL subdomains.txt` — un host per riga (tipicamente output di `subdomains_passive.py`)

## Output

- `stdout` → `URL<TAB>status_code<TAB>| titolo` (pipe-friendly)
- `live_hosts.txt` → solo gli URL vivi, uno per riga (pronto per il port scan)
- `live_hosts.json` → dettagli completi: status, titolo, tech, server, flag usate, `dead_hosts`

### Timestamp e scorciatoia `latest`
Timestamp in **ora locale** leggibile: `2026-10-02_08-51-11` (non UTC). Ogni
run aggiorna anche `<base>/live-host-probe/<label>/latest` (symlink all'ultimo run):
```bash
cat ../../output/live-host-probe/example.com/latest/live_hosts.txt
```

### Host senza risposta
Un host che non risponde (DNS fallito, connessione rifiutata, timeout) viene
**segnalato esplicitamente** su stderr e incluso nel campo `dead_hosts` del
JSON, invece di sparire in silenzio dal risultato.

---

## Casi d'uso

### Base — httpx, profilo normal
```bash
python3 live_hosts.py -d example.com
```

### File .txt di domini (scritto a mano o generato da un altro step)
Un dominio/host per riga; righe vuote e righe che iniziano con `#` sono ignorate.
```bash
cat > domains.txt << 'EOF'
example.com
api.example.com
# commento, viene ignorato
EOF
python3 live_hosts.py -iL domains.txt
```

### Concatenato con lo step precedente (subdomains.txt di subdomain-enum)
```bash
python3 live_hosts.py -iL ../../output/subdomain-enum/example.com/latest/subdomains.txt --label example.com
```

### Senza httpx installato (fallback builtin esplicito, utile anche su Windows)
```bash
python3 live_hosts.py -d example.com --prober builtin
```

### Profili
```bash
python3 live_hosts.py -d example.com --profile stealth
python3 live_hosts.py -d example.com --profile aggressive
```

### Passthrough: qualsiasi flag httpx
```bash
# solo porte 443/8443, con screenshot
python3 live_hosts.py -d example.com --httpx-args "-ports 443,8443"

# profilo aggressive ma rate-limit tuo che sovrascrive
python3 live_hosts.py -d example.com --profile aggressive --httpx-args "-rate-limit 50"
```

### TLS self-signed / certificati non validi (solo builtin)
```bash
python3 live_hosts.py -d internal.example.com --prober builtin --insecure
```

### Output e timeout
```bash
python3 live_hosts.py -d example.com -o results --label target-A
python3 live_hosts.py -d example.com --timeout 20
python3 live_hosts.py -d example.com --json
```

### Pipeline completa: subdomain-enum -> live-host-probe -> port-scan
Con `-o run1` (base custom) la struttura resta `run1/<tool>/<label>/<timestamp>/`.
Lancia dalla **radice del repo** (regola unica per tutti gli script: script
col path completo, cosi' `-o run1` e i path letti in input restano coerenti
con la stessa cartella):
```bash
python3 recon/subdomain-enum/subdomains_passive.py -d example.com -o run1
python3 recon/live-host-probe/live_hosts.py -iL run1/subdomain-enum/example.com/latest/subdomains.txt -o run1 --label example.com
python3 recon/port-scan/resolve_and_scan.py -iL run1/subdomain-enum/example.com/latest/subdomains.txt -o run1 --label example.com
```

---

## Tutte le opzioni

| Flag | Default | Descrizione |
|---|---|---|
| `-d, --domain` | — | Host (ripetibile o con virgole) |
| `-iL, --input-list` | — | File con un host per riga |
| `-o, --output` | `<radice>/output` | Cartella base (relativa alla radice o assoluta) |
| `--label` | suffisso di dominio comune (fallback: primo input) | Nome sotto-cartella output |
| `--prober` | `httpx` | `httpx` \| `builtin` (fallback automatico se httpx assente) |
| `--profile` | `normal` | `stealth` \| `normal` \| `aggressive` |
| `--httpx-args` | `""` | Flag grezze appese a httpx |
| `--insecure` | off | Ignora verifica TLS (solo probe builtin) |
| `--timeout` | `10` | Timeout per richiesta (secondi) |
| `--json` | off | Stampa JSON completo su stdout |

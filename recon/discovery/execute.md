# execute.md — `live_hosts.py`

Dati **host/sottodomini**, trova quali rispondono su **HTTP/HTTPS** e con
quali metadati (status code, titolo, tech-stack, web server). E' lo step
intermedio tra la recon passiva (`subdomains_passive.py`) e il port scan
(`resolve_and_scan.py`): restringe la lista a cio' che e' effettivamente
vivo prima di spendere tempo a scansionare porte.

Output in `<base>/<label>/<timestamp>/` (`live_hosts.txt` + `live_hosts.json`).

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
- `live_hosts.json` → dettagli completi: status, titolo, tech, server, flag usate

---

## Casi d'uso

### Base — httpx, profilo normal
```bash
python3 live_hosts.py -d example.com
```

### Concatenato con lo step passivo
```bash
python3 live_hosts.py -iL ../../output/example.com/<timestamp>/subdomains.txt --label example.com
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

### Pipeline completa: passive -> live -> scan
```bash
python3 ../passive/subdomains_passive.py -d example.com -o run1
python3 live_hosts.py -iL run1/example.com/<ts>/subdomains.txt -o run1 --label example.com
python3 ../active/resolve_and_scan.py -iL run1/example.com/<ts>/subdomains.txt -o run1 --label example.com
```

---

## Tutte le opzioni

| Flag | Default | Descrizione |
|---|---|---|
| `-d, --domain` | — | Host (ripetibile o con virgole) |
| `-iL, --input-list` | — | File con un host per riga |
| `-o, --output` | `<radice>/output` | Cartella base (relativa alla radice o assoluta) |
| `--label` | primo input | Nome sotto-cartella output |
| `--prober` | `httpx` | `httpx` \| `builtin` (fallback automatico se httpx assente) |
| `--profile` | `normal` | `stealth` \| `normal` \| `aggressive` |
| `--httpx-args` | `""` | Flag grezze appese a httpx |
| `--insecure` | off | Ignora verifica TLS (solo probe builtin) |
| `--timeout` | `10` | Timeout per richiesta (secondi) |
| `--json` | off | Stampa JSON completo su stdout |

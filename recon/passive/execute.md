# execute.md — `subdomains_passive.py`

Enumerazione **passiva** di sottodomini. Orchestra piu' sorgenti OSINT in
parallelo, deduplica e salva in `<base>/<dominio>/<timestamp>/`
(`subdomains.txt` + `subdomains.json`).

> Uso consentito solo su domini di tua proprieta' o per cui hai autorizzazione.

## Sorgenti

| Nome | Richiede tool esterno | Note |
|---|---|---|
| `crtsh` | no (pura Python) | Certificate Transparency, funziona sempre |
| `subfinder` | sì | il più completo |
| `assetfinder` | sì | veloce |
| `amass` | sì | modalità `-passive` |

Un tool non installato viene **saltato con warning** (non blocca gli altri).

## Output

- `stdout` → solo i sottodomini (uno per riga, pipe-friendly)
- `stderr` → log ed errori
- File salvati in `<base>/<dominio>/<timestamp>/`:
  - `subdomains.txt` — lista pulita e deduplicata
  - `subdomains.json` — metadati: `profile`, `effective_flags`, conteggi per sorgente, lista

### Cartella output (`-o`)
- **Default:** `<radice repo>/output`
- **Path relativo** (es. `-o results`) → risolto dalla **radice del repo** → `<radice>/results/...`
- **Path assoluto** (es. `-o /tmp/scan`) → usato così com'è

---

## Casi d'uso

### Base — tutte le sorgenti, profilo normal
```bash
python3 subdomains_passive.py -d example.com
```

### Senza tool esterni (solo crt.sh, utile anche su Windows)
```bash
python3 subdomains_passive.py -d example.com --only crtsh
```

### Scegliere le sorgenti
```bash
python3 subdomains_passive.py -d example.com --only crtsh,subfinder
```

### Profili di aggressivita'
```bash
# Lento, poco rumore verso le API
python3 subdomains_passive.py -d example.com --profile stealth

# Default
python3 subdomains_passive.py -d example.com --profile normal

# Tutte le sorgenti subfinder, ricorsivo, veloce
python3 subdomains_passive.py -d example.com --profile aggressive
```

### Passthrough: flag grezze dei singoli tool
Le flag passate qui vengono **appese dopo** quelle del profilo (quindi le tue
vincono). Splittate in modo sicuro, senza shell.
```bash
# Flag custom per subfinder
python3 subdomains_passive.py -d example.com --subfinder-args "-all -recursive"

# Profilo aggressive ma con rate-limit tuo che sovrascrive
python3 subdomains_passive.py -d example.com --profile aggressive --subfinder-args "-rate-limit 20"

# Flag custom per amass
python3 subdomains_passive.py -d example.com --amass-args "-max-dns-queries 2000"

# Combinare piu' tool
python3 subdomains_passive.py -d example.com \
  --subfinder-args "-all" \
  --amass-args "-norecursive" \
  --assetfinder-args ""
```

### Cartella output
```bash
# Relativo alla radice del repo -> <radice>/results/example.com/<timestamp>/
python3 subdomains_passive.py -d example.com -o results

# Assoluto
python3 subdomains_passive.py -d example.com -o /tmp/recon
```

### Timeout per sorgente
```bash
python3 subdomains_passive.py -d example.com --timeout 300
```

### Output JSON su stdout
```bash
python3 subdomains_passive.py -d example.com --json
```

### Pipeline verso lo step successivo (resolve/live)
```bash
# Usa solo la lista pulita su stdout
python3 subdomains_passive.py -d example.com --only crtsh,subfinder > subs.txt

# Oppure leggi il .txt salvato
cat output/example.com/*/subdomains.txt | sort -u
```

---

## Tutte le opzioni

| Flag | Default | Descrizione |
|---|---|---|
| `-d, --domain` | *(obbligatorio)* | Dominio radice |
| `-o, --output` | `<radice>/output` | Cartella base output (relativa alla radice o assoluta) |
| `--only` | tutte | Sorgenti separate da virgola: `crtsh,subfinder,assetfinder,amass` |
| `--profile` | `normal` | `stealth` \| `normal` \| `aggressive` |
| `--subfinder-args` | `""` | Flag grezze appese a subfinder |
| `--amass-args` | `""` | Flag grezze appese ad amass |
| `--assetfinder-args` | `""` | Flag grezze appese ad assetfinder |
| `--timeout` | `120` | Timeout per sorgente (secondi) |
| `--json` | off | Stampa anche il JSON completo su stdout |

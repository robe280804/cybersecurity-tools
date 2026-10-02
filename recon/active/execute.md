# execute.md — `resolve_and_scan.py`

Dati uno o piu' **domini** (o IP): li **risolve in IP** e fa un **port scan**
delle porte aperte. Output in `<base>/<label>/<timestamp>/`
(`results.json` + output grezzo dello scanner).

> ⚠️ Il port scan e' **attivita' attiva**: genera traffico verso il target.
> Eseguilo SOLO su host di tua proprieta' o per cui hai autorizzazione scritta.

## Due fasi, tool selezionabili

**Fase 1 — risoluzione (`--resolver`)**
- `builtin` (default) — `socket` di Python, sempre disponibile
- `dnsx` — ProjectDiscovery, piu' veloce in massa (fallback automatico a builtin)

**Fase 2 — port scan (`--scanner`)**
| Scanner | Velocita' | Service/versione | Note |
|---|---|---|---|
| `nmap` (default) | media | ✅ sì | standard, timing `-T0..-T5`, script NSE |
| `naabu` | alta | ❌ no | solo scoperta porte, ottimo come primo passo |
| `masscan` | altissima | ❌ no | range enormi; **richiede root** |

Tool non installato → viene **saltato con warning**, non blocca.

## Profili di aggressivita' (`--profile`)

| | nmap | naabu | masscan |
|---|---|---|---|
| `stealth` | `-T2 --top-ports 100` | `-rate 100 -top-ports 100` | `--rate 100 -p 1-1000` |
| `normal` | `-T3 --top-ports 1000` | `-top-ports 1000` | `--rate 1000 -p 1-1000` |
| `aggressive` | `-T4 --top-ports 1000 -sV` | `-rate 1000 -top-ports 1000` | `--rate 5000 -p 1-65535` |

Le flag di `--scanner-args` vengono **appese dopo** quelle del profilo (vincono).

## Input

- `-d example.com` — ripetibile: `-d a.com -d b.com`
- `-d a.com,b.com` — separati da virgola
- `-iL subdomains.txt` — un host per riga (es. output di `subdomains_passive.py`)
- combinabili; gli IP passano così come sono senza risoluzione

## Output

- `stdout` → `IP<TAB>porte<TAB>domini` (pipe-friendly)
- `stderr` → log
- `results.json` → risoluzione completa, IP unici, porte aperte con servizio/versione (nmap), flag usate

### Cartella output (`-o`)
- Default `<radice repo>/output`
- Path **relativo** → risolto dalla radice del repo
- Path **assoluto** → usato così com'è
- `--label` → nome della sotto-cartella (default: primo input)

---

## Casi d'uso

### Base — un dominio, nmap, profilo normal
```bash
python3 resolve_and_scan.py -d example.com
```

### Piu' domini
```bash
python3 resolve_and_scan.py -d example.com -d api.example.com
python3 resolve_and_scan.py -d example.com,api.example.com,www.example.com
```

### Concatenato con lo step passivo (subdomains.txt)
```bash
# prima: subdomains_passive.py ha prodotto output/example.com/<ts>/subdomains.txt
python3 resolve_and_scan.py -iL ../../output/example.com/20261002-120000/subdomains.txt --label example.com
```

### Profili
```bash
python3 resolve_and_scan.py -d example.com --profile stealth
python3 resolve_and_scan.py -d example.com --profile aggressive
```

### Scanner alternativi
```bash
# naabu veloce (solo porte aperte)
python3 resolve_and_scan.py -d example.com --scanner naabu

# masscan tutte le porte (richiede root)
sudo python3 resolve_and_scan.py -d example.com --scanner masscan --profile aggressive
```

### Workflow pro: naabu per le porte → nmap per i dettagli
```bash
# 1) scoperta veloce porte
python3 resolve_and_scan.py -d example.com --scanner naabu --json > naabu.json
# 2) poi nmap mirato (passthrough: solo quelle porte, con -sV -sC)
python3 resolve_and_scan.py -d example.com --scanner nmap \
  --scanner-args "-p 80,443,8080 -sV -sC"
```

### Passthrough: qualsiasi flag nmap
```bash
# scan completo tutte le porte + rilevamento SO + script default
sudo python3 resolve_and_scan.py -d example.com \
  --scanner-args "-p- -A"

# SYN scan silenzioso (richiede root) con timing custom
sudo python3 resolve_and_scan.py -d example.com --scanner-args "-sS -T4 --open"

# UDP top ports
sudo python3 resolve_and_scan.py -d example.com --scanner-args "-sU --top-ports 50"
```

### IPv6, timeout, output JSON e cartella
```bash
python3 resolve_and_scan.py -d example.com --ipv6
python3 resolve_and_scan.py -d example.com --timeout 1800
python3 resolve_and_scan.py -d example.com --json
python3 resolve_and_scan.py -d example.com -o results --label target-A
```

---

## Tutte le opzioni

| Flag | Default | Descrizione |
|---|---|---|
| `-d, --domain` | — | Dominio/IP (ripetibile o con virgole) |
| `-iL, --input-list` | — | File con un host per riga |
| `-o, --output` | `<radice>/output` | Cartella base (relativa alla radice o assoluta) |
| `--label` | primo input | Nome sotto-cartella output |
| `--resolver` | `builtin` | `builtin` \| `dnsx` |
| `--scanner` | `nmap` | `nmap` \| `naabu` \| `masscan` |
| `--profile` | `normal` | `stealth` \| `normal` \| `aggressive` |
| `--scanner-args` | `""` | Flag grezze appese allo scanner |
| `--ipv6` | off | Includi indirizzi IPv6 |
| `--timeout` | `600` | Timeout scan (secondi) |
| `--json` | off | Stampa JSON completo su stdout |

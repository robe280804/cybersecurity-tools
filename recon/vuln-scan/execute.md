# execute.md — `vuln_scan.py`

**ATT&CK:** TA0043 Reconnaissance → **T1595.002** Vulnerability Scanning
(template `takeover` → difesa su **T1584** Compromise Infrastructure).

**Tool:** `vuln-scan` → output sempre in `output/vuln-scan/<label>/<timestamp>/`

Qualifica le debolezze della superficie gia' mappata: orchestra **`nuclei`** su
host/URL vivi (output di `live-host-probe` o `web-enum`) per cercare CVE note,
misconfigurazioni, pannelli esposti, security header mancanti e subdomain
takeover. È il salto da "mappo la superficie" a "so dove è debole".

> ⚠️ Attivita' attiva e **invasiva**: nuclei invia payload reali verso il
> target. Usa SOLO su host di tua proprieta' o per cui hai autorizzazione
> scritta. I template `high`/`critical` sono i piu' aggressivi e restano
> **esclusi di default** — vanno abilitati esplicitamente (vedi sotto).

## Gating delle severita'

| Modalita' | Template inviati |
|---|---|
| default | `info`, `low`, `medium` |
| `--include-high` | aggiunge `high`, `critical` |
| `--severity "medium,high"` | override esplicito (ha precedenza su `--include-high`) |

Un output **senza findings non significa "sicuro"**: significa solo che i
template delle severita' scelte non hanno trovato nulla. Leggi comunque
`nuclei.jsonl` grezzo e valuta `--include-high`.

## Profili di aggressivita' (`--profile`)

| | nuclei |
|---|---|
| `stealth` | `-rate-limit 20 -c 10 -timeout 10` |
| `normal` | `-rate-limit 150 -c 25` |
| `aggressive` | `-rate-limit 500 -c 50` |

`-rate-limit` = richieste/s globali, `-c` = concorrenza dei template. Piu' bassi
= piu' lento ma meno rumoroso e piu' gentile verso target dietro WAF/rate-limit.
`--nuclei-args` appende flag grezze dopo il profilo (vincono in caso di conflitto),
es. `--nuclei-args "-tags cve,takeover -etags intrusive"`.

## Input (combinabili)

| Flag | Sorgente |
|---|---|
| `-u, --url` | URL o host singolo, ripetibile o separato da virgola |
| `-iL, --input-list` | file con un URL/host per riga (es. `live_hosts.txt`) |
| `--live` | `live_hosts.json` di `live-host-probe` → usa i campi `url` |

Gli URL completi passano cosi' come sono; i bare host/IP vengono validati
(dominio o IP) e i target duplicati deduplicati.

## Output

- `findings.json` → schema normalizzato, coerente con `docker-configuration`:
  `id, severity, target, evidence, technique_id, tool, timestamp` (+ `title`,
  `tags`, `cve`, `cwe`, `references`, `description`).
- `findings.txt` → stesso contenuto, leggibile, ordinato per severita'.
- `nuclei.jsonl` → output grezzo di nuclei (una riga per match), per ispezione.
- `targets.txt` → lista esatta dei target passati a nuclei.

Se nuclei va in **timeout**, il report è marcato `truncated: true`: il risultato
è parziale, non uno zero-findings "pulito".

---

## Casi d'uso

### Base — dall'output di live-host-probe
`output/` vive alla radice del repo — da qui (`recon/vuln-scan/`) ci si arriva
con `../../output/...`:
```bash
python3 vuln_scan.py --live ../../output/live-host-probe/<target>/latest/live_hosts.json
```

### Includere high/critical (opt-in)
```bash
python3 vuln_scan.py --live live_hosts.json --include-high --profile aggressive
```

### Solo takeover + CVE, stealth
```bash
python3 vuln_scan.py -iL live_hosts.txt --profile stealth --nuclei-args "-tags takeover,cve"
```

### Gating per CI (exit 3 se c'è almeno un HIGH)
```bash
python3 vuln_scan.py --live live_hosts.json --include-high --fail-on HIGH
```

### Pipeline completa (dalla recon al vuln-scan)
Lancia dalla **radice del repo** (regola unica per tutti gli script):
```bash
python3 recon/subdomain-enum/subdomains_passive.py -d example.com -o run1
python3 recon/live-host-probe/live_hosts.py -iL run1/subdomain-enum/example.com/latest/subdomains.txt -o run1 --label example.com
python3 recon/vuln-scan/vuln_scan.py --live run1/live-host-probe/example.com/latest/live_hosts.json -o run1 --label example.com
```

---

## Tutte le opzioni

| Flag | Default | Descrizione |
|---|---|---|
| `-u, --url` | — | URL/host (ripetibile o separato da virgola) |
| `-iL, --input-list` | — | file con un URL/host per riga |
| `--live` | — | `live_hosts.json` di live-host-probe |
| `-o, --output` | `<radice>/output` | cartella base (relativa alla radice o assoluta) |
| `--label` | suffisso di dominio comune | nome sotto-cartella output |
| `--profile` | `normal` | `stealth` \| `normal` \| `aggressive` |
| `--include-high` | off | aggiunge template `high`+`critical` |
| `--severity` | — | override esplicito (es. `medium,high`) |
| `--nuclei-args` | `""` | flag grezze appese a nuclei |
| `--timeout` | `1800` | timeout totale dello scan in secondi |
| `--fail-on` | — | exit 3 se esiste un finding >= a questa severita' |
| `--json` | off | stampa il JSON completo su stdout |

## Prossimi passi suggeriti

- Findings MEDIUM/HIGH confermati manualmente → `recon/report/consolidate.py`
  per unirli alla mappa della superficie.
- Template `takeover` positivi → verifica il CNAME dangling e rivendica/rimuovi
  il record prima che lo faccia un attaccante.
- CVE confermate → patch o mitigazione, poi ri-scan mirato con `-u` sul singolo host.

# execute.md — `web_enum.py`

**Tool:** `web-enum` → output sempre in `output/web-enum/<label>/<timestamp>/`

Dati uno o piu' **domini/host (o URL gia' risolti)**, per ognuno rileva:
1. **stack tecnologico** (CMS, framework, linguaggio, CDN/WAF)
2. **route/path nascosti** (pannelli admin, file sensibili, documentazione API)
3. **endpoint API scritti nel JS** — spesso le route reali di una SPA non si
   indovinano a wordlist: sono dentro i bundle `.js` caricati dalla pagina

> ⚠️ Attivita' attiva: centinaia di richieste reali per host (content
> discovery + crawling JS). Usa SOLO su host di tua proprieta' o per cui hai
> autorizzazione.

## I tre motori, uno per task

| Task | Motore esterno | Fallback builtin |
|---|---|---|
| Stack | `whatweb` | Firma su header/body per CMS/framework comuni (WordPress, Laravel, Django, React, ...) |
| Route discovery | `ffuf` + wordlist di sistema (`dirb`/SecLists se presenti) | Wordlist minima integrata (~30 path comuni) |
| Endpoint da JS | *(nessuno, sempre puro Python)* | Estrae `<script src>` dalla pagina, scarica i JS stesso-origine, regex sulle stringhe path-like |

Un tool esterno mancante viene **rilevato e sostituito dal fallback**, non
blocca lo script (stesso principio di `crtsh` per `subdomain-enum`).

## Input: host o URL

Se l'input e' un host semplice (`example.com`), prova `https://` poi
`http://` (come `live_hosts.py`). Se e' gia' un URL completo (tipicamente
preso da `live_hosts.json`/`live_hosts.txt`), viene usato cosi' com'e' —
evita di ri-sondare uno schema gia' noto.

## Output

- `web_enum.json` — per host: `tech[]`, `paths[{path,status,length}]`, `js_endpoints[]`
- `web_enum.txt` — stesso contenuto, leggibile (anche su stdout)

---

## Casi d'uso

### Base — un host
```bash
python3 web_enum.py -d example.com
```

### Concatenato con live-host-probe
```bash
python3 web_enum.py -iL ../../output/live-host-probe/example.com/latest/live_hosts.txt --label example.com
```
*(lancia dalla radice del repo — vedi README, "Convenzioni comuni")*

### Profili
```bash
python3 web_enum.py -d example.com --profile stealth
python3 web_enum.py -d example.com --profile aggressive
```

### Wordlist custom per il content discovery
```bash
python3 web_enum.py -d example.com --wordlist /percorso/mia-wordlist.txt
```

### Forzare i fallback builtin (utile senza whatweb/ffuf installati)
```bash
python3 web_enum.py -d example.com --stack builtin --routes builtin
```

### Saltare il mining JS (solo stack + route discovery)
```bash
python3 web_enum.py -d example.com --skip-js
```

### Passthrough: flag grezze
```bash
python3 web_enum.py -d example.com --whatweb-args "-v"
python3 web_enum.py -d example.com --ffuf-args "-mc 200,301,302,403"
```

### Host con certificato TLS self-signed/non valido
```bash
python3 web_enum.py -d internal.example.com --insecure
```

### Piu' host, output JSON su stdout
```bash
python3 web_enum.py -d example.com,api.example.com --json
```

---

## Tutte le opzioni

| Flag | Default | Descrizione |
|---|---|---|
| `-d, --domain` | — | Host o URL (ripetibile o con virgole) |
| `-iL, --input-list` | — | File con un host/URL per riga |
| `-o, --output` | `<radice>/output` | Cartella base (relativa alla radice o assoluta) |
| `--label` | suffisso di dominio comune | Nome sotto-cartella output |
| `--profile` | `normal` | `stealth` \| `normal` \| `aggressive` |
| `--stack` | `whatweb` | `whatweb` \| `builtin` |
| `--routes` | `ffuf` | `ffuf` \| `builtin` |
| `--wordlist` | auto (dirb/SecLists se presenti) | Wordlist custom per il content discovery |
| `--skip-js` | off | Salta il mining di endpoint dai JS |
| `--whatweb-args` | `""` | Flag grezze appese a whatweb |
| `--ffuf-args` | `""` | Flag grezze appese a ffuf |
| `--insecure` | off | Non verificare i certificati TLS |
| `--timeout` | `15` | Timeout per richiesta/esecuzione (secondi) |
| `--json` | off | Stampa il JSON completo su stdout |

## Limiti noti (onesti, non nascosti)

- Il fallback builtin per il content discovery copre ~30 path: utile come
  rete di sicurezza, non sostituisce `ffuf` + una wordlist seria (SecLists).
- Il mining JS guarda solo i file **stesso-origine** referenziati dalla
  pagina principale (non segue import dinamici/chunk splitting avanzato di
  bundler moderni) ed e' limitato a 15 file JS per host — e' un primo
  livello, non un crawler completo.
- Il rilevamento stack builtin e' basato su firme note (~18): copre i casi
  comuni, non sostituisce la profondita' di `whatweb` con tutti i suoi plugin.

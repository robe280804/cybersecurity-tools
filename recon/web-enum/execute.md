# execute.md — `web_enum.py`

**Tool:** `web-enum` → output sempre in `output/web-enum/<label>/<timestamp>/`

Dati uno o piu' **domini/host (o URL gia' risolti)**, per ognuno rileva:
1. **stack tecnologico** (CMS, framework, linguaggio, CDN/WAF)
2. **route/path nascosti** (pannelli admin, file sensibili, documentazione API),
   con **ricorsione opzionale** sulle directory trovate
3. **endpoint API e secret scritti nel JS** — spesso le route reali di una SPA
   non si indovinano a wordlist: sono dentro i bundle `.js` caricati dalla
   pagina. Oltre ai path-like estrae **URL assolute**, gli **argomenti di
   chiamate `fetch`/`axios`/`.get`/`$.ajax`** e **possibili secret** (chiavi
   API, JWT, token — mascherati e da verificare a mano)

> ⚠️ Attivita' attiva: centinaia di richieste reali per host (content
> discovery + crawling JS). Usa SOLO su host di tua proprieta' o per cui hai
> autorizzazione.

## I tre motori, uno per task

| Task | Motore esterno | Fallback builtin |
|---|---|---|
| Stack | `whatweb` | Firma su header/body per CMS/framework comuni (WordPress, Laravel, Django, React, ...) |
| Route discovery | `ffuf` **o** `gobuster` + wordlist di sistema (`dirb`/SecLists se presenti) | Wordlist minima integrata (~30 path comuni) |
| Endpoint/secret da JS | *(nessuno, sempre puro Python)* | Estrae `<script src>` dalla pagina, scarica i JS stesso-origine, regex su path-like, URL assolute, chiamate `fetch`/`axios` e pattern di secret |

Un tool esterno mancante viene **rilevato e sostituito dal fallback**, non
blocca lo script (stesso principio di `crtsh` per `subdomain-enum`).

### Ricorsione sulle directory (`--recursion-depth N`, default 0 = off)

Con `N>0` lo scanner scende dentro le directory trovate (status 200/301/302/403,
senza estensione nell'ultimo segmento), fino a profondita' `N`:

- **`ffuf`** usa la sua **ricorsione nativa** (`-recursion`): un solo processo.
- **`gobuster`** (che in `dir` mode non ricorre) e il **fallback builtin**
  ottengono la ricorsione **riavviando la scansione** sotto ogni dir trovata.
- Tetto di sicurezza: `MAX_DISCOVERY_RESULTS = 3000` risultati totali (per
  gobuster/builtin), poi la ricorsione si ferma con un warning e output parziale.

## Input: host o URL

Se l'input e' un host semplice (`example.com`), prova `https://` poi
`http://` (come `live_hosts.py`). Se e' gia' un URL completo (tipicamente
preso da `live_hosts.json`/`live_hosts.txt`), viene usato cosi' com'e' —
evita di ri-sondare uno schema gia' noto.

## Output

- `web_enum.json`:
  - `totals{hosts, hosts_responsive, paths, js_endpoints, js_urls, js_secrets}` —
    conteggi di riepilogo dell'intera run
  - per host: `tech[]`, `paths[{path, status, length, redirect?}]`,
    `js{endpoints[{endpoint, via}], urls[], secrets[{type, match, source}]}`
  - `paths[].redirect` presente solo per i 3xx (dove punta la `Location`)
  - `js.endpoints[].via`: `"call"` (da `fetch`/`axios`/..., piu' affidabile)
    oppure `"path"` (stringa path-like nel bundle)
- `web_enum.txt` — stesso contenuto, leggibile (anche su stdout)

> I secret sono **mascherati** (`AIzaSy...stuv`): restano identificabili e
> verificabili senza riversare il valore in chiaro. Il campo `source` indica
> il file JS da cui recuperare il valore completo. Sono **euristiche**: vanno
> verificati a mano, possono esserci falsi positivi.

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

### Motore gobuster invece di ffuf
```bash
python3 web_enum.py -d example.com --routes gobuster
```

### Ricorsione sulle directory trovate (profondita' 2)
```bash
python3 web_enum.py -d example.com --recursion-depth 2
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
python3 web_enum.py -d example.com --routes gobuster --gobuster-args "-s 200,204,301,302,307,403"
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
| `--routes` | `ffuf` | `ffuf` \| `gobuster` \| `builtin` |
| `--recursion-depth` | `0` | Profondita' ricorsione sulle dir trovate (0 = off) |
| `--wordlist` | auto (dirb/SecLists se presenti) | Wordlist custom per il content discovery |
| `--skip-js` | off | Salta il mining di endpoint/secret dai JS |
| `--whatweb-args` | `""` | Flag grezze appese a whatweb |
| `--ffuf-args` | `""` | Flag grezze appese a ffuf |
| `--gobuster-args` | `""` | Flag grezze appese a gobuster |
| `--insecure` | off | Non verificare i certificati TLS |
| `--timeout` | `15` | Timeout per singola richiesta HTTP (resolve, fetch builtin, mining JS) |
| `--tool-timeout` | `180` | Timeout per l'intera invocazione di ffuf/whatweb — alza questo valore (non `--timeout`) se usi wordlist grandi |
| `--json` | off | Stampa il JSON completo su stdout |

## `--timeout` vs `--tool-timeout`: non confonderli

- **`--timeout`** (default 15s) è il timeout di una **singola richiesta HTTP**
  (fetch di una pagina, di un file JS, risoluzione dell'host).
- **`--tool-timeout`** (default 180s) è il timeout dell'**intera esecuzione**
  di `ffuf`/`whatweb` — che deve scorrere *tutta* la wordlist, non una
  richiesta sola.

Se usi una wordlist grande (`/usr/share/wordlists/dirb/common.txt` ha
~4600 parole; una wordlist di SecLists puo' averne molte di piu') e
`--tool-timeout` e' troppo basso, **ffuf viene troncato a meta'** e lo
script ricade sulla mini-wordlist builtin (~30 path) — con un warning
esplicito (`ffuf non ha finito in <N>s...`), ma se non lo leggi con
attenzione puoi scambiare un risultato parziale/degradato per una
scansione completa. Con molti host in parallelo e wordlist grandi, alza
`--tool-timeout` (es. `--tool-timeout 600`) o usa una wordlist piu' corta
con `--wordlist`.

## Limiti noti (onesti, non nascosti)

- Il fallback builtin per il content discovery copre ~30 path: utile come
  rete di sicurezza, non sostituisce `ffuf` + una wordlist seria (SecLists).
- Il mining JS guarda solo i file **stesso-origine** referenziati dalla
  pagina principale (non segue import dinamici/chunk splitting avanzato di
  bundler moderni) ed e' limitato a 15 file JS per host — e' un primo
  livello, non un crawler completo.
- I **secret** nei JS sono trovati per **pattern euristici** (chiavi note tipo
  AWS/Google/Stripe/JWT + assegnazioni generiche `key/secret/token`): utili come
  segnale, **non sono una garanzia** — vanno verificati a mano e possono
  esserci falsi positivi (specie dalle assegnazioni generiche).
- `gobuster` in modalita' `dir` **non ricorre nativamente**: la ricorsione
  qui e' simulata riavviando la scansione per ogni dir (piu' richieste di
  `ffuf -recursion`). Per ricorsione profonda su molti host, `ffuf` e' piu'
  efficiente.
- Il rilevamento stack builtin e' basato su firme note (~18): copre i casi
  comuni, non sostituisce la profondita' di `whatweb` con tutti i suoi plugin.

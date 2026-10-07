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

## Non alterare il servizio target

Lo script e' pensato per non aggravare un servizio sotto test, non per
eludere i suoi controlli di sicurezza:

- **Back-off automatico su 429/503**: ogni richiesta (fetch builtin, mining
  JS) passa da un throttle per-host che rispetta `Retry-After` quando
  presente, o applica un backoff esponenziale (1s → 30s) altrimenti. Nessun
  loop aggressivo contro un target che sta chiedendo di rallentare.
- **Rilevamento WAF/CDN**: prima di qualunque scansione attiva, una singola
  richiesta leggera controlla le firme di Cloudflare, Akamai, Imperva/
  Incapsula, Sucuri, AWS WAF/CloudFront, F5 BIG-IP ASM, Fastly, Barracuda,
  ModSecurity e pagine di blocco generiche. Se trovato, il profilo effettivo
  viene **riportato a `stealth`** (concorrenza bassa, pausa minima tra
  richieste) indipendentemente dal `--profile` scelto, con un warning
  esplicito. `--ignore-waf-detection` forza il profilo scelto — usalo solo
  se sai cosa stai facendo e hai l'autorizzazione a farlo.
- Questi meccanismi **non nascondono** le richieste al WAF ne' tentano di
  aggirarlo: servono solo a non trasformare una scansione autorizzata in un
  carico che degrada il servizio.

## I tre motori, uno per task

| Task | Motore esterno | Fallback builtin |
|---|---|---|
| Stack | `whatweb` | Firma su header/body per CMS/framework comuni (WordPress, Laravel, Django, React, ...) |
| Route discovery | `ffuf` **o** `gobuster` + wordlist di sistema (`dirb`/SecLists se presenti) | Wordlist minima integrata (~30 path comuni) |
| Endpoint/secret da JS | `jsluice` (parsing AST, additivo) + `playwright`/Chromium (`--render playwright`, opt-in) | Crawl ricorsivo concorrente: pagine HTML (`--crawl-depth`, `--max-pages`) -> `<script>`/preload/JS inline -> chunk dinamici (`import()`, mappe webpack, Vite/Next) fino a `--max-js`; scarica anche le source map (`sourceMappingURL`) e ne analizza i sorgenti originali. Regex su path-like, URL assolute, chiamate `fetch`/`axios` e secret. In scope host e sottodomini; JS su altri host elencati ma non scaricati |

Un tool esterno mancante viene **rilevato e sostituito dal fallback**, non
blocca lo script (stesso principio di `crtsh` per `subdomain-enum`).

### jsluice (parsing AST, opzionale e additivo)

Se il binario [`jsluice`](https://github.com/BishopFox/jsluice) e' nel `PATH`,
ogni file JS analizzato (bundle, chunk, sorgente da source map, script
inline) viene passato anche a `jsluice urls`/`jsluice secrets`. Risolve
concatenazioni e template literal che i regex sopra non vedono (es.
`base + "/users/" + id`). E' **puramente additivo**: i regex restano
comunque la baseline, jsluice aggiunge solo cio' che trova in piu'. Se
assente, o se la sua esecuzione fallisce per qualunque motivo, la scansione
prosegue con i soli regex e un unico warning (non uno per file).

### Rendering con browser headless (`--render playwright`, opt-in)

Il crawl statico non esegue JavaScript: uno `<script>` iniettato a runtime,
una route client-side non linkata da `<a>`, o un chunk caricato solo dopo
un'interazione non vengono visti. Con `--render playwright` lo script
renderizza fino a `--max-render-pages` pagine (default 10) con Chromium
headless e intercetta il **traffico di rete reale**: le chiamate XHR/fetch
effettive diventano endpoint (`via: "render"`), gli script scaricati a
runtime vengono analizzati come gli altri (tag `[solo via rendering]` nel
`.txt`, `rendered: true` nel JSON).

Richiede l'installazione esplicita (non e' una dipendenza del repo):
```bash
pip install playwright
playwright install chromium
```
Se il pacchetto o il browser non sono disponibili, un warning lo segnala e
la scansione prosegue coi soli risultati statici — non si interrompe mai per
questo. `--header`/`--cookie` vengono inoltrati anche al contesto del
browser. Costoso (un browser per pagina): usarlo quando il crawl statico
sembra trovare meno endpoint di quanti l'applicazione sembri averne.

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
  - `totals{hosts, hosts_responsive, hosts_waf, paths, js_files, js_sourcemaps, js_endpoints, js_urls, js_secrets}` —
    conteggi di riepilogo dell'intera run
  - per host: `tech[]`, `waf[]` (WAF/CDN rilevati, vuoto se nessuno),
    `paths[{path, status, length, redirect?}]`,
    `js{endpoints[{endpoint, via}], urls[], secrets[{type, match, source}],
    js_files[{url, found_in, in_scope, status?, bytes?, truncated?, sourcemap?, rendered?}],
    sourcemaps[], sources[], pages, rendered_js}`
  - `paths[].redirect` presente solo per i 3xx (dove punta la `Location`)
  - `js.endpoints[].via`: `"call"` (da `fetch`/`axios`/..., piu' affidabile),
    `"path"` (stringa path-like nel bundle) oppure `"render"` (chiamata di
    rete reale catturata con `--render playwright`)
  - `js.secrets[].type` con prefisso `"jsluice: "` indica un secret trovato
    da jsluice, non dai regex
  - `js_files[].rendered: true` indica un JS visto solo tramite rendering
    (iniettato a runtime, assente nell'HTML statico)
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

### Dietro autenticazione (header custom / cookie di sessione)
```bash
python3 web_enum.py -d app.example.com --header "Authorization: Bearer <token>"
python3 web_enum.py -d app.example.com --cookie "session=abc123; csrftoken=xyz"
```
*(ripetibile: `--header "X-Api-Key: ..." --header "X-Tenant: acme"`. Applicato
a fetch builtin, ffuf e gobuster — non a whatweb.)*

### Forzare il profilo anche con un WAF rilevato
```bash
python3 web_enum.py -d example.com --profile aggressive --ignore-waf-detection
```
*(di default, se viene rilevato un WAF/CDN, il profilo scelto viene riportato
a `stealth` per non aggravare un servizio protetto — vedi sopra)*

### Rendering con browser headless (SPA, script a runtime)
```bash
pip install playwright && playwright install chromium   # una tantum
python3 web_enum.py -d app.example.com --render playwright --max-render-pages 5
```
*(opt-in, costoso: usalo quando sospetti route/chiamate che il crawl statico
non vede — vedi "jsluice (parsing AST, opzionale e additivo)" sopra per
l'analisi AST, anch'essa opzionale ma molto piu' leggera)*

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
| `--crawl-depth` | `2` | Profondita' del crawl HTML per trovare `<script>` |
| `--max-pages` | `60` | Max pagine HTML crawlate per host |
| `--max-js` | `200` | Max file JS scaricati per host, chunk inclusi |
| `--max-js-bytes` | `3000000` | Max byte letti per singolo JS/source map |
| `--render` | `off` | `off` \| `playwright` — rendering headless per script a runtime e chiamate reali (richiede `pip install playwright && playwright install chromium`) |
| `--max-render-pages` | `10` | Max pagine renderizzate per host con `--render playwright` |
| `--whatweb-args` | `""` | Flag grezze appese a whatweb |
| `--ffuf-args` | `""` | Flag grezze appese a ffuf |
| `--gobuster-args` | `""` | Flag grezze appese a gobuster |
| `--header` | — | Header custom (ripetibile), es. `"Authorization: Bearer ..."` |
| `--cookie` | — | Cookie di sessione, es. `"session=abc; csrf=xyz"` |
| `--ignore-waf-detection` | off | Non riportare il profilo a `stealth` se viene rilevato un WAF/CDN |
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
- Il mining JS crawla pagine e chunk dinamici (`import()`, mappe webpack,
  Vite/Next) fino ai tetti `--crawl-depth`/`--max-pages`/`--max-js`, ma di
  default **non esegue JavaScript**: uno `<script>` iniettato a runtime, una
  route client-side non linkata da `<a>`, o un chunk caricato solo dopo
  un'interazione utente non vengono visti dal crawl statico. `--render
  playwright` colma questo gap (vedi sopra), ma e' opt-in e costoso — non
  attivo di default.
- L'analisi con jsluice (vedi sopra) e' **additiva, non sostitutiva**: se
  jsluice non e' installato (il caso comune, va compilato con Go), si resta
  sui soli regex — che restano quindi il livello di affidabilita' di base.
- Non attinge a fonti storiche (Wayback/Common Crawl): un JS rimosso dal
  sito ma ancora indicizzato altrove non viene trovato.
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

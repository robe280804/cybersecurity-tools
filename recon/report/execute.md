# execute.md — `consolidate.py`

Unisce `results.json` (da `resolve_and_scan.py`) e, se disponibile,
`live_hosts.json` (da `live_hosts.py`) in un'unica vista leggibile:

```
IP -> porte/servizi (+ PTR/hosting) -> domini che ci puntano -> stato HTTP
```

E' il passo che chiude la fase di recon: invece di guardare 3 file JSON
separati, hai in un colpo d'occhio **quali IP hanno piu' superficie esposta**
(porte extra oltre http/https = interessanti), **chi li ospita** (PTR: es.
`clients.your-server.de` = Hetzner, `bc.googleusercontent.com` = GCP) e
**quali domini su quell'IP rispondono davvero e con che status**.

Output in `<base>/<label>/<timestamp>/`:
- `report.json` — dati completi, per script/tool successivi
- `report.md` — tabelle Markdown, leggibile/condivisibile
- `report.txt` — stesso contenuto, formato compatto da terminale (anche su stdout)

## Input

| Flag | Obbligatorio | Da dove |
|---|---|---|
| `--active` | sì | `results.json` di `recon/active/resolve_and_scan.py` |
| `--live` | no | `live_hosts.json` di `recon/discovery/live_hosts.py` |

Se `--live` non viene passato, lo stato HTTP di ogni dominio e' `unknown`
(non controllato) invece di `dead`/un codice reale.

## Come leggere lo stato HTTP di un dominio

| Valore | Significato |
|---|---|
| lista di `{url, status_code, title, ...}` | il dominio e' vivo (una voce per ogni scheme http/https rilevato) |
| `dead` | controllato da `live_hosts.py`, non ha risposto |
| `unknown` | non presente in `live_hosts.json` (non passato, o lista diversa) |

---

## Casi d'uso

### Base — solo porte/IP, senza stato HTTP
```bash
python3 consolidate.py --active ../active/output/netseven.it/<ts>/results.json
```

### Completo — porte + stato HTTP
```bash
python3 consolidate.py \
  --active ../active/output/netseven.it/<ts>/results.json \
  --live   ../discovery/output/netseven.it/<ts>/live_hosts.json
```

### Pipeline completa in un unico script di esempio
```bash
cd recon
D=netseven.it
TS_ACTIVE=$(ls active/output/$D | tail -1)
TS_LIVE=$(ls discovery/output/$D | tail -1)
python3 report/consolidate.py \
  --active discovery/../active/output/$D/$TS_ACTIVE/results.json \
  --live   discovery/output/$D/$TS_LIVE/live_hosts.json \
  --label $D
```

### Output e label custom
```bash
python3 consolidate.py --active results.json --live live_hosts.json -o results --label cliente-x
```

### JSON completo su stdout (per script/automazioni a valle)
```bash
python3 consolidate.py --active results.json --json
```

---

## Tutte le opzioni

| Flag | Default | Descrizione |
|---|---|---|
| `--active` | *(obbligatorio)* | `results.json` di `resolve_and_scan.py` |
| `--live` | — | `live_hosts.json` di `live_hosts.py` (opzionale) |
| `-o, --output` | `<radice>/output` | Cartella base (relativa alla radice o assoluta) |
| `--label` | suffisso di dominio comune ai domini mappati | Nome sotto-cartella output |
| `--json` | off | Stampa il JSON completo su stdout (oltre al testo) |

## Prossimi passi suggeriti dopo il report

Con la mappa IP→porte→domini→HTTP in mano, le direzioni piu' utili sono:
- **Servizi non-web esposti** (es. MySQL/Postgres/FTP visti su un IP nel
  report): verificarne l'esposizione e se richiedono autenticazione forte.
- **Screenshot di massa** degli URL vivi (`gowitness`/`aquatone`) per una
  review visiva veloce di decine di host.
- **Scan di vulnerabilita' mirato** (`nuclei` con i template su tech-stack
  rilevato da `live_hosts.py`) solo sugli host effettivamente vivi.
- **Controllo certificati TLS** (scadenza, wildcard, SAN) sugli host https.

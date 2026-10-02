# execute.md — `service_audit.py`

Audit mirato dei servizi **non-web** gia' individuati da
`recon/active/resolve_and_scan.py` (FTP, MySQL, PostgreSQL, SMTP/IMAP/POP3):
usa gli **NSE script di nmap** per verificare misconfigurazioni comuni.

> ⚠️ Attivita' attiva: tentativi reali di login anonimo/password vuota,
> probe open-relay. Nessun bruteforce di credenziali, nessun DoS — ma resta
> un probe verso servizi veri. Usa SOLO su host di tua proprieta' o per cui
> hai autorizzazione.

## Copertura per servizio

| Servizio (rilevato via `nmap -sV`) | NSE script usati | Cosa verifica |
|---|---|---|
| `ftp` | `ftp-anon`, `ftp-syst`, `ftp-bounce` | login anonimo consentito, info sistema, FTP bounce |
| `mysql` | `mysql-info`, `mysql-empty-password`, `mysql-enum` | account con password vuota, info versione |
| `smtp` / `smtps` / `submission` | `smtp-commands`, `smtp-open-relay`, `smtp-vuln-cve2010-4344` | open relay, comandi supportati, vulnerabilita' nota |
| `imap` / `imaps` | `imap-capabilities` | capability esposte |
| `pop3` / `pop3s` | `pop3-capabilities` | capability esposte |
| `postgresql` | *(nessuno)* | nmap non ha uno script NSE sicuro integrato di serie: viene segnalato esplicitamente come **"verifica manuale"**, non simulato con un falso senso di copertura |

Lo script lancia nmap **solo sulle porte/servizi pertinenti** di ogni host
(non un `--script` a tappeto su tutte le porte).

## Classificazione dei findings

L'output NSE grezzo e' sempre salvato (leggilo comunque: le euristiche sotto
sono un aiuto, non un sostituto della lettura manuale). I findings
automatici evitano i falsi positivi piu' comuni di un match ingenuo sulla
parola chiave (es. "NOT VULNERABLE" contiene "VULNERABLE" come sottostringa,
"doesn't seem to be an open relay" contiene comunque un output non vuoto):

| Finding | Severita' | Condizione |
|---|---|---|
| Login FTP anonimo consentito | HIGH | `ftp-anon` conferma l'accesso |
| Account MySQL con password vuota | HIGH | `mysql-empty-password` lo conferma |
| Vulnerabilita' nota (CVE-2010-4344) | HIGH | lo script segnala "VULNERABLE" (non "NOT VULNERABLE") |
| Possibile open relay SMTP | MEDIUM | `smtp-open-relay` produce un output diverso dal classico "non e' un open relay" — **verifica sempre a mano** |

Nessun finding automatico **non significa "sicuro"**: significa solo che le
euristiche note non hanno trovato nulla. Leggi comunque `manual_review` e
l'output raw.

## Profili di aggressivita' (`--profile`)

| | nmap |
|---|---|
| `stealth` | `-T2 --version-intensity 2` |
| `normal` | `-T3 --version-intensity 5` |
| `aggressive` | `-T4 --version-intensity 9` |

`--nmap-args` appende flag grezze dopo il profilo (vincono in caso di conflitto).

## Output

- `stdout` → riepilogo leggibile (anche salvato in `audit.txt`)
- `audit.json` → dati completi: findings classificati + output raw di ogni script
- `audit.txt` → stesso contenuto in formato testo
- `nmap-audit-<ip>.xml` → XML grezzo di nmap per host, per ispezione manuale

---

## Casi d'uso

### Base — tutti i servizi auditabili trovati nello scan attivo
```bash
python3 service_audit.py --active ../active/output/<target>/latest/results.json
```

### Profili
```bash
python3 service_audit.py --active results.json --profile stealth
python3 service_audit.py --active results.json --profile aggressive
```

### Passthrough: flag nmap aggiuntive
```bash
python3 service_audit.py --active results.json --nmap-args "--script-timeout 30s"
```

### Output e label custom
```bash
python3 service_audit.py --active results.json -o results --label cliente-x
```

### Pipeline completa (dalla recon all'audit)
```bash
cd recon
python3 passive/subdomains_passive.py -d example.com -o run1
python3 active/resolve_and_scan.py -iL run1/example.com/latest/subdomains.txt -o run1 --label example.com
python3 audit/service_audit.py --active run1/example.com/latest/results.json -o run1 --label example.com
```

---

## Tutte le opzioni

| Flag | Default | Descrizione |
|---|---|---|
| `--active` | *(obbligatorio)* | `results.json` di `resolve_and_scan.py` |
| `-o, --output` | `<radice>/output` | Cartella base (relativa alla radice o assoluta) |
| `--label` | suffisso di dominio comune ai domini in input | Nome sotto-cartella output |
| `--profile` | `normal` | `stealth` \| `normal` \| `aggressive` |
| `--nmap-args` | `""` | Flag grezze appese a nmap |
| `--timeout` | `300` | Timeout per host in secondi |
| `--json` | off | Stampa il JSON completo su stdout |

## Prossimi passi suggeriti

- **PostgreSQL in `manual_review`**: verifica con un client nativo (`psql`)
  usando un'utenza di test, mai credenziali reali in automazione.
- Findings MEDIUM/HIGH confermati manualmente → valutare se serve
  restringere l'esposizione (firewall, binding solo su rete interna) invece
  che fare affidamento solo su password/auth.
- **TLS/SSL audit** sugli host https rimasti fuori da questo step (servizi
  web non coperti qui: `testssl.sh`/`sslscan`).

# cybersecurity-tools

Raccolta di script Python/bash per automatizzare i passaggi ripetitivi di
una recon di sicurezza (OSINT, DNS, port scan, probing HTTP, audit servizi,
reportistica). Pensati per girare su Kali, versionati qui e sincronizzati
con `git pull`.

> ⚠️ Gli step "attivi" (tutto tranne `subdomain-enum`) generano traffico
> reale verso il target: usali solo su asset di tua proprieta' o per cui
> hai autorizzazione esplicita.

## La pipeline, in ordine

```
 1. subdomain-enum     dominio  -> lista di sottodomini           (passivo)
 2. live-host-probe    host     -> quali rispondono su HTTP/S     (attivo)
 3. port-scan          host/IP  -> IP + porte aperte + servizi    (attivo)
 4. service-audit      IP       -> check su FTP/MySQL/Postgres/SMTP trovati (attivo)
 5. recon-report       (tutto)  -> unisce 2+3 in un'unica vista leggibile
```

Ogni step e' indipendente: puoi lanciarli singolarmente, o incatenarli
passando l'output di uno come input del successivo (ogni script accetta
`-iL <file.txt>` o `--active <risultato.json precedente>`).

| # | Script | Cartella | `execute.md` |
|---|---|---|---|
| 1 | `subdomains_passive.py` | `recon/subdomain-enum/` | [recon/subdomain-enum/execute.md](recon/subdomain-enum/execute.md) |
| 2 | `live_hosts.py` | `recon/live-host-probe/` | [recon/live-host-probe/execute.md](recon/live-host-probe/execute.md) |
| 3 | `resolve_and_scan.py` | `recon/port-scan/` | [recon/port-scan/execute.md](recon/port-scan/execute.md) |
| 4 | `service_audit.py` | `recon/service-audit/` | [recon/service-audit/execute.md](recon/service-audit/execute.md) |
| 5 | `consolidate.py` | `recon/report/` | [recon/report/execute.md](recon/report/execute.md) |

**Ogni cartella ha il suo `execute.md`** con tutti i casi d'uso concreti
(profili, passthrough di flag, esempi copia-incolla). E' il primo posto
dove guardare prima di lanciare uno script.

## Dove finiscono i risultati

Tutti gli script scrivono sotto `output/`, con questa struttura fissa:

```
output/<nome-tool>/<dominio-target>/<timestamp>/<file-di-risultato>
```

- **`<nome-tool>`** identifica *quale script* ha prodotto il risultato
  (`subdomain-enum`, `live-host-probe`, `port-scan`, `service-audit`,
  `recon-report`) — cosi' scansioni diverse sullo stesso dominio non si
  mescolano mai in cartelle indistinguibili.
- **`<dominio-target>`** raggruppa i run per target: se passi piu'
  sottodomini dello stesso apex (es. `a.staging.example.com`,
  `b.prod.example.com`), finiscono comunque sotto la stessa cartella
  (`example.com`), calcolata come suffisso di dominio comune — non serve
  che siano scritti identici tra una run e l'altra.
- **`<timestamp>`** e' in ora locale, leggibile (`2026-10-02_08-51-11`).
  Ogni run aggiorna anche una scorciatoia `latest/` nella stessa cartella,
  cosi' non devi mai cercare il timestamp a mano:
  ```bash
  cat output/port-scan/example.com/latest/results.json
  ```

Esempio concreto di catena completa su un dominio. **Regola unica da
ricordare: lancia sempre i comandi dalla radice del repo**, riferendoti a
ogni script col suo path completo (`recon/<tool>/<script>.py`) — cosi'
`output/` (e qualunque `-o` relativo) si raggiunge sempre allo stesso modo,
senza dover contare quanti `../` servono:
```bash
# dalla radice del repo
D=example.com

python3 recon/subdomain-enum/subdomains_passive.py -d $D
# -> output/subdomain-enum/$D/latest/subdomains.txt

python3 recon/live-host-probe/live_hosts.py -iL output/subdomain-enum/$D/latest/subdomains.txt --label $D
# -> output/live-host-probe/$D/latest/live_hosts.json

python3 recon/port-scan/resolve_and_scan.py -iL output/subdomain-enum/$D/latest/subdomains.txt --label $D
# -> output/port-scan/$D/latest/results.json

python3 recon/report/consolidate.py \
  --active output/port-scan/$D/latest/results.json \
  --live   output/live-host-probe/$D/latest/live_hosts.json \
  --label $D
# -> output/recon-report/$D/latest/report.md  (vista unica leggibile)

python3 recon/service-audit/service_audit.py --active output/port-scan/$D/latest/results.json --label $D
# -> output/service-audit/$D/latest/audit.txt
```

## Convenzioni comuni a tutti gli script

- **Lancia sempre i comandi dalla radice del repo**, riferendoti a ogni
  script col path completo (`recon/<tool>/<script>.py`). Un `-o` relativo
  si risolve sempre dalla radice del repo, indipendentemente da dove lanci
  il comando: se invece lanci da dentro una sottocartella, un `-iL`/`--active`
  passato come path semplice viene letto relativo alla cartella in cui ti
  trovi, e i due meccanismi smettono di combaciare. Lanciando tutto dalla
  radice, questo problema non si pone mai.
- **`-o/--output`**: cartella base dei risultati. Path relativo -> risolto
  dalla radice del repo (non dalla cartella da cui lanci il comando).
  Path assoluto -> usato cosi' com'e'. Default: `<radice>/output`.
- **`--label`**: forza il nome della sotto-cartella target, altrimenti
  calcolato automaticamente dal dominio/suffisso comune.
- **`--profile stealth|normal|aggressive`**: preset di aggressivita' (timing,
  rate-limit, concorrenza) per ogni tool esterno orchestrato.
- **`--<tool>-args "..."`** (es. `--nmap-args`, `--subfinder-args`):
  passthrough di flag grezze del tool sottostante, appese dopo il profilo.
- Codice condiviso in `lib/common.py` (logging, validazione, gestione
  output, profili) — import comune a tutti gli script.

## Setup

```bash
git clone <repo> && cd cybersecurity-tools
pip install -r requirements.txt   # se presente, solo dipendenze Python
```

Gli script orchestrano tool esterni gia' presenti su Kali (`subfinder`,
`amass`, `assetfinder`, `nmap`, `naabu`, `masscan`, `httpx`...). Un tool
mancante viene saltato con un warning, non blocca l'intera pipeline.

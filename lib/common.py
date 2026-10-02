#!/usr/bin/env python3
"""
Codice condiviso tra gli script di recon/scanning:
  - logging su stderr
  - validazione dominio/IP
  - esecuzione tool esterni con timeout
  - risoluzione della cartella di output dalla radice del repo
  - combinazione profilo di aggressivita' + flag passthrough dell'utente

Importato cosi' dagli script in recon/<categoria>/*.py:

    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from lib import common
"""
from __future__ import annotations

import ipaddress
import re
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Radice del repo = cartella che contiene lib/
REPO_ROOT = Path(__file__).resolve().parent.parent

DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def log(msg: str) -> None:
    print(f"[*] {msg}", file=sys.stderr)


def warn(msg: str) -> None:
    print(f"[!] {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Validazione
# ---------------------------------------------------------------------------


def valid_domain(d: str) -> bool:
    return bool(DOMAIN_RE.match(d))


def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Esecuzione tool esterni
# ---------------------------------------------------------------------------


def run_cmd(cmd: list[str], timeout: int, input_text: str | None = None) -> tuple[int, str, str]:
    """Esegue un comando esterno. Ritorna (returncode, stdout, stderr).

    returncode 1 con stdout/stderr vuoti indica un errore locale
    (tool non trovato, timeout, eccezione) gia' loggato con warn().
    """
    try:
        proc = subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        warn(f"{cmd[0]} non trovato nel PATH, salto.")
    except subprocess.TimeoutExpired:
        warn(f"{cmd[0]} timeout dopo {timeout}s.")
    except Exception as e:  # noqa: BLE001
        warn(f"{cmd[0]} errore: {e}")
    return 1, "", ""


def run_cmd_lines(cmd: list[str], timeout: int) -> list[str]:
    """Come run_cmd ma ritorna direttamente le righe di stdout."""
    rc, out, err = run_cmd(cmd, timeout)
    if rc != 0 and not out and err.strip():
        warn(f"{cmd[0]} rc={rc}: {err.strip()[:200]}")
    return out.splitlines()


# ---------------------------------------------------------------------------
# Output dir
# ---------------------------------------------------------------------------


def resolve_output_base(output_arg: str | None) -> Path:
    """Path relativo passato con -o -> risolto dalla radice del repo.
    Path assoluto -> usato cosi' com'e'. None -> <radice>/output."""
    if not output_arg:
        return REPO_ROOT / "output"
    p = Path(output_arg)
    return p if p.is_absolute() else REPO_ROOT / p


def make_outdir(base: Path, label: str) -> Path:
    """Crea e ritorna <base>/<label>/<timestamp UTC>/."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    outdir = base / label / stamp
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir


# ---------------------------------------------------------------------------
# Profili di aggressivita' + passthrough
# ---------------------------------------------------------------------------


def parse_extra_args(raw: str) -> list[str]:
    """Split sicuro (no shell) delle flag passthrough dell'utente.
    Solleva ValueError se le virgolette non sono bilanciate."""
    return shlex.split(raw)


def effective_flags(profile_flags: dict[str, list[str]], profile: str, tool: str, user_raw: str) -> list[str]:
    """Combina preset del profilo + flag passthrough utente (appese dopo,
    quindi vincono in caso di conflitto)."""
    base = profile_flags.get(profile, {}).get(tool, [])
    return base + parse_extra_args(user_raw)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

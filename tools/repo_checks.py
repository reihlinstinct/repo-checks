"""Trusted local command: sensitive-scan --pre-merge (Python -I)."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from repo_checks.sensitive import main as scan
from repo_checks.pseudonymize import main as mask
commands = {'sensitive-scan': scan, 'pseudonymize': mask}
if not sys.argv[1:] or sys.argv[1] not in commands:
    print('{"schema_version":1,"status":"error"}')
    raise SystemExit(2)
raise SystemExit(commands[sys.argv[1]](sys.argv[2:]))

"""Trusted isolated entrypoint."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from repo_checks.secret_output import main
raise SystemExit(main())

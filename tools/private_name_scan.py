"""Trusted isolated name scanner entrypoint; no candidate imports."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from repo_checks.private_names import main
raise SystemExit(main())

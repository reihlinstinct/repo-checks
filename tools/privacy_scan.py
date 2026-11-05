"""Trusted isolated privacy scanner entrypoint, no consumer imports."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from repo_checks.privacy import main
raise SystemExit(main())

"""Run synthetic-only complete pruned-pass measurements."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from repo_checks.hmac_pruned_benchmark import main
raise SystemExit(main())

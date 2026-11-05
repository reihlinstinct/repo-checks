"""Enforce tracked repository placement; never print candidate file names."""
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from repo_checks.inputs import Inputs

try:
    with Inputs(Path('.')) as inputs:
        rules = json.loads(inputs.read('docs/repo-structure.json'))
        violations = 0
        for name in inputs.paths:
            if '/' not in name:
                violations += name not in rules['root_files']
            else:
                top = name.split('/')[0]
                violations += Path(name).suffix not in rules['directories'].get(top, [])
    print(json.dumps({'structure_violations': violations}))
    raise SystemExit(bool(violations))
except Exception:
    print('{"status":"error"}')
    raise SystemExit(2)

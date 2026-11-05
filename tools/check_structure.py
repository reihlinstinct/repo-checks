"""Enforce tracked allowed/forbidden/required placement; counts-only output."""
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from repo_checks.inputs import Inputs


def violations(paths, rules):
    missing = set(rules['required_root_files']) - paths
    count = len(missing)
    for name in paths:
        if '/' not in name:
            count += name not in rules['root_files']
        else:
            top = name.split('/')[0]
            count += Path(name).suffix not in rules['directories'].get(top, [])
        count += name in rules['forbidden_paths']
    for directory, required in rules['required_by_directory'].items():
        count += len({directory + '/' + item for item in required} - paths)
    return count


def main():
    try:
        with Inputs(Path('.')) as inputs:
            rules = json.loads(inputs.read('docs/repo-structure.json'))
            count = violations(inputs.paths, rules)
        print(json.dumps({'structure_violations': count}))
        return int(bool(count))
    except Exception:
        print('{"status":"error"}')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())

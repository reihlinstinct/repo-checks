import importlib.util
from pathlib import Path
import json
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('structure',ROOT/'tools/check_structure.py')
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
class StructureTests(unittest.TestCase):
    def test_allowed_forbidden_required(self):
        rules={'root_files':['README.md','SECURITY.md'],'required_root_files':['SECURITY.md'],'directories':{'src':['.py']},'required_by_directory':{'src':['main.py']},'forbidden_paths':['src/bad.py']}
        self.assertEqual(0,s.violations({'SECURITY.md','src/main.py'},rules))
        for paths in [{'src/main.py'},{'SECURITY.md'},{'SECURITY.md','src/main.py','bad.txt'},{'SECURITY.md','src/main.py','src/no.js'},{'SECURITY.md','src/main.py','src/bad.py'}]:self.assertGreater(s.violations(paths,rules),0)
    def test_cli_cannot_always_pass(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);subprocess.run(['git','init','-q',d],check=True);(p/'docs').mkdir()
            rules={'root_files':[],'required_root_files':['SECURITY.md'],'directories':{'docs':['.json']},'required_by_directory':{},'forbidden_paths':[]}
            (p/'docs/repo-structure.json').write_text(json.dumps(rules));subprocess.run(['git','-C',d,'add','.'],check=True)
            r=subprocess.run(['python3','-I',str(ROOT/'tools/check_structure.py')],cwd=d,capture_output=True,text=True)
            self.assertEqual(1,r.returncode)

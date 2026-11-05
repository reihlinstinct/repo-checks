"""Synthetic isolated action boundary tests, no real identifiers."""
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
BOOT=ROOT/'actions/privacy/bootstrap.py'
spec=importlib.util.spec_from_file_location('privacy_boot',BOOT)
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)

class PrivacyActionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'caller';self.root.mkdir()
        subprocess.run(['git','init','-q',str(self.root)],check=True)
        (self.root/'clean.md').write_text('synthetic@example.invalid')
        subprocess.run(['git','-C',str(self.root),'add','.'],check=True)
    def tearDown(self):self.temp.cleanup()
    def run_action(self,**changes):
        env=os.environ.copy();env.update(GITHUB_WORKSPACE=self.temp.name,CHECK_ROOT=str(self.root));env.update(changes)
        return subprocess.run([sys.executable,'-I',str(BOOT)],env=env,cwd=self.root,capture_output=True,text=True)
    def test_clean_failure_and_error_propagation(self):
        r=self.run_action();self.assertEqual(0,r.returncode);self.assertEqual('pass',json.loads(r.stdout)['status'])
        secret='ghp_'+'Z'*36
        (self.root/'candidate.txt').write_text(secret);subprocess.run(['git','-C',str(self.root),'add','.'],check=True)
        r=self.run_action();self.assertEqual(1,r.returncode);self.assertEqual('findings',json.loads(r.stdout)['status']);self.assertNotIn(secret,r.stdout+r.stderr)
        (self.root/'candidate.txt').unlink()
        self.assertEqual(2,self.run_action().returncode)
    def test_caller_python_never_imported(self):
        marker=Path(self.temp.name)/'executed';poison='from pathlib import Path\nPath('+repr(str(marker))+').touch()\nraise RuntimeError()\n'
        (self.root/'sitecustomize.py').write_text(poison);(self.root/'repo_checks.py').write_text(poison)
        r=self.run_action(PYTHONPATH=str(self.root))
        self.assertEqual(0,r.returncode);self.assertFalse(marker.exists())
    def test_root_alias_escape_overlap_and_injection(self):
        for root in [str(ROOT),str(self.root/'..'),str(self.root)+'-missing','--PRIVATE_ARGUMENT;touch x']:
            r=self.run_action(CHECK_ROOT=root);self.assertEqual(2,r.returncode);self.assertNotIn('PRIVATE_ARGUMENT',r.stdout+r.stderr)
        link=Path(self.temp.name)/'alias';link.symlink_to(self.root,target_is_directory=True)
        self.assertEqual(2,self.run_action(CHECK_ROOT=str(link)).returncode)
        with tempfile.TemporaryDirectory() as other,self.assertRaises(ValueError):a.safe_root(other,Path(self.temp.name),ROOT/'actions/privacy')
    def test_fixed_output_and_symlink_refusal(self):
        output=Path(self.temp.name)/'result';output.touch()
        r=self.run_action(GITHUB_OUTPUT=str(output));self.assertEqual(0,r.returncode)
        line=output.read_text();self.assertEqual(1,len(line.splitlines()));self.assertEqual(json.loads(line[7:]),json.loads(r.stdout))
        link=Path(self.temp.name)/'out-link';link.symlink_to(output);before=output.read_text()
        self.assertEqual(2,self.run_action(GITHUB_OUTPUT=str(link)).returncode);self.assertEqual(before,output.read_text())
    def test_schema_refuses_boolean_counts_extra_fields_and_invalid_status(self):
        valid={'schema_version':1,'status':'pass','counts':{key:0 for key in a.COUNT_KEYS},'text_files':1,'binary_files_unscanned':0}
        variants=[{**valid,'private':'value'},{**valid,'counts':{**valid['counts'],'phone':True}},{**valid,'status':'findings'},{**valid,'text_files':20001}]
        for value in variants:
            with self.assertRaises(ValueError):a.validate(value,0)
        with self.assertRaises(ValueError):a.validate({'schema_version':1,'status':'error','extra':'value'},2)
    def test_invalid_engine_result_not_forwarded(self):
        import repo_checks.privacy as engine
        def fake(_):print('{"PRIVATE_RESULT":"x"}');return 0
        env={'GITHUB_WORKSPACE':self.temp.name,'CHECK_ROOT':str(self.root)}
        out=io.StringIO()
        with patch.dict(os.environ,env),patch.object(engine,'main',side_effect=fake),redirect_stdout(out):self.assertEqual(2,a.main())
        self.assertNotIn('PRIVATE_RESULT',out.getvalue())
    def test_action_yaml_boundary(self):
        s=(ROOT/'actions/privacy/action.yml').read_text()
        self.assertIn('run: python3 -I "$TRUSTED_ACTION/bootstrap.py"',s)
        for unsafe in ['continue-on-error','run: ${{','pip install','uses:']:self.assertNotIn(unsafe,s)

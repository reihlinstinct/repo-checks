import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
BOOT=ROOT/'actions/scorecard/bootstrap.py'
spec=importlib.util.spec_from_file_location('action_boot',BOOT)
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)

class ActionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'caller';self.root.mkdir()
        subprocess.run(['git','init','-q',str(self.root)],check=True)
        for path,data in [('.repo-checks.json',{'version':1,'checks':{'scorecard':{'baseline':'.github/baseline.json'}}}),('.github/baseline.json',{'version':1,'findings':[]})]:
            p=self.root/path;p.parent.mkdir(exist_ok=True);p.write_text(json.dumps(data))
        subprocess.run(['git','-C',str(self.root),'add','.'],check=True)
    def tearDown(self):self.temp.cleanup()
    def run_action(self, **changes):
        env=os.environ.copy();env.update(GITHUB_WORKSPACE=self.temp.name,CHECK_ROOT=str(self.root),CHECK_POLICY='.repo-checks.json')
        env.update(changes)
        return subprocess.run([sys.executable,'-I',str(BOOT)],env=env,cwd=self.root,capture_output=True,text=True)
    def test_clean_result_and_failure_propagation(self):
        r=self.run_action();self.assertEqual(r.returncode,0);self.assertEqual(r.stderr,'')
        p=self.root/'scripts/a.sh';p.parent.mkdir();p.write_text('pip install synthetic\n')
        subprocess.run(['git','-C',str(self.root),'add','.'],check=True)
        r=self.run_action();self.assertEqual(r.returncode,1);self.assertEqual(json.loads(r.stdout)['status'],'fail')
    def test_poisoned_pythonpath_cwd_and_input_never_execute(self):
        marker=Path(self.temp.name)/'executed'
        poison='from pathlib import Path\nPath('+repr(str(marker))+').touch()\nraise RuntimeError()\n'
        (self.root/'sitecustomize.py').write_text(poison);(self.root/'repo_checks.py').write_text(poison)
        r=self.run_action(PYTHONPATH=str(self.root),CHECK_POLICY='--SECRET;touch '+str(marker))
        self.assertEqual(r.returncode,2);self.assertFalse(marker.exists());self.assertNotIn('SECRET',r.stdout+r.stderr)
    def test_alias_overlap_and_escape_refused(self):
        for path in [str(ROOT),str(ROOT/'actions'),str(self.root/'..'),str(self.root)+'-missing']:
            r=self.run_action(CHECK_ROOT=path);self.assertEqual(r.returncode,2)
        alias=Path(self.temp.name)/'alias';alias.symlink_to(self.root,target_is_directory=True)
        self.assertEqual(self.run_action(CHECK_ROOT=str(alias)).returncode,2)
    def test_output_fixed_schema_and_line(self):
        output=Path(self.temp.name)/'output';output.touch()
        r=self.run_action(GITHUB_OUTPUT=str(output));self.assertEqual(r.returncode,0)
        line=output.read_text();self.assertTrue(line.startswith('result='));self.assertEqual(len(line.splitlines()),1)
        self.assertEqual(json.loads(line[7:]),json.loads(r.stdout))
    def test_output_schema_rejects_malformed_counts_categories_and_extra(self):
        valid={'schema_version':1,'check_id':'scorecard','engine_version':'0.1.0','status':'pass','counts':{'current':0,'new':0,'stale':0},'error_category':None}
        variants=[{**valid,'extra':'private'},{**valid,'counts':{'current':True,'new':0,'stale':0}},{**valid,'error_category':'SECRET'},{**valid,'counts':{'current':1001,'new':0,'stale':0}},{**valid,'status':'fail'}]
        for v in variants:
            with self.assertRaises(ValueError):a.validate(v,0)
    def test_output_symlink_refused(self):
        dest=Path(self.temp.name)/'dest';dest.touch();link=Path(self.temp.name)/'link';link.symlink_to(dest)
        r=self.run_action(GITHUB_OUTPUT=str(link));self.assertEqual(r.returncode,2);self.assertEqual(dest.read_text(),'')
    def test_yaml_uses_quoted_env_not_shell_interpolation(self):
        text=(ROOT/'actions/scorecard/action.yml').read_text()
        self.assertIn('run: python3 -I "$TRUSTED_ACTION/bootstrap.py"',text)
        self.assertNotIn('run: ${{',text)
        self.assertNotIn('continue-on-error',text)
    def test_direct_workspace_and_action_overlap_bounds(self):
        workspace=Path(self.temp.name).resolve()
        with tempfile.TemporaryDirectory() as other, self.assertRaises(ValueError):
            a.safe_root(other,workspace,ROOT/'actions/scorecard')
        # Action stored inside caller: must reject even when both are inside workspace.
        action=self.root/'trusted-action';action.mkdir()
        with self.assertRaises(ValueError):a.safe_root(str(self.root),workspace,action)
    def test_main_validates_untrusted_wrapper_result_before_output(self):
        from unittest.mock import patch
        from contextlib import redirect_stdout
        import io
        sys.path.insert(0,str(ROOT/'src'))
        import repo_checks.wrapper as wrapper
        result={'schema_version':1,'check_id':'scorecard','engine_version':'0.1.0','status':'pass','counts':{'current':True,'new':0,'stale':0},'error_category':None}
        def fake(_):print(json.dumps(result));return 0
        output=Path(self.temp.name)/'result';output.touch()
        env={'GITHUB_WORKSPACE':self.temp.name,'CHECK_ROOT':str(self.root),'CHECK_POLICY':'.repo-checks.json','GITHUB_OUTPUT':str(output)}
        with patch.dict(os.environ,env),patch.object(wrapper,'main',side_effect=fake),redirect_stdout(io.StringIO()):
            self.assertEqual(a.main(),2)
        self.assertEqual(output.read_text(),'')

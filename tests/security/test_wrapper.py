import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]

class WrapperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        self.write('.repo-checks.json', {'version':1,'checks':{'scorecard':{'baseline':'.github/baseline.json'}}})
        self.write('.github/baseline.json', {'version':1,'findings':[]})
    def tearDown(self): self.temp.cleanup()
    def write(self, path, value):
        p=self.root/path; p.parent.mkdir(parents=True,exist_ok=True)
        p.write_text(value if isinstance(value,str) else json.dumps(value),encoding='utf-8')
        subprocess.run(['git','-C',str(self.root),'add','--',path],check=True)
    def run_check(self, *args):
        env=os.environ.copy(); env['PYTHONPATH']=str(ROOT/'src')
        r=subprocess.run([sys.executable,'-m','repo_checks.wrapper','--root',str(self.root),*args],env=env,capture_output=True,text=True)
        self.assertEqual(r.stderr,''); result=json.loads(r.stdout)
        self.assertEqual(set(result),{'schema_version','check_id','engine_version','status','counts','error_category'})
        return r,result
    def test_clean_and_new_finding_exits(self):
        r,v=self.run_check(); self.assertEqual(r.returncode,0); self.assertEqual(v['status'],'pass')
        self.write('.github/workflows/test.yml','jobs: {}\n')
        r,v=self.run_check(); self.assertEqual(r.returncode,1); self.assertEqual(v['counts']['new'],1)
    def test_private_evidence_and_paths_never_echo(self):
        marker='SECRET_SYNTHETIC_DO_NOT_PRINT'
        self.write('scripts/'+marker+'.sh','pip install '+marker+'\n')
        r,v=self.run_check(); self.assertEqual(r.returncode,1)
        self.assertNotIn(marker,r.stdout+r.stderr)
    def test_invalid_policy_unknown_duplicate_and_types(self):
        for value in ['{"version":1,"version":1,"checks":{"scorecard":{"baseline":".github/baseline.json"}}}', {'version':True,'checks':{}}, {'version':1,'checks':{},'extra':1}, []]:
            self.write('.repo-checks.json',value); r,v=self.run_check(); self.assertEqual(r.returncode,2)
    def test_baseline_invalid_issue_and_unknown_field(self):
        entry={'path':'a','rule':'x','scope':'x','evidence':'private','issue':'http://invalid','reason':'x'}
        for value in [{'version':1,'findings':[entry]}, {'version':1,'findings':[],'extra':1}]:
            self.write('.github/baseline.json',value); r,v=self.run_check(); self.assertEqual(r.returncode,2); self.assertNotIn('private',r.stdout)
    def test_missing_policy_and_invalid_arguments_do_not_echo(self):
        (self.root/'.repo-checks.json').unlink()
        r,v=self.run_check(); self.assertEqual(r.returncode,2)
        r,v=self.run_check('--SECRET_SYNTHETIC'); self.assertEqual(r.returncode,2); self.assertNotIn('SECRET_SYNTHETIC',r.stdout)
    def test_symlink_and_untracked_policy_stop(self):
        p=self.root/'.repo-checks.json'; p.unlink(); p.symlink_to(self.root/'.github/baseline.json')
        r,v=self.run_check(); self.assertEqual(r.returncode,2)
        p.unlink(); p.write_text('{}'); subprocess.run(['git','-C',str(self.root),'rm','-f','--cached','.repo-checks.json'],check=True,stdout=subprocess.DEVNULL)
        r,v=self.run_check(); self.assertEqual(r.returncode,2)
    def test_requirement_data_is_scanned_and_never_executed(self):
        self.write('scripts/setup.sh','pip install --require-hashes -r requirements.txt\n')
        self.write('requirements.txt','synthetic==1\n')
        r,v=self.run_check(); self.assertEqual(r.returncode,1); self.assertEqual(v['counts']['new'],1)
    def test_bad_requirement_path_fails_closed(self):
        self.write('scripts/setup.sh','pip install --require-hashes -r ../SECRET_SYNTHETIC\n')
        r,v=self.run_check(); self.assertEqual(r.returncode,2); self.assertNotIn('SECRET_SYNTHETIC',r.stdout)
    def test_findings_cap_end_to_end_fixed_redaction(self):
        self.write('scripts/SECRET_SYNTHETIC.sh', 'pip install SECRET_SYNTHETIC\n' * 1002)
        r,v=self.run_check(); self.assertEqual(r.returncode,2)
        self.assertEqual(v['status'],'error'); self.assertNotIn('SECRET_SYNTHETIC',r.stdout+r.stderr)
    def test_nested_baseline_unknown_duplicate_types_and_size_refused(self):
        entry={'path':'a','rule':'x','scope':'x','evidence':'x','issue':'https://example.invalid/issue','reason':'x'}
        variants=[{**entry,'extra':'x'}, {**entry,'reason':True}, {**entry,'evidence':'x'*8193}, {**entry,'path':[]}, {**entry,'issue':7}]
        for e in variants:
            self.write('.github/baseline.json',{'version':1,'findings':[e]})
            r,v=self.run_check(); self.assertEqual(r.returncode,2)
        raw=json.dumps({'version':1,'findings':[entry]}).replace('"reason": "x"','"reason":"x","reason":"x"')
        self.write('.github/baseline.json',raw);r,v=self.run_check();self.assertEqual(r.returncode,2)
    def test_sink_stops_before_unbounded_finding_allocation(self):
        import importlib
        from unittest.mock import patch
        sys.path.insert(0,str(ROOT/'src'))
        w=importlib.import_module('repo_checks.wrapper'); e=importlib.import_module('repo_checks.scorecard')
        self.write('scripts/many.sh','pip install synthetic\n'*10000)
        count=0; original=e.Finding
        def counted(*args,**kwargs):
            nonlocal count
            count+=1
            return original(*args,**kwargs)
        with patch.object(e,'Finding',side_effect=counted), self.assertRaises(w.InputError):
            w.check(self.root,'.repo-checks.json')
        self.assertLessEqual(count,w.MAX_FINDINGS+1)
    def test_normalized_current_tree_parity(self):
        import importlib
        sys.path.insert(0,str(ROOT/'src'))
        w=importlib.import_module('repo_checks.wrapper'); e=importlib.import_module('repo_checks.scorecard')
        fixtures=[('.github/workflows/a.yml','permissions: {}\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@v7\n'),('scripts/build.sh','pip install synthetic\n'),('Dockerfile','FROM ubuntu:latest\n')]
        for path,text in fixtures:self.write(path,text)
        with w.Inputs(self.root) as inputs:
            new=w.scan(inputs)
        old=e.scan(self.root)
        self.assertEqual([vars(f) for f in old],[vars(f) for f in new])

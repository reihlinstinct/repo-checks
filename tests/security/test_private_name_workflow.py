"""Exercise the actual trusted workflow's binding/report scripts with fake APIs."""
import copy
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/private-name-guard.yml'


def scripts():
    result = []
    lines = WORKFLOW.read_text().splitlines()
    for index, line in enumerate(lines):
        if line.strip() != 'script: |':
            continue
        indent = len(line) - len(line.lstrip()) + 2
        body = []
        for item in lines[index + 1:]:
            if item.strip() and len(item) - len(item.lstrip()) < indent:
                break
            body.append(item[indent:])
        result.append('\n'.join(body))
    return result


class WorkflowTests(unittest.TestCase):
    def sample(self):
        run = dict(id=7, event='pull_request', status='completed', head_sha='a' * 40,
                   path='.github/workflows/privacy-request.yml', conclusion='success',
                   repository={'id': 1}, head_repository={'id': 1})
        context = dict(eventName='workflow_run', repo={'owner': 'ZZOwner', 'repo': 'ZZRepo'},
                       payload={'repository': {'id': 1, 'private': False}, 'workflow_run': copy.deepcopy(run)},
                       serverUrl='https://github.com', runId=123)
        return context, run

    def execute(self, script, context=None, run=None, env=None):
        harness = '''const input=JSON.parse(process.argv[1]);
        const context=input.context; const result={outputs:{},statuses:[]};
        const core={setOutput:(k,v)=>result.outputs[k]=v};
        const github={rest:{actions:{getWorkflowRun:async()=>({data:input.run})},
          repos:{createCommitStatus:async x=>result.statuses.push(x)}}};
        process.env=input.env||{};
        (async()=>{try{await (new Function('context','core','github', 'return (async()=>{'+input.script+'})()'))(context,core,github);}
        catch(e){result.error=true;}console.log(JSON.stringify(result));})();'''
        p = subprocess.run(['node', '-e', harness, json.dumps(dict(script=script, context=context, run=run, env=env))],
                           text=True, capture_output=True, check=True)
        return json.loads(p.stdout)

    def test_binds_only_original_public_pr_request(self):
        context, run = self.sample()
        self.assertEqual({'sha': 'a' * 40, 'source-success': 'true', 'same-repository': 'true', 'run-id': '7'},
                         self.execute(scripts()[0], context, run)['outputs'])
        for field, value in [('id', 8), ('event', 'push'), ('status', 'queued'),
                             ('head_sha', 'b' * 40), ('repository', {'id': 3}),
                             ('head_repository', {'id': 4}), ('path', '.github/workflows/evil.yml'),
                             ('conclusion', 'failure')]:
            changed = copy.deepcopy(run)
            changed[field] = value
            self.assertTrue(self.execute(scripts()[0], context, changed).get('error'), field)

    def test_rejects_bad_source_payload_before_scanning(self):
        context, run = self.sample()
        cases = []
        changed = copy.deepcopy(context); changed['eventName'] = 'push'; cases.append(changed)
        changed = copy.deepcopy(context); changed['payload']['repository']['private'] = True; cases.append(changed)
        for field, value in [('event', 'push'), ('status', 'queued'), ('id', '7'),
                             ('head_sha', '$(touch /tmp/ZZNever)'), ('head_repository', None)]:
            changed = copy.deepcopy(context); changed['payload']['workflow_run'][field] = value; cases.append(changed)
        for changed in cases:
            result = self.execute(scripts()[0], changed, run)
            self.assertTrue(result.get('error'))
            self.assertEqual({}, result['outputs'])

    def test_source_failure_is_bound_but_never_success(self):
        context, run = self.sample()
        run['conclusion'] = context['payload']['workflow_run']['conclusion'] = 'failure'
        self.assertEqual('false', self.execute(scripts()[0], context, run)['outputs']['source-success'])

    def test_reporting_is_exact_head_and_fail_closed(self):
        context, run = self.sample()
        for scan in ['success', 'failure', 'cancelled', 'skipped', '']:
            for source in ['true', 'false', '']:
                result = self.execute(scripts()[1], context, run, env=dict(CANDIDATE_SHA='a' * 40,
                                      SCAN_RESULT=scan, SOURCE_SUCCESS=source,
                                      SOURCE_RUN_ID='7', SAME_REPOSITORY='true'))
                status = result['statuses'][0]
                self.assertEqual('a' * 40, status['sha'])
                self.assertEqual('private-name-guard', status['context'])
                self.assertEqual('success' if scan == 'success' and source == 'true' else 'failure', status['state'])
        self.assertTrue(self.execute(scripts()[1], context, env={'CANDIDATE_SHA': 'bad'}).get('error'))

    def test_fork_is_bound_for_constant_failure_without_policy_access(self):
        context, run = self.sample()
        run['head_repository'] = context['payload']['workflow_run']['head_repository'] = {'id': 2}
        bound = self.execute(scripts()[0], context, run)
        self.assertEqual('false', bound['outputs']['same-repository'])
        env = dict(CANDIDATE_SHA='a' * 40, SOURCE_RUN_ID='7', SAME_REPOSITORY='false',
                   SOURCE_SUCCESS='true', SCAN_RESULT='success')
        result = self.execute(scripts()[1], context, run, env)
        self.assertEqual('failure', result['statuses'][0]['state'])
        self.assertEqual('Trusted privacy scan failed or unavailable', result['statuses'][0]['description'])
        scan = WORKFLOW.read_text().split('  scan:\n')[1].split('  report:\n')[0]
        self.assertIn("if: needs.bind.outputs.same-repository == 'true' && needs.bind.outputs.source-success == 'true'", scan)

    def test_report_rebinds_api_sha_run_and_repository(self):
        context, run = self.sample()
        env = dict(CANDIDATE_SHA='a' * 40, SOURCE_RUN_ID='7', SAME_REPOSITORY='true',
                   SOURCE_SUCCESS='true', SCAN_RESULT='success')
        for field, value in [('id', 8), ('head_sha', 'b' * 40), ('repository', {'id': 3}),
                             ('event', 'push'), ('path', '.github/workflows/other.yml'),
                             ('status', 'queued')]:
            changed = copy.deepcopy(run); changed[field] = value
            result = self.execute(scripts()[1], context, changed, env)
            self.assertTrue(result.get('error'), field)
            self.assertEqual([], result['statuses'])
        for field, value in [('head_repository', {'id': 2}), ('conclusion', 'failure')]:
            changed = copy.deepcopy(run); changed[field] = value
            self.assertEqual('failure', self.execute(scripts()[1], context, changed, env)['statuses'][0]['state'])

    def test_fetch_exact_sha_and_clean_tree_are_executed(self):
        import os, tempfile
        text = WORKFLOW.read_text().split('          set -euo pipefail\n', 1)[1].split('      - name: Secret-sourced', 1)[0]
        code = 'set -euo pipefail\n' + '\n'.join(line[10:] for line in text.splitlines())
        for actual, dirty, expected in [('a' * 40, '', 0), ('b' * 40, '', 1), ('a' * 40, ' M item', 1)]:
            with self.subTest(actual=actual, dirty=dirty), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); (root / 'workspace').mkdir(); (root / 'bin').mkdir()
                git = root / 'bin/git'
                git.write_text('#!/bin/bash\ncase "$*" in *"rev-parse HEAD"*) printf "%s\\n" "$ACTUAL";; *"status --porcelain=v1 --untracked-files=all"*) printf "%s" "$DIRTY";; esac\n')
                git.chmod(0o700)
                env = dict(os.environ, PATH=str(root / 'bin') + ':' + os.environ['PATH'],
                           GITHUB_WORKSPACE=str(root / 'workspace'), GITHUB_REPOSITORY='ZZOwner/ZZRepo',
                           CANDIDATE_SHA='a' * 40, ACTUAL=actual, DIRTY=dirty)
                result = subprocess.run(['bash', '-c', code], env=env, capture_output=True)
                self.assertEqual(expected, result.returncode)

    def test_generic_findings_allowed_but_errors_missing_and_mismatch_fail(self):
        import os
        text = WORKFLOW.read_text().split("          python3 -I - <<'PYTHON'\n")[1].split('          PYTHON')[0]
        code = '\n'.join(line[10:] for line in text.splitlines())
        for state, outcome, expected in [('pass', 'success', 0), ('findings', 'failure', 0),
                                         ('error', 'failure', 1), ('pass', 'failure', 1),
                                         ('findings', 'success', 1), ('', '', 1)]:
            env = dict(os.environ, GENERIC_RESULT=json.dumps({'status': state}), GENERIC_OUTCOME=outcome)
            p = subprocess.run(['python3', '-I', '-c', code], env=env, capture_output=True)
            self.assertEqual(expected, p.returncode)

    def test_scorecard_baseline_is_exact_report_permission_only(self):
        value = json.loads((ROOT / 'docs/scorecard-baseline.json').read_text())
        self.assertEqual({'version', 'findings'}, set(value))
        self.assertEqual(1, value['version'])
        findings = [f for f in value['findings'] if f['path'] == '.github/workflows/private-name-guard.yml']
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual('.github/workflows/private-name-guard.yml', finding['path'])
        self.assertEqual('job-write', finding['rule'])
        self.assertEqual('report', finding['scope'])
        self.assertEqual('statuses: write', finding['evidence'])
        self.assertEqual('https://github.com/reihlinstinct/repo-checks/issues/30', finding['issue'])
        self.assertTrue(finding['reason'])
        self.assertIn('--baseline docs/scorecard-baseline.json',
                      (ROOT / '.github/workflows/ci.yml').read_text())

    def test_exact_job_privileges_and_secret_boundary(self):
        text = WORKFLOW.read_text()
        sections = {}
        for job in ('bind', 'scan', 'report'):
            body = text.split('\n  ' + job + ':\n', 1)[1]
            import re
            body = re.split(r'\n  [a-z][a-z-]*:\n', body, maxsplit=1)[0]
            sections[job] = body
        expected = {'bind': {'actions': 'read'}, 'scan': {'contents': 'read'},
                    'report': {'actions': 'read', 'statuses': 'write'}}
        for job, body in sections.items():
            lines = body.splitlines()
            start = lines.index('    permissions:') + 1
            actual = {}
            for line in lines[start:]:
                if not line.startswith('      '):
                    break
                key, value = line.strip().split(':', 1)
                self.assertNotIn(key, actual)
                actual[key] = value.strip()
            self.assertEqual(expected[job], actual)
        self.assertEqual(1, text.count('${{ secrets.'))
        self.assertEqual(0, sections['bind'].count('secrets.'))
        self.assertEqual(0, sections['report'].count('secrets.'))
        secret_step = sections['scan'].split('      - name: Secret-sourced private-name scan\n', 1)[1].split('      - name:', 1)[0]
        self.assertEqual(1, secret_step.count('secrets.'))
        self.assertIn('PRIVATE_NAME_TERMS_JSON: ${{ secrets.PRIVATE_NAME_TERMS_JSON }}', secret_step)
        self.assertIn("    if: always() && needs.bind.result == 'success'", sections['report'])
        self.assertIn('permissions: {}', text.split('jobs:', 1)[0])

    def test_both_landed_pins_and_exact_git_hardening(self):
        text = WORKFLOW.read_text()
        import re
        pins = re.findall(r'uses: reihlinstinct/repo-checks/actions/([^@]+)@([^\s]+)', text)
        self.assertEqual([('private-names', '52293de5de6c2257b531e36a24eb2be61d80d509'),
                          ('privacy', '52293de5de6c2257b531e36a24eb2be61d80d509')], pins)
        for line in ['export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0',
                     'export GIT_CONFIG_COUNT=3',
                     'export GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null',
                     'export GIT_CONFIG_KEY_1=core.fsmonitor GIT_CONFIG_VALUE_1=false',
                     'export GIT_CONFIG_KEY_2=protocol.file.allow GIT_CONFIG_VALUE_2=never']:
            self.assertIn('          ' + line + '\n', text)

    def test_privilege_and_execution_contract(self):
        text = WORKFLOW.read_text()
        scan = text.split('\n  scan:\n')[1].split('\n  report:\n')[0]
        report = text.split('\n  report:\n')[1]
        self.assertIn('environment: privacy-policy', scan)
        self.assertIn('PRIVATE_NAME_TERMS_JSON:\n        required: true', text)
        self.assertIn('contents: read', scan)
        self.assertIn('actions/private-names@52293de5de6c2257b531e36a24eb2be61d80d509', scan)
        self.assertNotIn('statuses: write', scan)
        self.assertEqual(1, scan.count('PRIVATE_NAME_TERMS_JSON:'))
        self.assertNotIn('secrets.', report)
        self.assertNotIn('checkout', report)
        self.assertIn('statuses: write', report)
        self.assertEqual(1, text.count('continue-on-error: true'))
        self.assertIn('Reject generic scanner errors', scan)
        for unsafe in [ 'pull_request_target', 'secrets: inherit', 'npm ', 'pip ', 'upload-artifact', 'cache@']:
            self.assertNotIn(unsafe, text)

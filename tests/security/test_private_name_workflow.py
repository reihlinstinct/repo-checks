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
                   repository={'id': 1}, head_repository={'id': 2})
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
        self.assertEqual({'sha': 'a' * 40, 'source-success': 'true'},
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
        context, _ = self.sample()
        for scan in ['success', 'failure', 'cancelled', 'skipped', '']:
            for source in ['true', 'false', '']:
                result = self.execute(scripts()[1], context, env=dict(CANDIDATE_SHA='b' * 40,
                                      SCAN_RESULT=scan, SOURCE_SUCCESS=source))
                status = result['statuses'][0]
                self.assertEqual('b' * 40, status['sha'])
                self.assertEqual('private-name-guard', status['context'])
                self.assertEqual('success' if scan == 'success' and source == 'true' else 'failure', status['state'])
        self.assertTrue(self.execute(scripts()[1], context, env={'CANDIDATE_SHA': 'bad'}).get('error'))

    def test_privilege_and_execution_contract(self):
        text = WORKFLOW.read_text()
        scan = text.split('\n  scan:\n')[1].split('\n  report:\n')[0]
        report = text.split('\n  report:\n')[1]
        self.assertIn('environment: privacy-policy', scan)
        self.assertIn('PRIVATE_NAME_TERMS_JSON:\n        required: true', text)
        self.assertIn('contents: read', scan)
        self.assertNotIn('statuses: write', scan)
        self.assertEqual(1, scan.count('PRIVATE_NAME_TERMS_JSON:'))
        self.assertNotIn('secrets.', report)
        self.assertNotIn('checkout', report)
        self.assertIn('statuses: write', report)
        for unsafe in ['continue-on-error', 'pull_request_target', 'secrets: inherit', 'npm ', 'pip ', 'upload-artifact', 'cache@']:
            self.assertNotIn(unsafe, text)

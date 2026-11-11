import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawnSync, spawn } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { validate, summarize, scan, TAGS, watchPage, assertNavigation } from './scan.mjs';

const good = '<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src &#39;self&#39;; script-src &#39;self&#39;"><title>ZZ fixture</title><body><main><h1>ZZ form</h1><label for="zz-input">ZZ field</label><input id="zz-input"><button>ZZ submit</button></main></body></html>';
const bad = '<!doctype html><html><body><main><img src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"><button></button></main></body></html>';
const config = { version: 1, paths: ['/'] };

test('origin/config fail closed and cannot select arbitrary remote targets', () => {
  for (const base of ['https://localhost/', 'http://example.invalid/',
    'http://u:p@localhost/', 'http://localhost/path', 'http://localhost/?q=1']) {
    assert.throws(() => validate(base, config));
  }
  for (const paths of [[], ['//example.invalid/'], ['/\\example.invalid/'], ['/\n'],
    ['/','/'], Array(13).fill('/'), ['x'], [null]]) {
    assert.throws(() => validate('http://localhost:8765/', { version: 1, paths }));
  }
  assert.throws(() => validate('http://localhost/', { ...config, exclude: ['button-name'] }));
  assert.throws(() => validate('http://localhost/', { paths: ['/'], version: 2 }));
  assert.equal(validate('http://127.0.0.1:8765/', config).paths.length, 1);
  assert.ok(TAGS.includes('wcag2a') && TAGS.includes('wcag2aa') && TAGS.includes('wcag22aa'));
});

test('output strips HTML, selectors, URLs and messages', () => {
  const result = summarize({ violations: [{ id: 'button-name', nodes: [{ html: 'ZZ secret' }],
    description: 'ZZ secret', helpUrl: 'https://example.invalid/' }], incomplete: [{}] });
  assert.deepEqual(result, { violations: 1, nodes: 1, incomplete: 1, rules: ['button-name'] });
  assert.doesNotMatch(JSON.stringify(result), /secret|invalid/);
  assert.throws(() => summarize({ violations: [{ id: 'unsafe\nvalue', nodes: [] }], incomplete: [] }));
});

test('CLI tool/config errors return 2 without leaking exception or path', () => {
  const run = spawnSync(process.execPath, ['scan.mjs'], { cwd: import.meta.dirname,
    env: { ...process.env, FORCE_COLOR: '', A11Y_CONFIG: '/ZZ-missing-config-secret' }, encoding: 'utf8' });
  assert.equal(run.status, 2);
  assert.equal(run.stderr, '');
  assert.equal(JSON.parse(run.stdout).status, 'error');
  assert.doesNotMatch(run.stdout, /ZZ-missing/);
});

test('independent request/response/pageerror and final-origin defense tripwires', () => {
  const handlers = {};
  const state = { blocked: false, pageError: false };
  const origin = 'http://127.0.0.1:8765';
  watchPage({ on: (event, handler) => { handlers[event] = handler; } }, origin, state);
  handlers.request({ url: () => origin + '/same' });
  assert.equal(state.blocked, false);
  handlers.request({ url: () => 'http://127.0.0.1:8766/image' });
  assert.equal(state.blocked, true);
  state.blocked = false;
  handlers.response({ status: () => 200 });
  assert.equal(state.pageError, false);
  handlers.response({ status: () => 404 });
  assert.equal(state.pageError, true);
  state.pageError = false;
  handlers.pageerror(new Error('ZZ error'));
  assert.equal(state.pageError, true);
  state.pageError = false;
  const response = { ok: () => true };
  assert.doesNotThrow(() => assertNavigation(response, origin + '/', origin, state));
  assert.throws(() => assertNavigation(response, 'http://127.0.0.1:8766/', origin, state));
  state.blocked = true;
  assert.throws(() => assertNavigation(response, origin + '/', origin, state));
  state.blocked = false;
  state.pageError = true;
  assert.throws(() => assertNavigation(response, origin + '/', origin, state));
  state.pageError = false;
  assert.throws(() => assertNavigation(null, origin + '/', origin, state));
  assert.throws(() => assertNavigation({ ok: () => false }, origin + '/', origin, state));
});

test('browser matrix: clean fixture passes, missing names/alt/lang fails, 404/external fail', async () => {
  let externalRequests = 0;
  const external = http.createServer((req, res) => { externalRequests++; res.end('ZZ external'); });
  await new Promise(resolve => external.listen(0, '127.0.0.1', resolve));
  const externalURL = `http://127.0.0.1:${external.address().port}/`;
  const server = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'text/html');
    if (req.url === '/external-img') res.end(good.replace('</main>', `<img alt="ZZ pixel" src="${externalURL}"></main>`));
    else if (req.url === '/error') res.end(good.replace('</body>', '<script>throw new Error("ZZ failure")</script></body>'));
    else if (req.url === '/missing-img') res.end(good.replace('</main>', '<img alt="ZZ pixel" src="/404"></main>'));
    else if (req.url === '/redirect-img') res.end(good.replace('</main>', '<img alt="ZZ pixel" src="/redirect-local"></main>'));
    else if (req.url === '/redirect-local') { res.writeHead(302, { Location: externalURL }); res.end(); }
    else if (req.url === '/nested-redirect') { res.writeHead(302, { Location: '/redirect-local' }); res.end(); }
    else if (req.url === '/ws') res.end(good.replace('</body>', `<script>new WebSocket("ws://127.0.0.1:${external.address().port}/")</script></body>`));
    else if (req.url === '/404') { res.writeHead(404); res.end('ZZ not found'); }
    else if (req.url === '/redirect') { res.writeHead(302, { Location: 'http://example.invalid/' }); res.end(); }
    else res.end(req.url === '/bad' ? bad : good);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}/`;
  try {
    const clean = await scan(base, config, { inspect: process.env.A11Y_INSPECT ? async (page, report) => {
      if (report.engine === 'chromium' && report.width === 390) {
        await page.screenshot({ path: process.env.A11Y_INSPECT });
      }
    } : undefined });
    assert.equal(clean.status, 'pass');
    assert.equal(clean.reports.length, 4);
    const broken = await scan(base, { version: 1, paths: ['/bad'] });
    assert.equal(broken.status, 'violations');
    assert.equal(broken.reports.length, 4);
    for (const report of broken.reports) {
      assert.ok(report.rules.includes('button-name'));
      assert.ok(report.rules.includes('image-alt'));
      assert.ok(report.rules.includes('html-has-lang'));
    }
    await assert.rejects(scan(base, { version: 1, paths: ['/404'] }));
    await assert.rejects(scan(base, { version: 1, paths: ['/redirect'] }));
    for (const path of ['/external-img', '/error', '/missing-img', '/redirect-img', '/redirect-local', '/nested-redirect', '/ws']) {
      await assert.rejects(scan(base, { version: 1, paths: [path] }), path);
    }
    assert.equal(externalRequests, 0, 'no second-origin fetch, including redirect hops');
  } finally { await new Promise(resolve => server.close(resolve)); await new Promise(resolve => external.close(resolve)); }
});


test('CLI actual browser exits 0/1 and reports are content-free', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'zz-a11y-'));
  const server = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.end(req.url === '/bad' ? bad : good);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}/`;
  try {
    for (const [path, expected] of [['/', 0], ['/bad', 1]]) {
      const configPath = join(dir, 'config.json');
      await writeFile(configPath, JSON.stringify({ version: 1, paths: [path] }));
      const run = spawn(process.execPath, ['scan.mjs'], { cwd: import.meta.dirname,
        env: { ...process.env, FORCE_COLOR: '', A11Y_CONFIG: configPath, A11Y_BASE_URL: base } });
      let out = '', err = '';
      run.stdout.on('data', data => { out += data; });
      run.stderr.on('data', data => { err += data; });
      const code = await new Promise(resolve => run.on('close', resolve));
      assert.equal(code, expected);
      assert.equal(err, '');
      const report = JSON.parse(out);
      assert.equal(report.scope, 'automated-only');
      assert.equal(report.reports.length, 4);
      assert.doesNotMatch(out, /ZZ fixture|ZZ form|<html|data:image|http:/);
    }
  } finally {
    await new Promise(resolve => server.close(resolve));
    await rm(dir, { recursive: true, force: true });
  }
});

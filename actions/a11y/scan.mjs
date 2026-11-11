import { readFile, stat } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { chromium, webkit } from 'playwright';
import axe from 'axe-core';

// Explicit A/AA tags include the SI 5568 WCAG 2.0 base plus later criteria.
export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];
export const VIEWPORTS = [{ width: 1280, height: 900 }, { width: 390, height: 844 }];
const BROWSERS = { chromium, webkit };

export function validate(base, config) {
  const url = new URL(base);
  if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost'].includes(url.hostname)
      || url.username || url.password || url.search || url.hash || url.pathname !== '/') {
    throw new Error('invalid preview origin');
  }
  if (!config || Object.keys(config).sort().join(',') !== 'paths,version'
      || config.version !== 1 || !Array.isArray(config.paths)
      || config.paths.length < 1 || config.paths.length > 12) throw new Error('invalid config');
  const paths = config.paths;
  if (new Set(paths).size !== paths.length) throw new Error('duplicate path');
  for (const path of paths) {
    if (typeof path !== 'string' || path.length > 300 || !path.startsWith('/')
        || path.startsWith('//') || /[\\\s\u0000-\u001f\u007f]/u.test(path)
        || new URL(path, url).origin !== url.origin) throw new Error('invalid path');
  }
  return { origin: url.origin, paths };
}

export function summarize(results) {
  const violations = results.violations;
  const ids = [...new Set(violations.map(v => v.id))].sort();
  // Never forward axe descriptions, HTML, selectors, URLs or exception messages.
  if (ids.some(id => !/^[a-z][a-z0-9-]{0,79}$/.test(id))) throw new Error('invalid rule ID');
  return { violations: violations.length, nodes: violations.reduce((n, v) => n + v.nodes.length, 0),
    incomplete: results.incomplete.length, rules: ids };
}

export async function scan(base, config, options = {}) {
  const { origin, paths } = validate(base, config);
  const reports = [];
  for (const [engine, type] of Object.entries(BROWSERS)) {
    const browser = await type.launch();
    try {
      for (const viewport of VIEWPORTS) {
        const context = await browser.newContext({ viewport, serviceWorkers: 'block' });
        try {
          let blocked = false;
          let pageError = false;
          await context.route('**/*', async route => {
            if (new URL(route.request().url()).origin !== origin) {
              blocked = true;
              await route.abort();
            } else await route.continue();
          });
          const page = await context.newPage();
          page.on('pageerror', () => { pageError = true; });
          page.on('response', response => { if (response.status() >= 400) pageError = true; });
          page.setDefaultTimeout(15000);
          page.setDefaultNavigationTimeout(15000);
          for (let index = 0; index < paths.length; index++) {
            const response = await page.goto(origin + paths[index], { waitUntil: 'networkidle' });
            if (!response || !response.ok() || new URL(page.url()).origin !== origin || blocked || pageError) {
              throw new Error('preview failed');
            }
            await page.evaluate(() => document.fonts.ready);
            await page.addScriptTag({ content: axe.source });
            const result = await page.evaluate(async tags => {
              return await Promise.race([
                window.axe.run(document, { runOnly: { type: 'tag', values: tags } }),
                new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 15000))
              ]);
            }, TAGS);
            if (blocked || pageError) throw new Error('preview request or script failure');
            const report = { engine, width: viewport.width, page: index + 1, ...summarize(result) };
            reports.push(report);
            // Test-only inspection hook; the CLI/action never enables screenshots.
            if (options.inspect) await options.inspect(page, report);
          }
        } finally { await context.close(); }
      }
    } finally { await browser.close(); }
  }
  return { schema_version: 1, status: reports.some(r => r.violations) ? 'violations' : 'pass',
    scope: 'automated-only', reports };
}

export async function main(env = process.env) {
  try {
    if (!env.A11Y_CONFIG || (await stat(env.A11Y_CONFIG)).size > 16384) throw new Error('config');
    const config = JSON.parse(await readFile(env.A11Y_CONFIG, 'utf8'));
    const result = await scan(env.A11Y_BASE_URL, config);
    console.log(JSON.stringify(result));
    return result.status === 'pass' ? 0 : 1;
  } catch {
    console.log('{"schema_version":1,"status":"error","scope":"automated-only"}');
    return 2;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main();
}

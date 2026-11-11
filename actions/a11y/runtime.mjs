import { chromium, webkit } from 'playwright';
import { pathToFileURL } from 'node:url';

// A missing image browser, missing OS library or failed launch must stop CI.
export async function verifyRuntime(browsers = { chromium, webkit }) {
  for (const type of Object.values(browsers)) {
    const browser = await type.launch();
    try {
      const page = await browser.newPage();
      await page.setContent('<!doctype html><title>ZZ runtime</title><p>ZZ runtime</p>');
      if (await page.title() !== 'ZZ runtime') throw new Error('runtime');
    } finally { await browser.close(); }
  }
  return { schema_version: 1, status: 'pass', engines: Object.keys(browsers).length };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { console.log(JSON.stringify(await verifyRuntime())); }
  catch {
    console.log('{"schema_version":1,"status":"error","scope":"browser-runtime"}');
    process.exitCode = 2;
  }
}

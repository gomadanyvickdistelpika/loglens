// End-to-end UI test + screenshots for a Vates bundle.
// Usage: node tests/ui_vates_playwright.js <baseUrl> <bundlePath> <outDir> "<issue>" <incidentTimeUTC>
// Needs the 'playwright' node module (NODE_PATH) and a Chromium (PLAYWRIGHT_BROWSERS_PATH or CHROMIUM_PATH).
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const [base, bundle, outDir, issue, when] = process.argv.slice(2);
const results = [];
function check(name, ok, extra) { results.push({ name, ok: !!ok, extra: extra || '' }); console.log((ok ? 'PASS ' : 'FAIL ') + name + (extra ? '  ' + extra : '')); }

async function openAndAnalyse(page) {
  await page.goto(base);
  await page.fill('#srvpath', bundle);
  await page.click('#openpath');
  await page.waitForFunction(() => !document.querySelector('#go').disabled, null, { timeout: 30000 });
  await page.fill('#issue', issue);
  await page.fill('#itime', when);
  await page.click('#go');
  await page.waitForSelector('#pane-find .card .vd', { timeout: 60000 });
}

(async () => {
  fs.mkdirSync(outDir, { recursive: true });
  const exe = process.env.CHROMIUM_PATH || undefined;
  const browser = await chromium.launch({ executablePath: exe, args: ['--no-sandbox'] });
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  await openAndAnalyse(page);

  const cards = await page.$$('#pane-find .card .vd');
  check('findings rendered with a verdict control each', cards.length >= 1, cards.length + ' findings');
  const card = (await page.$$('#pane-find .card'))[0];
  const title = await card.$eval('b', e => e.textContent);
  check('first finding is a Vates rule', /XCP-ng|Xen Orchestra/i.test(title), title);

  await card.$eval('button[data-vb=confirm]', b => b.click());
  await (await card.$('input.note')).fill('matches SMlog line, verified in the raw log');
  await page.waitForTimeout(700);
  check('Confirm button pressed', (await card.$eval('button[data-vb=confirm]', b => b.getAttribute('aria-pressed'))) === 'true');
  const reviewed = await page.textContent('#reviewed');
  check('reviewed counter updated', /1 confirmed/.test(reviewed), reviewed);

  await card.$eval('button[data-ev]', b => b.click());
  await page.waitForSelector('#pane-find .evc .r.hit', { timeout: 15000 });
  const rows = await card.$$eval('.evc .r', r => r.length);
  const hit = await card.$eval('.evc .r.hit', r => r.textContent);
  check('raw-log context shows hit plus surrounding lines', rows >= 3, rows + ' rows; hit=' + hit.slice(0, 90));
  const kbText = await card.$eval('.kbx', e => e.textContent);
  check('Vates KB block shows links with seen date or "No public Vates KB found"', /seen 20\d\d-\d\d-\d\d/.test(kbText) || /No public Vates KB found/.test(kbText), kbText.slice(0, 120));
  check('states that article text was not read', /article text was not read|No public Vates KB found/.test(kbText));
  await card.scrollIntoViewIfNeeded();
  await page.screenshot({ path: path.join(outDir, 'vates-findings-confirm.png') });
  await card.screenshot({ path: path.join(outDir, 'vates-finding-card.png') });

  const md = await page.evaluate(async () => (await fetch('/api/report/' + S.job + '.md')).text());
  check('markdown export carries the verdict and note', /Reviewer verdict:\*\* CONFIRMED against the raw log - matches SMlog line/.test(md));

  await card.$eval('.evc a[data-f]', a => a.click());
  await page.waitForSelector('#lines .ln.cur', { timeout: 15000 });
  const cur = await page.$eval('#lines .ln.cur', e => e.textContent);
  const nlines = await page.$$eval('#lines .ln', e => e.length);
  check('viewer opens the file at the matching line (highlighted)', cur.length > 10 && nlines > 5, nlines + ' lines; cur=' + cur.slice(0, 80));
  await page.screenshot({ path: path.join(outDir, 'vates-viewer.png') });

  // verdict survives a page reload + re-analysis (kept in this browser)
  await openAndAnalyse(page);
  const again = await page.$eval('#pane-find .card button[data-vb=confirm]', b => b.getAttribute('aria-pressed'));
  const note = await page.$eval('#pane-find .card input.note', i => i.value);
  check('verdict and note persisted in the browser across reload', again === 'true' && /verified in the raw log/.test(note), note);
  check('no page errors', errors.length === 0, errors.join(' | '));
  await browser.close();
  fs.writeFileSync(path.join(outDir, 'ui-test-results.json'), JSON.stringify(results, null, 1));
  process.exit(results.every(r => r.ok) ? 0 : 1);
})().catch(e => { console.error(e); process.exit(2); });

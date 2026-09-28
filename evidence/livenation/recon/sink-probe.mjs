import pw from '/opt/node22/lib/node_modules/playwright/index.js';
const { chromium } = pw;
import fs from 'node:fs';

const HOOKDIR = '/home/user/Bugbounty/.claude/skills/dom-sink-hooker/assets/hooks';
const hooks = ['sink-hook.js', 'source-watch.js', 'postmessage-watch.js']
  .map(f => fs.readFileSync(`${HOOKDIR}/${f}`, 'utf8'));

const MARKERS = ['DX_XSS', 'xss7q3z', 'lnpr0be'];
const targets = JSON.parse(process.argv[2]);

const browser = await chromium.launch({
  args: ['--no-sandbox', '--disable-dev-shm-usage'],
});
const ctx = await browser.newContext({
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
  viewport: { width: 1280, height: 900 },
  locale: 'en-GB',
});

// Hooks vor jedem Dokument -- uebersteht harte Navigation (SKILL.md Abschnitt 6).
for (const h of hooks) await ctx.addInitScript({ content: h });
await ctx.addInitScript({ content: `try{__xssMarkers(${JSON.stringify(MARKERS)})}catch(e){}` });

const results = [];
for (const url of targets) {
  const page = await ctx.newPage();
  const fired = [];
  page.on('dialog', async d => { fired.push({ type: d.type(), msg: d.message() }); await d.dismiss(); });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e).slice(0, 200)));
  let status = null;
  try {
    const r = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 45000 });
    status = r ? r.status() : null;
    await page.waitForTimeout(6000);            // Hydration + client-side fetches
    await page.evaluate(() => window.scrollBy(0, 1500)).catch(() => {});
    await page.waitForTimeout(2500);
  } catch (e) {
    results.push({ url, error: String(e).slice(0, 180) });
    await page.close(); continue;
  }
  // __xssDump/__srcDump geben JSON-STRINGS zurueck -- die Rohlogs sind die Wahrheit.
  const dump = await page.evaluate(() => {
    const sl = window.__xssLog || [], sr = window.__srcLog || [];
    const slim = e => ({ sink: e.sink, value: (e.value||'').slice(0,240),
                         frame: ((e.stack||'').split('\n').filter(l => /https?:\/\//.test(l))[1] || '').trim().slice(0,150) });
    return {
      installed: { sink: !!window.__xssHooksInstalled, src: !!window.__srcWatchInstalled, pm: !!window.__pmWatchInstalled },
      sinkTotal: sl.length, srcTotal: sr.length,
      taintedSinks: sl.filter(e => e.tainted).map(slim),
      taintedSrc:   sr.filter(e => e.tainted).map(e => ({ src: e.source || e.sink, value: (e.value||'').slice(0,240) })),
      pm: (window.__pmLog || []).map(e => ({ type: e.type, origin: e.origin,
              data: typeof e.data === 'string' ? e.data.slice(0,160) : JSON.stringify(e.data||null).slice(0,160),
              fnSource: (e.fnSource || '').slice(0, 300) })),
      sinkKinds: Object.entries(sl.reduce((a,e) => (a[e.sink]=(a[e.sink]||0)+1, a), {})),
      // Alle HTML-Sink-Werte, unabhaengig von Markern: zeigt WAS die App parst.
      htmlSinkSamples: sl.filter(e => /innerHTML|outerHTML|insertAdjacentHTML|document\.write|Range/.test(e.sink))
                         .map(slim).slice(0, 25),
      hrefSinkSamples: sl.filter(e => /setAttribute:href|href/.test(e.sink)).map(slim).slice(0, 15),
      codeSinkSamples: sl.filter(e => /Function|eval|setTimeout|setInterval/.test(e.sink)).map(slim).slice(0, 10),
      htmlHasMarker: ['DX_XSS','xss7q3z','lnpr0be'].filter(m => document.documentElement.innerHTML.includes(m)),
      // Belegt, dass der html-Prop-Sink live rendert: Elemente mit Rich-Text-Markup aus dem CMS.
      richTextBlocks: [...document.querySelectorAll('div,span,p')]
        .filter(el => /<(p|strong|em|a|ul|li|br)\b/i.test(el.innerHTML) && el.children.length && el.innerHTML.length < 1200)
        .slice(0, 6).map(el => ({ tag: el.tagName, cls: (el.className||'').slice(0,40), html: el.innerHTML.slice(0,180) })),
    };
  }).catch(e => ({ evalError: String(e).slice(0,180) }));
  results.push({ url, status, dialogs: fired, pageErrors: errors.slice(0,3), ...dump });
  await page.close();
}
await browser.close();
console.log(JSON.stringify(results, null, 1));

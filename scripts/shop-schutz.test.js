'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const vm = require('node:vm');
const root = path.join(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
const admin = fs.readFileSync(path.join(root, 'admin.html'), 'utf8');
const catalogCode = fs.readFileSync(path.join(root, 'assets/catalog.js'), 'utf8');
const telegramCode = fs.readFileSync(path.join(root, 'assets/telegram-loader.js'), 'utf8');
function catalog(fetcher) {
  const ctx = vm.createContext({ URLSearchParams, AbortController, setTimeout, clearTimeout, fetch: fetcher });
  vm.runInContext(catalogCode, ctx); return ctx.VisioCatalog;
}
function telegram(hash) {
  const appended = [], timers = [], cleared = [];
  const window = { location: { hash } };
  const ctx = vm.createContext({ window, URLSearchParams,
    setTimeout: cb => { timers.push(cb); return timers.length; }, clearTimeout: n => cleared.push(n),
    document: { createElement: () => ({ remove() { this.removed = true; } }), head: { appendChild: el => appended.push(el) } } });
  vm.runInContext(telegramCode, ctx); return { window, appended, timers, cleared };
}
for (const hash of ['', '#access_token=abc&type=recovery', '#tgWebAppData=', '#tgWebAppData=abc', '#tgWebAppData=abc&tgWebAppVersion=8.0&tgWebAppPlatform=unknown']) {
  test(`No Telegram request on normal/invalid context (${hash})`, async () => {
    const t = telegram(hash); assert.equal(await t.window.visioTelegramReady, null); assert.equal(t.appended.length, 0);
  });
}
const tgHash = '#tgWebAppData=query_id%3Dtest&tgWebAppVersion=8.0&tgWebAppPlatform=android';
test('Telegram Mini App context loads once and resolves existing SDK', async () => {
  const t = telegram(tgHash); assert.equal(t.appended.length, 1);
  assert.equal(t.appended[0].src, 'https://telegram.org/js/telegram-web-app.js');
  t.window.Telegram = { WebApp: { ready() {} } }; t.appended[0].onload();
  assert.equal(await t.window.visioTelegramReady, t.window.Telegram.WebApp); assert.equal(t.cleared.length, 1);
});
for (const outcome of ['error', 'timeout', 'missing-sdk']) {
  test(`Telegram ${outcome}: shop continues without SDK`, async () => {
    const t = telegram(tgHash);
    if (outcome === 'error') t.appended[0].onerror();
    else if (outcome === 'timeout') t.timers[0]();
    else t.appended[0].onload();
    assert.equal(await t.window.visioTelegramReady, null);
  });
}
test('Catalog transport uses only backend public read model, no key or direct Supabase', async () => {
  const calls = [];
  const api = catalog(async (url, options) => { calls.push({ url, options }); return { ok: true, json: async () => ({ ok: true, katalog: {
    produkte: [{ id: 1, name: 'Eiche', aktiv: true }], pakete: [], kategorien: [], arten: [], sortierungen: [] } }) }; });
  const read = api.create('https://backend.example.invalid');
  const [a, b] = await Promise.all([read('produkte', '?id=eq.1&aktiv=eq.true&limit=1'), read('produkte', '?id=in.(1,2)')]);
  assert.equal(calls.length, 1); assert.equal(calls[0].url, 'https://backend.example.invalid/api/katalog');
  assert.equal(calls[0].options.credentials, 'omit'); assert.equal(calls[0].options.headers, undefined);
  a[0].name = 'changed'; assert.equal(b[0].name, 'Eiche');
});
test('Catalog failure has no fallback to public Supabase', async () => {
  const calls = []; const api = catalog(async url => { calls.push(url); return { ok: false }; });
  await assert.rejects(api.create('https://backend.example.invalid')('pakete'), /Katalog/);
  assert.deepEqual(calls, ['https://backend.example.invalid/api/katalog']);
});
test('All current catalog filters work on reduced data', () => {
  const api = catalog(async () => assert.fail('No fetch'));
  const rows = [{ id: 2, name: 'B', sortierung_id: null, aktiv: true, reihenfolge: 1 }, { id: 1, name: 'A', sortierung_id: 3, aktiv: true, reihenfolge: 2 }];
  assert.equal(api.filter(rows, '?sortierung_id=is.null')[0].id, 2);
  assert.equal(api.filter(rows, '?order=reihenfolge&limit=1')[0].id, 2);
  assert.equal(api.filter(rows, '?id=in.(1,2)&order=id.asc&limit=1')[0].id, 1);
  assert.deepEqual(JSON.parse(JSON.stringify(api.filter(rows, '?select=id,name'))), [{ id: 2, name: 'B' }, { id: 1, name: 'A' }]);
});
for (const query of ['?select=*', '?select=*,pakete(*)', '?lagerort=eq.A', '?order=lagerort', '?id=or.(true)', '?limit=-1']) {
  test(`Unsupported catalog selector rejected: ${query}`, () => {
    assert.throws(() => catalog(async () => {}).filter([], query));
  });
}
test('Headers cover ALL shop/admin paths; minimal CSP leaves payment scripts untouched', () => {
  const config = JSON.parse(fs.readFileSync(path.join(root, 'vercel.json')));
  assert.equal(config.headers[0].source, '/(.*)');
  const headers = Object.fromEntries(config.headers[0].headers.map(h => [h.key, h.value]));
  assert.equal(headers['Content-Security-Policy'], "frame-ancestors 'none'");
  assert.equal(headers['X-Frame-Options'], 'DENY'); assert.equal(headers['X-Content-Type-Options'], 'nosniff');
  assert.equal(headers['Referrer-Policy'], 'strict-origin-when-cross-origin');
  assert.equal(headers['Strict-Transport-Security'], undefined); // Vercel's existing HSTS is not overridden.
});
test('No external fonts, raw legal links or exact inventory in shop HTML/logic', () => {
  assert.doesNotMatch(html + admin, /fonts\.googleapis|fonts\.gstatic|raw\.githubusercontent/);
  assert.doesNotMatch(html, /verfuegbare_pakete|bestand_pakete|lagerort|verfuegbar_m2|_verfuegbarM2/);
  assert.doesNotMatch(html, /<script[^>]+src="https:\/\/telegram/);
  assert.match(html, /VisioCatalog\.tables\.includes\(table\)/);
  assert.match(html, /verfuegbar === true/);
});
test('Admin stock has backend reads only, not direct PostgREST', () => {
  assert.doesNotMatch(admin, /\/rest\/v1|\bdb\(|\bdbAuth\(/);
  assert.match(admin, /backendApi\('\/api\/admin\/produkte'\)/);
  assert.match(admin, /backendApi\(`\/api\/admin\/produkte\/\$\{produktId\}\/pakete`\)/);
});
test('PDFs are exact copies on shop and BOTH maintenance source variants', () => {
  const hash = f => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');
  for (const [original, name] of [['AGB_VisioTrade.pdf', 'agb.pdf'], ['Datenschutzerklaerung_VisioTrade.pdf', 'datenschutz.pdf']]) {
    const expected = hash(path.join(root, original));
    for (const dir of ['recht', '../wartung/public/recht', '../wartung/vercel-static/recht']) assert.equal(hash(path.join(root, dir, name)), expected);
  }
  for (const relative of ['../wartung/app/page.tsx', '../wartung/vercel-static/index.html']) {
    const page = fs.readFileSync(path.join(root, relative), 'utf8');
    assert.doesNotMatch(page, /raw\.githubusercontent/); assert.match(page, /\/recht\/agb.pdf/); assert.match(page, /\/recht\/datenschutz.pdf/);
  }
});
test('Original variable font binaries and licenses match pinned upstream Git objects', () => {
  for (const [file, expected] of [['dm-sans.ttf', 'c672f98060af9b2c85fca704ebd5ad9a8717c1df'],
    ['playfair-display.ttf', '7a09eb71f10622fd083134ac9ed46f59b21bee18'],
    ['DM-Sans-OFL.txt', '4430b85ac62998e2edb914360f9ebdfe43f4deaa'],
    ['Playfair-Display-OFL.txt', '13153890847ba9bde8a852596d1515261156e474']]) {
    const bytes = fs.readFileSync(path.join(root, 'assets/fonts', file));
    const actual = crypto.createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
    assert.equal(actual, expected, file);
    if (file.endsWith('.ttf')) assert.equal(bytes.readUInt32BE(), 0x00010000);
    else assert.match(bytes.toString(), /SIL OPEN FONT LICENSE/);
  }
});
test('Package rounding and cart amounts do not invent/cap inventory', () => {
  const start = html.indexOf('function optimierePakete('), end = html.indexOf('function warenkorbSignatur(', start);
  const ctx = vm.createContext({}); vm.runInContext(html.slice(start, end), ctx);
  const result = ctx.optimierePakete(100, [{ id: 1, menge_m2: 1.4, verfuegbar: true }]);
  assert.equal(result[0].anzahl, 72);
  for (const amount of [0, -1, Infinity, NaN]) assert.equal(ctx.optimierePakete(amount, [{ menge_m2: 1.4 }]), null);
  assert.equal(ctx.optimierePakete(1, [{ menge_m2: 0 }]), null);
});
test('Product table renders availability words, not warehouse quantities', () => {
  const start = html.indexOf('function b2bRowHtml('), end = html.indexOf('function b2bRowUpdate(', start);
  assert.ok(start >= 0 && end > start);
  const ctx = vm.createContext({ sichereHttpsUrl: () => null, HOLZ_ICON: '',
    escapeHtml: s => String(s), b2bSpalte2Modus: () => 'aus', b2bNum: n => Number(n).toFixed(2),
    cartSvg: () => '', anfrageSvg: () => '' });
  vm.runInContext(html.slice(start, end), ctx);
  for (const available of [true, false]) {
    const row = ctx.b2bRowHtml({ id: 30, name: 'Eiche', _verfuegbar: available, _veM2: 1.4, preis_pro_m2: 60 });
    assert.match(row, available ? /b2b-stock-ok">verfügbar<\/span>/ : /b2b-stock-no">nicht verfügbar<\/span>/);
    assert.doesNotMatch(row, /data-label="Verfügbar">[^<]*\d|b2b-stock-(ok|no)">\d/);
  }
});
test('Cart quantity changes accept requested integers and never use a stock ceiling', () => {
  const start = html.indexOf('function setWarenkorbMenge('), end = html.indexOf('function renderWarenkorb(', start);
  const item = { id: 1, kombi: [{ paket: { id: 40, menge_m2: 1.4 }, anzahl: 1 }], gewichtProPaket: 20 };
  let refreshed = 0, warnings = 0;
  const ctx = vm.createContext({ warenkorb: [item], alert: () => warnings++, posBetrag: (_p, n) => n * 84,
    aktualisiereNachMengenAenderung: () => refreshed++ });
  vm.runInContext(html.slice(start, end), ctx);
  ctx.setWarenkorbMenge(1, '1000'); assert.equal(item.kombi[0].anzahl, 1000); assert.equal(refreshed, 1);
  ctx.aendereWarenkorbMenge(1, 1); assert.equal(item.kombi[0].anzahl, 1001);
  for (const value of ['1.5', '-2', 'NaN', '9007199254740992']) ctx.setWarenkorbMenge(1, value);
  assert.equal(warnings, 4); assert.equal(item.kombi[0].anzahl, 1001);
});

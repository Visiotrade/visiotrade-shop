'use strict';
// Echte Frontendfunktionen mit Browser-/API-Doubles. Keine Anmeldung/Netzaufrufe.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '..', 'admin.html'), 'utf8');
const start = html.indexOf('const lagerGesehenCache =');
const end = html.indexOf('function lagerLieferadresse(', start);
assert.ok(start > 0 && end > start);
const code = html.slice(start, end);
function funktion(name) {
  const a = html.search(new RegExp(`^(?:async )?function ${name}\\(`, 'm'));
  assert.ok(a >= 0, name); return html.slice(a, html.indexOf('\n}', a) + 2);
}
const flush = () => new Promise(resolve => setImmediate(resolve));
function deferred() { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; }
function harness(storage = new Map()) {
  const nodes = {}, calls = [];
  function node(id) {
    if (!nodes[id]) {
      const classes = new Set();
      nodes[id] = { style: {}, innerHTML: '', textContent: '', attrs: {}, contains: () => false,
        setAttribute(k, v) { this.attrs[k] = v; },
        classList: { contains: c => classes.has(c), add: c => classes.add(c), remove: c => classes.delete(c) } };
    }
    return nodes[id];
  }
  const ctx = vm.createContext({
    Map, Set, console: { warn() {} }, adminToken: 'test-token',
    adminMe: { email: 'lager@example.test' }, adminUser: null, allowed: true, ids: [117, 129],
    document: { hidden: false, getElementById: node, querySelector: () => null, addEventListener() {} },
    localStorage: { getItem: k => storage.get(k) ?? null, setItem: (k, v) => storage.set(k, v), removeItem: k => storage.delete(k) },
    darfLagerZugang: () => ctx.allowed, istAbholung: () => false, lagerCardHtml: b => `<article>${b.id}</article>`,
    h: String, vtIco: () => '',
    backendApi: async url => {
      calls.push(url);
      if (url === '/api/admin/lager/neu-ids') return { ids: [...ctx.ids] };
      if (url === '/api/admin/lager') return { bestellungen: ctx.ids.map(id => ({ id, phase: 'in_bearbeitung' })) };
      throw new Error('Unerwartete API: ' + url);
    },
    nachrichtenPoller: null, adminVisibilityBound: false, threadAktuelleId: null,
    setInterval: cb => { ctx.tick = cb; return 1; }, window: { addEventListener() {} },
    istNurLager: () => true, darf: () => false,
    aktualisiereNachrichtenBadge() { throw new Error('Kein Chat-Recht'); },
    aktualisierePreisanfrageBadge() { throw new Error('Kein kaufmännischer Zugriff'); },
    aktualisiereBestellBadge() { throw new Error('Kein kaufmännischer Zugriff'); },
    ladeAdminUngelesen() { throw new Error('Kein kaufmännischer Zugriff'); },
    ladeVersandplanung() {}, ladeNachrichten() {}, ladeBestellungen() {}, ladeThreadDetail() {}, ladeLagerChat() {}
  });
  vm.runInContext(code + funktion('startNachrichtenPoller') + funktion('adminLogout'), ctx);
  return { ctx, node, calls, storage, badge: () => node('navLagerBadge').textContent };
}

test('Altbestand ist Ausgangsstand, eine neue Bestellung ergibt rote 1', async () => {
  const h = harness(); await h.ctx.aktualisiereLagerBadge();
  assert.equal(h.badge(), '0'); assert.equal(h.node('navLagerBadge').style.display, 'none');
  h.ctx.ids.push(168); await h.ctx.aktualisiereLagerBadge();
  assert.equal(h.badge(), '1'); assert.equal(h.node('navLagerBadge').style.display, 'inline-block');
  assert.equal(h.node('navLagerBadge').attrs['aria-label'], '1 neue Lagerbestellungen');
});
test('Später bezahlte ältere Bestell-ID wird ebenfalls als neu erkannt', async () => {
  const h = harness(); await h.ctx.aktualisiereLagerBadge(); h.ctx.ids.push(100);
  await h.ctx.aktualisiereLagerBadge(); assert.equal(h.badge(), '1');
});
test('Mehrere neue Bestellungen zählen eindeutig, abgeschlossene fallen heraus', async () => {
  const h = harness(); await h.ctx.aktualisiereLagerBadge(); h.ctx.ids.push(168, 169, 169);
  await h.ctx.aktualisiereLagerBadge(); assert.equal(h.badge(), '2');
  h.ctx.ids = [117, 129, 169]; await h.ctx.aktualisiereLagerBadge(); assert.equal(h.badge(), '1');
});
test('Automatische Listenaktualisierung quittiert nicht, bewusster Aufruf quittiert', async () => {
  const h = harness(); await h.ctx.aktualisiereLagerBadge();
  h.ctx.ids.push(168); h.node('page-lager').classList.add('active');
  await h.ctx.ladeLager({ silent: true }); await flush();
  assert.equal(h.badge(), '1'); assert.match(h.node('lagerCards').innerHTML, /168/);
  await h.ctx.ladeLager(); await flush(); assert.equal(h.badge(), '0');
});
test('Ungesehene Bestellung bleibt bei Neuladen im selben Konto/Browser neu', async () => {
  const h = harness(); await h.ctx.aktualisiereLagerBadge(); h.ctx.ids.push(168);
  await h.ctx.aktualisiereLagerBadge();
  const reloaded = harness(h.storage); reloaded.ctx.ids.push(168);
  await reloaded.ctx.aktualisiereLagerBadge(); assert.equal(reloaded.badge(), '1');
});
test('Lesestände sind pro Benutzer getrennt und werden zwischen Tabs berücksichtigt', async () => {
  const h = harness(); await h.ctx.aktualisiereLagerBadge(); h.ctx.ids.push(168);
  await h.ctx.aktualisiereLagerBadge();
  const second = harness(h.storage); second.ctx.ids.push(168);
  second.ctx.adminMe.email = 'andere@example.test'; await second.ctx.aktualisiereLagerBadge();
  assert.equal(second.badge(), '0'); await h.ctx.aktualisiereLagerBadge(); assert.equal(h.badge(), '1');
  second.ctx.adminMe.email = 'lager@example.test'; second.node('page-lager').classList.add('active');
  await second.ctx.ladeLager(); await flush();
  await h.ctx.aktualisiereLagerBadge(); assert.equal(h.badge(), '0');
});
test('Versteckter Tab oder inzwischen verlassene Lagerseite quittiert nichts', async () => {
  for (const hidden of [true, false]) {
    const h = harness(); await h.ctx.aktualisiereLagerBadge(); h.ctx.ids.push(168);
    h.ctx.document.hidden = hidden;
    if (hidden) h.node('page-lager').classList.add('active');
    await h.ctx.ladeLager(); await flush(); assert.equal(h.badge(), '1');
  }
});
test('Netzfehler und fehlerhafte Antwort löschen weder Zähler noch Lesestand', async () => {
  const h = harness(); await h.ctx.aktualisiereLagerBadge(); h.ctx.ids.push(168);
  await h.ctx.aktualisiereLagerBadge(); const before = [...h.storage.entries()];
  h.ctx.backendApi = async () => { throw new Error('offline'); };
  await h.ctx.aktualisiereLagerBadge(); assert.equal(h.badge(), '1');
  h.ctx.backendApi = async () => ({ ids: ['oops'] }); await h.ctx.aktualisiereLagerBadge();
  assert.equal(h.badge(), '1'); assert.deepEqual([...h.storage.entries()], before);
});
test('Fehler beim Öffnen der Liste quittiert keine neue Bestellung', async () => {
  const h = harness(); await h.ctx.aktualisiereLagerBadge(); h.ctx.ids.push(168);
  const api = h.ctx.backendApi;
  h.ctx.backendApi = async url => { if (url === '/api/admin/lager') throw new Error('offline'); return api(url); };
  h.node('page-lager').classList.add('active'); await h.ctx.ladeLager(); await flush();
  assert.equal(h.badge(), '1'); assert.match(h.node('lagerCards').innerHTML, /Fehler/);
});
test('Ohne Lagerrecht oder Anmeldung keine Zählerabfrage', async () => {
  const h = harness(); h.ctx.allowed = false; await h.ctx.aktualisiereLagerBadge();
  h.ctx.allowed = true; h.ctx.adminToken = null; await h.ctx.aktualisiereLagerBadge();
  assert.equal(h.calls.length, 0); assert.equal(h.badge(), '0');
});
test('Verzögerte Antwort nach Logout kann keinen fremden Zähler mehr einblenden', async () => {
  const h = harness(); await h.ctx.aktualisiereLagerBadge(); const pending = deferred();
  h.ctx.backendApi = () => pending.promise;
  const reading = h.ctx.aktualisiereLagerBadge(); h.ctx.adminLogout();
  pending.resolve({ ids: [117, 129, 168] }); await reading; assert.equal(h.badge(), '0');
});
test('Gleichzeitige Abrufe werden zusammengefasst, alter Poll überschreibt keinen manuellen Lesestand', async () => {
  const h = harness(); await h.ctx.aktualisiereLagerBadge(); const pending = deferred(); let reads = 0;
  h.ctx.backendApi = async url => {
    if (url.endsWith('/neu-ids')) { reads++; return pending.promise; }
    return { bestellungen: [117, 129, 168].map(id => ({ id, phase: 'in_bearbeitung' })) };
  };
  const polling = h.ctx.aktualisiereLagerBadge(); await h.ctx.aktualisiereLagerBadge(); assert.equal(reads, 1);
  h.node('page-lager').classList.add('active'); await h.ctx.ladeLager();
  pending.resolve({ ids: [117, 129, 168, 169] }); await polling;
  await h.ctx.aktualisiereLagerBadge(); assert.equal(h.badge(), '1');
});
test('Gesperrter Browserspeicher blockiert weder Lageransicht noch Zähler', async () => {
  const h = harness(); h.ctx.localStorage.getItem = h.ctx.localStorage.setItem = () => { throw new Error('blocked'); };
  await h.ctx.aktualisiereLagerBadge(); h.ctx.ids.push(168); await h.ctx.aktualisiereLagerBadge();
  assert.equal(h.badge(), '1'); h.node('page-lager').classList.add('active');
  await h.ctx.ladeLager(); await flush(); assert.equal(h.badge(), '0');
});
test('12-Sekunden-Poller aktualisiert Badge auch außerhalb Lager ohne Chatrechte', async () => {
  const h = harness(); await h.ctx.aktualisiereLagerBadge(); h.ctx.ids.push(168);
  h.ctx.startNachrichtenPoller(); h.ctx.tick(); await flush(); assert.equal(h.badge(), '1');
  const before = h.calls.length; h.ctx.document.hidden = true; h.ctx.tick(); await flush();
  assert.equal(h.calls.length, before);
});
test('Badge-Markup verwendet denselben roten Stil wie Nachrichten', () => {
  assert.match(html, /id="navLagerBadge"[^>]+aria-live="polite"[^>]+background:#B91C1C/);
});

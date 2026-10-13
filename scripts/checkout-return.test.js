'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const start = html.indexOf('async function pruefeStripeRueckkehr(');
const end = html.indexOf("window.addEventListener('DOMContentLoaded', async () => {", start);
assert.ok(start >= 0 && end > start);
const code = html.slice(start, end);
const validQuery = '?success=1&zahlung=stripe&bestellung_id=42&session_id=cs_test_abcdefghijklmnopqrstuv';

function harness(query = validQuery, response = { state: 'confirmed' }, status = 200) {
  const nodes = Object.fromEntries(['cartCount', 'zahlung-pruefung-text', 'zahlung-pruefung-erneut'].map((id) => [id, {}]));
  const screens = [], requests = [], alerts = [], cleared = [], timers = new Set();
  const context = vm.createContext({
    URLSearchParams, AbortController,
    setTimeout: (fn) => { timers.add(fn); return fn; }, clearTimeout: (fn) => timers.delete(fn),
    API_URL: 'https://backend.example.test', warenkorb: [{ id: 7 }],
    window: { location: { search: query, pathname: '/' }, history: { replaceState: (...args) => cleared.push(args) } },
    document: { title: 'Testshop', getElementById: (id) => { assert.ok(nodes[id], id); return nodes[id]; } },
    showScreen: (name) => screens.push(name), alert: (text) => alerts.push(text),
    tryGetAktuellenAuthUser: async () => null,
    fetch: async (url, opts) => { requests.push({ url, opts });
      if (response instanceof Error) throw response;
      return { ok: status < 400, json: async () => response };
    }
  });
  vm.runInContext(code, context);
  return { context, nodes, screens, requests, alerts, cleared, timers,
    run: () => context.checkPayPalReturn() };
}
test('Nur serverseitig bestätigte Stripe-Rückkehr leert Warenkorb und zeigt Erfolg', async () => {
  const h = harness(); assert.equal(await h.run(), 'erfolg');
  assert.equal(h.context.warenkorb.length, 0);
  assert.equal(h.screens.at(-1), 'erfolg');
  assert.ok(h.requests[0].url.endsWith('/api/stripe/checkout-status'));
  assert.equal(h.requests[0].opts.method, 'POST');
  assert.equal(JSON.parse(h.requests[0].opts.body).session_id, 'cs_test_abcdefghijklmnopqrstuv');
  assert.equal(h.timers.size, 0);
  assert.ok(h.cleared.length > 0);
});
for (const state of ['processing', 'unconfirmed', 'cancelled', 'unknown', null]) {
  test(`Status ${state}: Warenkorb bleibt, keine Erfolgsbehauptung`, async () => {
    const h = harness(validQuery, { state }); assert.equal(await h.run(), 'pruefung');
    assert.equal(h.context.warenkorb.length, 1);
    assert.ok(!h.screens.includes('erfolg'));
    assert.equal(h.nodes['zahlung-pruefung-erneut'].disabled, false);
    assert.match(h.nodes['zahlung-pruefung-text'].textContent, /nicht.*bezahlen|bevor Sie erneut bezahlen/i);
  });
}
for (const query of ['?success=1', '?success=1&zahlung=stripe&bestellung_id=42',
  '?success=1&zahlung=stripe&bestellung_id=42&session_id=erfunden', '?success=1&zahlung=paypal']) {
  test(`Alter, unvollständiger oder gefälschter Rückkehrlink: ${query}`, async () => {
    const h = harness(query); assert.equal(await h.run(), 'pruefung');
    assert.equal(h.requests.length, 0); assert.equal(h.context.warenkorb.length, 1);
    assert.ok(!h.screens.includes('erfolg')); assert.equal(h.nodes['zahlung-pruefung-erneut'].hidden, true);
  });
}
for (const [response, status] of [[new Error('Netzfehler'), 200], [{ state: 'confirmed' }, 500], [{ state: 'confirmed' }, 429]]) {
  test(`Netz-/HTTP-Fehler ${status}: kein Erfolg, erneute Statusprüfung möglich`, async () => {
    const h = harness(validQuery, response, status); assert.equal(await h.run(), 'pruefung');
    assert.equal(h.context.warenkorb.length, 1); assert.ok(!h.screens.includes('erfolg'));
    assert.equal(h.timers.size, 0);
    await h.nodes['zahlung-pruefung-erneut'].onclick();
    assert.equal(h.requests.length, 2);
    assert.ok(h.requests.every((r) => r.url.endsWith('/checkout-status')));
  });
}
test('Abbruch und normaler Seitenaufruf bleiben unverändert', async () => {
  const cancelled = harness('?cancelled=1'); assert.equal(await cancelled.run(), 'abbruch');
  assert.equal(cancelled.requests.length, 0);
  const normal = harness(''); assert.equal(await normal.run(), 'keine');
  assert.equal(normal.requests.length, 0);
});
test('PayPal nutzt weiterhin Capture und verlangt COMPLETED', async () => {
  const query = '?success=1&zahlung=paypal&bestellung_id=42&token=PP_TEST';
  const h = harness(query, { capture_status: 'COMPLETED' });
  assert.equal(await h.run(), 'erfolg'); assert.ok(h.requests[0].url.includes('/api/paypal/capture/'));
  const pending = harness(query, { capture_status: 'PENDING' });
  assert.equal(await pending.run(), 'fehler'); assert.equal(pending.context.warenkorb.length, 1);
});
test('Prüfseite existiert und wird beim Laden nicht von der Produktliste überschrieben', () => {
  assert.ok(html.includes('id="screen-zahlung-pruefung"'));
  assert.ok(html.includes("if (_rueckkehr === 'erfolg' || _rueckkehr === 'pruefung') return;"));
});
test('Gemeinsame Erfolgsseite behauptet bei Rechnungskauf keinen Zahlungseingang', () => {
  const success = html.slice(html.indexOf('<div id="screen-erfolg"'), html.indexOf('<!-- ZAHLUNGSRUECKKEHR'));
  assert.match(success, /Bestellung wurde erfolgreich aufgenommen/);
  assert.doesNotMatch(success, /Zahlung wurde bestätigt|Zahlungsbestätigung/);
});

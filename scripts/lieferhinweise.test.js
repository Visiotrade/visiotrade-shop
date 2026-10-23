'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const shop = fs.readFileSync(path.join(__dirname, '../index.html'), 'utf8');
const admin = fs.readFileSync(path.join(__dirname, '../admin.html'), 'utf8');
function funktion(source, name) {
  const start = source.search(new RegExp(`^(?:async )?function ${name}\\(`, 'm'));
  const end = source.indexOf('\n}', start); assert.ok(start >= 0 && end > start, name);
  return source.slice(start, end + 2);
}
function harness() {
  const nodes = {};
  const node = id => nodes[id] || (nodes[id] = { value: '', checked: false, style: {} });
  const context = vm.createContext({ document: { getElementById: node }, gespeicherteCheckoutAdressen: [],
    h: s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;') });
  vm.runInContext(['checkoutLieferangaben', 'waehleGespeicherteLieferadresse', 'resetCheckoutIdentityFields'].map(n => funktion(shop, n)).join('\n')
    + '\n' + funktion(admin, 'lieferhinweiseHtml'), context);
  return { node, context };
}
test('Checkout: Hinweis und beide Optionen stammen nur von der gewählten Adresse', () => {
  const { node, context: c } = harness();
  node('rech-sonstiges').value = '8 bis 20 Uhr'; node('lief-sonstiges').value = 'Baustelle Tor 2';
  node('hebebuehne').checked = true; node('lief-eigenAbladung').checked = true;
  const normal = c.checkoutLieferangaben('lieferung', false);
  assert.equal(normal.lieferhinweise, '8 bis 20 Uhr'); assert.equal(normal.hebebuehne, true);
  assert.equal(normal.eigenentladung, false);
  const abw = c.checkoutLieferangaben('lieferung', true);
  assert.equal(abw.lieferhinweise, 'Baustelle Tor 2'); assert.equal(abw.hebebuehne, false);
  assert.equal(abw.lieferadresse_hebebuehne, false); assert.equal(abw.eigenentladung, true);
  node('lief-hebebuehne').checked = true;
  assert.equal(c.checkoutLieferangaben('lieferung', true).lieferadresse_hebebuehne, true);
});
test('Abholung sendet keine unsichtbaren Lieferhinweise; 2000-Zeichen-Grenze wird geprüft', () => {
  const { node, context: c } = harness();
  node('rech-sonstiges').value = 'x'.repeat(2001); node('hebebuehne').checked = true;
  assert.throws(() => c.checkoutLieferangaben('lieferung', false), /2000/);
  assert.equal(c.checkoutLieferangaben('abholung', false).lieferhinweise, null);
  assert.equal(c.checkoutLieferangaben('abholung', false).hebebuehne, false);
  node('rech-sonstiges').value = 'x'.repeat(2000);
  assert.equal(c.checkoutLieferangaben('lieferung', false).lieferhinweise.length, 2000);
  assert.match(shop, /id="rech-sonstiges" maxlength="2000"/);
  assert.match(shop, /id="lief-sonstiges" maxlength="2000"/);
  assert.match(funktion(shop, 'bestellungAbsenden'), /\.\.\.checkoutLieferangaben\(lieferart, abwLiefChecked\)/);
});
test('Gespeicherte Adresse/Neueingabe wechseln: keine veralteten Standortangaben', () => {
  const { node, context: c } = harness();
  c.gespeicherteCheckoutAdressen = [{ id: 5, empfaenger: 'Test', hebebuehne: true, anlieferzeiten: '8-20 Uhr', liefer_hinweise: 'Tor 2' }];
  node('gespeicherteLieferadresse').value = '5'; node('lief-eigenAbladung').checked = true;
  c.waehleGespeicherteLieferadresse();
  assert.equal(node('lief-eigenAbladung').checked, false);
  assert.equal(node('lief-hebebuehne').checked, true);
  assert.match(c.checkoutLieferangaben('lieferung', true).lieferhinweise, /8-20 Uhr.*Tor 2/);
  node('gespeicherteLieferadresse').value = ''; c.waehleGespeicherteLieferadresse();
  assert.equal(node('lief-sonstiges').value, ''); assert.equal(node('lief-hebebuehne').checked, false);
});
test('Konto-Wechsel/Logout löscht auch die bisherigen Lieferhinweise und Entladeoptionen', () => {
  const { node, context: c } = harness();
  node('rech-sonstiges').value = 'Privater Zugangscode'; node('lief-sonstiges').value = 'Tor 2';
  for (const id of ['hebebuehne', 'eigenAbladung', 'lief-hebebuehne', 'lief-eigenAbladung']) node(id).checked = true;
  c.resetCheckoutIdentityFields();
  assert.equal(node('rech-sonstiges').value, ''); assert.equal(node('lief-sonstiges').value, '');
  for (const id of ['hebebuehne', 'eigenAbladung', 'lief-hebebuehne', 'lief-eigenAbladung']) assert.equal(node(id).checked, false);
});
test('Adminanzeige: richtige Adresse, Altbestellungen und sichere mehrzeilige Ausgabe', () => {
  const { context: c } = harness();
  const b = { lieferart: 'lieferung', hebebuehne: true, eigenentladung: true, lieferhinweise: '<img src=x onerror=alert(1)>\nTor 2' };
  const html = c.lieferhinweiseHtml(b);
  assert.match(html, /Hebebühne/); assert.match(html, /Eigenständige Entladung/);
  assert.match(html, /&lt;img.*&gt;\nTor 2/); assert.doesNotMatch(html, /<img/);
  assert.match(html, /pre-wrap/); assert.match(html, /overflow-wrap:anywhere/);
  assert.doesNotMatch(c.lieferhinweiseHtml({ ...b, abweichende_lieferadresse: true }), /Hebebühne/);
  assert.equal(c.lieferhinweiseHtml({ ...b, lieferart: 'abholung' }), '');
  assert.equal(c.lieferhinweiseHtml({ lieferart: 'lieferung' }), '');
  assert.match(c.lieferhinweiseHtml({ lieferart: 'lieferung', hebebuehne: true }), /Hebebühne/);
  for (const name of ['lagerCardHtml', 'versandplanungRow', 'zeigeBestellung', 'renderThreadOrderPane']) {
    assert.match(funktion(admin, name), /lieferhinweiseHtml\(b\)/, name);
  }
});

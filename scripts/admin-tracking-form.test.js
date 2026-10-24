'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '..', 'admin.html'), 'utf8');
function funktion(name) {
  const start = html.search(new RegExp(`^(?:async )?function ${name}\\(`, 'm'));
  assert.ok(start >= 0); return html.slice(start, html.indexOf('\n}', start) + 2);
}
const code = ['zeigeVersandFormFehler', 'versandSpeditionOeffnen', 'versandSpeditionBeauftragen',
  'versandVersenden', 'versandVersendenAbsenden'].map(funktion).join('\n');
function harness() {
  const nodes = {}, calls = [], closed = [];
  function node(id) {
    if (!nodes[id]) {
      const classes = new Set();
      nodes[id] = { value: '', style: {}, attrs: {}, textContent: '', innerHTML: '', disabled: false,
        setAttribute(k, v) { this.attrs[k] = v; }, focus() { this.focused = true; },
        classList: { add: c => classes.add(c), contains: c => classes.has(c) } };
    }
    return nodes[id];
  }
  const ctx = vm.createContext({ document: { getElementById: node },
    versandplanungCache: [{ id: 168, spediteur: 'Raben' }], threadOrderAktuell: null,
    threadAktuelleId: null, zeigeToast() {}, ladeVersandplanung() {}, ladeThreadDetail() {},
    schliesseModal: id => closed.push(id), backendApi: async (...args) => { calls.push(args); throw new Error('Ungültiger Tracking-Link. Bitte HTTPS-Link verwenden oder leer lassen.'); }
  });
  vm.runInContext(code, ctx); return { ctx, node, calls, closed };
}
for (const [prefix, open, submit, modal] of [
  ['vs', 'versandSpeditionOeffnen', 'versandSpeditionBeauftragen', 'versandSpeditionModal'],
  ['vv', 'versandVersenden', 'versandVersendenAbsenden', 'versandVersendenModal']
]) {
  test(`${prefix}: ungültiger Tracking-Link lässt Dialog und Eingaben zur Korrektur offen`, async () => {
    const h = harness(); h.ctx[open](168);
    h.node(prefix + 'TrackingNr').value = '123456'; h.node(prefix + 'TrackingUrl').value = 'raben.de/123456';
    await h.ctx[submit]();
    assert.equal(h.calls.length, 1); assert.equal(h.closed.length, 0);
    assert.equal(h.node(prefix + 'TrackingUrl').value, 'raben.de/123456');
    assert.match(h.node(prefix + 'Fehler').textContent, /HTTPS-Link.*leer lassen/);
    assert.equal(h.node(prefix + 'Fehler').style.display, 'block');
    assert.equal(h.node(prefix + 'TrackingUrl').attrs['aria-invalid'], 'true');
    assert.equal(h.node(prefix + 'TrackingUrl').focused, true);
    assert.equal(h.node(prefix + 'Btn').disabled, false);
  });
  test(`${prefix}: Link bewusst leeren ist möglich, erfolgreicher Versand unverändert`, async () => {
    const h = harness(); h.ctx[open](168); await h.ctx[submit]();
    h.ctx.backendApi = async (...args) => { h.calls.push(args); return { ok: true }; };
    h.node(prefix + 'TrackingUrl').value = ''; await h.ctx[submit]();
    assert.equal(h.calls[1][2].tracking_url, ''); assert.deepEqual(h.closed, [modal]);
    assert.equal(h.node(prefix + 'Fehler').style.display, 'none');
    assert.equal(h.node(prefix + 'TrackingUrl').attrs['aria-invalid'], 'false');
  });
  test(`${prefix}: Fehlermeldungen werden nur als Text angezeigt und beim Neuöffnen gelöscht`, () => {
    const h = harness(); h.ctx.zeigeVersandFormFehler(prefix, '<img src=x onerror=alert(1)>');
    assert.equal(h.node(prefix + 'Fehler').innerHTML, '');
    h.ctx[open](168); assert.equal(h.node(prefix + 'Fehler').textContent, '');
    assert.equal(h.node(prefix + 'Fehler').style.display, 'none');
  });
}

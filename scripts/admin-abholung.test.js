'use strict';
// Offline-Regressionen: echte Admin-Renderfunktionen, nur DOM-/API-Doubles.
// Kein Laden der Admin-App, keine Zugangsdaten und keine echten API-Aufrufe.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '..', 'admin.html'), 'utf8');

function funktion(name) {
  const start = html.search(new RegExp(`^(?:async )?function ${name}\\(`, 'm'));
  assert.ok(start >= 0, `Funktion fehlt: ${name}`);
  const end = html.indexOf('\n}', start);
  assert.ok(end > start, `Funktionsende fehlt: ${name}`);
  return html.slice(start, end + 2);
}
const code = [
  'istAbholung', 'statusLabel', 'statusBadge', 'istLagerfaehigFrontend', 'anzeigeStatus',
  'feVersandPhase', 'ladeBestellungen', 'zeigeBestellung', 'renderThreadOrderPane',
  'versandPhaseLabel', 'versandplanungRow', 'lagerLieferadresse', 'lagerStatusLabel',
  'lieferhinweiseHtml', 'lagerCardHtml', 'versanddatenOeffnen', 'versanddatenAbsenden',
  'versandAbholungAbschliessen', 'ladeThreadDetail'
].map(funktion).join('\n');

const order = Object.freeze({
  id: 166, status: 'bezahlt', zahlungsart: 'stripe', lieferart: 'abholung',
  lager_status: 'in_bearbeitung', versandstatus: null, phase: 'in_bearbeitung',
  gesamtbetrag: 63, lieferkosten_netto: 0, kundenname: 'Testkunde', firma: 'Testfirma',
  reservierung_status: 'consumed', auftragsbestaetigung_versendet_am: '2026-10-13T05:48:52Z',
  lieferschein_versendet_am: '2026-10-13T05:48:52Z'
});
const position = Object.freeze({ produktname: 'Testparkett', anzahl_pakete: 1,
  menge_m2_gesamt: 1.4, einzelpreis: 63, gesamtpreis: 63 });
const escape = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));

function harness(overrides = {}, rights = ['bestellungen.status', 'warehouse.mark_ready', 'warehouse.mark_handed_to_carrier']) {
  const b = Object.freeze({ ...order, ...overrides });
  const nodes = {}, requests = [], toasts = [], confirms = [], refreshes = [];
  function node(id) {
    if (!nodes[id]) {
      const classes = new Set();
      nodes[id] = { value: '', textContent: '', innerHTML: '', disabled: false, dataset: {},
        classList: { add: v => classes.add(v), remove: v => classes.delete(v), contains: v => classes.has(v) } };
    }
    return nodes[id];
  }
  // Verhalten eines echten <select>: ein unbekannter Wert führt zu leerer Auswahl.
  const selectMarkup = html.match(/<select\b[^>]*id="threadStatusSelect"[^>]*>([\s\S]*?)<\/select>/)[1];
  const options = [...selectMarkup.matchAll(/<option value="([^"]+)"/g)].map(m => m[1]);
  let selected = options[0];
  Object.defineProperty(node('threadStatusSelect'), 'value', {
    get: () => selected, set: v => { selected = options.includes(v) ? v : ''; }
  });
  const context = vm.createContext({
    URLSearchParams, console,
    document: { getElementById: node, querySelector: () => null },
    adminMe: { ist_super_admin: false }, adminUnread: {}, STATUS_OPTIONEN: ['offen', 'bezahlt', 'versendet', 'geliefert', 'storniert'],
    darf: p => rights.includes(p), istNurLager: () => false,
    h: escape, euro: n => Number(n || 0).toFixed(2).replace('.', ',') + ' €', vtIco: () => '',
    zahlungsartLabel: () => 'Kreditkarte / Debitkarte', reservierungBadge: () => '', reservierungLabel: () => 'Verbraucht',
    istOffeneVorkasse: () => false, vorkasseLagerbuchungWiederholbar: () => false,
    vorkasseLagerbuchungManuell: () => false, b18StornoHtml: () => '',
    lieferzeitHinweisFuerBestellung: () => 'Test-Hinweis',
    aktualisiereBestellBadge: () => {}, ladeB18Aufgaben: () => {}, ladeAdminUngelesen: () => {},
    ladeBestellNachrichten: () => {},
    ladeLager: () => refreshes.push('lager'), ladeVersandplanung: () => refreshes.push('planung'),
    schliesseModal: id => node(id).classList.remove('open'),
    zeigeToast: (message, error) => toasts.push({ message, error }),
    confirm: message => { confirms.push(message); return context.confirmResult; }, confirmResult: false,
    threadAktuelleId: 7, threadOrderAktuell: null, threadOrderAktuellThreadId: null,
    NACHRICHT_TYP_LABEL: {}, threadStatus: 'kundenantwort',
    renderThreadVerlauf: msgs => { context.messages = msgs; },
    rebuildThreadModusSelect: () => {},
    backendApi: async (url, method = 'GET', body) => {
      requests.push({ url, method, body });
      if (url === '/api/admin/bestellungen/166/voll') return { bestellung: b, positionen: [position] };
      if (url === '/api/admin/bestellungen') return [b];
      if (url === '/api/admin/threads/7') return { bestellung: b, positionen: [position],
        thread: { status: context.threadStatus }, dokumente: {}, nachrichten: [{ nachricht_text: 'Vielen Dank' }] };
      if (['/api/admin/versand/166/versenden', '/api/admin/lager/166/an-disposition'].includes(url) && method === 'POST') return { ok: true };
      throw new Error(`Unerwarteter Test-Aufruf: ${method} ${url}`);
    }
  });
  vm.runInContext(code, context);
  return { context, b, node, requests, toasts, confirms, refreshes, options,
    ok: () => assert.deepEqual(toasts.filter(t => t.error), []) };
}

for (const status of ['offen', 'kundenantwort', 'in_bearbeitung', 'beantwortet', 'erledigt', 'geschlossen']) {
  test(`Nachrichtenstatus ${status} bleibt beim Laden sichtbar, ohne Status-Schreibzugriff`, async () => {
    const h = harness(); h.context.threadStatus = status;
    await h.context.ladeThreadDetail(true); h.ok();
    assert.equal(h.node('threadStatusSelect').value, status);
    assert.equal(h.context.messages[0].nachricht_text, 'Vielen Dank');
    assert.ok(h.requests.every(r => r.method === 'GET'));
  });
}
for (const lieferart of ['abholung', ' Abholung ', 'ABHOLUNG']) {
  test(`Bestellliste ${lieferart}: keine Speditionsaktion, Betrag und Zahlung unverändert`, async () => {
    const h = harness({ lieferart }); await h.context.ladeBestellungen(); h.ok();
    const output = h.node('bestellungenTable').innerHTML;
    assert.doesNotMatch(output, /anSpedition\(|An Spedition übergeben/);
    assert.match(output, /74,97 €/); assert.match(output, /63,00 €/);
    assert.match(output, /value="bezahlt" selected/);
    assert.equal(h.b.status, 'bezahlt'); assert.ok(h.requests.every(r => r.method === 'GET'));
  });
}
test('Bestelldetail Abholung: passende Rechnungserklärung, kein Speditionsknopf/Tracking', async () => {
  const h = harness(); await h.context.zeigeBestellung(166); h.ok();
  const output = h.node('bestellModalContent').innerHTML;
  assert.match(output, /Lager \/ Abholung/);
  assert.match(output, /bei Abholbereit-Meldung/);
  assert.doesNotMatch(output, /Spedition|trackingInput|Sendungsnummer/);
  assert.match(output, /74,97 €/);
  assert.ok(h.requests.every(r => r.method === 'GET'));
});
test('Abgeschlossene Abholung: Abgeholt statt Als geliefert markieren', async () => {
  const h = harness({ status: 'versendet', lager_status: 'abgeschlossen', an_spedition_uebergeben_am: '2026-10-14T09:00:00Z' });
  await h.context.zeigeBestellung(166); h.ok();
  assert.match(h.node('bestellModalContent').innerHTML, /Abgeholt/);
  assert.doesNotMatch(h.node('bestellModalContent').innerHTML, /alsGeliefert\(|anSpedition\(/);
});
test('Lieferung behält Speditionsaktion, Tracking und bisherigen Rechnungshinweis', async () => {
  const h = harness({ lieferart: 'lieferung' });
  await h.context.ladeBestellungen(); await h.context.zeigeBestellung(166); h.ok();
  assert.match(h.node('bestellungenTable').innerHTML, /anSpedition\(166\)/);
  assert.match(h.node('bestellModalContent').innerHTML, /kommt bei Spedition/);
  assert.match(h.node('bestellModalContent').innerHTML, /id="trackingInput"/);
});
for (const phase of ['in_bearbeitung', 'an_disposition', 'abholbereit']) {
  test(`Nachrichtenfenster Abholung ${phase}: nur passender Abholschritt`, () => {
    const h = harness({ versandstatus: phase, phase });
    h.context.renderThreadOrderPane(h.b, [position], {}); h.ok();
    const output = h.node('threadOrderPane').innerHTML;
    const action = { in_bearbeitung: 'versanddatenOeffnen', an_disposition: 'lagerAbholbereit', abholbereit: 'versandAbholungAbschliessen' }[phase];
    assert.match(output, new RegExp(action + '\\(166'));
    assert.doesNotMatch(output, /versandVersenden\(|versandSpeditionOeffnen\(|Kunde informieren \/ Versenden/);
    assert.equal(h.requests.length, 0);
  });
}
test('Nachrichtenfenster Lieferung behält Versandabschluss', () => {
  const h = harness({ lieferart: 'lieferung', versandstatus: 'abgeholt' });
  h.context.renderThreadOrderPane(h.b, [position], {});
  assert.match(h.node('threadOrderPane').innerHTML, /versandVersenden\(166\)/);
  assert.doesNotMatch(h.node('threadOrderPane').innerHTML, /versandAbholungAbschliessen\(/);
});
test('Abholabschluss wird ohne Statusrecht und für reine Lagerrolle nicht angeboten', () => {
  for (const lager of [false, true]) {
    const h = harness({ versandstatus: 'abholbereit' }, lager ? ['bestellungen.status'] : []);
    h.context.istNurLager = () => lager;
    h.context.renderThreadOrderPane(h.b, [position], {});
    assert.doesNotMatch(h.node('threadOrderPane').innerHTML, /onclick="versandAbholungAbschliessen/);
  }
});
test('Abholung blendet alte Trackingangabe aus und erhält HTML-Escaping', () => {
  const h = harness({ tracking_nr: 'ALTES_TRACKING', kundenname: '<img src=x onerror=alert(1)>' });
  h.context.renderThreadOrderPane(h.b, [position], {});
  const output = h.node('threadOrderPane').innerHTML;
  assert.doesNotMatch(output, /ALTES_TRACKING|<img src=x/); assert.match(output, /&lt;img/);
});
test('Abholabschluss fragt tatsächliche Übergabe ab, Abbrechen schreibt nichts', async () => {
  const h = harness(); await h.context.versandAbholungAbschliessen(166);
  assert.match(h.confirms[0], /Abgeholt/); assert.match(h.confirms[0], /tatsächlich/);
  assert.doesNotMatch(h.confirms[0], /Versendet|Versandbestätigung/);
  assert.equal(h.requests.length, 0);
});
test('Bestätigter Abholabschluss nutzt nur bestehenden Endpunkt und keine Mail-/Rechnungsroute', async () => {
  const h = harness(); h.context.confirmResult = true;
  await h.context.versandAbholungAbschliessen(166); h.ok();
  assert.deepEqual(h.requests.map(r => [r.method, r.url]), [['POST', '/api/admin/versand/166/versenden']]);
  assert.match(h.toasts[0].message, /Abholung abgeschlossen/);
});
test('Kommissionierdialog wechselt zwischen Abholungs- und Versandtext, ohne Anfrage', () => {
  const h = harness();
  h.context.versanddatenOeffnen(166, true);
  assert.match(h.node('vdTitel').textContent, /Abholung/);
  assert.doesNotMatch(h.node('vdHinweis').textContent, /Spedition|Versanddaten/);
  assert.equal(h.node('vdBtn').textContent, 'Kommissionierung speichern');
  h.context.versanddatenOeffnen(167, false);
  assert.equal(h.node('vdTitel').textContent, 'Versanddaten erfassen');
  assert.equal(h.node('vdBtn').textContent, 'An Disposition weitergeben');
  assert.equal(h.requests.length, 0);
});
test('Abhol-Kommissionierung: gleicher Endpunkt/Payload, kein automatisches Abholbereit oder Abschluss', async () => {
  const h = harness(); h.context.versanddatenOeffnen(166, true);
  h.node('vdPakete').value = '1';
  await h.context.versanddatenAbsenden(); h.ok();
  assert.equal(h.requests.length, 1); assert.equal(h.requests[0].url, '/api/admin/lager/166/an-disposition');
  assert.equal(h.requests[0].body.pakete, '1'); assert.equal(h.requests[0].body.paletten.length, 0);
  assert.match(h.toasts[0].message, /Noch nicht abholbereit/);
  assert.equal(h.node('vdBtn').textContent, 'Kommissionierung speichern');
});
test('Kommissionierknöpfe aus Lager und Nachrichtenfenster übergeben Abholungsart', () => {
  const h = harness();
  assert.match(h.context.lagerCardHtml(h.b), /versanddatenOeffnen\(166, true\)/);
  h.context.renderThreadOrderPane(h.b, [position], {});
  assert.match(h.node('threadOrderPane').innerHTML, /versanddatenOeffnen\(166, true\)/);
});

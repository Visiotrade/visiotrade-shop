'use strict';
// Echte Frontendfunktionen, DOM-/API-Doubles; keine Anmeldung oder externen Dienste.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '..', 'admin.html'), 'utf8');
function funktion(name) {
  const start = html.search(new RegExp(`^(?:async )?function ${name}\\(`, 'm'));
  const end = html.indexOf('\n}', start);
  assert.ok(start >= 0 && end > start, name);
  return html.slice(start, end + 2);
}
const code = ['darfSeite', 'zeigeSeite', 'ladeAdminMe', 'threadKarteHtml', 'ladeNachrichten',
  'aktualisiereNachrichtenBadge', 'lagerChatOeffnen', 'ladeLagerChat', 'renderLagerChat',
  'lagerChatSenden', 'startNachrichtenPoller'].map(funktion).join('\n');
const escape = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));
const message = text => ({ nachricht_text: text, sichtbarkeit: 'intern_admin', absender_name: 'Testteam' });
function deferred() { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; }
function harness(rights = ['warehouse.chat_view', 'warehouse.chat_write'], nurLager = true) {
  const nodes = {}, requests = [], pages = [], toasts = [];
  const me = { ist_super_admin: false, nur_lager: nurLager, rechte: rights };
  function node(id) {
    if (!nodes[id]) {
      const classes = new Set(); let value = '';
      nodes[id] = { innerHTML: '', textContent: '', disabled: false, style: {},
        get value() { return value; }, set value(v) { value = String(v); },
        scrollTop: 0, scrollHeight: 0, clientHeight: 200, contains: () => false,
        classList: { add: c => classes.add(c), remove: c => classes.delete(c), contains: c => classes.has(c) } };
    }
    return nodes[id];
  }
  const ctx = vm.createContext({
    console, adminMe: me, lagerChatLadefolge: 0, lagerChatSendet: false,
    nachrichtenPoller: null, adminVisibilityBound: false, threadAktuelleId: null,
    document: { getElementById: node, querySelector: () => null, addEventListener: () => {}, hidden: false },
    window: { addEventListener: () => {} }, setInterval: cb => { ctx.tick = cb; return 1; },
    darf: p => me.ist_super_admin || rights.includes(p), istNurLager: () => nurLager,
    darfLagerZugang: () => rights.some(p => p.startsWith('warehouse.')),
    BREITE_RECHTE_FE: ['messages.view'], renderTestmodusBanner: () => {},
    aktualisierePreisanfrageBadge: () => {}, aktualisiereBestellBadge: () => {},
    aktualisiereLagerBadge: () => {}, renderLagerBadge: () => {},
    ladeAdminUngelesen: () => {}, ladeKategorienListe: () => {}, ladeLager: () => {},
    ladeVersandplanung: () => {}, ladeBestellungen: () => {}, ladeThreadDetail: () => {},
    aktiviereSeite: page => pages.push(page), zeigeToast: (...args) => toasts.push(args),
    h: escape, vtIco: () => '', kanalChip: () => 'Shop', NACHRICHT_TYP_LABEL: {},
    NACHRICHT_STATUS_FARBE: {}, NACHRICHT_STATUS_LABEL: { kundenantwort: 'Kundenantwort' },
    backendApi: async (url, method = 'GET', body) => {
      requests.push({ url, method, body });
      if (url === '/api/admin/me') return me;
      if (url.endsWith('/notizen')) return { nachrichten: [message('Morgen')] };
      if (url.endsWith('/notiz')) return { nachrichten: [message(body.nachricht)] };
      return { anzahl: 2, nachrichten: [{ id: 7, bestellung_id: 166,
        status: 'kundenantwort', erstellt_von_email: 'unsichtbar@example.test',
        bestellung: { id: 166, firma: 'Testfirma', rechnung_nummer: 'RE-GEHEIM' },
        letzte_nachricht: { text: 'Morgen' }, ungelesen: 2 }] };
    }
  });
  vm.runInContext(code, ctx);
  return { ctx, node, requests, pages, toasts, me };
}

test('Lager mit Chat-Leserecht erreicht Nachrichten, keine kaufmännischen Seiten', () => {
  const h = harness(); h.ctx.zeigeSeite('nachrichten');
  assert.deepEqual(h.pages, ['nachrichten']); assert.deepEqual(h.toasts, []);
  for (const page of ['dashboard', 'bestellungen', 'produkte', 'kunden', 'preisanfragen', 'versandplanung', 'adminusers', 'auditlog', 'papierkorb']) {
    assert.equal(h.ctx.darfSeite(page), false, page);
  }
});
test('Ohne Lager-Chat-Leserecht bleiben Menü und Direktaufruf gesperrt', async () => {
  const h = harness(['warehouse.view_orders', 'messages.view']);
  await h.ctx.ladeAdminMe(); h.ctx.zeigeSeite('nachrichten');
  assert.equal(h.node('navNachrichten').style.display, 'none');
  assert.equal(h.ctx.darfSeite('nachrichten'), false);
  assert.ok(h.requests.every(r => r.url === '/api/admin/me'));
});
test('Chat-Leserecht ohne messages.view genügt für Menü und Lager-Badge', async () => {
  const h = harness(['warehouse.chat_view']); await h.ctx.ladeAdminMe();
  assert.equal(h.node('navNachrichten').style.display, '');
  assert.ok(h.requests.some(r => r.url === '/api/admin/lager/nachrichten'));
  assert.ok(!h.requests.some(r => r.url.startsWith('/api/admin/nachrichten')));
});
test('Lagerübersicht ignoriert Kundenfilter und öffnet nur den internen Bestellchat', async () => {
  const h = harness(); h.node('filterNachrichtStatus').value = 'offen'; h.node('filterNachrichtKanal').value = 'email';
  await h.ctx.ladeNachrichten();
  assert.equal(h.requests[0].url, '/api/admin/lager/nachrichten');
  assert.equal(h.node('nachrichtenTitel').textContent, 'Interne Lagernachrichten');
  assert.equal(h.node('filterNachrichtKanal').style.display, 'none');
  const output = h.node('nachrichtenListe').innerHTML;
  assert.match(output, /lagerChatOeffnen\(166\)/);
  assert.match(output, /Morgen/);
  assert.doesNotMatch(output, /oeffneThread\(|Kundenantwort|RE-GEHEIM|unsichtbar@example/);
});
test('Verkaufs-Admin behält normales Kundenpostfach und Statusfilter', async () => {
  const h = harness(['messages.view'], false); h.node('filterNachrichtStatus').value = 'kundenantwort';
  await h.ctx.ladeNachrichten();
  assert.equal(h.requests[0].url, '/api/admin/nachrichten?status=kundenantwort');
  assert.equal(h.node('nachrichtenTitel').textContent, 'Kundennachrichten');
  assert.match(h.node('nachrichtenListe').innerHTML, /oeffneThread\(7\)/);
});
test('Lagerkarte escaped Texte und akzeptiert keine fremden Inline-Aktionen als Bestell-ID', () => {
  const h = harness();
  assert.equal(h.ctx.threadKarteHtml({ bestellung_id: '1);alert(1)' }), '');
  const output = h.ctx.threadKarteHtml({ bestellung_id: 166, letzte_nachricht: { text: '<img onerror=x>' } });
  assert.match(output, /&lt;img/); assert.doesNotMatch(output, /<img/);
});
test('Nur lesender Lagerzugang kann weder per Button noch Direktaufruf schreiben', async () => {
  const h = harness(['warehouse.chat_view']); await h.ctx.lagerChatOeffnen(166);
  assert.equal(h.node('lagerChatSendBtn').disabled, true);
  h.node('lagerChatText').value = 'Nicht senden'; await h.ctx.lagerChatSenden();
  assert.ok(h.requests.every(r => r.method === 'GET'));
});
test('Chat-Aktualisierung erhält Entwurf und Scrollposition beim Lesen älterer Nachrichten', async () => {
  const h = harness(); await h.ctx.lagerChatOeffnen(166);
  h.node('lagerChatText').value = 'Mein Entwurf';
  Object.assign(h.node('lagerChatVerlauf'), { scrollTop: 35, scrollHeight: 900, clientHeight: 200 });
  h.ctx.backendApi = async () => ({ nachrichten: [message('Neue Antwort')] });
  await h.ctx.ladeLagerChat(true);
  assert.match(h.node('lagerChatVerlauf').innerHTML, /Neue Antwort/);
  assert.equal(h.node('lagerChatText').value, 'Mein Entwurf');
  assert.equal(h.node('lagerChatVerlauf').scrollTop, 35);
});
test('Späte Antwort einer anderen Bestellung überschreibt den aktuellen Chat nicht', async () => {
  const h = harness(), first = deferred();
  h.ctx.backendApi = url => url.includes('/166/') ? first.promise : Promise.resolve({ nachrichten: [message('Bestellung 167')] });
  const opening = h.ctx.lagerChatOeffnen(166); await h.ctx.lagerChatOeffnen(167);
  first.resolve({ nachrichten: [message('Alte Bestellung 166')] }); await opening;
  assert.match(h.node('lagerChatVerlauf').innerHTML, /Bestellung 167/);
  assert.doesNotMatch(h.node('lagerChatVerlauf').innerHTML, /Alte Bestellung/);
});
test('Späte Leseantwort nach Senden überschreibt die neue Nachricht nicht', async () => {
  const h = harness(); await h.ctx.lagerChatOeffnen(166); const read = deferred();
  h.ctx.backendApi = (url, method) => method === 'POST'
    ? Promise.resolve({ nachrichten: [message('Neu gesendet')] })
    : url.endsWith('/notizen') ? read.promise : Promise.resolve({ anzahl: 0 });
  const reading = h.ctx.ladeLagerChat(true);
  h.node('lagerChatText').value = 'Neu gesendet'; await h.ctx.lagerChatSenden();
  read.resolve({ nachrichten: [message('Veraltet')] }); await reading;
  assert.match(h.node('lagerChatVerlauf').innerHTML, /Neu gesendet/);
  assert.doesNotMatch(h.node('lagerChatVerlauf').innerHTML, /Veraltet/);
});
test('Doppelklick sendet nur einmal und ein währenddessen ergänzter Entwurf bleibt erhalten', async () => {
  const h = harness(); await h.ctx.lagerChatOeffnen(166); const sending = deferred(); let count = 0;
  h.ctx.backendApi = (url, method) => { if (method === 'POST') { count++; return sending.promise; } return Promise.resolve({ anzahl: 0 }); };
  h.node('lagerChatText').value = 'Notiz'; const first = h.ctx.lagerChatSenden();
  h.node('lagerChatText').value = 'Notiz ergänzt'; await h.ctx.lagerChatSenden();
  sending.resolve({ nachrichten: [message('Notiz')] }); await first;
  assert.equal(count, 1); assert.equal(h.node('lagerChatText').value, 'Notiz ergänzt');
});
test('Geschlossener oder nicht berechtigter Chat wird nicht abgefragt', async () => {
  const h = harness(); await h.ctx.ladeLagerChat(true); assert.equal(h.requests.length, 0);
  const forbidden = harness([]); await forbidden.ctx.lagerChatOeffnen(166); assert.equal(forbidden.requests.length, 0);
});
test('Vorhandener Poller aktualisiert offenen Lagerchat, versteckter Tab bleibt ruhig', () => {
  const h = harness(); let reads = 0;
  h.ctx.aktualisiereNachrichtenBadge = () => {};
  h.ctx.ladeLagerChat = silent => { assert.equal(silent, true); reads++; };
  h.node('lagerChatModal').classList.add('open');
  h.ctx.startNachrichtenPoller(); h.ctx.tick(); assert.equal(reads, 1);
  h.ctx.document.hidden = true; h.ctx.tick(); assert.equal(reads, 1);
});

#!/usr/bin/env node
'use strict';
// =============================================================================
// Syntaxprüfung für die Inline-Skripte in index.html und admin.html
// =============================================================================
// AUFRUF (identisch lokal und in der CI):
//     node scripts/check-inline-js.js
//     node scripts/check-inline-js.js index.html          (einzelne Datei)
//
// Exit-Code 0 = alles in Ordnung · Exit-Code 1 = Syntaxfehler oder Prüfung leer.
//
// WARUM ES DIESE PRÜFUNG GIBT
// ---------------------------
// index.html (~6.700 Zeilen) und admin.html (~3.600 Zeilen) enthalten den
// gesamten Anwendungscode als Inline-<script>. Bisher hat sie NIEMAND geprüft:
// Vercel liefert sie als statische Dateien aus, ohne sie zu parsen. Ein
// Tippfehler beim Bearbeiten über den GitHub-Web-Editor ging damit unbemerkt
// live und legte den kompletten Shop bzw. das Admin-Panel lahm – ohne dass
// irgendein Lauf rot geworden wäre.
//
// UNTERSTÜTZTE SKRIPTFORMEN (bewusst dokumentiert)
// ------------------------------------------------
//   GEPRÜFT (klassisch, via node:vm – kompiliert nur, führt NICHTS aus):
//     <script> … </script>
//     <script type="text/javascript">  ·  "application/javascript"  ·  "text/ecmascript"
//   GEPRÜFT (ESM, via temporäre .mjs + `node --check`):
//     <script type="module">
//   ÜBERSPRUNGEN (wird im Bericht ausgewiesen):
//     <script src="…">                → externe Datei, kein Inhalt zu prüfen
//     type="application/json", "text/template", "text/x-template" u. Ä.
//                                     → kein JavaScript
//     leere Blöcke
//
// ZUR BLOCK-ERKENNUNG UND `</script>` IN STRINGS
// ----------------------------------------------
// Ein Skriptblock endet beim ERSTEN `</script` – auch wenn die Zeichenfolge in
// einem JavaScript-String steht. Das ist keine Schwäche des Extraktors, sondern
// exakt das Verhalten des HTML-Parsers im Browser: Wer `"</script>"` in einen
// String schreibt, MUSS `"<\/script>"` maskieren, sonst ist die Seite bereits im
// Browser kaputt. Der Extraktor bildet dieses Verhalten 1:1 nach und meldet einen
// solchen Fall folgerichtig als Syntaxfehler – das ist gewollt.
// Attributwerte in Anführungszeichen werden korrekt behandelt: ein `>` innerhalb
// von "…" oder '…' beendet das öffnende Tag NICHT.
//
// ZEILENNUMMERN
// -------------
// Jeder Block wird vor der Prüfung mit so vielen Leerzeilen aufgefüllt, wie er in
// der HTML-Datei nach unten versetzt ist. Gemeldete Zeilennummern zeigen dadurch
// direkt auf die Zeile in index.html bzw. admin.html.
// =============================================================================

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { execFileSync } = require('node:child_process');

const STANDARD_DATEIEN = ['index.html', 'admin.html'];
const KLASSISCHE_TYPEN = new Set(['', 'text/javascript', 'application/javascript', 'text/ecmascript']);

function extrahiereSkriptbloecke(html) {
  const klein = html.toLowerCase();
  const bloecke = [];
  let suchAb = 0;

  while (true) {
    const tagStart = klein.indexOf('<script', suchAb);
    if (tagStart === -1) break;

    // Ende des öffnenden Tags finden – ein '>' in einem Attributwert zählt nicht.
    let i = tagStart + '<script'.length;
    let quote = null;
    while (i < html.length) {
      const c = html[i];
      if (quote) { if (c === quote) quote = null; }
      else if (c === '"' || c === "'") quote = c;
      else if (c === '>') break;
      i++;
    }
    if (i >= html.length) break; // unvollständiges Tag am Dateiende

    const attribute = html.slice(tagStart + '<script'.length, i);
    const inhaltStart = i + 1;

    let inhaltEnde = klein.indexOf('</script', inhaltStart);
    if (inhaltEnde === -1) inhaltEnde = html.length;

    const srcT = /\ssrc\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attribute);
    const typT = /\stype\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attribute);
    const wert = (t) => t ? (t[2] ?? t[3] ?? t[4] ?? '').trim() : '';

    bloecke.push({
      index: bloecke.length + 1,
      startZeile: html.slice(0, inhaltStart).split('\n').length,
      code: html.slice(inhaltStart, inhaltEnde),
      typ: wert(typT).toLowerCase(),
      src: srcT ? wert(srcT) : null
    });

    suchAb = inhaltEnde + 1;
  }
  return bloecke;
}

/** Klassisches Skript: kompilieren, nicht ausführen. Wirft bei Syntaxfehler. */
function pruefeKlassisch(code, dateiname) {
  new vm.Script(code, { filename: dateiname });
}

/** ES-Modul: temporäre .mjs + `node --check`. Wirft bei Syntaxfehler. */
function pruefeModul(code, dateiname, blockIndex) {
  const ordner = fs.mkdtempSync(path.join(os.tmpdir(), 'vt-htmljs-'));
  const tmp = path.join(ordner, `${path.basename(dateiname, '.html')}-block${blockIndex}.mjs`);
  try {
    fs.writeFileSync(tmp, code, 'utf8');
    execFileSync(process.execPath, ['--check', tmp], { stdio: 'pipe' });
  } catch (e) {
    const stderr = (e.stderr && e.stderr.toString()) || e.message || '';
    throw new SyntaxError(stderr.trim() || 'Modul-Syntaxfehler');
  } finally {
    try { fs.rmSync(ordner, { recursive: true, force: true }); } catch (_) {}
  }
}

function pruefeDatei(datei) {
  const bericht = { datei, geprueft: 0, uebersprungen: [], fehler: [] };

  if (!fs.existsSync(datei)) {
    bericht.fehler.push(`Datei nicht gefunden: ${datei}`);
    return bericht;
  }

  const html = fs.readFileSync(datei, 'utf8');
  const bloecke = extrahiereSkriptbloecke(html);

  for (const b of bloecke) {
    if (b.src) { bericht.uebersprungen.push(`#${b.index} Z.${b.startZeile} – extern (src)`); continue; }
    if (!b.code.trim()) { bericht.uebersprungen.push(`#${b.index} Z.${b.startZeile} – leer`); continue; }

    const istModul = b.typ === 'module';
    if (!istModul && !KLASSISCHE_TYPEN.has(b.typ)) {
      bericht.uebersprungen.push(`#${b.index} Z.${b.startZeile} – type="${b.typ}" (kein JavaScript)`);
      continue;
    }

    // Zeilenversatz auffüllen → gemeldete Zeilennummern passen zur HTML-Datei.
    const code = '\n'.repeat(Math.max(0, b.startZeile - 1)) + b.code;

    try {
      if (istModul) pruefeModul(code, datei, b.index);
      else pruefeKlassisch(code, datei);
      bericht.geprueft++;
    } catch (e) {
      bericht.fehler.push(
        `${datei} · Skriptblock #${b.index} (beginnt bei Zeile ${b.startZeile}` +
        `${istModul ? ', type="module"' : ''})\n      ` +
        String(e.message).split('\n').join('\n      ')
      );
    }
  }

  // Ein Lauf, der NICHTS geprüft hat, ist kein Erfolg – sonst wäre Grün wertlos.
  if (bericht.geprueft === 0 && bericht.fehler.length === 0) {
    bericht.fehler.push(
      `${datei}: kein prüfbarer Inline-Skriptblock gefunden. Entweder ist die Datei kaputt ` +
      `oder der Extraktor greift nicht mehr – in beiden Fällen prüft dieser Lauf nichts.`
    );
  }
  return bericht;
}

// ----------------------------------------------------------------------------
function main() {
  const argumente = process.argv.slice(2).filter(a => !a.startsWith('-'));
  const dateien = argumente.length ? argumente : STANDARD_DATEIEN;

  console.log('Prüfe Inline-JavaScript in: ' + dateien.join(', ') + '\n');

  let fehlerGesamt = 0;
  let geprueftGesamt = 0;

  for (const datei of dateien) {
    const b = pruefeDatei(datei);
    geprueftGesamt += b.geprueft;

    if (b.fehler.length) {
      fehlerGesamt += b.fehler.length;
      console.error(`  ✗ ${datei}`);
      for (const f of b.fehler) console.error(`    ${f}`);
    } else {
      console.log(`  ✓ ${datei} – ${b.geprueft} Skriptblock/-blöcke syntaktisch gültig`);
    }
    for (const u of b.uebersprungen) console.log(`      übersprungen: ${u}`);
  }

  console.log('');
  if (fehlerGesamt > 0) {
    console.error(`FEHLGESCHLAGEN: ${fehlerGesamt} Problem(e). Diese Datei(en) würden im Browser NICHT laden.`);
    process.exit(1);
  }
  console.log(`OK: ${geprueftGesamt} Skriptblock/-blöcke geprüft, keine Syntaxfehler.`);
  process.exit(0);
}

// Selbsttest: `node scripts/check-inline-js.js --selftest`
// Beweist, dass die Prüfung greift – ohne dafür eine echte Datei zerstören zu müssen.
function selftest() {
  const probleme = [];
  const pruefe = (name, ist, soll) => {
    const ok = JSON.stringify(ist) === JSON.stringify(soll);
    console.log(`  ${ok ? '✓' : '✗'} ${name}` + (ok ? '' : `\n      erwartet: ${JSON.stringify(soll)}\n      erhalten: ${JSON.stringify(ist)}`));
    if (!ok) probleme.push(name);
  };

  const html = [
    '<html><head>',
    '<script src="https://example.org/x.js"></script>',
    '<script type="application/json">{ "kein": "javascript" }</script>',
    '</head><body>',
    '<script>const a = 1;</script>',
    '<script type="text/javascript">function b(){ return 2; }</script>',
    '</body></html>'
  ].join('\n');
  const bloecke = extrahiereSkriptbloecke(html);

  pruefe('alle vier <script>-Vorkommen erkannt', bloecke.length, 4);
  pruefe('externes Skript erkannt', bloecke[0].src, 'https://example.org/x.js');
  pruefe('Nicht-JS-Typ erkannt', bloecke[1].typ, 'application/json');
  pruefe('Inhalt korrekt extrahiert', bloecke[2].code, 'const a = 1;');
  pruefe('Startzeile zeigt auf die HTML-Zeile', bloecke[3].startZeile, 6);

  const mitGroesser = extrahiereSkriptbloecke('<script data-x="a>b">const c = 1;</script>');
  pruefe('">" im Attributwert beendet das Tag nicht', mitGroesser[0].code, 'const c = 1;');

  // --- Syntaxbewertung: was MUSS durchgehen, was MUSS scheitern ---------------
  // Wichtig ist beides. Ein Prüfer, der alles beanstandet, ist genauso wertlos
  // wie einer, der alles durchwinkt.
  const parst = (code) => { try { pruefeKlassisch(code, 'selbsttest'); return true; } catch (_) { return false; } };
  const scheitertMitSyntaxError = (code) => {
    try { pruefeKlassisch(code, 'selbsttest'); return false; } catch (e) { return e instanceof SyntaxError; }
  };

  // MUSS akzeptiert werden – gültiger Code, auch wenn er hier nicht lauffähig wäre.
  pruefe('einfacher gültiger Code', parst('const x = 1;'), true);
  pruefe('Pfeilfunktion', parst('const ok = () => 42;'), true);
  pruefe('Browser-Referenz (document) wird NICHT beanstandet',
    parst("document.querySelector('#test');"), true);
  pruefe('weitere Browser-Globals (window, localStorage, fetch)',
    parst("window.addEventListener('load', () => { localStorage.getItem('k'); fetch('/x'); });"), true);
  pruefe('moderne Syntax: Optional Chaining + Nullish Coalescing',
    parst("const wert = objekt?.eigenschaft ?? 'fallback';"), true);
  pruefe('moderne Syntax: Klassenfeld, Spread, async/await',
    parst("class A { #p = 1; async m(){ const [a,...r] = [1,2,3]; return await Promise.resolve({...{}, a, r}); } }"), true);
  pruefe('Template-Literal mit eingebettetem HTML',
    parst("const h = `<div class=\"x\">${1 + 1}</div>`;"), true);

  // MUSS scheitern – echte Syntaxfehler.
  pruefe('fehlende schließende Klammer', scheitertMitSyntaxError('if (x) {\n  console.log(x);'), true);
  pruefe('ungültige Funktionssignatur', scheitertMitSyntaxError('function defekt( {\n  return true;\n}'), true);
  pruefe('unvollständiger String', scheitertMitSyntaxError("const s = 'nicht geschlossen;"), true);
  // Bewusst im GLEICHEN Gültigkeitsbereich – in getrennten Blöcken wäre eine
  // zweite Deklaration zulässig und der erwartete Fehler träte gar nicht auf.
  pruefe('doppeltes const im selben Gültigkeitsbereich',
    scheitertMitSyntaxError('const x = 1;\nconst x = 2;'), true);
  // Gegenprobe: in getrennten Blöcken ist dasselbe korrekt und muss durchgehen.
  pruefe('gleicher Name in getrennten Blöcken ist zulässig',
    parst('{ const x = 1; }\n{ const x = 2; }'), true);
  pruefe('unerwartetes Token', scheitertMitSyntaxError('const a = ;'), true);

  // Bewusste Abgrenzung: Laufzeitfehler sind KEINE Syntaxfehler und werden – korrekt –
  // nicht gemeldet. Diese Prüfung hält das ausdrücklich fest, damit niemand vom
  // grünen Lauf mehr erwartet, als er leisten kann.
  pruefe('Laufzeitfehler (nicht definierte Funktion) wird bewusst NICHT beanstandet',
    parst('nichtDefinierteFunktion();'), true);

  console.log('');
  if (probleme.length) { console.error(`SELBSTTEST FEHLGESCHLAGEN: ${probleme.join(', ')}`); process.exit(1); }
  console.log('Selbsttest bestanden – die Prüfung greift nachweislich.');
  process.exit(0);
}

if (process.argv.includes('--selftest')) selftest();
else main();

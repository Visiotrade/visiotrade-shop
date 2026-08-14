require('dotenv').config();

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
// stripe-Client liegt in services/payments.js (Phase 4, Commit 9); hier importiert (Webhook-Route).

// Helmet (Security-Header) + compression (Antwort-Kompression) sind feste
// Dependencies in package.json – hart laden, damit ein Deploy ohne sie klar scheitert
// statt still ohne Security-Header/Kompression zu laufen.
const helmet = require('helmet');
const compression = require('compression');

// Aus server.js in Module ausgelagert (Phase 1+2 Modularisierung, KEINE Logikänderung).
// fetchFn liegt in lib/utils.js (Variante a); FETCH_TIMEOUT_MS wird dort intern
// genutzt und hier nicht mehr importiert (Paket 4). escapeHtml/centsFromNet/
// readResponseBuffer ebenfalls nach lib/utils.js verschoben (Paket 4).
const { euro, toNumber, round2, normalizeEmail, secretsGleich, clientIp, sendError, setErrorReporter, fetchFn, requiredEnv, escapeHtml, centsFromNet, readResponseBuffer, zahlungsartLabel } = require('./lib/utils');
const { pruefeTurnstile, verlangeTurnstile } = require('./lib/turnstile');
const { getSupabaseKey, supabaseRequest, supabaseQuery, supabaseUpdate, supabaseInsert, supabaseUpsert, supabasePatchWhere, supabaseRpc, ladeBestellung, ladePositionen, ladePaket, _produktCache, produktCacheLeeren, ladeProdukt, ladePaketeMap, ladeProdukteMap } = require('./lib/supabase');
// Auth-/Autorisierungs-Guards (Phase 3, aus server.js verschoben – byte-identisch).
const { getUserFromAuthHeader, getOptionalUserFromAuthHeader, assertBestellungGehoertZuUser, ladeAdmin, assertAdmin, istLegacyAdmin, assertAdminPermission, assertSuperAdmin, WAREHOUSE_KEYS, assertWarehouse, MONEY_ADMIN_KEYS, istNurLagerUser, verbieteNurLager, LAGER_GELD_FELDER, entferneGeldfelderBestellung, entferneGeldfelderPosition, schreibeAuditLog } = require('./lib/auth');
// Serverseitiger Frachtrechner (Phase 4, Commit 2, aus server.js verschoben – byte-identisch).
const { stellplatzFaktorJeKategorie, berechneLieferkostenServerseitig } = require('./services/fracht');
// E-Mail-Transport über Brevo (Phase 4, Commit 3, aus server.js verschoben – byte-identisch).
const { sendeEmail, sendeMehrfachEmail } = require('./services/email');
// Storage-Helfer + PDF-Hilfsfunktionen (Phase 4, Commit 4, aus server.js verschoben – byte-identisch).
const { speicherePdfInStorage, signierteRechnungUrl, ladePdfAusStorage, encodeStoragePath, speichereDateiInStorage, ladeDateiAusStorage, signierteDateiUrl, markiereAlsKopie, nfMenge, erweiterePositionenMitProdukt, erzeugeProfiPdf } = require('./services/pdf');
// Preis-/Bestellwert-Berechnung (Phase 4, Commit 5, aus server.js verschoben – byte-identisch).
const { lieferzeitHinweis, lieferzeitHinweisFuerBestellung, berechneUndFixiereBestellungServerseitig, ermittleSendungsdatenAusPositionen, ermittleNettoBetraege, buildStripeLineItemsFromPositionen } = require('./services/pricing');
// Lexoffice-Rechnungserstellung + Nachladen (Phase 4, Commit 6, aus server.js verschoben – byte-identisch).
const { erstelleLexofficeRechnung, holeLexofficePdf, holeLexofficeVoucherNumber, backfillRechnungNummer } = require('./services/lexoffice');
// Lagerbestand & Reservierungen (Phase 4, Commit 7, aus server.js verschoben – byte-identisch).
const { reduziereLagerbestandAtomar, reserviereLagerbestandAtomar, verbraucheBestellReservierungen, bucheBezahlteBestellungLagerAtomar, gebeBestellReservierungenFrei, gebeAbgelaufeneReservierungenFrei, storniereRechnungskaufAtomar } = require('./services/stock');
// Zahlungsanbieter Stripe + PayPal (Phase 4, Commit 9, aus server.js verschoben – byte-identisch).
// stripe = SDK-Client (auch für die Webhook-Route unten). require läuft VOR der Webhook-Definition.
const { stripe, PAYPAL_API_BASE_URL, getPayPalToken, erstelleStripeSessionFuerBestellung, erstellePayPalOrderFuerBestellung, bewerteCaptureAntwort } = require('./services/payments');
const { createAutoJobRunner } = require('./services/auto-jobs');
// Telegram-Versand (Phase 4, Commit 10, aus server.js verschoben – byte-identisch). supportBotToken
// wird vom (vorerst) hier verbliebenen ladeTelegramDatei genutzt.
const { sendeTelegram, sendeAdminBenachrichtigung, supportBotToken, sendeTelegramSupport } = require('./services/telegram');
// Nachrichten-/Vorgangscenter-Fundament (Phase 4, Commit 11a, aus server.js verschoben – byte-identisch).
const { NACHRICHT_TYPEN, NACHRICHT_STATUS, NACHRICHT_MAX_ANHAENGE, NACHRICHT_MAX_BYTES, NACHRICHT_MIME, typLabelServer, darfBestellungSehen, nachrichtEmpfaenger, holeOderErstelleThread, adminSichtbarkeiten, markiereThreadGelesen, ungeleseneProBestellung, ladeSichtbareBestellIds, ladeThreadVerlauf, fuegeNachrichtHinzu, baueNachrichtMailHtml, replyToToken, betreffMitToken, ensureThreadToken, bestellMailThreadToken, extrahiereThreadToken, bereinigeEmailText, parseBestellReferenz, findeBestellungFuerReferenz, findeKundeFuerTelegram, speichereTelegramKanal, holeOderErstelleThreadFuerBestellung, vorgangEreignis, vorgangEreignisPA, holeOderErstelleThreadFuerPreisanfrage, holeOderErstelleAllgemeinenThread, ladeTelegramDatei, kundenZielEmail, dispatchKundenantwort } = require('./services/vorgang');
// Fehler-Monitoring (Paket 5): dependency-freier Sentry-Mini-Client. Inaktiv ohne
// SENTRY_DSN. captureException wird als 5xx-Reporter in sendError injiziert; damit
// landen alle echten Serverfehler (auch aus dem Fallback-Handler unten) in Sentry.
const sentry = require('./lib/sentry');
sentry.init({ dsn: process.env.SENTRY_DSN, release: process.env.RAILWAY_GIT_COMMIT_SHA });
setErrorReporter((err) => sentry.captureException(err));

const app = express();
const PORT = process.env.PORT || 3000;

// Railway/Vercel/Proxy: echte Client-IP für Rate-Limiting korrekt auswerten
app.set('trust proxy', 1);

// Security-Header (nur API/JSON, kein HTML-Ausliefern → CSP unkritisch).
// crossOriginResourcePolicy gelockert, da das Frontend von einer anderen Origin (Vercel) lädt.
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));

// Antworten (JSON, PDFs) transparent gzip-komprimieren – spürbar kleinere
// Payloads für Bestelllisten, Threads und PDF-Downloads.
app.use(compression());

// -----------------------------------------------------------------------------
// Grundeinstellungen
// -----------------------------------------------------------------------------

const DEFAULT_ALLOWED_ORIGINS = [
  'https://visiotrade.shop',
  'https://www.visiotrade.shop',
  'https://visiotrade-shop.vercel.app',
  'http://localhost:3000'
];

// Defaults + optionale Zusatz-Origins aus ENV ZUSAMMENFÜHREN (nicht ersetzen),
// damit ein gesetztes ALLOWED_ORIGINS die Produktiv-Domains nicht versehentlich
// verdrängt – genau der Fehler, der die Lieferkosten auf visiotrade.shop lahmlegte.
const ALLOWED_ORIGINS = [
  ...DEFAULT_ALLOWED_ORIGINS,
  ...String(process.env.ALLOWED_ORIGINS || '').split(',')
]
  .map(origin => origin.trim())
  .filter(Boolean);

function isAllowedOrigin(origin) {
  if (!origin) return true;
  return ALLOWED_ORIGINS.includes(origin);
}

app.use(cors({
  origin(origin, callback) {
    if (isAllowedOrigin(origin)) {
      return callback(null, true);
    }
    // Unerlaubte Origin sauber ablehnen (kein 500): der Browser erhält einfach
    // keinen Access-Control-Allow-Origin-Header und blockt selbst.
    console.warn('⚠️ CORS blockiert Origin:', origin);
    return callback(null, false);
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Stripe-Signature']
}));

// Stripe-Webhook MUSS vor express.json() stehen
app.post('/webhook/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  let event;

  try {
    const signature = req.headers['stripe-signature'];

    if (!process.env.STRIPE_WEBHOOK_SECRET) {
      console.error('❌ STRIPE_WEBHOOK_SECRET fehlt in .env');
      return res.status(500).send('Stripe webhook secret missing');
    }

    event = stripe.webhooks.constructEvent(
      req.body,
      signature,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('❌ Stripe Webhook Signatur ungültig:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  console.log(`✅ Stripe Webhook empfangen: ${event.type}`);

  try {
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      const bestellungId = Number.parseInt(session.metadata?.bestellung_id, 10);

      if (!Number.isInteger(bestellungId)) {
        console.error('❌ Stripe Webhook ohne gültige bestellung_id:', session.metadata);
        return res.status(400).json({ error: 'Ungültige bestellung_id' });
      }

      const bestellung = await ladeBestellung(bestellungId);
      const positionen = await ladePositionen(bestellungId);
      const { lieferkostenNetto } = ermittleNettoBetraege(bestellung);

      // Erwarteten Betrag aus EXAKT denselben Line-Items berechnen, die an Stripe
      // gesendet wurden. centsFromNet(gesamtNetto) würde die Gesamtsumme runden,
      // Stripe summiert aber pro Position gerundete Cent-Beträge — das kann bei
      // mehreren Positionen um 1 Cent abweichen und eine echte Zahlung fälschlich
      // als Betrugsversuch ablehnen.
      const expectedLineItems = buildStripeLineItemsFromPositionen(
        positionen,
        lieferkostenNetto,
        bestellungId
      );
      const expectedAmountTotal = expectedLineItems.reduce(
        (sum, li) => sum + li.price_data.unit_amount * li.quantity,
        0
      );

      if (Number.isFinite(session.amount_total) && session.amount_total !== expectedAmountTotal) {
        // PERMANENTER Fehler (manipulierter/abweichender Betrag): ein erneuter
        // Webhook-Versuch würde exakt dasselbe Ergebnis liefern. Darum NICHT 500
        // (das löst tagelange Stripe-Retries aus), sondern loggen, Admin per
        // Telegram alarmieren und mit 200 quittieren – Stripe stoppt die Retries
        // nur bei einer 2xx-Antwort (auch 4xx würde weiter retryt).
        console.error(
          `🚨 Stripe Betrag stimmt nicht (Bestellung ${bestellungId}): erwartet ${expectedAmountTotal} Cent, erhalten ${session.amount_total} Cent – KEINE Abwicklung.`
        );
        try {
          const adminId = process.env.ADMIN_TELEGRAM_ID || process.env.TELEGRAM_ADMIN_ID;
          if (adminId) {
            await sendeTelegram(
              adminId,
              `🚨 <b>Stripe-Betragsabweichung</b>\nBestellung #${bestellungId} wurde <b>NICHT</b> abgewickelt.\nErwartet: ${(expectedAmountTotal / 100).toFixed(2)} €\nErhalten: ${(session.amount_total / 100).toFixed(2)} €\nBitte manuell prüfen (mögliche Manipulation).`
            );
          }
        } catch (_) {}
        return res.status(200).json({ received: true, ignored: 'amount_mismatch' });
      }

      await bestellungAbwickeln(bestellungId, session.payment_intent || session.id);
    }

    return res.json({ received: true });
  } catch (err) {
    console.error('❌ Fehler im Stripe Webhook:', err);
    return res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// Body-Limits gezielt: Nur Routen, die base64-Anhänge (Reklamations-/Nachrichten-
// Fotos, Lager-Chat-Bilder) oder eingehende E-Mails empfangen, dürfen große Bodies
// (15 MB) haben. Alles andere wird auf 200 KB begrenzt – DoS-Schutz gegen
// aufgeblähte JSON-Bodies auf normalen API-Routen.
const jsonGross = express.json({ limit: '15mb' });
app.use('/api/b2b/bestellungen', jsonGross);   // Bestell-Thread: Nachricht + Fotos
app.use('/api/b2b/preisanfragen', jsonGross);  // Preisanfrage-Thread: Nachricht + Fotos
app.use('/api/admin/threads', jsonGross);      // Admin-Antwort im Thread + Fotos
app.use('/api/admin/lager', jsonGross);        // Interner Lager-Chat: Notiz + Fotos
app.use('/api/inbound/email', jsonGross);      // Eingehende E-Mail (Brevo-Webhook)
app.use(express.json({ limit: '200kb' }));

// -----------------------------------------------------------------------------
// Rate-Limiting / Reservierungseinstellungen
// -----------------------------------------------------------------------------

const RESERVIERUNG_TAGE = Number.parseInt(process.env.RESERVIERUNG_TAGE || '3', 10);

// Vorkasse: kurze Reservierungsfrist. Geht in dieser Zeit kein Zahlungseingang
// ein, wird die Bestellung automatisch storniert (siehe storniereAbgelaufeneVorkasseBestellungen).
const RESERVIERUNG_VORKASSE_STUNDEN = Number.parseInt(process.env.RESERVIERUNG_VORKASSE_STUNDEN || '8', 10);

// Wie oft der Auto-Storno-Lauf abgelaufene Vorkasse-Bestellungen prüft (in Minuten).
const STORNO_CHECK_MINUTEN = Number.parseInt(process.env.STORNO_CHECK_MINUTEN || '15', 10);

function berechneReserviertBis() {
  const tage = Number.isInteger(RESERVIERUNG_TAGE) && RESERVIERUNG_TAGE > 0 ? RESERVIERUNG_TAGE : 3;
  return new Date(Date.now() + tage * 24 * 60 * 60 * 1000).toISOString();
}

function berechneReserviertBisVorkasse() {
  const std = Number.isInteger(RESERVIERUNG_VORKASSE_STUNDEN) && RESERVIERUNG_VORKASSE_STUNDEN > 0
    ? RESERVIERUNG_VORKASSE_STUNDEN
    : 8;
  return new Date(Date.now() + std * 60 * 60 * 1000).toISOString();
}

// RESERVIERUNG_CHECKOUT_MINUTEN + berechneReserviertBisCheckout nach services/payments.js (Phase 4, Commit 9).

// -----------------------------------------------------------------------------
// Rate-Limiting für offene API-Endpunkte
// -----------------------------------------------------------------------------

const paymentLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Zu viele Zahlungsanfragen. Bitte versuchen Sie es später erneut.'
  }
});

const strictOrderLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Zu viele Bestellanfragen. Bitte warten Sie einige Minuten.'
  }
});

app.use('/api/stripe/create-session', paymentLimiter);
app.use('/api/paypal/create-order', paymentLimiter);
app.use('/api/paypal/capture', paymentLimiter);
app.use('/api/vorkasse/bestellen', strictOrderLimiter);
app.use('/api/vorkasse/stornieren', strictOrderLimiter);
app.use('/api/admin/vorkasse/zahlung-erhalten', paymentLimiter);
app.use('/api/admin/vorkasse/stornieren', paymentLimiter);
app.use('/api/admin/reservierungen/freigeben', paymentLimiter);

// -----------------------------------------------------------------------------
// Hilfsfunktionen
// -----------------------------------------------------------------------------

// escapeHtml + centsFromNet nach lib/utils.js verschoben (Paket 4). Import siehe oben.

// HTML-Block mit der tatsächlichen Lieferadresse für Auftragsbestätigungen.
function lieferadresseEmailBlock(b) {
  if (String(b.lieferart || '').toLowerCase() !== 'lieferung') return '';
  const strasse = b.lieferadresse_strasse || b.rechnungsadresse_strasse;
  const plz = b.lieferadresse_plz || b.rechnungsadresse_plz;
  const ort = b.lieferadresse_ort || b.rechnungsadresse_ort;
  const land = b.lieferadresse_land || b.rechnungsadresse_land || 'DE';
  if (!strasse && !plz && !ort) return '';
  const empfaenger = b.lieferadresse_empfaenger || b.firma || b.kundenname;
  const zeilen = [
    empfaenger ? 'Empfänger: ' + empfaenger : '',
    strasse,
    [plz, ort].filter(Boolean).join(' '),
    land,
    b.lieferadresse_telefon ? 'Telefon vor Ort: ' + b.lieferadresse_telefon : ''
  ].filter(Boolean).map(escapeHtml).join('<br>');
  return `<div style="background:#F5EDD8;border-radius:8px;padding:12px 14px;margin:12px 0;">
            <div style="font-weight:bold;color:#3D2B1F;margin-bottom:4px;">📦 Lieferadresse</div>
            <div style="font-size:14px;color:#3D2B1F;line-height:1.6;">${zeilen}</div>
          </div>`;
}

// readResponseBuffer nach lib/utils.js verschoben (Paket 4). Import siehe oben.

// zahlungsartLabel nach lib/utils.js verschoben (Phase 4, Commit 8). Import oben.

// Serverseitiger Frachtrechner (BOLL/Raben) inkl. ermittleLieferPlz nach
// services/fracht.js verschoben (Phase 4, Commit 2). Import siehe oben.
// Preis-/Bestellwert-Berechnung (berechneUndFixiere…, ermittleSendungsdaten,
// ermittleNettoBetraege, buildStripeLineItems) nach services/pricing.js verschoben
// (Phase 4, Commit 5). Import siehe oben.


// -----------------------------------------------------------------------------
// E-Mail / Telegram
// -----------------------------------------------------------------------------

// sendeEmail + sendeMehrfachEmail (Brevo-Transport) nach services/email.js
// verschoben (Phase 4, Commit 3). Import siehe oben. Telegram bleibt hier.


// sendeTelegram + sendeAdminBenachrichtigung nach services/telegram.js verschoben (Phase 4, Commit 10). Import oben.

// -----------------------------------------------------------------------------
// Lexoffice-Rechnungserstellung (baueLexofficePositionen, erstelleLexofficeRechnung) nach
// services/lexoffice.js verschoben (Phase 4, Commit 6). Import siehe oben.
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// Rechnungs-PDF: Supabase Storage + Lexoffice-Nachladen (für In-App-Vorschau)
// -----------------------------------------------------------------------------
// RECHNUNG_BUCKET + Storage-Helfer liegen in services/pdf.js (Phase 4, Commit 4).

// holeLexofficePdf/VoucherNumber + backfillRechnungNummer nach services/lexoffice.js (Phase 4, Commit 6). Import oben.

// Storage-Helfer + markiereAlsKopie nach services/pdf.js verschoben (Phase 4, Commit 4). Import oben.

// Versendet eine KOPIE der bestehenden Rechnung (keine neue Rechnung, gleiche Nummer/Datum).
async function versendeRechnungsKopie(bestellungId) {
  const bestellung = await ladeBestellung(bestellungId);
  let pdf = null;
  if (bestellung.rechnung_pdf_storage_path) pdf = await ladePdfAusStorage(bestellung.rechnung_pdf_storage_path);
  if (!pdf && bestellung.lexoffice_id && process.env.LEXOFFICE_API_KEY) {
    pdf = await holeLexofficePdf(bestellung.lexoffice_id);
    if (pdf) {
      try {
        const p = `rechnung-${bestellungId}.pdf`;
        await speicherePdfInStorage(p, pdf);
        const patch = { rechnung_pdf_storage_path: p, rechnung_pdf_gespeichert_am: new Date().toISOString() };
        if (!bestellung.rechnung_nummer) { const vn = await holeLexofficeVoucherNumber(bestellung.lexoffice_id); if (vn) patch.rechnung_nummer = vn; }
        await supabaseUpdate('bestellungen', bestellungId, patch);
      } catch (_) {}
    }
  }
  if (!pdf) { const e = new Error('Für diese Bestellung ist noch keine Rechnung als PDF vorhanden.'); e.statusCode = 400; throw e; }

  const kopie = await markiereAlsKopie(pdf);
  const reNr = bestellung.rechnung_nummer ? ` Rechnungsnr.: ${escapeHtml(bestellung.rechnung_nummer)}.` : '';
  const html = `
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
      <div style="background:#3D2B1F;padding:20px;text-align:center;"><h1 style="color:#C49A2B;font-family:Georgia,serif;margin:0;">VisioTrade</h1></div>
      <div style="padding:30px;background:#FAF7F2;">
        <h2 style="color:#3D2B1F;">Kopie Ihrer Rechnung</h2>
        <p>Sehr geehrte/r ${escapeHtml(bestellung.kundenname)},</p>
        <p>auf Kundenwunsch erhalten Sie anbei eine <strong>Kopie der Rechnung</strong> zu Ihrer Bestellung <strong>#${bestellungId}</strong>.${reNr}</p>
        <p style="color:#6B7280;font-size:13px;">Es wurde keine neue Rechnung erstellt – Rechnungsnummer und -datum bleiben unverändert. Die beigefügte PDF ist als „RECHNUNGSKOPIE" gekennzeichnet.</p>
        <p style="color:#6B7280;font-size:13px;margin-top:20px;">VisioTrade GmbH</p>
      </div>
    </div>`;
  await sendeBestellEmail(bestellung, `Kopie Ihrer Rechnung zu Bestellung #${bestellungId} | VisioTrade`, html, kopie);
  return { ok: true };
}

// FIRMA (PDF-Stammdaten) + erzeugeProfiPdf nach services/pdf.js verschoben
// (Phase 4, Commit 8). Import siehe oben.

// Zugriffsprüfung für Bestell-Dokumente (Admin / Kunde-Firma / Mitarbeiter eigene).
async function bestellungZugriffErlaubt(user, bestellung) {
  const admin = await ladeAdmin(user.email);
  if (admin && admin.aktiv !== false) {
    return istLegacyAdmin(admin) || admin.ist_super_admin === true || admin._perms.has('orders.view_invoice_pdf');
  }
  const ctx = await ladeKundenprofilFuerAuthUser(user);
  const istEigene = String(bestellung.user_id || '') === String(user.id)
    || (normalizeEmail(bestellung.bestellt_von_email) && normalizeEmail(bestellung.bestellt_von_email) === normalizeEmail(user.email))
    || (normalizeEmail(bestellung.email) && normalizeEmail(bestellung.email) === normalizeEmail(user.email));
  const istFirma = ctx?.profil && bestellung.kundenprofil_id === ctx.profil.id;
  return (ctx?.mitglied?.rolle === 'einkaufsleiter') ? !!istFirma : !!istEigene;
}

// -----------------------------------------------------------------------------
// Bestellabwicklung
// -----------------------------------------------------------------------------

// Lagerbestand & Reservierungen (reduziere/reserviere/verbrauche/gebe*Frei,
// _bulkNichtVerfuegbar, istBestandsFehler) nach services/stock.js verschoben
// (Phase 4, Commit 7). Import siehe oben.

const LAGER_EMAIL = process.env.LAGER_EMAIL || 'lager@visiotrade.shop';

// Auftragsbestätigung-E-Mail (KEINE Rechnung) – nach Zahlungseingang an den Kunden.
function auftragsbestaetigungEmailHtml(b) {
  const { gesamtNetto, lieferkostenNetto, warenwertNetto } = ermittleNettoBetraege(b);
  return `
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
      <div style="background:#3D2B1F;padding:20px;text-align:center;">
        <h1 style="color:#C49A2B;font-family:Georgia,serif;margin:0;">VisioTrade</h1>
        <p style="color:white;margin:5px 0 0;">Premium Parkett</p>
      </div>
      <div style="padding:30px;background:#FAF7F2;">
        <h2 style="color:#3D2B1F;">Auftragsbestätigung</h2>
        <p>Sehr geehrte/r ${escapeHtml(b.kundenname)},</p>
        <p>vielen Dank. Wir haben Ihre Zahlung zur Bestellung <strong>#${b.id}</strong> erhalten und Ihren Auftrag bestätigt. Ihre Bestellung wird nun für den Versand vorbereitet.</p>
        <table style="width:100%;border-collapse:collapse;margin:20px 0;">
          <tr style="background:#F5EDD8;"><td style="padding:10px;font-weight:bold;">Bestellnummer</td><td style="padding:10px;">#${b.id}</td></tr>
          ${b.filiale ? `<tr><td style="padding:10px;font-weight:bold;">Filiale</td><td style="padding:10px;">${escapeHtml(b.filiale)}</td></tr>` : ''}
          <tr><td style="padding:10px;font-weight:bold;">Warenwert netto</td><td style="padding:10px;">${euro(warenwertNetto)}</td></tr>
          <tr style="background:#F5EDD8;"><td style="padding:10px;font-weight:bold;">Lieferkosten netto</td><td style="padding:10px;">${lieferkostenNetto > 0 ? euro(lieferkostenNetto) : '0,00 €'}</td></tr>
          <tr><td style="padding:10px;font-weight:bold;">Umsatzsteuer 19 %</td><td style="padding:10px;">${euro(gesamtNetto * 0.19)}</td></tr>
          <tr style="background:#F5EDD8;"><td style="padding:10px;font-weight:bold;">Gesamtbetrag brutto</td><td style="padding:10px;font-weight:bold;color:#8B6914;">${euro(gesamtNetto * 1.19)}</td></tr>
        </table>
        ${bestellerHinweisBlock(b)}
        ${lieferadresseEmailBlock(b)}
        <div style="background:#FFF4D6;border:1px solid #E0C36B;border-radius:8px;padding:14px 16px;margin:12px 0;">
          <p style="margin:0;color:#6B4E00;font-size:14px;"><strong>${lieferzeitHinweisFuerBestellung(b)}</strong></p>
        </div>
        <p style="color:#6B7280;font-size:13px;">Die offizielle Rechnung erhalten Sie separat, sobald die Ware an die Spedition übergeben wurde.</p>
        <p style="color:#6B7280;font-size:13px;margin-top:20px;">Bei Fragen stehen wir Ihnen gerne zur Verfügung.<br>VisioTrade GmbH</p>
      </div>
    </div>`;
}

// Lieferschein/Kommissionierschein fürs Lager (ohne Preise).
function lieferscheinEmailHtml(b, positionen) {
  const empf = b.lieferadresse_empfaenger || b.firma || b.kundenname || '';
  const liefStr = b.lieferadresse_strasse || b.rechnungsadresse_strasse || '';
  const liefPlz = b.lieferadresse_plz || b.rechnungsadresse_plz || '';
  const liefOrt = b.lieferadresse_ort || b.rechnungsadresse_ort || '';
  const liefLand = b.lieferadresse_land || b.rechnungsadresse_land || 'DE';
  const tel = b.lieferadresse_telefon || b.telefon || '';
  const posRows = (positionen || []).map(p => `
    <tr style="border-top:1px solid #ddd;">
      <td style="padding:8px;">${escapeHtml(p.produktname || 'Parkett')}</td>
      <td style="padding:8px;">${toNumber(p.menge_m2_gesamt, 0).toFixed(2)} m²</td>
      <td style="padding:8px;">${p.anzahl_pakete || 0} Paket(e)</td>
      <td style="padding:8px;">${p.bauvorhaben ? escapeHtml(p.bauvorhaben) : '—'}</td>
    </tr>`).join('');
  return `
    <div style="font-family:Arial,sans-serif;max-width:640px;margin:0 auto;">
      <div style="background:#3D2B1F;padding:16px;text-align:center;">
        <h1 style="color:#C49A2B;font-family:Georgia,serif;margin:0;">VisioTrade · Lieferschein</h1>
      </div>
      <div style="padding:24px;background:#fff;color:#222;">
        <h2 style="margin:0 0 6px;">Kommissionierschein – Bestellung #${b.id}</h2>
        <p style="color:#666;margin:0 0 16px;">Bestelldatum: ${b.erstellt_am ? new Date(b.erstellt_am).toLocaleDateString('de-DE') : '—'} · Lieferart: <strong>${escapeHtml(b.lieferart || '—')}</strong>${b.lieferkosten_spediteur ? ' · Spediteur: <strong>' + escapeHtml(b.lieferkosten_spediteur) + '</strong>' : ''}${b.filiale ? ' · Filiale: <strong>' + escapeHtml(b.filiale) + '</strong>' : ''}</p>
        <div style="background:#F5EDD8;border-radius:8px;padding:14px;margin-bottom:16px;">
          <strong>Lieferadresse / Empfänger</strong><br>
          ${escapeHtml(empf)}<br>${escapeHtml(liefStr)}<br>${escapeHtml(liefPlz)} ${escapeHtml(liefOrt)}<br>${escapeHtml(liefLand)}
          ${tel ? '<br>Telefon vor Ort: ' + escapeHtml(tel) : ''}
        </div>
        <table style="width:100%;border-collapse:collapse;font-size:14px;">
          <thead><tr style="background:#F5EDD8;text-align:left;"><th style="padding:8px;">Material</th><th style="padding:8px;">Menge</th><th style="padding:8px;">Pakete</th><th style="padding:8px;">BV / Bauvorhaben</th></tr></thead>
          <tbody>${posRows || '<tr><td colspan="4" style="padding:8px;">Keine Positionen</td></tr>'}</tbody>
        </table>
        <p style="color:#666;font-size:13px;margin-top:18px;">Dieser Lieferschein enthält bewusst keine Preisangaben.</p>
      </div>
    </div>`;
}

// Eine Bestellung ist lagerfähig, wenn entweder bereits bezahlt wurde oder ein
// serverseitig freigeschalteter Rechnungskauf vorliegt. Der technische Status
// `auf_rechnung` bleibt bewusst erhalten: Es ist noch keine Zahlung eingegangen.
function istLagerfaehig(bestellung) {
  const status = String(bestellung && bestellung.status || '');
  const zahlungsart = String(bestellung && bestellung.zahlungsart || '');
  return status === 'bezahlt' || (status === 'auf_rechnung' && zahlungsart === 'rechnung');
}

function assertLagerfaehig(bestellung, aktion = 'Diese Aktion') {
  if (istLagerfaehig(bestellung)) return;
  const err = new Error(`${aktion} ist nur für bezahlte Bestellungen oder freigegebene Rechnungskäufe möglich.`);
  err.statusCode = 400;
  throw err;
}

// Erzeugt den preislosen Lieferschein, speichert ihn im privaten Storage und
// hängt genau dieses PDF an die Lager-Mail. Kein Rechnungsname und keine Preise.
async function sendeLieferscheinAnsLager(bestellungId, bestellung, positionen) {
  if (bestellung.lieferschein_versendet_am) {
    return { already: true, patch: {} };
  }

  const pdf = await erzeugeProfiPdf('Lieferschein', bestellung, positionen, false);
  const path = bestellung.lieferschein_pdf_path || `lieferschein-${bestellungId}.pdf`;
  await speicherePdfInStorage(path, pdf);

  const token = await bestellMailThreadToken(bestellung);
  await sendeEmail(
    LAGER_EMAIL,
    betreffMitToken(`Lieferschein – Bestellung #${bestellungId}`, token),
    lieferscheinEmailHtml(bestellung, positionen),
    pdf,
    `Lieferschein_${bestellungId}.pdf`,
    replyToToken(token)
  );

  const jetzt = new Date().toISOString();
  return {
    already: false,
    patch: {
      lieferschein_pdf_path: path,
      lieferschein_versendet_am: jetzt,
      lieferschein_erstellt_am: jetzt
    }
  };
}

// Nach Zahlungseingang: Auftragsbestätigung an Kunde + Lieferschein ans Lager.
// Idempotent – versendet nichts doppelt. KEINE Rechnung.
async function nachZahlungAuftragUndLieferschein(bestellungId, bestellung, positionen) {
  const patch = {};
  if (!bestellung.auftragsbestaetigung_versendet_am) {
    try {
      // AB-PDF erzeugen und anhängen (soll IMMER mit der Auftragsbestätigung kommen).
      let abPdf = null;
      try {
        abPdf = await erzeugeProfiPdf('Auftragsbestätigung', bestellung, positionen, true);
      } catch (e) {
        console.warn('⚠️ AB-PDF konnte nicht erzeugt werden, sende ohne Anhang:', e.message);
      }
      const _abToken = await bestellMailThreadToken(bestellung);
      await sendeBestellEmail(
        bestellung,
        betreffMitToken(`Auftragsbestätigung zu Bestellung #${bestellungId} | VisioTrade`, _abToken),
        auftragsbestaetigungEmailHtml(bestellung),
        abPdf,
        `Auftragsbestaetigung_${bestellungId}.pdf`,
        replyToToken(_abToken)
      );
      patch.auftragsbestaetigung_versendet_am = new Date().toISOString();
      patch.auftragsbestaetigung_erstellt_am = patch.auftragsbestaetigung_versendet_am;
    } catch (e) { console.error('❌ Auftragsbestätigung E-Mail:', e.message); }
  }
  if (!bestellung.lieferschein_versendet_am) {
    try {
      const lieferschein = await sendeLieferscheinAnsLager(bestellungId, bestellung, positionen);
      Object.assign(patch, lieferschein.patch);
    } catch (e) { console.error('❌ Lieferschein E-Mail:', e.message); }
  }
  if (!bestellung.lager_status) patch.lager_status = 'in_bearbeitung';
  if (Object.keys(patch).length) {
    try { await supabaseUpdate('bestellungen', bestellungId, patch); } catch (e) { console.warn('⚠️ Workflow-Status speichern:', e.message); }
  }
  // Vorgangscenter (bezahlte Wege: Stripe/PayPal + Vorkasse-Geldeingang). Alles idempotent.
  await vorgangEreignis(bestellung, 'bestellung_eingegangen', { text: 'Bestellung erfolgreich aufgenommen.', meta: { betrag: bestellung.gesamtbetrag } });
  await vorgangEreignis(bestellung, 'bezahlt', { text: 'Zahlung eingegangen.', meta: { betrag: bestellung.gesamtbetrag } });
  await vorgangEreignis(bestellung, 'auftrag_bestaetigt', { text: 'Auftragsbestätigung erstellt.', meta: { dok_typ: 'auftragsbestaetigung' } });
}

// Rechnung erst nach Übergabe an Spedition: Lexoffice-Rechnung + E-Mail. Idempotent.
async function erstelleUndVersendeRechnung(bestellungId, { force = false, mailSubject = null, mailHeading = null, mailIntroHtml = null } = {}) {
  const bestellung = await ladeBestellung(bestellungId);
  if (!force && (bestellung.rechnung_versendet_am || bestellung.lexoffice_id)) {
    return { already: true, lexoffice_id: bestellung.lexoffice_id || null };
  }
  const positionen = await ladePositionen(bestellungId);
  const bestellungBezahlt = { ...bestellung, status: 'bezahlt' };
  let lexofficeId = bestellung.lexoffice_id || null;
  let rechnungNummer = bestellung.rechnung_nummer || null;
  let pdfBuffer = null;
  let rechnungFehler = null;
  if (process.env.LEXOFFICE_API_KEY && !lexofficeId) {
    // Atomarer Claim gegen Doppelrechnung (Audit S2-02): Zwischen der Prüfung oben und dem
    // Schreiben der lexoffice_id liegen ~10 s (Lexoffice-Create + PDF-Download + Mailversand).
    // Ohne Claim erzeugen zwei parallele Läufe (Doppelklick auf „versenden") ZWEI finalisierte
    // Rechnungen mit zwei fortlaufenden Nummern für dieselbe Bestellung – steuerlich stornopflichtig.
    // Gleiches Muster wie der Claim in bestellungAbwickeln. Bei force=true übersprungen, weil das
    // eine bewusste Admin-Wiederholung ist (z. B. nach einem fehlgeschlagenen Versuch).
    if (!force) {
      const beansprucht = await supabasePatchWhere(
        'bestellungen',
        `?id=eq.${encodeURIComponent(bestellungId)}&rechnung_erstellt_am=is.null`,
        { rechnung_erstellt_am: new Date().toISOString() }
      );
      if (!Array.isArray(beansprucht) || beansprucht.length === 0) {
        console.log(`ℹ️ Rechnung für Bestellung ${bestellungId} wird bereits parallel erstellt. Überspringe.`);
        const aktuell = await ladeBestellung(bestellungId);
        return { already: true, lexoffice_id: aktuell.lexoffice_id || null, rechnung_nummer: aktuell.rechnung_nummer || null };
      }
    }
    try {
      const lexResult = await erstelleLexofficeRechnung(bestellungBezahlt, positionen);
      if (lexResult && lexResult.id) {
        lexofficeId = lexResult.id;
        pdfBuffer = lexResult.pdfBuffer;
        rechnungNummer = lexResult.voucherNumber || rechnungNummer;
      } else {
        rechnungFehler = 'Lexoffice hat keine Rechnung zurückgegeben';
      }
    } catch (e) {
      rechnungFehler = e.message || String(e);
    }

    if (rechnungFehler) {
      // Claim wieder freigeben, sonst wäre die Bestellung dauerhaft für einen erneuten
      // Versuch gesperrt (Audit S2-01: Ware raus, aber kein Beleg – §14 UStG / GoBD).
      // Der Filter lexoffice_id=is.null verhindert, dass ein parallel erfolgreicher Lauf
      // versehentlich zurückgesetzt wird.
      try {
        await supabasePatchWhere(
          'bestellungen',
          `?id=eq.${encodeURIComponent(bestellungId)}&lexoffice_id=is.null`,
          { rechnung_erstellt_am: null }
        );
      } catch (_) {}
      console.error(`🚨 Rechnungserstellung für Bestellung ${bestellungId} fehlgeschlagen:`, rechnungFehler);
      try {
        const adminId = process.env.ADMIN_TELEGRAM_ID || process.env.TELEGRAM_ADMIN_ID;
        if (adminId) {
          await sendeTelegram(
            adminId,
            `🚨 <b>Rechnung NICHT erstellt</b>\nBestellung #${bestellungId}: Lexoffice-Rechnung fehlgeschlagen (${escapeHtml(String(rechnungFehler))}).\nDie Ware wurde ggf. bereits übergeben – es existiert KEIN Beleg. Bitte manuell nachholen (Admin → Rechnung erneut senden).`
          );
        }
      } catch (_) {}
    }
  }
  const { gesamtNetto, lieferkostenNetto, warenwertNetto } = ermittleNettoBetraege(bestellungBezahlt);
  const istAbholung = String(bestellung.lieferart || '') === 'abholung';
  const emailHtml = `
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
      <div style="background:#3D2B1F;padding:20px;text-align:center;"><h1 style="color:#C49A2B;font-family:Georgia,serif;margin:0;">VisioTrade</h1></div>
      <div style="padding:30px;background:#FAF7F2;">
        <h2 style="color:#3D2B1F;">${mailHeading || 'Ihre Rechnung'}</h2>
        <p>Sehr geehrte/r ${escapeHtml(bestellung.kundenname)},</p>
        ${mailIntroHtml || `<p>Ihre Bestellung <strong>#${bestellungId}</strong> wurde an die Spedition übergeben. Anbei Ihre Rechnung.</p>`}
        <table style="width:100%;border-collapse:collapse;margin:20px 0;">
          <tr style="background:#F5EDD8;"><td style="padding:10px;font-weight:bold;">Warenwert netto</td><td style="padding:10px;">${euro(warenwertNetto)}</td></tr>
          ${istAbholung ? '' : `<tr><td style="padding:10px;font-weight:bold;">Lieferkosten netto</td><td style="padding:10px;">${lieferkostenNetto > 0 ? euro(lieferkostenNetto) : '0,00 €'}</td></tr>`}
          <tr style="background:#F5EDD8;"><td style="padding:10px;font-weight:bold;">Umsatzsteuer 19 %</td><td style="padding:10px;">${euro(gesamtNetto * 0.19)}</td></tr>
          <tr><td style="padding:10px;font-weight:bold;">Gesamtbetrag brutto</td><td style="padding:10px;font-weight:bold;color:#8B6914;">${euro(gesamtNetto * 1.19)}</td></tr>
        </table>
        ${(pdfBuffer && !mailIntroHtml) ? '<p>Ihre Rechnung finden Sie im Anhang dieser E-Mail.</p>' : ''}
        ${rechnungFehler ? '<p style="color:#8B6914;"><strong>Hinweis:</strong> Ihre Rechnung wird Ihnen in Kürze separat per E-Mail zugestellt.</p>' : ''}
        ${bestellerHinweisBlock(bestellungBezahlt)}
        ${lieferadresseEmailBlock(bestellungBezahlt)}
        <p style="color:#6B7280;font-size:13px;margin-top:20px;">VisioTrade GmbH</p>
      </div>
    </div>`;
  await sendeBestellEmail(bestellungBezahlt, mailSubject || `Rechnung zu Bestellung #${bestellungId} | VisioTrade`, emailHtml, pdfBuffer);

  // PDF dauerhaft im Storage ablegen (für die In-App-Vorschau).
  let storagePath = bestellung.rechnung_pdf_storage_path || null;
  if (pdfBuffer && !storagePath) {
    try {
      storagePath = `rechnung-${bestellungId}.pdf`;
      await speicherePdfInStorage(storagePath, pdfBuffer);
    } catch (e) { console.error('❌ Rechnung in Storage speichern:', e.message); storagePath = null; }
  }

  const jetzt = new Date().toISOString();
  // WICHTIG (Audit S2-01): `rechnung_versendet_am` NUR setzen, wenn tatsächlich eine Rechnung
  // existiert. Sonst würde der Idempotenz-Schutz oben jeden weiteren Versuch blockieren –
  // Ergebnis: Ware ausgeliefert, Kunde hat eine Mail, in Lexoffice existiert KEIN Beleg,
  // und es wird nie nachgeholt. Bei Fehler bleibt die Bestellung wiederholbar.
  if (rechnungFehler) {
    return {
      already: false,
      lexoffice_id: null,
      rechnung_nummer: null,
      rechnung_fehler: rechnungFehler
    };
  }
  await supabaseUpdate('bestellungen', bestellungId, {
    lexoffice_id: lexofficeId,
    ...(rechnungNummer ? { rechnung_nummer: rechnungNummer } : {}),
    rechnung_erstellt_am: bestellung.rechnung_erstellt_am || jetzt,
    rechnung_versendet_am: jetzt,
    ...(storagePath ? { rechnung_pdf_storage_path: storagePath, rechnung_pdf_gespeichert_am: jetzt } : {})
  });
  return { already: false, lexoffice_id: lexofficeId, rechnung_nummer: rechnungNummer };
}

async function bestellungAbwickeln(bestellungId, zahlungsId) {
  console.log(`🔄 Starte Abwicklung für Bestellung ${bestellungId}`);

  try {
    const bestellung = await ladeBestellung(bestellungId);

    if (bestellung.status === 'bezahlt') {
      console.log(`ℹ️ Bestellung ${bestellungId} ist bereits bezahlt/abgewickelt. Überspringe.`);
      return;
    }

    let positionen = await ladePositionen(bestellungId);

    // Falls eine ältere/offene Bestellung noch keine serverseitig fixierten Summen hat,
    // vor der Abwicklung einmal sicher nachberechnen.
    let bestellungFuerAbwicklung = bestellung;
    if (toNumber(bestellung.gesamtbetrag, 0) <= 0 || toNumber(bestellung.warenwert_netto, 0) <= 0) {
      const calc = await berechneUndFixiereBestellungServerseitig(bestellungId, {
        pruefeBestand: false,
        fixiere: true
      });
      bestellungFuerAbwicklung = calc.bestellung;
      positionen = calc.positionen;
    }

    // Atomarer Claim: Nur EIN paralleler Lauf darf die Bestellung auf 'bezahlt' setzen.
    // Stripe sendet Webhooks mehrfach (Retries); ohne diesen Schutz könnten zwei Läufe
    // beide passieren und Lager doppelt reduzieren + doppelte Rechnung erstellen.
    // Der Filter status=neq.bezahlt wird von Postgres unter Row-Lock erneut ausgewertet,
    // sodass der zweite Lauf 0 Zeilen erhält. (Kein zahlungs_id-Check, da PayPal die
    // zahlungs_id bereits bei der Order-Erstellung setzt.)
    const beansprucht = await supabasePatchWhere(
      'bestellungen',
      `?id=eq.${encodeURIComponent(bestellungId)}&status=neq.bezahlt&status=neq.storniert`,
      {
        status: 'bezahlt',
        zahlungs_id: zahlungsId,
        bezahlt_am: new Date().toISOString()
      }
    );

    if (!Array.isArray(beansprucht) || beansprucht.length === 0) {
      console.log(`ℹ️ Bestellung ${bestellungId} wurde parallel bereits abgewickelt. Überspringe.`);
      return;
    }

    console.log('✅ Status auf bezahlt gesetzt (atomar beansprucht)');

    // Bestand buchen: Wurde beim Checkout reserviert (Stripe/PayPal), die Reservierung
    // KONSUMIEREN (kein zweites Abziehen → keine Doppelbuchung). Ohne aktive Reservierung
    // (Altbestellung, Reservierung bereits abgelaufen) direkt reduzieren. Scheitert die
    // Buchung (Ware vergriffen), die Abwicklung NICHT abbrechen (sonst 500 → Webhook-
    // Retry-Sturm), sondern Admin per Telegram alarmieren – manuelle Klärung.
    const _resBis = bestellungFuerAbwicklung.reserviert_bis ? new Date(bestellungFuerAbwicklung.reserviert_bis) : null;
    const _hatAktiveReservierung = bestellungFuerAbwicklung.reservierung_status === 'reserved'
      && _resBis && _resBis.getTime() > Date.now();
    try {
      if (_hatAktiveReservierung) {
        await verbraucheBestellReservierungen(bestellungId);
        console.log('✅ Reservierung verbraucht (Bestand gebucht)');
      } else {
        await reduziereLagerbestandAtomar(positionen);
        console.log('✅ Lager atomar reduziert (ohne aktive Reservierung)');
      }
    } catch (lagerErr) {
      console.error(`🚨 Lagerbuchung für bezahlte Bestellung ${bestellungId} fehlgeschlagen:`, lagerErr.message);
      try {
        const adminId = process.env.ADMIN_TELEGRAM_ID || process.env.TELEGRAM_ADMIN_ID;
        if (adminId) {
          await sendeTelegram(
            adminId,
            `🚨 <b>Lagerbuchung fehlgeschlagen</b>\nBezahlte Bestellung #${bestellungId} konnte nicht vom Lager gebucht werden (Ware evtl. vergriffen). Bitte SOFORT manuell prüfen.`
          );
        }
      } catch (_) {}
    }

    const bestellungBezahlt = {
      ...bestellungFuerAbwicklung,
      status: 'bezahlt',
      zahlungs_id: zahlungsId
    };

    // NEU: Zahlung erhalten → Auftragsbestätigung an Kunde + Lieferschein ans Lager.
    // Die Rechnung wird NICHT hier erzeugt, sondern erst bei „An Spedition übergeben".
    await nachZahlungAuftragUndLieferschein(bestellungId, bestellungBezahlt, positionen);

    await sendeAdminBenachrichtigung(bestellungBezahlt);

    console.log(`✅ Bestellung ${bestellungId} vollständig abgewickelt`);
  } catch (err) {
    console.error('❌ Fehler bei Bestellabwicklung:', err);
    throw err;
  }
}

// Audit S2-05: Eine Zahlungssession darf nur für Bestellungen entstehen, die noch bezahlbar sind.
// Ohne diese Prüfung ließ sich für eine STORNIERTE Bestellung eine gültige Stripe-Session bzw.
// PayPal-Order erzeugen. Zahlt der Kunde daraufhin, scheitert der atomare Claim in
// bestellungAbwickeln am Filter status=neq.storniert – die Abwicklung wird still übersprungen.
// Ergebnis: Geld eingezogen, keine Bestellung, kein automatischer Rückerstattungspfad.
// Bei Status 'bezahlt' wäre umgekehrt eine Doppelzahlung möglich.
const BESTELLUNG_ZAHLBAR_STATUS = ['offen', 'warte_auf_zahlung'];
function assertBestellungZahlbar(bestellung) {
  const status = String(bestellung?.status || '');
  if (!BESTELLUNG_ZAHLBAR_STATUS.includes(status)) {
    const err = new Error(`Für diese Bestellung kann keine Zahlung mehr gestartet werden (Status: ${status || 'unbekannt'}).`);
    err.statusCode = 409; // sendError reicht bei 4xx die Meldung an den Client durch
    throw err;
  }
}

// -----------------------------------------------------------------------------
// Stripe
// -----------------------------------------------------------------------------

app.post('/api/stripe/create-session', async (req, res) => {
  try {
    const { bestellung_id } = req.body;

    if (!bestellung_id) {
      return res.status(400).json({
        error: 'bestellung_id fehlt'
      });
    }

    const bestellungVorPruefung = await ladeBestellung(bestellung_id);
    await assertBestellungGehoertZuUser(req, bestellungVorPruefung);
    assertBestellungZahlbar(bestellungVorPruefung);

    // Sicherheit: Preise und Lieferkosten werden serverseitig aus Supabase neu berechnet.
    // Client-Werte wie req.body.items, req.body.netto oder req.body.lieferkosten_netto werden ignoriert.
    const sessionData = await erstelleStripeSessionFuerBestellung(bestellung_id, { gast: false });

    console.log(`✅ Stripe Session erstellt für Bestellung ${bestellung_id} / Serverbetrag brutto: ${euro(sessionData.server_total_brutto)}`);

    return res.json(sessionData);
  } catch (err) {
    console.error('❌ Stripe Error:', err);

    return sendError(res, err);
  }
});

// -----------------------------------------------------------------------------
// PayPal
// -----------------------------------------------------------------------------

// getPayPalToken nach services/payments.js verschoben (Phase 4, Commit 9). Import oben.

app.post('/api/paypal/create-order', async (req, res) => {
  try {
    const { bestellung_id } = req.body;

    if (!bestellung_id) {
      return res.status(400).json({
        error: 'bestellung_id fehlt'
      });
    }

    const bestellungVorPruefung = await ladeBestellung(bestellung_id);
    await assertBestellungGehoertZuUser(req, bestellungVorPruefung);
    assertBestellungZahlbar(bestellungVorPruefung);

    // Sicherheit: Client-Beträge werden ignoriert; der Betrag kommt aus Serverberechnung.
    const orderData = await erstellePayPalOrderFuerBestellung(bestellung_id, { gast: false });

    return res.json(orderData);
  } catch (err) {
    console.error('❌ PayPal Error:', err);

    return sendError(res, err);
  }
});

app.post('/api/paypal/capture/:orderId', async (req, res) => {
  try {
    const { orderId } = req.params;
    const { bestellung_id } = req.body;

    if (!bestellung_id) {
      return res.status(400).json({
        error: 'bestellung_id fehlt'
      });
    }

    const bestellungVorPruefung = await ladeBestellung(bestellung_id);
    const hasAuthHeader = Boolean((req.headers.authorization || '').replace('Bearer ', '').trim());

    // 1) ZUERST Berechtigung: angemeldet über die reguläre Eigentumsprüfung, als Gast nur
    //    für Bestellungen ohne Kundenkonto. Diese Prüfung MUSS vor der Zuordnung stehen,
    //    sonst entsteht ein Orakel: Ein anonymer Aufrufer bekäme bei falschem Order-Paar
    //    eine 400 und bei richtigem Paar einer Konto-Bestellung eine 401 – und könnte
    //    daran ablesen, welche Order-ID zu welcher Bestellung gehört. Für Fremde ist eine
    //    Konto-Bestellung jetzt immer 401, unabhängig vom Order-Paar.
    if (hasAuthHeader) {
      await assertBestellungGehoertZuUser(req, bestellungVorPruefung);
    } else if (bestellungVorPruefung.user_id) {
      return res.status(401).json({
        error: 'PayPal-Zahlung kann ohne Kundenkonto nicht zugeordnet werden.'
      });
    }

    // 2) DANN die PayPal-Zuordnung – für alle zugelassenen Aufrufer gleich, angemeldet wie
    //    Gast, und VOR jedem Status-Kurzweg. Früher stand diese Prüfung nur im Gast-Zweig:
    //    Ein angemeldeter Kunde bekam damit für eine EIGENE, bereits verarbeitete
    //    Vorkasse-Bestellung `capture_status: 'COMPLETED'` – Eigentum war ja gegeben.
    const istPayPalBestellung =
      String(bestellungVorPruefung.zahlungsart) === 'paypal' &&
      String(bestellungVorPruefung.zahlungs_id || '') === String(orderId);

    if (!istPayPalBestellung) {
      return res.status(400).json({
        error: 'Diese Bestellung gehört nicht zu dieser PayPal-Zahlung.'
      });
    }

    // Statusprüfung VOR dem PayPal-Aufruf – nicht erst danach.
    // Ohne sie kann für eine stornierte Bestellung Geld eingezogen werden: PayPal bucht ab,
    // der atomare Claim in bestellungAbwickeln filtert `status=neq.storniert` und liefert
    // deshalb keine Zeile, die Abwicklung kehrt still zurück – und die Route meldete
    // trotzdem HTTP 200. Geld weg, Bestellung storniert, niemand erfährt davon.
    // Über die Oberfläche ist das derzeit nicht erreichbar (nur Vorkasse ist stornierbar),
    // über Altbestände und Direktaufrufe aber sehr wohl.
    const statusVorher = String(bestellungVorPruefung.status || '');
    if (statusVorher === 'storniert') {
      return res.status(409).json({
        error: 'Diese Bestellung wurde storniert und kann nicht mehr bezahlt werden. Es wurde kein Betrag eingezogen.',
        status: null,
        order_status: null,
        capture_status: null,
        bestell_status: statusVorher
      });
    }
    // Bereits verarbeitet → idempotent mit Erfolg antworten, NICHT als Fehler behandeln.
    // Typischer Fall: Der Kunde landet über Zurück-Taste oder Neuladen ein zweites Mal auf
    // der Rückkehr-URL. Ein erneuter Capture-Aufruf ist dafür überflüssig – die Zahlung ist
    // verbucht, sonst stünde die Bestellung nicht auf einem dieser Status.
    if (['bezahlt', 'bestaetigt', 'bestätigt', 'versendet', 'geliefert'].includes(statusVorher)) {
      return res.json({
        status: 'COMPLETED',
        order_status: null,
        capture_status: 'COMPLETED',
        bereits_verarbeitet: true,
        bestell_status: statusVorher
      });
    }

    const token = await getPayPalToken();
    const bestellungIdInt = Number.parseInt(bestellung_id, 10);

    const captureRes = await fetchFn(
      // Dieselbe Basis wie Token und Order-Anlage (services/payments.js) – sonst würde mit einem
      // Sandbox-Token gegen die Produktion gecaptured oder umgekehrt.
      `${PAYPAL_API_BASE_URL}/v2/checkout/orders/${encodeURIComponent(orderId)}/capture`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
          // Vollständige Antwort erzwingen. Ohne diesen Header darf PayPal eine MINIMALE
          // Antwort liefern (nur id, status, links) – dann fehlt purchase_units[0].payments
          // .captures[0], obwohl das Geld eingezogen wurde. Die Auswertung würde „kein
          // capture-Objekt" melden und die bezahlte Bestellung nicht abwickeln.
          'Prefer': 'return=representation',
          // Stabiler Idempotenzschlüssel (PayPal-Empfehlung für wiederholbare POSTs):
          // Bricht die Verbindung NACH dem Abbuchen ab, liefert derselbe Aufruf dieselbe
          // Antwort zurück, statt ein zweites Mal zu buchen oder zu scheitern.
          // Bewusst OHNE Date.now() – bei jeder Wiederholung muss derselbe Schlüssel entstehen.
          'PayPal-Request-Id': `vt-capture-${bestellungIdInt}-${orderId}`
        }
      }
    );

    const captureData = await captureRes.json();

    if (!captureRes.ok) {
      throw new Error(`PayPal Capture Fehler: ${JSON.stringify(captureData)}`);
    }

    const bestellung = await ladeBestellung(bestellungIdInt);
    const { gesamtNetto } = ermittleNettoBetraege(bestellung);
    const expectedBrutto = round2(gesamtNetto * 1.19).toFixed(2);

    // Maßgeblich ist der CAPTURE-Status, nicht der Order-Status (siehe Kommentar an
    // bewerteCaptureAntwort). reference_id und Betrag werden dort mitgeprüft.
    const bewertung = bewerteCaptureAntwort(captureData, {
      bestellungId: bestellung_id,
      erwarteterBrutto: expectedBrutto
    });
    if (bewertung.fehler) throw new Error(bewertung.fehler);

    // `status` trägt bewusst den CAPTURE-Status, nicht den Order-Status. Ein Frontend, das
    // `status` prüft, wird durch diese Änderung höchstens strenger, nie laxer.
    // Die vor dem 29.07.2026 ausgelieferte index.html prüft das Feld allerdings gar nicht,
    // sondern wertet nur `res.ok` aus. Deshalb ist JEDER nicht erfolgreiche Ausgang unten
    // ein 4xx/5xx – siehe die Begründung am PENDING-Zweig. Damit ist die Antwort auch für
    // alte, in offenen Tabs weiterlebende Seiten sicher.
    // Umgekehrt gilt weiterhin: eine NEUE index.html gegen ein ALTES Backend kennt
    // `capture_status` nicht und meldete jede erfolgreiche Zahlung als Fehler.
    // → Deploy-Reihenfolge bleibt zwingend: Railway zuerst, dann Vercel.
    const antwort = {
      status: bewertung.captureStatus,
      order_status: bewertung.orderStatus,
      capture_status: bewertung.captureStatus
    };

    if (bewertung.ok) {
      await bestellungAbwickeln(bestellungIdInt, orderId);

      // Der atomare Claim in bestellungAbwickeln filtert `status=neq.bezahlt` UND
      // `status=neq.storniert`. Eine leere Rückgabe ist dort MEHRDEUTIG: „läuft parallel
      // bereits" oder „wurde zwischenzeitlich storniert" – die Funktion behandelt beides
      // gleich und kehrt still zurück. Zwischen der Vorprüfung oben und dieser Zeile liegt
      // der PayPal-Aufruf; in diesem Fenster kann der Status gewechselt haben. Das Geld ist
      // jetzt eingezogen, also muss der tatsächliche Endzustand festgestellt werden, statt
      // pauschal Erfolg zu melden.
      const danach = await ladeBestellung(bestellungIdInt).catch(() => null);
      const statusDanach = String(danach?.status || '');
      const alarmAn = process.env.ADMIN_TELEGRAM_ID || process.env.TELEGRAM_ADMIN_ID;

      if (statusDanach === 'storniert') {
        console.error(`🚨 PayPal-Zahlung für STORNIERTE Bestellung ${bestellungIdInt} eingezogen (Order ${orderId}).`);
        try {
          if (alarmAn) {
            await sendeTelegram(
              alarmAn,
              `🚨 <b>Geld für stornierte Bestellung eingezogen</b>\nBestellung #${bestellungIdInt} (PayPal-Order ${escapeHtml(String(orderId))}) wurde zwischen Prüfung und Zahlung storniert. Der Betrag ist eingezogen, die Bestellung wurde NICHT abgewickelt.\n<b>Erstattung erforderlich.</b>`
            );
          }
        } catch (_) {}
        return res.status(409).json({
          ...antwort,
          bestell_status: statusDanach,
          error: 'Ihre Zahlung ist eingegangen, die Bestellung wurde zwischenzeitlich jedoch storniert. Wir haben unser Team informiert und kümmern uns um die Erstattung.'
        });
      }

      if (!['bezahlt', 'bestaetigt', 'bestätigt', 'versendet', 'geliefert'].includes(statusDanach)) {
        // Geld da, Bestellung aber in keinem verarbeiteten Zustand – nie als Erfolg melden.
        console.error(`🚨 PayPal-Zahlung eingezogen, Bestellung ${bestellungIdInt} steht danach auf "${statusDanach || 'unbekannt'}".`);
        try {
          if (alarmAn) {
            await sendeTelegram(
              alarmAn,
              `🚨 <b>PayPal-Zahlung ohne Abwicklung</b>\nBestellung #${bestellungIdInt}: Betrag eingezogen, Status danach <b>${escapeHtml(String(statusDanach || 'unbekannt'))}</b>. Bitte SOFORT manuell prüfen.`
            );
          }
        } catch (_) {}
        return res.status(500).json({
          ...antwort,
          bestell_status: statusDanach,
          error: 'Ihre Zahlung ist eingegangen, die Bestellung konnte aber nicht abgeschlossen werden. Wir haben unser Team informiert und melden uns bei Ihnen.'
        });
      }

      return res.json({ ...antwort, bestell_status: statusDanach });
    }

    // Capture nicht abgeschlossen: NICHT abwickeln – kein Bestand ausbuchen, keine
    // Auftragsbestätigung. Es gibt (noch) KEINEN PayPal-Webhook: Bestätigt PayPal eine
    // schwebende Zahlung später, erfährt das sonst niemand. Darum Alarm an den Admin.
    console.error(`🚨 PayPal-Capture nicht abgeschlossen (Bestellung ${bestellungIdInt}): order=${bewertung.orderStatus}, capture=${bewertung.captureStatus}`);
    const alarmTexte = {
      fehlgeschlagen: `⚠️ <b>PayPal-Zahlung abgelehnt</b>\nBestellung #${bestellungIdInt}: Capture-Status <b>${escapeHtml(String(bewertung.captureStatus))}</b>. Es wurde kein Geld eingezogen und nichts abgewickelt. Der Kunde kann die Zahlung erneut versuchen.`,
      erstattet: `🚨 <b>PayPal-Capture bereits erstattet</b>\nBestellung #${bestellungIdInt}: Capture-Status <b>${escapeHtml(String(bewertung.captureStatus))}</b>. Die Bestellung wurde NICHT abgewickelt. Bitte prüfen, warum zu dieser Bestellung bereits eine Erstattung vorliegt.`,
      schwebend: `🚨 <b>PayPal-Zahlung schwebt</b>\nBestellung #${bestellungIdInt}: Capture-Status <b>${escapeHtml(String(bewertung.captureStatus))}</b> (Order-Status ${escapeHtml(String(bewertung.orderStatus || 'unbekannt'))}).\nDie Bestellung wurde NICHT abgewickelt. Bestätigt PayPal die Zahlung später, muss sie MANUELL nachgezogen werden – es existiert kein PayPal-Webhook.`
    };
    try {
      const adminId = process.env.ADMIN_TELEGRAM_ID || process.env.TELEGRAM_ADMIN_ID;
      if (adminId && alarmTexte[bewertung.klassifikation]) {
        await sendeTelegram(adminId, alarmTexte[bewertung.klassifikation]);
      }
    } catch (_) {}

    // Drei verschiedene Sachverhalte, drei verschiedene Antworten. Ein unbekannter oder
    // fehlender Status kommt hier nicht an – der wird oben als `fehler` geworfen und darf
    // NIEMALS als „wird noch geprüft" beim Kunden landen.
    if (bewertung.klassifikation === 'erstattet') {
      return res.status(409).json({
        ...antwort,
        error: `Zu dieser Zahlung liegt bereits eine Erstattung vor (Status: ${bewertung.captureStatus}). Die Bestellung wurde nicht verarbeitet. Bitte kontaktieren Sie uns.`
      });
    }
    if (bewertung.klassifikation === 'fehlgeschlagen') {
      return res.status(402).json({
        ...antwort,
        error: `PayPal hat die Zahlung nicht ausgeführt (Status: ${bewertung.captureStatus}). Es wurde kein Betrag eingezogen. Bitte versuchen Sie es erneut oder wählen Sie eine andere Zahlungsart.`
      });
    }
    // PENDING bewusst als NICHT-2xx (statt des fachlich naheliegenden 202):
    // Ein 202 ist für jeden Client, der nur `res.ok` auswertet, ein Erfolg – und genau das
    // tut die vor dem 29.07.2026 ausgelieferte index.html. Solche Seiten leben in offenen
    // Browser-Tabs weiter, auch Tage nach dem Vercel-Deploy. Das Zeitfenster endet also
    // NICHT mit dem Deploy. Mit 4xx zeigt weder die alte noch die neue Fassung jemals
    // Erfolg für eine schwebende Zahlung. Den genauen Fall trägt `capture_status` im Body.
    return res.status(409).json({
      ...antwort,
      error: 'Die Zahlung wird von PayPal noch geprüft. Ihre Bestellung wurde noch nicht verarbeitet. Sobald PayPal die Zahlung bestätigt, kümmern wir uns darum und melden uns bei Ihnen.'
    });
  } catch (err) {
    console.error('❌ PayPal Capture Error:', err);

    return sendError(res, err);
  }
});


// -----------------------------------------------------------------------------
// Gastcheckout / Vorkasse-Helfer
// -----------------------------------------------------------------------------

function validateGuestCheckoutPayload(payload, erlaubteZahlungsarten = ['vorkasse', 'stripe', 'paypal'], { stammdatenAusProfilQuelle = false } = {}) {
  const bestellung = payload?.bestellung || {};
  const positionen = Array.isArray(payload?.positionen) ? payload.positionen : [];
  const bestaetigungen = payload?.bestaetigungen || {};

  const errors = [];
  const email = normalizeEmail(bestellung.email);

  // Eingeloggte Kunden (stammdatenAusProfilQuelle): Firmen-/Kontakt-/Rechnungsdaten
  // kommen ausschließlich aus dem Kundenprofil – die Body-Felder werden ignoriert
  // und hier deshalb auch nicht als Pflicht geprüft (das Profil wird separat
  // vollständig geprüft, siehe stammdatenAusProfil).
  if (!stammdatenAusProfilQuelle) {
    if (!String(bestellung.kundenname || '').trim()) errors.push('Kundenname fehlt');
    if (!String(bestellung.firma || '').trim()) errors.push('Firma fehlt');
    if (!String(bestellung.telefon || '').trim()) errors.push('Telefon fehlt');
  }
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.push('E-Mail ist ungültig');
  if (!['abholung', 'lieferung'].includes(String(bestellung.lieferart || ''))) errors.push('Lieferart ist ungültig');
  if (!erlaubteZahlungsarten.includes(String(bestellung.zahlungsart || ''))) errors.push('Zahlungsart ist für den Gastkauf nicht freigeschaltet');
  if (!bestaetigungen.b2b) errors.push('B2B-Bestätigung fehlt');
  if (!bestaetigungen.agb) errors.push('AGB-Bestätigung fehlt');
  if (!bestaetigungen.datenschutz) errors.push('Datenschutz-Bestätigung fehlt');

  if (!stammdatenAusProfilQuelle && String(bestellung.lieferart || '') === 'lieferung') {
    if (!String(bestellung.rechnungsadresse_strasse || '').trim()) errors.push('Rechnungsstraße fehlt');
    if (!/^\d{5}$/.test(String(bestellung.rechnungsadresse_plz || '').trim())) errors.push('Rechnungs-PLZ ist ungültig');
    if (!String(bestellung.rechnungsadresse_ort || '').trim()) errors.push('Rechnungsort fehlt');
    if (!String(bestellung.rechnungsadresse_land || '').trim()) errors.push('Rechnungsland fehlt');
  }

  if (!positionen.length) errors.push('Keine Bestellpositionen vorhanden');
  for (const [idx, pos] of positionen.entries()) {
    const paketId = Number.parseInt(pos.paket_id, 10);
    const produktId = Number.parseInt(pos.produkt_id, 10);
    const anzahl = Number.parseInt(pos.anzahl_pakete, 10);
    if (!Number.isInteger(paketId) || paketId <= 0) errors.push(`Position ${idx + 1}: Paket fehlt`);
    if (!Number.isInteger(produktId) || produktId <= 0) errors.push(`Position ${idx + 1}: Produkt fehlt`);
    if (!Number.isInteger(anzahl) || anzahl <= 0) errors.push(`Position ${idx + 1}: Anzahl ungültig`);
  }

  if (errors.length) {
    const err = new Error(errors.join(', '));
    err.statusCode = 400;
    throw err;
  }

  return { bestellung, positionen, email };
}

// Commit B (Checkout-Absicherung): Bei eingeloggten Kunden sind die Firmen- und
// Rechnungsdaten AUSSCHLIESSLICH das Kundenprofil – der Browser ist keine
// vertrauenswürdige Quelle, es gibt KEINEN Body-Fallback. Unvollständiges
// Profil ⇒ Bestellung wird mit klarer Meldung blockiert (400), bevor irgendetwas
// angelegt wird (keine Bestellung, keine Rechnung, kein Zahlungsprozess).
function stammdatenAusProfil(profil) {
  if (!profil) return null;
  const s = (v) => String(v ?? '').trim();
  const fehlt = [];
  if (!s(profil.firma)) fehlt.push('Firma');
  if (!s(profil.kontakt_name)) fehlt.push('Ansprechpartner');
  if (!s(profil.telefon)) fehlt.push('Telefon');
  if (!s(profil.rechnungsadresse_strasse)) fehlt.push('Straße');
  if (!s(profil.rechnungsadresse_hausnr)) fehlt.push('Hausnummer');
  if (!s(profil.rechnungsadresse_plz)) fehlt.push('PLZ');
  if (!s(profil.rechnungsadresse_ort)) fehlt.push('Ort');
  if (!s(profil.rechnungsadresse_land)) fehlt.push('Land');
  if (fehlt.length) {
    const e = new Error('Ihre Firmendaten sind noch nicht vollständig. Bitte vervollständigen Sie zuerst Ihre Firmendaten unter „Mein Konto → Adressen → Firmendaten". Erst danach kann eine Bestellung abgeschlossen werden. (Es fehlt: ' + fehlt.join(', ') + ')');
    e.statusCode = 400;
    throw e;
  }
  return {
    kundenname: s(profil.kontakt_name),
    firma: s(profil.firma),
    telefon: s(profil.telefon),
    ust_idnr: s(profil.ust_idnr) || null,
    rechnungsadresse_strasse: s(profil.rechnungsadresse_strasse) + ' ' + s(profil.rechnungsadresse_hausnr),
    rechnungsadresse_plz: s(profil.rechnungsadresse_plz),
    rechnungsadresse_ort: s(profil.rechnungsadresse_ort),
    rechnungsadresse_land: s(profil.rechnungsadresse_land)
  };
}


// =============================================================================
// B2B: Kundenprofil, Mitarbeiter, erlaubte Zahlungsarten (serverseitig erzwungen)
// =============================================================================

// Lieferzeit-Hinweis nach services/pricing.js verschoben (Phase 4, Commit 5) und dort
// von einer Konstante zu lieferzeitHinweis({lieferart, zahlungsart}) geworden. Import oben.
// Anzeigestellen verwenden lieferzeitHinweisFuerBestellung(b) – gespeicherter Wert zuerst.
const BASIS_ZAHLUNGSARTEN = ['stripe', 'paypal', 'vorkasse'];

// Membership (Einkaufsleiter/Mitarbeiter) des Auth-Users – unabhängig von aktiv.
async function ladeMitgliedFuerAuthUser(authUser) {
  if (!authUser?.id) return null;
  const rows = await supabaseQuery(
    'kunden_mitarbeiter',
    `?auth_user_id=eq.${encodeURIComponent(authUser.id)}&limit=1`
  );
  return Array.isArray(rows) ? rows[0] || null : null;
}

async function ladeKundenprofilFuerAuthUser(authUser) {
  const mitglied = await ladeMitgliedFuerAuthUser(authUser);
  if (!mitglied) return null;
  const profile = await supabaseQuery(
    'kundenprofil',
    `?id=eq.${encodeURIComponent(mitglied.kundenprofil_id)}&limit=1`
  );
  const profil = Array.isArray(profile) ? profile[0] : null;
  return profil ? { profil, mitglied } : null;
}

// Stellt sicher, dass ein eingeloggter Nutzer einem Kundenkonto zugeordnet ist.
// - bereits zugeordnet (egal ob aktiv): zurückgeben
// - als (eingeladener) Mitarbeiter per E-Mail vorhanden: Auth-User verknüpfen
// - sonst: neues Profil anlegen, Nutzer wird Einkaufsleiter
async function ensureKundenprofilFuerAuthUser(authUser) {
  if (!authUser?.id) return null;

  const vorhanden = await ladeKundenprofilFuerAuthUser(authUser);
  if (vorhanden) {
    // Erstkontakt nach Einladung: Annahme-Zeitpunkt einmalig stempeln, damit der
    // Einkaufsleiter sieht, dass der Mitarbeiter sein Konto aktiviert hat.
    if (vorhanden.mitglied && !vorhanden.mitglied.einladung_angenommen_am) {
      const jetzt = new Date().toISOString();
      try {
        await supabasePatchWhere('kunden_mitarbeiter', `?id=eq.${vorhanden.mitglied.id}`, {
          einladung_angenommen_am: jetzt
        });
        vorhanden.mitglied.einladung_angenommen_am = jetzt;
      } catch (_) {}
    }
    return vorhanden;
  }

  const email = normalizeEmail(authUser.email);

  const bestehende = await supabaseQuery(
    'kunden_mitarbeiter',
    `?email=ilike.${encodeURIComponent(email)}&limit=1`
  );
  if (Array.isArray(bestehende) && bestehende[0]) {
    const m = bestehende[0];
    if (!m.auth_user_id) {
      await supabasePatchWhere('kunden_mitarbeiter', `?id=eq.${m.id}`, {
        auth_user_id: authUser.id,
        einladung_angenommen_am: m.einladung_angenommen_am || new Date().toISOString()
      });
    }
    return ladeKundenprofilFuerAuthUser(authUser);
  }

  // Interne Admins werden NICHT automatisch zu B2B-Kunden angelegt.
  try {
    const adminRows = await supabaseQuery('admin_users', `?email=ilike.${encodeURIComponent(email)}&limit=1`);
    if (Array.isArray(adminRows) && adminRows[0]) return null;
  } catch (_) {}

  const profilRows = await supabaseInsert('kundenprofil', {
    hauptbenutzer_id: authUser.id,
    firma: authUser.user_metadata?.firma || null,
    einkaufsleiter_email: email
  });
  const profil = Array.isArray(profilRows) ? profilRows[0] : null;
  if (!profil?.id) throw new Error('Kundenprofil konnte nicht angelegt werden');

  await supabaseInsert('kunden_mitarbeiter', {
    kundenprofil_id: profil.id,
    auth_user_id: authUser.id,
    email,
    name: authUser.user_metadata?.name || null,
    rolle: 'einkaufsleiter',
    aktiv: true,
    einladung_angenommen_am: new Date().toISOString()
  });

  return ladeKundenprofilFuerAuthUser(authUser);
}

function erlaubteZahlungsartenAusProfil(profil) {
  let arten = [];
  try {
    arten = Array.isArray(profil?.erlaubte_zahlungsarten)
      ? profil.erlaubte_zahlungsarten
      : JSON.parse(profil?.erlaubte_zahlungsarten || '[]');
  } catch (_) { arten = []; }
  arten = arten.filter(a => BASIS_ZAHLUNGSARTEN.includes(a));
  if (profil?.rechnung_erlaubt === true) arten.push('rechnung');
  return arten;
}

// Serverseitige Checkout-Prüfung. Gäste (kein Login): bisheriges Verhalten
// (stripe/paypal/vorkasse erlaubt, NIE rechnung). Eingeloggt: aktives Kundenkonto
// + freigeschaltete Zahlungsart erforderlich. Gibt den B2B-Kontext zurück.
async function pruefeCheckoutKontext(authUser, zahlungsart) {
  if (!authUser?.id) {
    if (zahlungsart === 'rechnung') {
      const err = new Error('Kauf auf Rechnung ist nur für freigeschaltete Kundenkonten möglich.');
      err.statusCode = 403; throw err;
    }
    return { gast: true, profil: null, mitglied: null };
  }

  const ctx = await ensureKundenprofilFuerAuthUser(authUser);
  if (!ctx?.profil) {
    const err = new Error('Ihr Konto ist keinem aktiven Kundenkonto zugeordnet.');
    err.statusCode = 403; throw err;
  }
  if (ctx.profil.deleted_at || ctx.profil.aktiv === false) {
    const err = new Error('Ihr Firmenkundenkonto ist derzeit nicht aktiv. Bitte kontaktieren Sie den Support.');
    err.statusCode = 403; throw err;
  }
  if (ctx.mitglied && ctx.mitglied.aktiv === false) {
    const err = new Error('Ihr Mitarbeiter-Zugang ist deaktiviert. Bestellungen sind nicht möglich.');
    err.statusCode = 403; throw err;
  }
  const erlaubt = erlaubteZahlungsartenAusProfil(ctx.profil);
  if (!erlaubt.includes(zahlungsart)) {
    const err = new Error(`Die Zahlungsart "${zahlungsart}" ist für Ihr Kundenkonto nicht freigeschaltet.`);
    err.statusCode = 403; throw err;
  }
  return { gast: false, profil: ctx.profil, mitglied: ctx.mitglied };
}

// Hinweis-Block „Bestellt durch …" – nur wenn ein Mitarbeiter (nicht der
// Einkaufsleiter selbst) die Bestellung ausgelöst hat.
function bestellerHinweisBlock(b) {
  const bestellerEmail = normalizeEmail(b?.bestellt_von_email);
  const leiterEmail = normalizeEmail(b?.einkaufsleiter_email);
  if (!bestellerEmail || bestellerEmail === leiterEmail) return '';
  const name = String(b?.kundenname || '').trim();
  return `
    <div style="background:#F0F4F8;border:1px solid #D4DEE8;border-radius:8px;padding:12px 16px;margin:0 0 16px;">
      <p style="margin:0;color:#33475B;font-size:14px;">
        <strong>Bestellt durch:</strong> ${name ? escapeHtml(name) + ', ' : ''}${escapeHtml(bestellerEmail)}
      </p>
    </div>`;
}

// Auftragsbestätigung an Einkaufsleiter UND bestellenden Mitarbeiter (dedupliziert).
async function sendeBestellEmail(bestellung, subject, html, pdfBuffer = null, attachmentName = 'Rechnung_VisioTrade.pdf', replyTo = null) {
  // Ohne explizites Reply-To: automatisch Thread-Token setzen, damit JEDE
  // Vorgangs-Mail bidirektional ist (Antwort → richtiger Vorgang). So sind alle
  // sendeBestellEmail-Aufrufe (AB, Rechnung, Bestätigungen …) automatisch abgedeckt.
  if (!replyTo && bestellung && bestellung.id) {
    const _tok = await bestellMailThreadToken(bestellung);
    if (_tok) { replyTo = replyToToken(_tok); subject = betreffMitToken(subject, _tok); }
  }
  const empfaenger = new Set();
  [bestellung.email, bestellung.bestellt_von_email, bestellung.einkaufsleiter_email]
    .map(e => normalizeEmail(e))
    .filter(Boolean)
    .forEach(e => empfaenger.add(e));

  // Falls die Einkaufsleiter-Adresse auf der Bestellung fehlt (Altbestand), aus dem
  // zugeordneten Kundenprofil nachladen, damit der Einkaufsleiter immer mitliest.
  if (!normalizeEmail(bestellung.einkaufsleiter_email) && bestellung.kundenprofil_id) {
    try {
      const rows = await supabaseQuery(
        'kundenprofil',
        `?id=eq.${bestellung.kundenprofil_id}&select=einkaufsleiter_email&limit=1`
      );
      const el = normalizeEmail(Array.isArray(rows) && rows[0] ? rows[0].einkaufsleiter_email : '');
      if (el) empfaenger.add(el);
    } catch (e) { console.warn('⚠️ Einkaufsleiter-Adresse nachladen fehlgeschlagen:', e.message); }
  }

  // Fehler pro Empfänger werden bewusst NICHT geworfen (ein unerreichbarer Mitleser darf den
  // Vorgang nicht abbrechen). Der Aufrufer bekommt aber einen BERICHT zurück und kann daraus
  // ableiten, ob wirklich jemand erreicht wurde. Ohne den galt jeder Aufruf als Erfolg – auch
  // wenn gar keine Adresse vorhanden war oder alle Zustellungen scheiterten.
  const versendet = [];
  const fehlgeschlagen = [];
  for (const to of empfaenger) {
    try {
      await sendeEmail(to, subject, html, pdfBuffer, attachmentName, replyTo);
      versendet.push(to);
      console.log(`✅ E-Mail gesendet an ${to}`);
    } catch (e) {
      fehlgeschlagen.push({ empfaenger: to, fehler: e.message });
      console.error('❌ E-Mail Fehler an', to, e.message);
    }
  }
  return { empfaenger: [...empfaenger], versendet, fehlgeschlagen };
}

// Vollständiger Erfolg = mindestens ein Empfänger vorhanden UND kein einziger Fehlschlag.
// Teilzustellung zählt bewusst als NICHT erfolgreich: Wenn der Einkaufsleiter die Storno-Mail
// bekommt, der Besteller aber nicht, muss jemand nachfassen.
function mailVollstaendigZugestellt(bericht) {
  return !!bericht
    && Array.isArray(bericht.empfaenger) && bericht.empfaenger.length > 0
    && Array.isArray(bericht.versendet) && bericht.versendet.length > 0
    && Array.isArray(bericht.fehlgeschlagen) && bericht.fehlgeschlagen.length === 0;
}

async function erstelleGastBestellungAusPayload(payload, zahlungsart, authUser = null, b2bCtx = null) {
  // Eingeloggte Kunden: Stammdaten NUR aus dem Profil (Body wird ignoriert).
  // Wirft 400 bei unvollständigem Profil – VOR jeder Anlage/Zahlung.
  const profilStamm = stammdatenAusProfil(b2bCtx?.profil || null);
  const { bestellung, positionen, email } = validateGuestCheckoutPayload(
    {
      ...payload,
      bestellung: {
        ...(payload?.bestellung || {}),
        zahlungsart
      }
    },
    [zahlungsart],
    { stammdatenAusProfilQuelle: !!profilStamm }
  );

  // Lieferadresse serverseitig auflösen: gespeicherte Firmen-Adresse ODER neue Eingabe;
  // neue Adresse nur auf ausdrücklichen Wunsch dem Kundenkonto zuordnen (geprüft).
  let liefAdr = {
    abweichend: !!bestellung.abweichende_lieferadresse,
    empfaenger: String(bestellung.lieferadresse_empfaenger || '').trim() || null,
    strasse: bestellung.lieferadresse_strasse || null,
    plz: bestellung.lieferadresse_plz || null,
    ort: bestellung.lieferadresse_ort || null,
    land: bestellung.lieferadresse_land || null,
    telefon: bestellung.lieferadresse_telefon || null
  };
  if (b2bCtx?.profil) {
    const selId = Number.parseInt(payload?.lieferadresse_id, 10);
    if (Number.isInteger(selId) && selId > 0) {
      const adr = await ladeAdresseFuerProfil(selId, b2bCtx.profil.id);
      if (!adr) { const e = new Error('Die gewählte Lieferadresse ist ungültig.'); e.statusCode = 403; throw e; }
      liefAdr = { abweichend: true, empfaenger: adr.empfaenger, strasse: adr.strasse, plz: adr.plz, ort: adr.ort, land: adr.land, telefon: adr.telefon };
    } else if (liefAdr.abweichend && payload?.lieferadresse_speichern && liefAdr.strasse && liefAdr.plz && liefAdr.ort) {
      try {
        await supabaseInsert('kunden_adressen', {
          kundenprofil_id: b2bCtx.profil.id,
          user_id: authUser?.id || null,
          empfaenger: liefAdr.empfaenger, strasse: liefAdr.strasse, plz: liefAdr.plz,
          ort: liefAdr.ort, land: liefAdr.land || 'DE', telefon: liefAdr.telefon
        });
      } catch (e) { console.warn('⚠️ Adresse beim Checkout speichern fehlgeschlagen:', e.message); }
    }
  }

  // ENTFERNT (Commit B): Der frühere „stammdaten_speichern"-Inline-Save schrieb
  // Browser-Formulardaten während des Checkouts ins Kundenprofil – genau der
  // Pfad, den dieser Commit schließt. Stammdaten-Pflege läuft ausschließlich
  // über die validierte Adressen-Seite (PUT /api/b2b/profil, nur Einkaufsleiter).

  const orderRows = await supabaseInsert('bestellungen', {
    telegram_user_id: bestellung.telegram_user_id || null,
    telegram_username: bestellung.telegram_username || null,
    user_id: authUser?.id || null,
    // Eingeloggt (profilStamm): Stammdaten AUSSCHLIESSLICH aus dem Kundenprofil,
    // KEIN Body-Fallback. Gast: Formulardaten wie bisher.
    kundenname: profilStamm ? profilStamm.kundenname : String(bestellung.kundenname || '').trim(),
    firma: profilStamm ? profilStamm.firma : String(bestellung.firma || '').trim(),
    ust_idnr: profilStamm ? profilStamm.ust_idnr : (String(bestellung.ust_idnr || '').trim() || null),
    email,
    telefon: profilStamm ? profilStamm.telefon : String(bestellung.telefon || '').trim(),
    lieferart: bestellung.lieferart,
    rechnungsadresse_strasse: profilStamm ? profilStamm.rechnungsadresse_strasse : (bestellung.rechnungsadresse_strasse || null),
    rechnungsadresse_plz: profilStamm ? profilStamm.rechnungsadresse_plz : (bestellung.rechnungsadresse_plz || null),
    rechnungsadresse_ort: profilStamm ? profilStamm.rechnungsadresse_ort : (bestellung.rechnungsadresse_ort || null),
    rechnungsadresse_land: profilStamm ? profilStamm.rechnungsadresse_land : (bestellung.rechnungsadresse_land || null),
    hebebuehne: !!bestellung.hebebuehne,
    abweichende_lieferadresse: liefAdr.abweichend,
    lieferadresse_empfaenger: liefAdr.empfaenger,
    lieferadresse_strasse: liefAdr.strasse,
    lieferadresse_plz: liefAdr.plz,
    lieferadresse_ort: liefAdr.ort,
    lieferadresse_land: liefAdr.land,
    lieferadresse_telefon: liefAdr.telefon,
    lieferadresse_hebebuehne: !!bestellung.lieferadresse_hebebuehne,
    gesamtbetrag: 0,
    warenwert_netto: 0,
    lieferkosten_netto: 0,
    zahlungsart,
    status: 'offen',
    lieferkosten_spediteur: null,
    lieferkosten_intern: null,
    // B2B-Zuordnung (null bei Gastbestellung)
    kundenprofil_id: b2bCtx?.profil?.id || null,
    bestellt_von_auth_user_id: authUser?.id || null,
    bestellt_von_email: authUser ? normalizeEmail(authUser.email) : null,
    bestellt_von_rolle: b2bCtx?.mitglied?.rolle || null,
    einkaufsleiter_email: b2bCtx?.profil?.einkaufsleiter_email || null,
    bonus_prozent_zum_bestellzeitpunkt: b2bCtx?.profil ? toNumber(b2bCtx.profil.bonus_prozent, 0) : null,
    // Hier ENTSTEHT die Zusage – deshalb berechnen, nicht lesen. Ab jetzt gilt der
    // gespeicherte Wert als das, was dem Kunden versprochen wurde.
    lieferzeit_hinweis: lieferzeitHinweis({ lieferart: bestellung.lieferart, zahlungsart }),
    // Filiale = Standort des Bestellers (Mitarbeiter-Filiale → sonst Stadt der Rechnungsadresse).
    filiale: (b2bCtx?.mitglied?.filiale || b2bCtx?.profil?.rechnungsadresse_ort || String(bestellung.rechnungsadresse_ort || '').trim() || null)
  });

  const createdOrder = Array.isArray(orderRows) ? orderRows[0] : null;
  if (!createdOrder?.id) {
    throw new Error('Gastbestellung konnte nicht erstellt werden');
  }

  // Alle Positionen in EINEM Insert (Bulk) statt einzeln – ein Request statt N.
  const positionRows = positionen.map(pos => ({
    bestellung_id: createdOrder.id,
    produkt_id: Number.parseInt(pos.produkt_id, 10),
    produktname: String(pos.produktname || '').trim(),
    paket_id: Number.parseInt(pos.paket_id, 10),
    anzahl_pakete: Number.parseInt(pos.anzahl_pakete, 10),
    menge_m2_gesamt: toNumber(pos.menge_m2_gesamt),
    preis_je_paket: toNumber(pos.preis_je_paket),
    gesamtpreis: toNumber(pos.gesamtpreis),
    bauvorhaben: String(pos.bauvorhaben || '').trim().slice(0, 200) || null
  }));
  if (positionRows.length) {
    await supabaseInsert('bestellpositionen', positionRows);
  }

  return {
    bestellung: createdOrder,
    positionen,
    email
  };
}

// erstelleStripeSessionFuerBestellung + erstellePayPalOrderFuerBestellung nach services/payments.js (Phase 4, Commit 9). Import oben.

async function verarbeiteVorkasseBestellung(bestellung_id, meta = {}) {
  const bestellung = await ladeBestellung(bestellung_id);

  if (bestellung.status === 'warte_auf_zahlung' || bestellung.status === 'bezahlt') {
    console.log(`ℹ️ Vorkasse-Bestellung ${bestellung_id} wurde bereits verarbeitet. Überspringe.`);
    return {
      ok: true,
      already_processed: true,
      bestellung_id,
      bestellung
    };
  }

  // Positivliste (Audit S2-04): Nur eine frisch angelegte Bestellung ('offen', siehe Anlage
  // weiter oben) darf in den Vorkasse-Weg. Vorher liefen auch 'storniert', 'auf_rechnung',
  // 'versendet' usw. durch – mit drei Folgen:
  //   * Storno-Wiederbelebung: eine stornierte Bestellung sprang zurück auf 'warte_auf_zahlung',
  //     die Ware wurde erneut reserviert und eine Zahlungsaufforderung verschickt.
  //   * Doppelbuchung: bei 'auf_rechnung' war der Bestand bereits abgezogen; die Reservierung
  //     kam obendrauf → Ware zweimal ausgebucht.
  //   * Umgehung der freigeschalteten Zahlungsart (z. B. nur Stripe erlaubt → auf Vorkasse gedreht).
  if (bestellung.status !== 'offen') {
    const err = new Error(`Bestellung #${bestellung_id} kann nicht per Vorkasse abgeschlossen werden (Status: ${bestellung.status}).`);
    err.statusCode = 400; // sendError liest statusCode – bei 4xx wird err.message an den Client durchgereicht
    throw err;
  }

  const calc = await berechneUndFixiereBestellungServerseitig(bestellung_id, {
    pruefeBestand: true,
    fixiere: true
  });

  const bestellungVorkasse = {
    ...calc.bestellung,
    zahlungsart: 'vorkasse',
    status: 'warte_auf_zahlung'
  };

  const positionen = calc.positionen;
  const { gesamtNetto, warenwertNetto, lieferkostenNetto } = calc;

  if (gesamtNetto <= 0) {
    const err = new Error('Ungültiger Zahlungsbetrag');
    err.statusCode = 400;
    throw err;
  }

  const reserviertBis = berechneReserviertBisVorkasse();
  await reserviereLagerbestandAtomar(positionen, bestellung_id, reserviertBis);

  await supabaseUpdate('bestellungen', bestellung_id, {
    zahlungsart: 'vorkasse',
    status: 'warte_auf_zahlung',
    proforma_gesendet_am: new Date().toISOString(),
    reserviert_bis: reserviertBis,
    reservierung_status: 'reserved'
  });

  // Vorgangscenter: Vorkasse → Eingang sofort (Auftragsbestätigung erst bei Geldeingang).
  await vorgangEreignis(bestellungVorkasse, 'bestellung_eingegangen', { text: 'Bestellung erfolgreich aufgenommen.', meta: { betrag: bestellungVorkasse.gesamtbetrag } });

  console.log(`✅ Lager für Vorkasse-Bestellung bis ${reserviertBis} reserviert`);
  console.log('✅ Keine echte Lexoffice-Rechnung erstellt');

  const verwendung = 'VT-' + String(bestellung_id).padStart(4, '0');
  const zielEmail = meta.email || bestellungVorkasse.email;
  const zielName = meta.kundenname || bestellungVorkasse.kundenname;

  const emailHtml = `
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
      <div style="background:#3D2B1F;padding:20px;text-align:center;">
        <h1 style="color:#C49A2B;font-family:Georgia,serif;margin:0;">VisioTrade</h1>
        <p style="color:white;margin:5px 0 0;">Premium Parkett</p>
      </div>
      <div style="padding:30px;background:#FAF7F2;">
        <h2 style="color:#3D2B1F;">Bestellung aufgenommen</h2>
        <p>Sehr geehrte/r ${escapeHtml(zielName)},</p>
        <p>Ihre Bestellung <strong>#${bestellung_id}</strong> wurde erfolgreich aufgenommen.</p>
        <p>Bitte überweisen Sie den folgenden Betrag auf unser Konto. Nach Zahlungseingang erstellen und senden wir Ihnen die offizielle Rechnung.</p>

        <table style="width:100%;border-collapse:collapse;margin:20px 0;background:white;border-radius:8px;">
          <tr style="background:#F5EDD8;"><td style="padding:12px;font-weight:bold;">Empfänger</td><td style="padding:12px;">VISIO TRADE GMBH</td></tr>
          <tr><td style="padding:12px;font-weight:bold;">IBAN</td><td style="padding:12px;font-weight:bold;letter-spacing:1px;">DE49 2665 0001 1060 0159 95</td></tr>
          <tr style="background:#F5EDD8;"><td style="padding:12px;font-weight:bold;">BIC</td><td style="padding:12px;">NOLADE21EMS</td></tr>
          <tr><td style="padding:12px;font-weight:bold;">Bank</td><td style="padding:12px;">Sparkasse Emsland</td></tr>
          <tr style="background:#F5EDD8;"><td style="padding:12px;font-weight:bold;">Verwendungszweck</td><td style="padding:12px;font-weight:bold;color:#8B6914;">${verwendung}</td></tr>
          <tr><td style="padding:12px;font-weight:bold;">Warenwert netto</td><td style="padding:12px;">${euro(warenwertNetto)}</td></tr>
          <tr style="background:#F5EDD8;"><td style="padding:12px;font-weight:bold;">Lieferkosten netto</td><td style="padding:12px;">${lieferkostenNetto > 0 ? euro(lieferkostenNetto) : '0,00 €'}</td></tr>
          <tr><td style="padding:12px;font-weight:bold;font-size:16px;">Betrag brutto</td><td style="padding:12px;font-weight:bold;font-size:16px;color:#8B6914;">${euro(gesamtNetto * 1.19)}</td></tr>
        </table>

        <div style="background:#FFF4D6;border:1px solid #E0C36B;border-radius:8px;padding:14px 16px;margin:0 0 16px;">
          <p style="margin:0;color:#6B4E00;font-size:14px;line-height:1.5;">
            <strong>Wichtiger Hinweis:</strong> Bitte führen Sie die Zahlung als <strong>Echtzeitüberweisung</strong> durch.
            Ihre Bestellung ist <strong>${RESERVIERUNG_VORKASSE_STUNDEN} Stunden</strong> reserviert. Geht innerhalb dieser Frist
            kein Zahlungseingang ein, wird die Bestellung <strong>automatisch storniert</strong> und die Ware wieder freigegeben.
            Die Bearbeitung Ihrer Bestellung beginnt erst <strong>ab Zahlungseingang</strong>.
          </p>
        </div>

        ${bestellerHinweisBlock(bestellungVorkasse)}
        ${lieferadresseEmailBlock(bestellungVorkasse)}
        <div style="background:#FFF4D6;border:1px solid #E0C36B;border-radius:8px;padding:12px 16px;margin:8px 0;">
          <p style="margin:0;color:#6B4E00;font-size:14px;"><strong>${lieferzeitHinweisFuerBestellung(bestellungVorkasse)}</strong></p>
        </div>
        <p style="color:#6B7280;font-size:13px;">Dies ist eine Zahlungsaufforderung zur Vorkasse. Die offizielle Rechnung erhalten Sie nach Zahlungseingang.</p>
        <p style="color:#6B7280;font-size:13px;margin-top:30px;">Bei Fragen stehen wir Ihnen gerne zur Verfügung.<br>VisioTrade GmbH</p>
      </div>
    </div>
  `;

  // Zahlungsaufforderung an Einkaufsleiter UND bestellenden Mitarbeiter (dedupliziert).
  // Reply-To-Token, damit Kundenantworten im richtigen Vorgang landen.
  const _vkToken = await bestellMailThreadToken(bestellungVorkasse);
  await sendeBestellEmail(
    { ...bestellungVorkasse, email: zielEmail },
    betreffMitToken(`Zahlungsaufforderung zu Bestellung #${bestellung_id} | VisioTrade`, _vkToken),
    emailHtml,
    null,
    'Rechnung_VisioTrade.pdf',
    replyToToken(_vkToken)
  );

  const adminId = process.env.ADMIN_TELEGRAM_ID || process.env.TELEGRAM_ADMIN_ID;
  if (adminId) {
    const tgText =
      `🏦 <b>Neue Vorkasse-Bestellung #${bestellung_id}</b>${meta.gast ? ' (Gastkauf)' : ''}\n\n` +
      `👤 Kunde: ${escapeHtml(zielName)}\n` +
      `📧 Email: ${escapeHtml(zielEmail)}\n` +
      `💰 Netto: ${euro(gesamtNetto)}\n` +
      `💰 Brutto: ${euro(gesamtNetto * 1.19)}\n` +
      `🏦 Verwendungszweck: ${verwendung}\n` +
      `📊 Status: Warte auf Zahlung ⏳\n\n` +
      `ℹ️ Keine echte Rechnung erstellt.`;

    await sendeTelegram(adminId, tgText);
  }

  console.log(`✅ Vorkasse-Bestellung ${bestellung_id} abgeschlossen`);

  return {
    ok: true,
    bestellung_id,
    server_total_netto: gesamtNetto,
    server_total_brutto: round2(gesamtNetto * 1.19),
    reserviert_bis: reserviertBis
  };
}

app.post('/api/checkout/gastbestellung', strictOrderLimiter, async (req, res) => {
  try {
    const authUser = await getOptionalUserFromAuthHeader(req);
    if (!authUser) await verlangeTurnstile(req);
    const ctx = await pruefeCheckoutKontext(authUser, 'vorkasse');
    const { bestellung } = await erstelleGastBestellungAusPayload(req.body, 'vorkasse', authUser, ctx);

    const result = await verarbeiteVorkasseBestellung(bestellung.id, {
      gast: !authUser,
      kundenname: bestellung.kundenname,
      email: bestellung.email,
      user_id: authUser?.id || null
    });

    return res.json({
      ...result,
      gast: !authUser
    });
  } catch (err) {
    console.error('❌ Gastbestellung Vorkasse Fehler:', err);
    return sendError(res, err, { ok: false });
  }
});

app.post('/api/checkout/gastbestellung/stripe', strictOrderLimiter, async (req, res) => {
  try {
    const authUser = await getOptionalUserFromAuthHeader(req);
    if (!authUser) await verlangeTurnstile(req);
    const ctx = await pruefeCheckoutKontext(authUser, 'stripe');
    const { bestellung } = await erstelleGastBestellungAusPayload(req.body, 'stripe', authUser, ctx);
    const sessionData = await erstelleStripeSessionFuerBestellung(bestellung.id, { gast: !authUser });

    return res.json({
      ok: true,
      gast: !authUser,
      bestellung_id: bestellung.id,
      ...sessionData
    });
  } catch (err) {
    console.error('❌ Gastbestellung Stripe Fehler:', err);
    return sendError(res, err, { ok: false });
  }
});

app.post('/api/checkout/gastbestellung/paypal', strictOrderLimiter, async (req, res) => {
  try {
    const authUser = await getOptionalUserFromAuthHeader(req);
    if (!authUser) await verlangeTurnstile(req);
    const ctx = await pruefeCheckoutKontext(authUser, 'paypal');
    const { bestellung } = await erstelleGastBestellungAusPayload(req.body, 'paypal', authUser, ctx);
    const orderData = await erstellePayPalOrderFuerBestellung(bestellung.id, { gast: !authUser });

    return res.json({
      ok: true,
      gast: !authUser,
      bestellung_id: bestellung.id,
      ...orderData
    });
  } catch (err) {
    console.error('❌ Gastbestellung PayPal Fehler:', err);
    return sendError(res, err, { ok: false });
  }
});

// Kauf auf Rechnung: nur eingeloggte Kunden mit serverseitig freigeschalteter Zahlungsart.
async function verarbeiteRechnungBestellung(bestellung_id) {
  const bestellung = await ladeBestellung(bestellung_id);

  if (bestellung.status === 'auf_rechnung') {
    if (String(bestellung.zahlungsart || '') !== 'rechnung') {
      const err = new Error('Inkonsistenter Rechnungskauf: Status auf_rechnung ohne Zahlungsart rechnung.');
      err.statusCode = 409;
      throw err;
    }
    // Wiederholungs-/Reparaturweg: Der Bestand wird NICHT erneut reduziert. Falls
    // die Lager-Mail im ersten Lauf fehlgeschlagen ist, wird sie nachgeholt.
    const positionen = await ladePositionen(bestellung_id);
    const patch = {};
    if (!bestellung.lager_status) patch.lager_status = 'in_bearbeitung';
    try {
      const lieferschein = await sendeLieferscheinAnsLager(bestellung_id, bestellung, positionen);
      Object.assign(patch, lieferschein.patch);
    } catch (e) { console.error('❌ Lieferschein Rechnungskauf (Wiederholung):', e.message); }
    if (Object.keys(patch).length) await supabaseUpdate('bestellungen', bestellung_id, patch);
    return { ok: true, already_processed: true, bestellung_id, bestellung };
  }
  if (bestellung.status === 'bezahlt') {
    return { ok: true, already_processed: true, bestellung_id, bestellung };
  }

  const calc = await berechneUndFixiereBestellungServerseitig(bestellung_id, {
    pruefeBestand: true,
    fixiere: true
  });
  if (calc.gesamtNetto <= 0) {
    const err = new Error('Ungültiger Zahlungsbetrag'); err.statusCode = 400; throw err;
  }

  // Feste Bestellung → Bestand reduzieren, Status auf 'auf_rechnung'.
  await reduziereLagerbestandAtomar(calc.positionen);
  await supabaseUpdate('bestellungen', bestellung_id, {
    zahlungsart: 'rechnung',
    status: 'auf_rechnung',
    zahlungs_id: `rechnung-${bestellung_id}`,
    lager_status: 'in_bearbeitung'
  });

  const bestellungVoll = await ladeBestellung(bestellung_id);
  const { gesamtNetto, lieferkostenNetto, warenwertNetto } = ermittleNettoBetraege(bestellungVoll);

  const emailHtml = `
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
      <div style="background:#3D2B1F;padding:20px;text-align:center;">
        <h1 style="color:#C49A2B;font-family:Georgia,serif;margin:0;">VisioTrade</h1>
        <p style="color:white;margin:5px 0 0;">Premium Parkett</p>
      </div>
      <div style="padding:30px;background:#FAF7F2;">
        <h2 style="color:#3D2B1F;">Auftragsbestätigung – Kauf auf Rechnung</h2>
        <p>Sehr geehrte/r ${escapeHtml(bestellungVoll.kundenname)},</p>
        <p>vielen Dank für Ihre Bestellung <strong>#${bestellung_id}</strong>${bestellungVoll.firma ? ' (' + escapeHtml(bestellungVoll.firma) + ')' : ''}.</p>
        <p>Ihre Bestellung wird auf Rechnung bearbeitet. Die Rechnung erhalten Sie separat.</p>

        <table style="width:100%;border-collapse:collapse;margin:20px 0;">
          <tr style="background:#F5EDD8;"><td style="padding:10px;font-weight:bold;">Bestellnummer</td><td style="padding:10px;">#${bestellung_id}</td></tr>
          <tr><td style="padding:10px;font-weight:bold;">Bestelldatum</td><td style="padding:10px;">${new Date().toLocaleDateString('de-DE')}</td></tr>
          <tr style="background:#F5EDD8;"><td style="padding:10px;font-weight:bold;">Zahlungsart</td><td style="padding:10px;">Kauf auf Rechnung</td></tr>
          ${bestellungVoll.filiale ? `<tr><td style="padding:10px;font-weight:bold;">Filiale</td><td style="padding:10px;">${escapeHtml(bestellungVoll.filiale)}</td></tr>` : ''}
          <tr><td style="padding:10px;font-weight:bold;">Warenwert netto</td><td style="padding:10px;">${euro(warenwertNetto)}</td></tr>
          <tr style="background:#F5EDD8;"><td style="padding:10px;font-weight:bold;">Lieferkosten netto</td><td style="padding:10px;">${lieferkostenNetto > 0 ? euro(lieferkostenNetto) : '0,00 €'}</td></tr>
          <tr><td style="padding:10px;font-weight:bold;">USt. 19 %</td><td style="padding:10px;">${euro(gesamtNetto * 0.19)}</td></tr>
          <tr style="background:#F5EDD8;"><td style="padding:10px;font-weight:bold;">Gesamtbetrag brutto</td><td style="padding:10px;font-weight:bold;color:#8B6914;">${euro(gesamtNetto * 1.19)}</td></tr>
        </table>

        ${bestellerHinweisBlock(bestellungVoll)}
        ${lieferadresseEmailBlock(bestellungVoll)}
        <div style="background:#FFF4D6;border:1px solid #E0C36B;border-radius:8px;padding:14px 16px;margin:0 0 16px;">
          <p style="margin:0;color:#6B4E00;font-size:14px;"><strong>${lieferzeitHinweisFuerBestellung(bestellungVoll)}</strong></p>
        </div>

        <p style="color:#6B7280;font-size:13px;margin-top:30px;">Bei Fragen stehen wir Ihnen gerne zur Verfügung.<br>VisioTrade GmbH</p>
      </div>
    </div>`;

  let abPdfRe = null;
  try {
    abPdfRe = await erzeugeProfiPdf('Auftragsbestätigung', bestellungVoll, calc.positionen, true);
  } catch (e) { console.warn('⚠️ AB-PDF (Kauf auf Rechnung) konnte nicht erzeugt werden:', e.message); }
  const _reToken = await bestellMailThreadToken(bestellungVoll);
  await sendeBestellEmail(bestellungVoll, betreffMitToken(`Auftragsbestätigung #${bestellung_id} (Kauf auf Rechnung) | VisioTrade`, _reToken), emailHtml, abPdfRe, `Auftragsbestaetigung_${bestellung_id}.pdf`, replyToToken(_reToken));

  // Rechnungskäufe sind sofort lagerfähig, obwohl noch keine Zahlung eingegangen
  // ist. Das Lager erhält einen echten, preislosen Lieferschein als PDF.
  try {
    const lieferschein = await sendeLieferscheinAnsLager(bestellung_id, bestellungVoll, calc.positionen);
    if (Object.keys(lieferschein.patch).length) {
      await supabaseUpdate('bestellungen', bestellung_id, lieferschein.patch);
    }
  } catch (e) {
    // Der Auftrag bleibt sichtbar (lager_status wurde bereits gesetzt). Ein
    // Mail-/PDF-Fehler darf nach erfolgter Bestandsbuchung keinen zweiten Checkout
    // provozieren; der Wiederholungsweg oben kann den Lieferschein nachholen.
    console.error('❌ Lieferschein Rechnungskauf:', e.message);
  }
  await sendeAdminBenachrichtigung(bestellungVoll);

  // Vorgangscenter: Kauf auf Rechnung → Eingang + Auftragsbestätigung sofort.
  await vorgangEreignis(bestellungVoll, 'bestellung_eingegangen', { text: 'Bestellung erfolgreich aufgenommen.', meta: { betrag: bestellungVoll.gesamtbetrag } });
  await vorgangEreignis(bestellungVoll, 'auftrag_bestaetigt', { text: 'Auftragsbestätigung erstellt (Kauf auf Rechnung).', meta: { dok_typ: 'auftragsbestaetigung' } });

  return {
    ok: true,
    bestellung_id,
    server_total_netto: gesamtNetto,
    server_total_brutto: round2(gesamtNetto * 1.19),
    status: 'auf_rechnung'
  };
}

app.post('/api/checkout/gastbestellung/rechnung', strictOrderLimiter, async (req, res) => {
  try {
    const authUser = await getOptionalUserFromAuthHeader(req);
    const ctx = await pruefeCheckoutKontext(authUser, 'rechnung'); // wirft 403, wenn nicht freigeschaltet
    const { bestellung } = await erstelleGastBestellungAusPayload(req.body, 'rechnung', authUser, ctx);
    const result = await verarbeiteRechnungBestellung(bestellung.id);
    return res.json({ ok: true, gast: false, bestellung_id: bestellung.id, ...result });
  } catch (err) {
    console.error('❌ Gastbestellung Rechnung Fehler:', err);
    return sendError(res, err, { ok: false });
  }
});

// Liefert dem eingeloggten Nutzer sein Kundenkonto-Profil (für Checkout-Anzeige + Kundenkonto).
app.get('/api/b2b/profil', async (req, res) => {
  try {
    const user = await getUserFromAuthHeader(req); // erfordert gültigen Login
    const ctx = await ensureKundenprofilFuerAuthUser(user);
    if (!ctx?.profil) {
      return res.json({ angemeldet: true, kundenkonto: false });
    }
    const p = ctx.profil;
    const istLeiter = (ctx.mitglied?.rolle || 'mitarbeiter') === 'einkaufsleiter';

    // Fallback-Daten für den Checkout-Prefill aus der jüngsten Firmenbestellung,
    // falls das Profil noch keine Stammdaten (Telefon/USt/Rechnungsadresse) hat.
    let letzte = null;
    try {
      const rows = await supabaseQuery(
        'bestellungen',
        `?or=(kundenprofil_id.eq.${p.id},user_id.eq.${user.id})&order=id.desc&limit=1` +
        `&select=kundenname,telefon,ust_idnr,rechnungsadresse_strasse,rechnungsadresse_plz,rechnungsadresse_ort,rechnungsadresse_land`
      );
      letzte = Array.isArray(rows) && rows[0] ? rows[0] : null;
    } catch (e) { console.warn('⚠️ Prefill-Fallback laden fehlgeschlagen:', e.message); }

    return res.json({
      angemeldet: true,
      kundenkonto: true,
      kundenprofil_id: p.id,
      kundennummer: 'VT-KD-' + String(p.id).padStart(5, '0'),
      firma: p.firma || null,
      kontakt_name: p.kontakt_name || null,
      mitarbeiter_name: ctx.mitglied?.name || null,
      einkaufsleiter_email: p.einkaufsleiter_email || null,
      telefon: p.telefon || null,
      ust_idnr: p.ust_idnr || null,
      steuernummer: p.steuernummer || null,
      kontakt_email: p.kontakt_email || null,
      rechnungsadresse_strasse: p.rechnungsadresse_strasse || null,
      rechnungsadresse_hausnr: p.rechnungsadresse_hausnr || null,
      rechnungsadresse_plz: p.rechnungsadresse_plz || null,
      rechnungsadresse_ort: p.rechnungsadresse_ort || null,
      rechnungsadresse_bundesland: p.rechnungsadresse_bundesland || null,
      rechnungsadresse_land: p.rechnungsadresse_land || null,
      lieferadresse_identisch: p.lieferadresse_identisch !== false,
      lieferadresse_strasse: p.lieferadresse_strasse || null,
      lieferadresse_hausnr: p.lieferadresse_hausnr || null,
      lieferadresse_plz: p.lieferadresse_plz || null,
      lieferadresse_ort: p.lieferadresse_ort || null,
      lieferadresse_bundesland: p.lieferadresse_bundesland || null,
      lieferadresse_land: p.lieferadresse_land || null,
      kunden_referenz: p.kunden_referenz || null,
      abteilung: p.abteilung || null,
      lieferhinweise: p.lieferhinweise || null,
      bestaetigung_email: p.bestaetigung_email || null,
      rechnung_email: p.rechnung_email || null,
      // Nur der Einkaufsleiter darf die Firmen-Stammdaten bearbeiten.
      darf_stammdaten_bearbeiten: istLeiter,
      // Eigene Filiale des Bestellers (Mitarbeiter-Filiale → sonst Stadt der Rechnungsadresse).
      meine_filiale: ctx.mitglied?.filiale || p.rechnungsadresse_ort || null,
      letzte_bestellung: letzte,
      rolle: ctx.mitglied?.rolle || 'mitarbeiter',
      aktiv: ctx.mitglied?.aktiv !== false,
      // Bonus/Rabatt NUR dem Einkaufsleiter offenlegen – Mitarbeiter sehen ihn weder
      // in der Oberfläche noch über die API.
      ...(istLeiter ? { bonus_prozent: toNumber(p.bonus_prozent, 0) } : {}),
      erlaubte_zahlungsarten: erlaubteZahlungsartenAusProfil(p)
      // `lieferzeit_hinweis` wurde hier ENTFERNT: Das B2B-Profil hat weder Bestellung
      // noch Lieferart noch Zahlungsart – ein Hinweis ohne diesen Zusammenhang ist
      // genau die Vermischung, die den Fehler bei #163 verursacht hat. Geprüft: keine
      // Oberfläche hat das Feld gelesen.
    });
  } catch (err) {
    console.error('❌ B2B-Profil Fehler:', err);
    return sendError(res, err);
  }
});

// Firmen-Stammdaten speichern (zentrale Adress-/Unternehmensverwaltung).
// NUR der Einkaufsleiter darf schreiben; Mitarbeiter erhalten 403. Reine
// Stammdatenpflege – bestehende Bestellungen/Belege bleiben unberührt.
app.put('/api/b2b/profil', paymentLimiter, async (req, res) => {
  try {
    console.log('➡️  PUT /api/b2b/profil – Request eingegangen. Body-Keys:', Object.keys(req.body || {}));
    const user = await getUserFromAuthHeader(req);
    const ctx = await ensureKundenprofilFuerAuthUser(user);
    console.log('   Auth/Context:', { userId: user?.id, profilId: ctx?.profil?.id, rolle: ctx?.mitglied?.rolle });
    if (!ctx?.profil) { const e = new Error('Kein Kundenkonto.'); e.statusCode = 403; throw e; }
    if (ctx.mitglied?.aktiv === false) { const e = new Error('Ihr Zugang ist deaktiviert.'); e.statusCode = 403; throw e; }
    if ((ctx.mitglied?.rolle || 'mitarbeiter') !== 'einkaufsleiter') {
      const e = new Error('Nur der Einkaufsleiter darf die Firmen-Stammdaten bearbeiten.'); e.statusCode = 403; throw e;
    }

    const b = req.body || {};
    const s = (v, max = 200) => { const t = String(v ?? '').trim(); return t ? t.slice(0, max) : null; };
    const istEmail = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(v || '').trim());

    // --- Pflichtfelder Unternehmensdaten ---
    const firma = s(b.firma, 160);
    const kontakt_email = s(b.kontakt_email, 160);
    if (!firma) { const e = new Error('Firmenname ist erforderlich.'); e.statusCode = 400; throw e; }
    if (!kontakt_email || !istEmail(kontakt_email)) { const e = new Error('Eine gültige E-Mail-Adresse ist erforderlich.'); e.statusCode = 400; throw e; }

    // --- Pflicht: Rechnungsadresse ---
    const r_strasse = s(b.rechnungsadresse_strasse, 160);
    const r_hausnr  = s(b.rechnungsadresse_hausnr, 30);
    const r_plz     = s(b.rechnungsadresse_plz, 20);
    const r_ort     = s(b.rechnungsadresse_ort, 120);
    const r_land    = s(b.rechnungsadresse_land, 60) || 'DE';
    if (!r_strasse || !r_hausnr || !r_plz || !r_ort) {
      const e = new Error('Rechnungsadresse: Straße, Hausnummer, PLZ und Ort sind erforderlich.'); e.statusCode = 400; throw e;
    }

    // --- Pflicht: Lieferadresse (oder identisch mit Rechnungsadresse) ---
    const identisch = b.lieferadresse_identisch !== false; // Default: identisch
    let l_strasse, l_hausnr, l_plz, l_ort, l_bundesland, l_land;
    if (identisch) {
      l_strasse = r_strasse; l_hausnr = r_hausnr; l_plz = r_plz; l_ort = r_ort;
      l_bundesland = s(b.rechnungsadresse_bundesland, 80); l_land = r_land;
    } else {
      l_strasse = s(b.lieferadresse_strasse, 160); l_hausnr = s(b.lieferadresse_hausnr, 30);
      l_plz = s(b.lieferadresse_plz, 20); l_ort = s(b.lieferadresse_ort, 120);
      l_bundesland = s(b.lieferadresse_bundesland, 80); l_land = s(b.lieferadresse_land, 60) || 'DE';
      if (!l_strasse || !l_hausnr || !l_plz || !l_ort) {
        const e = new Error('Lieferadresse: Straße, Hausnummer, PLZ und Ort sind erforderlich.'); e.statusCode = 400; throw e;
      }
    }

    // --- Optionale Benachrichtigungs-E-Mails (nur prüfen, wenn gesetzt) ---
    const bestaetigung_email = s(b.bestaetigung_email, 160);
    const rechnung_email = s(b.rechnung_email, 160);
    if (bestaetigung_email && !istEmail(bestaetigung_email)) { const e = new Error('E-Mail für Auftragsbestätigungen ist ungültig.'); e.statusCode = 400; throw e; }
    if (rechnung_email && !istEmail(rechnung_email)) { const e = new Error('E-Mail für Rechnungen ist ungültig.'); e.statusCode = 400; throw e; }

    const patch = {
      firma,
      kontakt_name: s(b.kontakt_name, 120),
      kontakt_email,
      telefon: s(b.telefon, 60),
      ust_idnr: s(b.ust_idnr, 40),
      rechnungsadresse_strasse: r_strasse,
      rechnungsadresse_hausnr: r_hausnr,
      rechnungsadresse_plz: r_plz,
      rechnungsadresse_ort: r_ort,
      rechnungsadresse_bundesland: s(b.rechnungsadresse_bundesland, 80),
      rechnungsadresse_land: r_land,
      lieferadresse_identisch: identisch,
      lieferadresse_strasse: l_strasse,
      lieferadresse_hausnr: l_hausnr,
      lieferadresse_plz: l_plz,
      lieferadresse_ort: l_ort,
      lieferadresse_bundesland: l_bundesland,
      lieferadresse_land: l_land,
      kunden_referenz: s(b.kunden_referenz, 80),
      abteilung: s(b.abteilung, 80),
      lieferhinweise: s(b.lieferhinweise, 2000),
      bestaetigung_email,
      rechnung_email
    };

    console.log('   DB-Update kundenprofil #' + ctx.profil.id + ' mit Feldern:', Object.keys(patch).join(', '));
    try {
      await supabaseUpdate('kundenprofil', ctx.profil.id, patch);
    } catch (dbErr) {
      console.error('   ❌ Supabase-Update fehlgeschlagen:', dbErr?.message, '| Detail:', dbErr?.detail || dbErr?.response || dbErr);
      const e = new Error('Datenbankfehler beim Speichern der Stammdaten: ' + (dbErr?.message || 'unbekannt'));
      e.statusCode = 500; throw e;
    }
    try { await schreibeAuditLog(req, 'b2b_stammdaten_aktualisiert', 'kundenprofil', ctx.profil.id, null, null); } catch (_) {}
    console.log('   ✅ Stammdaten gespeichert (kundenprofil #' + ctx.profil.id + ').');
    return res.json({ ok: true });
  } catch (err) {
    console.error('❌ B2B-Stammdaten speichern Fehler:', err?.statusCode || 500, '-', err?.message);
    console.error('   Stacktrace:', err?.stack || err);
    return sendError(res, err);
  }
});

// Rücksendungs-/Reklamationsfrist: 7 Tage ab Lieferdatum (geliefert_am).
// Gibt das Fristende (Ende des 7. Tages) zurück oder null, wenn (noch) nicht geliefert.
const REKLAMATION_TAGE = 7;
function reklamationFrist(o) {
  if (!o || !o.geliefert_am) return null;
  const d = new Date(o.geliefert_am);
  if (isNaN(d.getTime())) return null;
  d.setDate(d.getDate() + REKLAMATION_TAGE);
  d.setHours(23, 59, 59, 999);
  return d;
}

// Bestellungen des Kundenkontos. Einkaufsleiter sieht ALLE Bestellungen seiner Firma
// (nach kundenprofil_id), Mitarbeiter nur die selbst ausgelösten. Rolle wird
// serverseitig geprüft; gelesen wird mit dem geheimen Key (umgeht RLS kontrolliert).
app.get('/api/b2b/bestellungen', async (req, res) => {
  try {
    const user = await getUserFromAuthHeader(req);
    const ctx = await ensureKundenprofilFuerAuthUser(user);
    if (!ctx?.profil) return res.json({ ok: true, rolle: 'gast', bestellungen: [] });

    const istLeiter = ctx.mitglied?.rolle === 'einkaufsleiter';
    const uid = user.id;
    const filter = istLeiter
      // Firmenweit (inkl. evtl. Altbestellungen des Einkaufsleiters ohne kundenprofil_id).
      ? `?or=(kundenprofil_id.eq.${ctx.profil.id},user_id.eq.${uid})&deleted_at=is.null&order=erstellt_am.desc`
      // Mitarbeiter: nur eigene (per Auth-User-ID oder Alt-user_id).
      : `?or=(bestellt_von_auth_user_id.eq.${uid},user_id.eq.${uid})&deleted_at=is.null&order=erstellt_am.desc`;

    const orders = await supabaseQuery('bestellungen', filter) || [];

    // Self-Healing: Bestellungen mit Status „geliefert" ohne Lieferdatum bekommen
    // `geliefert_am` nachgetragen (nie überschreiben), damit die 7-Tage-Reklamationsfrist
    // berechnet werden kann. Betrifft v. a. Altbestellungen / per Dropdown gesetzte.
    await Promise.all(orders.map(async o => {
      if (String(o.status) === 'geliefert' && !o.geliefert_am) {
        const jetzt = new Date().toISOString();
        try { await supabaseUpdate('bestellungen', o.id, { geliefert_am: jetzt }); o.geliefert_am = jetzt; } catch (_) {}
      }
    }));

    const ids = orders.map(o => o.id).filter(Boolean);
    let positionen = [];
    if (ids.length) {
      positionen = await supabaseQuery('bestellpositionen', `?bestellung_id=in.(${ids.join(',')})&order=id.asc`) || [];
    }

    const bestellungen = orders.map(o => {
      // Rücksendung/Reklamation: nur nach Lieferung und innerhalb von 7 Tagen ab Lieferdatum.
      const frist = reklamationFrist(o);
      return {
        ...o,
        positionen: positionen.filter(p => Number(p.bestellung_id) === Number(o.id)),
        besteller_name: o.kundenname || null,
        besteller_email: o.bestellt_von_email || o.email || null,
        reklamation_moeglich: !!frist && frist.getTime() >= Date.now() && String(o.status) !== 'storniert',
        reklamation_frist: frist ? frist.toISOString() : null
      };
    });

    // Echte Rechnungsnummer (RE…) für Altbestellungen lazy aus Lexoffice nachtragen,
    // damit das Kundenkonto nicht „—" anzeigt, obwohl eine Rechnung existiert.
    if (process.env.LEXOFFICE_API_KEY) {
      await Promise.all(
        bestellungen
          .filter(b => b.lexoffice_id && !b.rechnung_nummer)
          .map(b => backfillRechnungNummer(b).catch(() => null))
      );
    }

    return res.json({ ok: true, rolle: ctx.mitglied?.rolle || 'mitarbeiter', bestellungen });
  } catch (err) {
    console.error('❌ B2B-Bestellungen Fehler:', err);
    return sendError(res, err);
  }
});

// =============================================================================
// Preisanfrage ab 500 m² (RFQ) – Phase 1: Kunde stellt Anfrage → eigener Vorgang
// =============================================================================
const PREISANFRAGE_MIN_M2 = 500;

// Paketrundung wie bei normalen Bestellungen: Wunschmenge auf volle VE/Pakete aufrunden.
function paPaketRundung(mengeWunsch, ve) {
  const w = Number(mengeWunsch) || 0;
  const v = Number(ve) || 0;
  if (v <= 0) return { pakete: null, effektiv: Math.round(w * 1000) / 1000 };
  // Epsilon gegen Float-Ungenauigkeit: ein exaktes Vielfaches (z. B. 503,808 = 123×4,096)
  // soll NICHT fälschlich auf das nächste Paket aufgerundet werden.
  const pakete = Math.ceil(w / v - 1e-6);
  return { pakete, effektiv: Math.round(pakete * v * 1000) / 1000 };
}
// Verbindliche Menge einer Position: effektiv (paketgerundet) – Fallback Wunschmenge.
function paBindeMenge(p) {
  return (p && p.menge_m2_effektiv != null) ? Number(p.menge_m2_effektiv) : (Number(p?.menge_m2_wunsch) || 0);
}

// Status-Labels (für Anzeige/Mails).
function paStatusLabel(s) {
  const m = {
    angefragt: 'Angefragt', in_pruefung: 'In Prüfung', angebot_erhalten: 'Angebot erhalten',
    rueckfrage: 'Rückfrage offen', angenommen: 'Angenommen', abgelehnt: 'Abgelehnt',
    abgelaufen: 'Abgelaufen', in_bestellung: 'In Bestellung umgewandelt'
  };
  return m[String(s || '').toLowerCase()] || 'Angefragt';
}

// Neue Preisanfrage anlegen. Verfügbarkeit ist NUR Information und blockiert NIE.
app.post('/api/b2b/preisanfragen', strictOrderLimiter, async (req, res) => {
  try {
    const user = await getUserFromAuthHeader(req);
    const ctx = await ensureKundenprofilFuerAuthUser(user);
    if (!ctx?.profil) { const e = new Error('Preisanfragen sind nur für angemeldete B2B-Kunden möglich.'); e.statusCode = 403; throw e; }
    if (ctx.profil.deleted_at || ctx.profil.aktiv === false) { const e = new Error('Ihr Firmenkundenkonto ist derzeit nicht aktiv.'); e.statusCode = 403; throw e; }

    const rohPositionen = Array.isArray(req.body?.positionen) ? req.body.positionen : [];
    if (!rohPositionen.length) { const e = new Error('Die Preisanfrage enthält keine Positionen.'); e.statusCode = 400; throw e; }
    if (rohPositionen.length > 50) { const e = new Error('Zu viele Positionen in einer Preisanfrage.'); e.statusCode = 400; throw e; }

    // Filiale serverseitig ableiten (wie bei Bestellungen) – Kunde kann sie nicht fälschen.
    const filiale = ctx.mitglied?.filiale || ctx.profil?.rechnungsadresse_ort || null;

    // Positionen serverseitig validieren: ≥ 500 m² je Position + Pflicht-Lieferdatum.
    const positionen = [];
    for (const p of rohPositionen) {
      const menge = Number(p.menge_m2_wunsch);
      if (!Number.isFinite(menge) || menge < PREISANFRAGE_MIN_M2) {
        const e = new Error(`Preisanfragen sind ab ${PREISANFRAGE_MIN_M2} m² je Position möglich.`); e.statusCode = 400; throw e;
      }
      const datum = String(p.wunsch_lieferdatum || '').trim();
      if (!/^\d{4}-\d{2}-\d{2}$/.test(datum)) {
        const e = new Error('Bitte geben Sie für jede Position ein gewünschtes Lieferdatum an.'); e.statusCode = 400; throw e;
      }
      // Paketgerundete (verbindliche) Menge aus der VE/Paketgröße ableiten.
      const ve = Number.isFinite(Number(p.ve_m2)) && Number(p.ve_m2) > 0 ? Number(p.ve_m2) : 0;
      const { pakete, effektiv } = paPaketRundung(menge, ve);
      positionen.push({
        produkt_id: Number.parseInt(p.produkt_id, 10) || null,
        produktname: String(p.produktname || '').trim().slice(0, 200),
        artikelnummer: String(p.artikelnummer || '').trim().slice(0, 80) || null,
        menge_m2_wunsch: Math.round(menge),          // Wunschmenge (Hinweis)
        ve_m2: ve || null,
        anzahl_pakete: pakete,
        menge_m2_effektiv: effektiv,                 // verbindliche, paketgerundete Menge
        verfuegbar_m2_snapshot: Number.isFinite(Number(p.verfuegbar_m2)) ? Math.max(0, Math.round(Number(p.verfuegbar_m2))) : null,
        bauvorhaben: String(p.bauvorhaben || '').trim().slice(0, 200) || null,
        wunsch_lieferdatum: datum,
        hinweis: String(p.hinweis || '').trim().slice(0, 500) || null
      });
    }

    const paRows = await supabaseInsert('preisanfragen', {
      kundenprofil_id: ctx.profil.id,
      erstellt_von_auth_user_id: user.id || null,
      erstellt_von_email: normalizeEmail(user.email) || null,
      erstellt_von_rolle: ctx.mitglied?.rolle || null,
      kundenname: ctx.mitglied?.name || ctx.profil.kontakt_name || null,
      firma: ctx.profil.firma || null,
      email: normalizeEmail(user.email) || null,
      telefon: ctx.profil.telefon || null,
      filiale,
      hinweis: String(req.body?.hinweis || '').trim().slice(0, 1000) || null,
      status: 'angefragt'
    });
    const pa = Array.isArray(paRows) ? paRows[0] : paRows;
    if (!pa?.id) throw new Error('Preisanfrage konnte nicht angelegt werden.');

    for (const pos of positionen) {
      await supabaseInsert('preisanfrage_positionen', { preisanfrage_id: pa.id, ...pos });
    }

    // Vorgangscenter: eigener Vorgang + Eingangs-Ereignis (eindeutig je PA).
    await vorgangEreignisPA(pa, 'preisanfrage_eingegangen', {
      text: `Preisanfrage ${pa.pa_nummer} eingegangen (${positionen.length} Position${positionen.length !== 1 ? 'en' : ''}). Wir prüfen Preis und Lieferzeit individuell und melden uns mit einem Angebot.`,
      meta: { pa_nummer: pa.pa_nummer, anzahl_positionen: positionen.length },
      status: 'offen'
    });

    // Admins informieren (nicht blockierend).
    try {
      const zeilen = positionen.map(p =>
        `<tr><td style="padding:4px 10px 4px 0;">${escapeHtml(p.produktname || '—')}${p.artikelnummer ? ' · ' + escapeHtml(p.artikelnummer) : ''}</td>` +
        `<td style="padding:4px 10px;text-align:right;"><strong>${p.menge_m2_wunsch} m²</strong></td>` +
        `<td style="padding:4px 0;color:#6B7280;">verf. ${p.verfuegbar_m2_snapshot == null ? '—' : p.verfuegbar_m2_snapshot + ' m²'} · bis ${escapeHtml(p.wunsch_lieferdatum)}${p.bauvorhaben ? ' · BV: ' + escapeHtml(p.bauvorhaben) : ''}</td></tr>`
      ).join('');
      const html = `<div style="font-family:Arial,sans-serif;color:#1F2937;max-width:640px;">
        <h2 style="color:#6B4E00;margin:0 0 6px;">📩 Neue Preisanfrage ${escapeHtml(pa.pa_nummer)}</h2>
        <p style="color:#6B7280;font-size:13px;margin:0 0 12px;">${escapeHtml(pa.firma || '—')}${filiale ? ' · Filiale: ' + escapeHtml(filiale) : ''} · ${escapeHtml(pa.erstellt_von_email || '—')}</p>
        <table style="font-size:14px;border-collapse:collapse;">${zeilen}</table>
        ${req.body?.hinweis ? `<p style="font-size:13px;margin:12px 0 0;"><strong>Hinweis:</strong> ${escapeHtml(String(req.body.hinweis).slice(0, 1000))}</p>` : ''}
        <p style="color:#6B7280;font-size:12px;margin:14px 0 0;">Bitte im Admin-Vorgangscenter prüfen und ein Angebot erstellen.</p>
      </div>`;
      await sendeMehrfachEmail(['visiotradegmbh@gmail.com'], `📩 Preisanfrage ${pa.pa_nummer} – ${pa.firma || ''}`.trim(), html, [], null);
    } catch (e) { console.warn('⚠️ Preisanfrage Admin-Mail:', e?.message); }

    return res.json({ ok: true, pa_nummer: pa.pa_nummer, id: pa.id });
  } catch (err) {
    console.error('❌ Preisanfrage anlegen:', err);
    return sendError(res, err);
  }
});

// Eigene Preisanfragen des B2B-Kunden (Einkaufsleiter: firmenweit; Mitarbeiter: eigene).
app.get('/api/b2b/preisanfragen', async (req, res) => {
  try {
    const user = await getUserFromAuthHeader(req);
    const ctx = await ensureKundenprofilFuerAuthUser(user);
    if (!ctx?.profil) return res.json({ ok: true, preisanfragen: [] });

    const istLeiter = ctx.mitglied?.rolle === 'einkaufsleiter';
    const filter = istLeiter
      ? `?kundenprofil_id=eq.${ctx.profil.id}&deleted_at=is.null&order=created_at.desc`
      : `?erstellt_von_auth_user_id=eq.${user.id}&deleted_at=is.null&order=created_at.desc`;
    const anfragen = await supabaseQuery('preisanfragen', filter) || [];

    const ids = anfragen.map(a => a.id).filter(Boolean);
    let positionen = [];
    if (ids.length) {
      positionen = await supabaseQuery('preisanfrage_positionen', `?preisanfrage_id=in.(${ids.join(',')})&order=id.asc`) || [];
    }
    const preisanfragen = anfragen.map(a => {
      const pos = positionen.filter(p => Number(p.preisanfrage_id) === Number(a.id));
      return {
        ...a,
        status_label: paStatusLabel(a.status),
        positionen: pos,
        summe: berechnePreisanfrageSumme(a, pos)
      };
    });

    return res.json({ ok: true, rolle: ctx.mitglied?.rolle || 'mitarbeiter', preisanfragen });
  } catch (err) {
    console.error('❌ B2B-Preisanfragen Fehler:', err);
    return sendError(res, err);
  }
});

// --- Preisanfrage-Summen (zentral, damit Backend & Frontend identisch rechnen) ---
function berechnePreisanfrageSumme(pa, positionen) {
  let warenwert = 0;
  let alleBepreist = positionen.length > 0;
  for (const p of positionen) {
    const preis = (p.angebot_final_preis_pro_m2 != null) ? Number(p.angebot_final_preis_pro_m2)
      : (p.angebot_preis_pro_m2 != null ? Number(p.angebot_preis_pro_m2) : null);
    if (preis == null || !Number.isFinite(preis)) { alleBepreist = false; continue; }
    // Zeilensumme = exakte (paketgerundete) Menge × Netto-Einzelpreis, erst die Zeile auf Cent runden.
    warenwert += Math.round(preis * paBindeMenge(p) * 100) / 100;
  }
  const r2 = n => Math.round(n * 100) / 100;
  // Erst am Ende auf Cent runden: Warenwert → Netto → MwSt(aus Netto) → Brutto(=Netto+MwSt).
  const warenwertR = r2(warenwert);
  const lieferkosten = r2(pa.angebot_gratis_lieferung ? 0 : (Number(pa.angebot_lieferkosten_netto) || 0));
  const netto = r2(warenwertR + lieferkosten);
  const mwst = r2(netto * 0.19);
  const brutto = r2(netto + mwst);
  return { warenwert: warenwertR, lieferkosten, netto, mwst, brutto, alleBepreist };
}

// =============================================================================
// Admin: Preisanfragen verwalten + Angebot erstellen (Phase 2)
// =============================================================================
const PA_ZAHLUNGSARTEN = ['vorkasse', 'paypal', 'stripe', 'rechnung'];

// Übersicht aller Preisanfragen (optional ?status=…).
app.get('/api/admin/preisanfragen', async (req, res) => {
  try {
    const _u = await assertAdmin(req); verbieteNurLager(_u, 'Preisanfragen');
    const status = String(req.query?.status || '').trim().toLowerCase();
    const filter = (status && status !== 'alle')
      ? `?status=eq.${encodeURIComponent(status)}&deleted_at=is.null&order=created_at.desc`
      : `?deleted_at=is.null&order=created_at.desc`;
    const anfragen = await supabaseQuery('preisanfragen', filter) || [];
    const ids = anfragen.map(a => a.id).filter(Boolean);
    let positionen = [];
    if (ids.length) positionen = await supabaseQuery('preisanfrage_positionen', `?preisanfrage_id=in.(${ids.join(',')})&order=id.asc`) || [];
    const liste = anfragen.map(a => {
      const pos = positionen.filter(p => Number(p.preisanfrage_id) === Number(a.id));
      return { ...a, status_label: paStatusLabel(a.status), positionen: pos, summe: berechnePreisanfrageSumme(a, pos) };
    });
    return res.json({ ok: true, preisanfragen: liste });
  } catch (err) { console.error('❌ admin preisanfragen', err); return sendError(res, err); }
});

// Anzahl offener (noch nicht bearbeiteter) Preisanfragen – für das Sidebar-Badge.
app.get('/api/admin/preisanfragen/anzahl', async (req, res) => {
  try {
    const _u = await assertAdmin(req); verbieteNurLager(_u, 'Preisanfragen');
    const rows = await supabaseQuery('preisanfragen', `?status=in.(angefragt,in_pruefung,rueckfrage)&deleted_at=is.null&select=id`) || [];
    return res.json({ ok: true, anzahl: Array.isArray(rows) ? rows.length : 0 });
  } catch (err) { console.error('❌ admin preisanfragen-anzahl', err); return sendError(res, err); }
});

// Status manuell setzen (z. B. „In Prüfung", „Abgelehnt", „Abgelaufen").
app.post('/api/admin/preisanfragen/:id/status', async (req, res) => {
  try {
    const _u = await assertAdmin(req); verbieteNurLager(_u, 'Preisanfragen');
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const ERLAUBT = ['angefragt', 'in_pruefung', 'angebot_erhalten', 'rueckfrage', 'angenommen', 'abgelehnt', 'abgelaufen', 'in_bestellung'];
    const status = String(req.body?.status || '').trim().toLowerCase();
    if (!ERLAUBT.includes(status)) { const e = new Error('Ungültiger Status.'); e.statusCode = 400; throw e; }
    const paRows = await supabaseQuery('preisanfragen', `?id=eq.${id}&limit=1`);
    const pa = Array.isArray(paRows) ? paRows[0] : null;
    if (!pa) { const e = new Error('Preisanfrage nicht gefunden.'); e.statusCode = 404; throw e; }
    await supabaseUpdate('preisanfragen', id, { status, updated_at: new Date().toISOString() });
    if (status === 'abgelehnt') await vorgangEreignisPA(pa, 'preisanfrage_abgelehnt', { text: `Preisanfrage ${pa.pa_nummer} wurde abgelehnt.`, meta: { pa_nummer: pa.pa_nummer }, idempotencyKey: `pa-${pa.id}:abgelehnt:${Date.now()}` });
    return res.json({ ok: true, status, status_label: paStatusLabel(status) });
  } catch (err) { console.error('❌ admin pa-status', err); return sendError(res, err); }
});

// Angebot zu einer Preisanfrage speichern + an den Kunden senden.
app.post('/api/admin/preisanfragen/:id/angebot', paymentLimiter, async (req, res) => {
  try {
    const _u = await assertAdmin(req); verbieteNurLager(_u, 'Preisanfragen');
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const paRows = await supabaseQuery('preisanfragen', `?id=eq.${id}&limit=1`);
    const pa = Array.isArray(paRows) ? paRows[0] : null;
    if (!pa) { const e = new Error('Preisanfrage nicht gefunden.'); e.statusCode = 404; throw e; }

    const b = req.body || {};
    const gratis = !!b.gratis_lieferung;
    const lieferkosten = gratis ? 0 : (Number.isFinite(Number(b.lieferkosten_netto)) ? Math.max(0, Number(b.lieferkosten_netto)) : null);
    const zahlungsart = PA_ZAHLUNGSARTEN.includes(String(b.zahlungsart)) ? String(b.zahlungsart) : null;
    const gueltigBis = /^\d{4}-\d{2}-\d{2}$/.test(String(b.gueltig_bis || '')) ? String(b.gueltig_bis) : null;
    const lieferdatum = /^\d{4}-\d{2}-\d{2}$/.test(String(b.lieferdatum || '')) ? String(b.lieferdatum) : null;

    // Positions-Preise übernehmen (final = Preis − Rabatt%, falls nicht explizit gesetzt).
    const posInput = Array.isArray(b.positionen) ? b.positionen : [];
    let mindEinPreis = false;
    for (const pp of posInput) {
      const pid = Number.parseInt(pp.id, 10);
      if (!Number.isInteger(pid)) continue;
      const preis = Number(pp.preis_pro_m2);
      const rabatt = Number(pp.rabatt_prozent);
      let final = Number(pp.final_preis_pro_m2);
      if (!Number.isFinite(final)) {
        final = Number.isFinite(preis) ? preis * (1 - (Number.isFinite(rabatt) ? rabatt : 0) / 100) : NaN;
      }
      if (Number.isFinite(final)) mindEinPreis = true;
      await supabaseUpdate('preisanfrage_positionen', pid, {
        angebot_preis_pro_m2: Number.isFinite(preis) ? preis : null,
        angebot_rabatt_prozent: Number.isFinite(rabatt) ? rabatt : null,
        angebot_final_preis_pro_m2: Number.isFinite(final) ? Math.round(final * 100) / 100 : null
      });
    }
    if (!mindEinPreis) { const e = new Error('Bitte mindestens für eine Position einen Preis eintragen.'); e.statusCode = 400; throw e; }

    await supabaseUpdate('preisanfragen', id, {
      status: 'angebot_erhalten',
      angebot_lieferkosten_netto: lieferkosten,
      angebot_gratis_lieferung: gratis,
      angebot_zahlungsart: zahlungsart,
      angebot_lieferdatum: lieferdatum,
      angebot_gueltig_bis: gueltigBis,
      angebot_kommentar: String(b.kommentar || '').trim().slice(0, 2000) || null,
      angebot_erstellt_am: new Date().toISOString(),
      updated_at: new Date().toISOString()
    });

    // Frisch laden (mit gespeicherten Preisen) für Summe + Mail.
    const posNeu = await supabaseQuery('preisanfrage_positionen', `?preisanfrage_id=eq.${id}&order=id.asc`) || [];
    const paNeu = { ...pa, angebot_lieferkosten_netto: lieferkosten, angebot_gratis_lieferung: gratis };
    const summe = berechnePreisanfrageSumme(paNeu, posNeu);

    await vorgangEreignisPA(pa, 'angebot_erstellt', {
      text: `Ihr Angebot zu ${pa.pa_nummer} liegt vor: ${summe.brutto.toFixed(2).replace('.', ',')} € brutto.${gueltigBis ? ' Gültig bis ' + gueltigBis + '.' : ''}`,
      meta: { pa_nummer: pa.pa_nummer, betrag: summe.brutto, waehrung: 'EUR', gueltig_bis: gueltigBis || undefined },
      status: 'beantwortet',
      idempotencyKey: `pa-${pa.id}:angebot_erstellt:${Date.now()}`   // Angebot kann mehrfach aktualisiert werden
    });

    // Kunde per E-Mail benachrichtigen (nicht blockierend).
    try {
      if (pa.email) {
        const zeilen = posNeu.map(p => {
          const fp = (p.angebot_final_preis_pro_m2 != null) ? Number(p.angebot_final_preis_pro_m2) : (p.angebot_preis_pro_m2 != null ? Number(p.angebot_preis_pro_m2) : null);
          const zeilensumme = fp != null ? fp * (Number(p.menge_m2_wunsch) || 0) : null;
          return `<tr><td style="padding:4px 10px 4px 0;">${escapeHtml(p.produktname || '—')}</td>` +
            `<td style="padding:4px 10px;text-align:right;">${p.menge_m2_wunsch} m²</td>` +
            `<td style="padding:4px 10px;text-align:right;">${fp != null ? fp.toFixed(2).replace('.', ',') + ' €/m²' : '—'}</td>` +
            `<td style="padding:4px 0;text-align:right;"><strong>${zeilensumme != null ? zeilensumme.toFixed(2).replace('.', ',') + ' €' : '—'}</strong></td></tr>`;
        }).join('');
        const html = `<div style="font-family:Arial,sans-serif;color:#1F2937;max-width:640px;">
          <h2 style="color:#6B4E00;margin:0 0 6px;">Ihr Angebot ${escapeHtml(pa.pa_nummer)}</h2>
          <p style="color:#6B7280;font-size:13px;margin:0 0 12px;">${escapeHtml(pa.firma || '')}</p>
          <table style="font-size:14px;border-collapse:collapse;width:100%;">${zeilen}</table>
          <hr style="border:none;border-top:1px solid #eee;margin:12px 0;">
          <table style="font-size:14px;margin-left:auto;">
            <tr><td style="padding:2px 16px 2px 0;color:#6B7280;">Warenwert netto</td><td style="text-align:right;">${summe.warenwert.toFixed(2).replace('.', ',')} €</td></tr>
            <tr><td style="padding:2px 16px 2px 0;color:#6B7280;">Lieferkosten netto</td><td style="text-align:right;">${gratis ? 'kostenlos' : summe.lieferkosten.toFixed(2).replace('.', ',') + ' €'}</td></tr>
            <tr><td style="padding:2px 16px 2px 0;color:#6B7280;">MwSt. 19 %</td><td style="text-align:right;">${summe.mwst.toFixed(2).replace('.', ',')} €</td></tr>
            <tr><td style="padding:2px 16px 2px 0;"><strong>Gesamt brutto</strong></td><td style="text-align:right;"><strong>${summe.brutto.toFixed(2).replace('.', ',')} €</strong></td></tr>
          </table>
          ${zahlungsart ? `<p style="font-size:13px;margin:12px 0 0;">Zahlungsart: <strong>${escapeHtml(zahlungsart)}</strong></p>` : ''}
          ${lieferdatum ? `<p style="font-size:13px;margin:4px 0 0;">Spätestes Lieferdatum: <strong>${escapeHtml(lieferdatum)}</strong></p>` : ''}
          ${gueltigBis ? `<p style="font-size:13px;margin:4px 0 0;">Angebot gültig bis: <strong>${escapeHtml(gueltigBis)}</strong></p>` : ''}
          ${b.kommentar ? `<div style="background:#F5EDD8;border-radius:8px;padding:12px;margin:12px 0 0;font-size:14px;">${escapeHtml(String(b.kommentar).slice(0, 2000)).replace(/\n/g, '<br>')}</div>` : ''}
          <p style="color:#6B7280;font-size:12px;margin:14px 0 0;">Das Angebot finden Sie auch in Ihrem Kundenkonto unter „Preisanfragen".</p>
        </div>`;
        await sendeMehrfachEmail([pa.email], `Angebot ${pa.pa_nummer} – VisioTrade`, html, [], null);
      }
    } catch (e) { console.warn('⚠️ Angebot-Mail:', e?.message); }

    return res.json({ ok: true, summe });
  } catch (err) { console.error('❌ admin angebot', err); return sendError(res, err); }
});

// Aus einer angenommenen Preisanfrage die verbindliche Bestellung erzeugen (fixe Preise).
async function erstelleBestellungAusPreisanfrage(paId, mengenInput) {
  const paRows = await supabaseQuery('preisanfragen', `?id=eq.${paId}&limit=1`);
  const pa = Array.isArray(paRows) ? paRows[0] : null;
  if (!pa) { const e = new Error('Preisanfrage nicht gefunden.'); e.statusCode = 404; throw e; }
  if (pa.bestellung_id) return { ok: true, already: true, bestellung_id: pa.bestellung_id };
  if (String(pa.status) !== 'angenommen') { const e = new Error('Es liegt keine angenommene Annahme des Kunden vor.'); e.statusCode = 400; throw e; }

  const positionen = await supabaseQuery('preisanfrage_positionen', `?preisanfrage_id=eq.${paId}&order=id.asc`) || [];
  if (!positionen.length) { const e = new Error('Die Preisanfrage hat keine Positionen.'); e.statusCode = 400; throw e; }
  const ad = pa.annahme_daten || {};
  const adMengen = {}; (ad.positionen || []).forEach(p => { adMengen[p.id] = Number(p.menge_m2); });
  const la = ad.lieferadresse || {};

  let profil = null;
  try { const pr = await supabaseQuery('kundenprofil', `?id=eq.${pa.kundenprofil_id}&limit=1`); profil = Array.isArray(pr) ? pr[0] : null; } catch (_) {}

  // Bestellmenge je Position: 1) Admin-Override (aus der Karte), 2) vom Kunden akzeptierte Menge, 3) Wunschmenge.
  const overrideMengen = {};
  (Array.isArray(mengenInput) ? mengenInput : []).forEach(m => {
    const pid = Number.parseInt(m.id, 10); const mv = Number(m.menge_m2);   // EXAKT (Paketrundung folgt)
    if (Number.isInteger(pid) && Number.isFinite(mv) && mv > 0) overrideMengen[pid] = mv;
  });

  let warenwert = 0;
  const bestellPos = positionen.map(p => {
    const fp = (p.angebot_final_preis_pro_m2 != null) ? Number(p.angebot_final_preis_pro_m2) : (p.angebot_preis_pro_m2 != null ? Number(p.angebot_preis_pro_m2) : 0);
    const ve = Number(p.ve_m2) || 0;
    const roh = overrideMengen[p.id] != null ? overrideMengen[p.id]
      : ((adMengen[p.id] != null && adMengen[p.id] > 0) ? adMengen[p.id] : paBindeMenge(p));
    // Verbindliche Bestellmenge IMMER paketgerundet (wie normale Bestellungen).
    const { pakete, effektiv } = paPaketRundung(roh, ve);
    const menge = effektiv;
    const gesamt = round2(fp * menge);
    warenwert += gesamt;
    return { produkt_id: p.produkt_id || null, produktname: p.produktname, menge, pakete, fp, gesamt, bauvorhaben: p.bauvorhaben || null };
  });
  warenwert = round2(warenwert);
  const lieferkosten = pa.angebot_gratis_lieferung ? 0 : round2(Number(pa.angebot_lieferkosten_netto) || 0);
  const gesamtNetto = round2(warenwert + lieferkosten);
  const zahlungsart = ['vorkasse', 'paypal', 'stripe', 'rechnung'].includes(String(pa.angebot_zahlungsart)) ? String(pa.angebot_zahlungsart) : 'rechnung';

  const orderRows = await supabaseInsert('bestellungen', {
    kundenname: pa.kundenname || profil?.kontakt_name || '',
    firma: pa.firma || profil?.firma || '',
    email: pa.email,
    telefon: pa.telefon || profil?.telefon || '',
    ust_idnr: profil?.ust_idnr || null,
    lieferart: 'lieferung',
    rechnungsadresse_strasse: profil?.rechnungsadresse_strasse || null,
    rechnungsadresse_plz: profil?.rechnungsadresse_plz || null,
    rechnungsadresse_ort: profil?.rechnungsadresse_ort || null,
    rechnungsadresse_land: profil?.rechnungsadresse_land || 'DE',
    abweichende_lieferadresse: !!(la.strasse || la.ort),
    lieferadresse_empfaenger: la.empfaenger || null,
    lieferadresse_strasse: la.strasse || null,
    lieferadresse_plz: la.plz || null,
    lieferadresse_ort: la.ort || null,
    lieferadresse_land: la.land || 'DE',
    lieferadresse_telefon: la.telefon || null,
    zahlungsart,
    // Erststatus = „Warte auf Zahlung" (Zahlungsart bleibt separat sichtbar). NICHT 'auf_rechnung'
    // – der eigentliche Zahlungseingang wird von VisioTrade bestätigt (danach 'bezahlt' → Bearbeitung).
    status: 'warte_auf_zahlung',
    warenwert_netto: warenwert,
    lieferkosten_netto: lieferkosten,
    gesamtbetrag: gesamtNetto,
    gesamt_brutto: round2(gesamtNetto * 1.19),
    transportkosten_netto: lieferkosten,
    bonusfaehige_netto_summe: warenwert,
    lieferkosten_spediteur: null,
    lieferkosten_intern: null,
    kundenprofil_id: pa.kundenprofil_id || null,
    bestellt_von_auth_user_id: pa.erstellt_von_auth_user_id || null,
    bestellt_von_email: pa.erstellt_von_email || null,
    bestellt_von_rolle: pa.erstellt_von_rolle || null,
    einkaufsleiter_email: profil?.einkaufsleiter_email || null,
    bonus_prozent_zum_bestellzeitpunkt: null,
    // Angebots-Bestellungen aus einer Preisanfrage laufen immer über Lieferung
    // (siehe `lieferart` oben) – der Hinweis entsteht trotzdem über dieselbe
    // Funktion, damit hier keine zweite Textquelle aufmacht.
    lieferzeit_hinweis: lieferzeitHinweis({ lieferart: 'lieferung', zahlungsart }),
    filiale: pa.filiale || null,
    aus_preisanfrage_id: pa.id,
    preise_fixiert: true,
    preisanfrage_nummer: pa.pa_nummer || null
  });
  const order = Array.isArray(orderRows) ? orderRows[0] : null;
  if (!order?.id) throw new Error('Bestellung konnte nicht erstellt werden.');

  // Alle Positionen in EINEM Insert (Batch statt N+1 – wie im Gast-Checkout, positionRows).
  const positionRows = bestellPos.map(bp => ({
    bestellung_id: order.id,
    produkt_id: bp.produkt_id,
    produktname: bp.produktname,
    paket_id: null,
    anzahl_pakete: bp.pakete != null ? bp.pakete : null,   // informativ (Angebots-Bestellung, kein Paketbezug)
    menge_m2_gesamt: bp.menge,
    preis_je_paket: bp.fp,   // Preis pro m² (fix aus Angebot)
    gesamtpreis: bp.gesamt,
    bauvorhaben: bp.bauvorhaben
  }));
  if (positionRows.length) await supabaseInsert('bestellpositionen', positionRows);

  await supabaseUpdate('preisanfragen', paId, { status: 'in_bestellung', bestellung_id: order.id, updated_at: new Date().toISOString() });

  const orderVoll = await ladeBestellung(order.id);
  // WICHTIG: KEINE Auftragsbestätigung bei der Erstellung. Die Bestellung startet mit
  // „Warte auf Zahlung"; die AB (PDF + Mail + Vorgangseintrag + Button) entsteht erst,
  // wenn der Admin den Zahlungseingang bestätigt (→ nachZahlungAuftragUndLieferschein).
  await vorgangEreignis(orderVoll, 'bestellung_eingegangen', { text: `Bestellung aus Angebot ${pa.pa_nummer} erstellt. Bitte Zahlung leisten – die Auftragsbestätigung folgt nach Zahlungseingang.`, meta: { betrag: orderVoll.gesamtbetrag, pa_nummer: pa.pa_nummer } });
  await vorgangEreignisPA(pa, 'preisanfrage_in_bestellung', { text: `Aus Angebot ${pa.pa_nummer} wurde Bestellung #${order.id} erstellt.`, meta: { pa_nummer: pa.pa_nummer }, status: 'beantwortet', idempotencyKey: `pa-${pa.id}:in_bestellung:${order.id}` });

  return { ok: true, bestellung_id: order.id };
}

app.post('/api/admin/preisanfragen/:id/bestellung-erstellen', paymentLimiter, async (req, res) => {
  try {
    const _u = await assertAdmin(req); verbieteNurLager(_u, 'Preisanfragen');
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const r = await erstelleBestellungAusPreisanfrage(id, Array.isArray(req.body?.positionen) ? req.body.positionen : null);
    return res.json(r);
  } catch (err) { console.error('❌ pa bestellung-erstellen', err); return sendError(res, err); }
});

// =============================================================================
// Nachrichten-/Vorgangscenter (Konstanten, Threads, fuegeNachrichtHinzu, Sichtbarkeit,
// E-Mail-Token-Sync, Telegram-Routing, Systemereignisse/vorgangEreignis[PA],
// dispatchKundenantwort, ladeTelegramDatei …) nach services/vorgang.js verschoben
// (Phase 4, Commit 11a + 11b). Import siehe oben.
// =============================================================================

// Webhook des Telegram-SUPPORT-Bots (getrennt vom Shop-Bot). Secret im Pfad.
app.post('/api/telegram/support-webhook/:secret', async (req, res) => {
  try {
    const secret = (process.env.TELEGRAM_SUPPORT_WEBHOOK_SECRET || '').trim();
    if (!secret || !secretsGleich(req.params.secret, secret)) return res.status(401).json({ ok: false });
    const upd = req.body || {};
    const msg = upd.message || upd.edited_message;
    if (!msg || !msg.from) return res.json({ ok: true });

    const from = msg.from;
    const chatId = String(msg.chat?.id || from.id);
    const userId = String(from.id);
    const name = [from.first_name, from.last_name].filter(Boolean).join(' ') || from.username || 'Telegram-Kunde';
    const externalRef = `telegram:${chatId}`;
    let text = String(msg.text || msg.caption || '').trim();

    // Deep-Link /start order_<id> → Bestellkontext.
    let startBestellId = null;
    const startMatch = text.match(/^\/start\s+order_(\d{1,6})/i);
    if (startMatch) { startBestellId = parseInt(startMatch[1], 10); text = text.replace(/^\/start\s+\S+/i, '').trim(); }
    if (/^\/start\b/i.test(text)) text = text.replace(/^\/start\b.*$/i, '').trim();

    // Anhänge (Foto/Dokument) herunterladen.
    const dateien = [];
    if (Array.isArray(msg.photo) && msg.photo.length) {
      const best = msg.photo[msg.photo.length - 1];
      const f = await ladeTelegramDatei(best.file_id, 'foto.jpg', 'image/jpeg');
      if (f) dateien.push(f);
    }
    if (msg.document) {
      const f = await ladeTelegramDatei(msg.document.file_id, msg.document.file_name, (msg.document.mime_type || '').toLowerCase());
      if (f) dateien.push(f);
    }
    // Zuordnung: Deep-Link (start order_X) > Referenz im Text > gespeicherte
    // Session (letzte Bestellung) > Kanal-Zuordnung. So bleibt der Bestellbezug
    // auch ohne erneuten Startparameter erhalten.
    const kanalKunde = await findeKundeFuerTelegram(userId);
    let bestellung = null;
    if (startBestellId) bestellung = await findeBestellungFuerReferenz({ bestellungId: startBestellId });
    if (!bestellung && text) { const ref = parseBestellReferenz(text); if (ref) bestellung = await findeBestellungFuerReferenz(ref); }
    if (!bestellung && kanalKunde?.letzte_bestellung_id) { try { bestellung = await ladeBestellung(kanalKunde.letzte_bestellung_id); } catch (_) {} }
    console.log(`📨 TG-Support: user=${userId} start=${startBestellId || '-'} bestellung=${bestellung?.id || 'keine'} text="${(text || '').slice(0, 60)}"`);

    // Reiner /start (ggf. mit order_X) ohne Inhalt: Session registrieren +
    // Begrüßung. Nachricht geht NICHT verloren – der Bestellbezug wird gemerkt.
    if (!text && !dateien.length) {
      let thread = null;
      if (bestellung) thread = await holeOderErstelleThreadFuerBestellung(bestellung, { kanal: 'telegram_support', name, kundenprofilId: kanalKunde?.kundenprofil_id || bestellung.kundenprofil_id });
      await speichereTelegramKanal(userId, { username: from.username, firstName: from.first_name, lastName: from.last_name, kundenprofilId: bestellung?.kundenprofil_id || kanalKunde?.kundenprofil_id || null, bestellungId: bestellung?.id || null, threadId: thread?.id || null });
      console.log(`✅ TG-Support: Session registriert (user=${userId}, bestellung=${bestellung?.id || 'keine'})`);
      try {
        await sendeTelegramSupport(chatId, bestellung
          ? `Sie sind jetzt mit Bestellung #${bestellung.id} verbunden. Schreiben Sie hier Ihre Frage – wir antworten Ihnen im Shop und hier.`
          : 'Willkommen beim VisioTrade-Support. Bitte schreiben Sie Ihre Frage – gern mit Bestellnummer (z. B. #84).');
      } catch (_) {}
      return res.json({ ok: true });
    }

    let thread;
    if (bestellung) {
      thread = await holeOderErstelleThreadFuerBestellung(bestellung, { kanal: 'telegram_support', name, kundenprofilId: kanalKunde?.kundenprofil_id || bestellung.kundenprofil_id });
    } else {
      thread = await holeOderErstelleAllgemeinenThread(externalRef, { kanal: 'telegram_support', name, kundenprofilId: kanalKunde?.kundenprofil_id || null, betreff: 'Telegram-Support: ' + name });
    }

    // Dedup über Telegram message_id.
    const extMsgId = `tg:${chatId}:${msg.message_id}`;
    const dup = await supabaseQuery('nachrichten', `?external_message_id=eq.${encodeURIComponent(extMsgId)}&limit=1`);
    if (Array.isArray(dup) && dup[0]) { console.log(`ℹ️ TG-Support: Duplikat ${extMsgId} übersprungen`); return res.json({ ok: true }); }

    // SPEICHERN (vor der Bot-Bestätigung!). Schlägt das fehl, wirft es →
    // catch loggt und es wird KEINE „Danke"-Bestätigung gesendet.
    const warOffen = ['beantwortet', 'erledigt', 'geschlossen'].includes(String(thread.status));
    await fuegeNachrichtHinzu(thread, bestellung, {
      text: text || '(nur Anhang)', dateien,
      absender: { authUserId: kanalKunde?.auth_user_id || null, email: null, name, rolle: 'kunde' },
      istAdmin: false, sichtbarkeit: 'kunde', neuerStatus: warOffen ? 'kundenantwort' : 'offen',
      quelle: 'telegram_support', kanal: 'telegram_support', externalChannel: 'telegram_support',
      externalMessageId: extMsgId, externalRef
    });
    // Session aktualisieren (Bestellbezug + Thread merken).
    await speichereTelegramKanal(userId, { username: from.username, firstName: from.first_name, lastName: from.last_name, kundenprofilId: bestellung?.kundenprofil_id || kanalKunde?.kundenprofil_id || null, bestellungId: bestellung?.id || null, threadId: thread.id });
    console.log(`✅ TG-Support: gespeichert in Thread ${thread.id}${bestellung ? ' (Bestellung #' + bestellung.id + ')' : ' (allgemein)'}`);

    // ERST JETZT (nach erfolgreichem Speichern) Bestätigung an den Kunden.
    try { await sendeTelegramSupport(chatId, 'Danke! Ihre Nachricht ist beim VisioTrade-Team eingegangen. Wir melden uns hier.'); } catch (e) { console.error('❌ TG-Bestätigung:', e.message); }
    // Admins per E-Mail benachrichtigen (Badge greift bei Bestell-Threads ohnehin).
    try {
      const empf = bestellung ? await nachrichtEmpfaenger(bestellung.id) : ['visiotradegmbh@gmail.com'];
      const b = bestellung || { id: '—', firma: '', rechnung_nummer: null };
      const html = baueNachrichtMailHtml({ titel: 'Neue Telegram-Support-Nachricht', bestellung: b, absenderName: name, absenderEmail: null, absenderRolle: 'Kunde (Telegram)', text: text || '(nur Anhang)', anzahlAnhaenge: dateien.length, fuerKunde: false });
      await sendeMehrfachEmail(empf, `💬 Telegram-Support${bestellung ? ' zu Bestellung #' + bestellung.id : ' (allgemeine Anfrage)'}`, html, [], null);
    } catch (e) { console.error('❌ TG-Support Admin-Mail:', e.message); }

    return res.json({ ok: true });
  } catch (err) { console.error('❌ Telegram-Support-Webhook', err); return res.status(200).json({ ok: false }); }
});

// GET: Chat-Verlauf einer Bestellung (Kunde/Mitarbeiter). Legt KEINEN Thread an.
app.get('/api/b2b/bestellungen/:id/thread', async (req, res) => {
  try {
    const user = await getUserFromAuthHeader(req);
    const ctx = await ensureKundenprofilFuerAuthUser(user);
    if (!ctx?.profil) { const e = new Error('Ihr Konto ist keinem Kundenkonto zugeordnet.'); e.statusCode = 403; throw e; }
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const bestellung = await ladeBestellung(id);
    if (!darfBestellungSehen(ctx, bestellung, user.id)) {
      const e = new Error('Diese Bestellung gehört nicht zu Ihrem Konto.'); e.statusCode = 403; throw e;
    }
    const rows = await supabaseQuery('nachrichten_threads', `?bestellung_id=eq.${id}&limit=1`);
    const thread = Array.isArray(rows) ? rows[0] : null;
    // Kunde sieht NUR kunde-sichtbare Nachrichten – keine internen Notizen.
    const nachrichten = thread ? await ladeThreadVerlauf(thread.id, ['kunde']) : [];
    if (thread) await markiereThreadGelesen(thread.id, user.id); // beim Öffnen als gelesen markieren
    return res.json({ ok: true, thread: thread || null, nachrichten });
  } catch (err) { console.error('❌ b2b thread', err); return sendError(res, err); }
});

// Ungelesene Kundennachrichten je Bestellung (für den roten Badge an der Bestellkarte).
app.get('/api/b2b/nachrichten/ungelesen', async (req, res) => {
  try {
    const user = await getUserFromAuthHeader(req);
    const ctx = await ensureKundenprofilFuerAuthUser(user);
    if (!ctx?.profil) return res.json({ ok: true, counts: {} });
    const ids = await ladeSichtbareBestellIds(ctx, user.id);
    const counts = await ungeleseneProBestellung(ids, user.id, ['kunde']);
    return res.json({ ok: true, counts });
  } catch (err) { console.error('❌ b2b ungelesen', err); return sendError(res, err); }
});

// Sammelübersicht aller Nachrichten-Threads des Kunden (für den Menüpunkt „Nachrichten").
// Nur kundensichtbare Nachrichten; interne Notizen bleiben außen vor.
app.get('/api/b2b/nachrichten', async (req, res) => {
  try {
    const user = await getUserFromAuthHeader(req);
    const ctx = await ensureKundenprofilFuerAuthUser(user);
    if (!ctx?.profil) return res.json({ ok: true, threads: [] });

    const out = [];

    // --- 1) Bestell-Vorgänge ---
    const bestellIds = await ladeSichtbareBestellIds(ctx, user.id);
    if (bestellIds.length) {
      const threads = await supabaseQuery('nachrichten_threads', `?bestellung_id=in.(${bestellIds.join(',')})&order=letzte_nachricht_am.desc&limit=200`) || [];
      if (threads.length) {
        const tIds = threads.map(t => t.id);
        const bIds = [...new Set(threads.map(t => t.bestellung_id).filter(Boolean))];
        const orders = await supabaseQuery('bestellungen', `?id=in.(${bIds.join(',')})&select=id,firma,kundenname,rechnung_nummer,status`) || [];
        const omap = {}; orders.forEach(o => { omap[o.id] = o; });
        const msgs = await supabaseQuery('nachrichten', `?thread_id=in.(${tIds.join(',')})&sichtbarkeit=eq.kunde&order=created_at.asc&select=thread_id,nachricht_text,ist_admin_antwort,created_at`) || [];
        const letzte = {}; msgs.forEach(m => { letzte[m.thread_id] = m; });
        const counts = await ungeleseneProBestellung(bIds, user.id, ['kunde']);
        threads.filter(t => letzte[t.id]).forEach(t => out.push({
          id: t.id, bestellung_id: t.bestellung_id, preisanfrage_id: null,
          typ: t.typ, status: t.status, betreff: t.betreff,
          letzte_nachricht_am: t.letzte_nachricht_am,
          bestellung: omap[t.bestellung_id] || null,
          letzte_nachricht: { text: letzte[t.id].nachricht_text, ist_admin_antwort: letzte[t.id].ist_admin_antwort, created_at: letzte[t.id].created_at },
          ungelesen: counts[t.bestellung_id] || 0
        }));
      }
    }

    // --- 2) Preisanfrage-Vorgänge (eigener Vorgang, KEINE Bestellung) ---
    const istLeiter = ctx.mitglied?.rolle === 'einkaufsleiter';
    const paFilter = istLeiter
      ? `?kundenprofil_id=eq.${ctx.profil.id}&deleted_at=is.null&select=id,pa_nummer,status`
      : `?erstellt_von_auth_user_id=eq.${user.id}&deleted_at=is.null&select=id,pa_nummer,status`;
    const pas = await supabaseQuery('preisanfragen', paFilter) || [];
    if (pas.length) {
      const paMap = {}; pas.forEach(p => { paMap[p.id] = p; });
      const paThreads = await supabaseQuery('nachrichten_threads', `?preisanfrage_id=in.(${pas.map(p => p.id).join(',')})&order=letzte_nachricht_am.desc&limit=200`) || [];
      if (paThreads.length) {
        const ptIds = paThreads.map(t => t.id);
        const pmsgs = await supabaseQuery('nachrichten', `?thread_id=in.(${ptIds.join(',')})&sichtbarkeit=eq.kunde&order=created_at.asc&select=thread_id,nachricht_text,ist_admin_antwort,created_at,absender_auth_user_id`) || [];
        const pLetzte = {}; pmsgs.forEach(m => { pLetzte[m.thread_id] = m; });
        const gelesen = await supabaseQuery('nachrichten_gelesen', `?thread_id=in.(${ptIds.join(',')})&user_id=eq.${user.id}&select=thread_id,gelesen_am`) || [];
        const gMap = {}; gelesen.forEach(g => { gMap[g.thread_id] = g.gelesen_am; });
        const unread = {};
        pmsgs.forEach(m => {
          if (m.absender_auth_user_id && String(m.absender_auth_user_id) === String(user.id)) return;
          const g = gMap[m.thread_id];
          if (g && new Date(m.created_at) <= new Date(g)) return;
          unread[m.thread_id] = (unread[m.thread_id] || 0) + 1;
        });
        paThreads.filter(t => pLetzte[t.id]).forEach(t => {
          const pa = paMap[t.preisanfrage_id] || {};
          out.push({
            id: t.id, bestellung_id: null, preisanfrage_id: t.preisanfrage_id,
            pa_nummer: pa.pa_nummer || null, pa_status: pa.status || null,
            typ: t.typ, status: t.status, betreff: t.betreff,
            letzte_nachricht_am: t.letzte_nachricht_am,
            bestellung: null,
            letzte_nachricht: { text: pLetzte[t.id].nachricht_text, ist_admin_antwort: pLetzte[t.id].ist_admin_antwort, created_at: pLetzte[t.id].created_at },
            ungelesen: unread[t.id] || 0
          });
        });
      }
    }

    out.sort((a, b) => new Date(b.letzte_nachricht_am || 0) - new Date(a.letzte_nachricht_am || 0));
    return res.json({ ok: true, threads: out });
  } catch (err) { console.error('❌ b2b nachrichten-uebersicht', err); return sendError(res, err); }
});

// --- Preisanfrage-Vorgang: Thread laden + Kunde antwortet ---------------------
// Lädt die Preisanfrage und prüft, ob der eingeloggte Kunde sie sehen darf
// (Einkaufsleiter: firmenweit; Mitarbeiter: nur eigene).
async function ladePreisanfrageFuerKunde(id, ctx, uid) {
  const rows = await supabaseQuery('preisanfragen', `?id=eq.${id}&deleted_at=is.null&limit=1`);
  const pa = Array.isArray(rows) ? rows[0] : null;
  if (!pa) return null;
  const istLeiter = ctx?.mitglied?.rolle === 'einkaufsleiter';
  const darf = istLeiter
    ? Number(pa.kundenprofil_id) === Number(ctx.profil.id)
    : String(pa.erstellt_von_auth_user_id) === String(uid);
  return darf ? pa : null;
}

app.get('/api/b2b/preisanfragen/:id/thread', async (req, res) => {
  try {
    const user = await getUserFromAuthHeader(req);
    const ctx = await ensureKundenprofilFuerAuthUser(user);
    if (!ctx?.profil) { const e = new Error('Nur für angemeldete B2B-Kunden.'); e.statusCode = 403; throw e; }
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const pa = await ladePreisanfrageFuerKunde(id, ctx, user.id);
    if (!pa) { const e = new Error('Diese Preisanfrage gehört nicht zu Ihrem Konto.'); e.statusCode = 403; throw e; }
    const thread = await holeOderErstelleThreadFuerPreisanfrage(pa);
    const nachrichten = await ladeThreadVerlauf(thread.id, ['kunde']);
    if (user.id) await markiereThreadGelesen(thread.id, user.id);
    const positionen = await supabaseQuery('preisanfrage_positionen', `?preisanfrage_id=eq.${id}&order=id.asc`) || [];
    const summe = berechnePreisanfrageSumme(pa, positionen);
    return res.json({ ok: true, thread, preisanfrage: { ...pa, status_label: paStatusLabel(pa.status), positionen, summe }, nachrichten });
  } catch (err) { console.error('❌ b2b pa-thread', err); return sendError(res, err); }
});

app.post('/api/b2b/preisanfragen/:id/nachricht', strictOrderLimiter, async (req, res) => {
  try {
    const user = await getUserFromAuthHeader(req);
    const ctx = await ensureKundenprofilFuerAuthUser(user);
    if (!ctx?.profil) { const e = new Error('Nur für angemeldete B2B-Kunden.'); e.statusCode = 403; throw e; }
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const pa = await ladePreisanfrageFuerKunde(id, ctx, user.id);
    if (!pa) { const e = new Error('Diese Preisanfrage gehört nicht zu Ihrem Konto.'); e.statusCode = 403; throw e; }
    const text = String(req.body?.nachricht || req.body?.text || '').trim();
    if (!text) { const e = new Error('Bitte geben Sie eine Nachricht ein.'); e.statusCode = 400; throw e; }
    if (text.length > 5000) { const e = new Error('Nachricht ist zu lang (max. 5000 Zeichen).'); e.statusCode = 400; throw e; }
    const dateien = Array.isArray(req.body?.anhaenge) ? req.body.anhaenge : (Array.isArray(req.body?.fotos) ? req.body.fotos : []);

    const thread = await holeOderErstelleThreadFuerPreisanfrage(pa);
    const warBeantwortet = ['beantwortet', 'erledigt', 'geschlossen'].includes(String(thread.status));
    const neuerStatus = warBeantwortet ? 'kundenantwort' : 'offen';
    const absenderName = ctx.mitglied?.name || pa.kundenname || null;
    const absenderEmail = normalizeEmail(user.email) || pa.email || null;

    await fuegeNachrichtHinzu(thread, null, {
      text, dateien,
      absender: { authUserId: user.id, email: absenderEmail, name: absenderName, rolle: ctx.mitglied?.rolle || 'mitarbeiter' },
      istAdmin: false, neuerStatus, quelle: 'account_chat'
    });
    // Kundenrückfrage → PA-Status auf „rueckfrage" (sofern Vorgang noch offen ist).
    if (!['angenommen', 'abgelehnt', 'in_bestellung'].includes(String(pa.status))) {
      try { await supabaseUpdate('preisanfragen', id, { status: 'rueckfrage', updated_at: new Date().toISOString() }); } catch (_) {}
    }
    // Admins benachrichtigen.
    try {
      const html = `<div style="font-family:Arial,sans-serif;color:#1F2937;max-width:640px;">
        <h2 style="color:#6B4E00;margin:0 0 6px;">💬 Kundenantwort zu Preisanfrage ${escapeHtml(pa.pa_nummer)}</h2>
        <p style="color:#6B7280;font-size:13px;margin:0 0 12px;">${escapeHtml(pa.firma || '')} · ${escapeHtml(absenderName || '')}${absenderEmail ? ' (' + escapeHtml(absenderEmail) + ')' : ''}</p>
        <div style="background:#F5EDD8;border-radius:8px;padding:14px;font-size:14px;line-height:1.6;">${escapeHtml(text).replace(/\n/g, '<br>')}</div>
      </div>`;
      await sendeMehrfachEmail(['visiotradegmbh@gmail.com'], `💬 Kundenantwort zu Preisanfrage ${pa.pa_nummer}`, html, [], absenderEmail || null);
    } catch (e) { console.warn('⚠️ PA-Kundenantwort-Mail:', e?.message); }

    const nachrichten = await ladeThreadVerlauf(thread.id, ['kunde']);
    return res.json({ ok: true, thread_id: thread.id, nachrichten });
  } catch (err) { console.error('❌ pa-nachricht senden', err); return sendError(res, err); }
});

// Kunde nimmt das Angebot an (Menge/Adresse anpassbar, Preis/m² bleibt fix) → zurück an VisioTrade.
app.post('/api/b2b/preisanfragen/:id/annehmen', strictOrderLimiter, async (req, res) => {
  try {
    const user = await getUserFromAuthHeader(req);
    const ctx = await ensureKundenprofilFuerAuthUser(user);
    if (!ctx?.profil) { const e = new Error('Nur für angemeldete B2B-Kunden.'); e.statusCode = 403; throw e; }
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const pa = await ladePreisanfrageFuerKunde(id, ctx, user.id);
    if (!pa) { const e = new Error('Diese Preisanfrage gehört nicht zu Ihrem Konto.'); e.statusCode = 403; throw e; }
    if (String(pa.status) === 'in_bestellung') { const e = new Error('Aus dieser Anfrage wurde bereits eine Bestellung erstellt.'); e.statusCode = 400; throw e; }
    if (!['angebot_erhalten', 'rueckfrage', 'angenommen'].includes(String(pa.status))) {
      const e = new Error('Für diese Anfrage liegt noch kein Angebot vor.'); e.statusCode = 400; throw e;
    }

    const positionen = await supabaseQuery('preisanfrage_positionen', `?preisanfrage_id=eq.${id}&order=id.asc`) || [];
    const inMengen = {};
    (Array.isArray(req.body?.positionen) ? req.body.positionen : []).forEach(p => {
      const pid = Number.parseInt(p.id, 10);
      const m = Number(p.menge_m2);   // EXAKT übernehmen (Paketrundung erfolgt separat)
      if (Number.isInteger(pid) && Number.isFinite(m) && m > 0) inMengen[pid] = m;
    });
    const annahmePos = positionen.map(p => {
      const ve = Number(p.ve_m2) || 0;
      // Angepasste Menge ebenfalls paketgerundet; ohne Anpassung die effektive (paketgerundete) Menge.
      const menge = inMengen[p.id] != null ? paPaketRundung(inMengen[p.id], ve).effektiv : paBindeMenge(p);
      return {
        id: p.id,
        produktname: p.produktname,
        menge_m2: menge,
        preis_pro_m2: (p.angebot_final_preis_pro_m2 != null) ? Number(p.angebot_final_preis_pro_m2) : (p.angebot_preis_pro_m2 != null ? Number(p.angebot_preis_pro_m2) : null)
      };
    });

    const la = req.body?.lieferadresse || {};
    const lieferadresse = {
      empfaenger: String(la.empfaenger || '').trim().slice(0, 160) || null,
      strasse: String(la.strasse || '').trim().slice(0, 160) || null,
      plz: String(la.plz || '').trim().slice(0, 16) || null,
      ort: String(la.ort || '').trim().slice(0, 120) || null,
      land: String(la.land || '').trim().slice(0, 80) || 'DE',
      telefon: String(la.telefon || '').trim().slice(0, 40) || null
    };
    const hinweis = String(req.body?.hinweis || '').trim().slice(0, 1000) || null;
    const annahme = { positionen: annahmePos, lieferadresse, hinweis, zahlungsart: pa.angebot_zahlungsart || null };

    // Neue Lieferadresse auf Wunsch dauerhaft im Kundenkonto ablegen (erscheint dann unter „Adressen").
    if (req.body?.lieferadresse_speichern && lieferadresse.strasse && lieferadresse.plz && lieferadresse.ort) {
      try {
        await supabaseInsert('kunden_adressen', {
          kundenprofil_id: ctx.profil.id, user_id: user.id,
          empfaenger: lieferadresse.empfaenger, strasse: lieferadresse.strasse,
          plz: lieferadresse.plz, ort: lieferadresse.ort, land: lieferadresse.land || 'DE',
          telefon: lieferadresse.telefon
        });
      } catch (e) { console.warn('⚠️ PA-Lieferadresse speichern:', e?.message); }
    }

    await supabaseUpdate('preisanfragen', id, {
      status: 'angenommen',
      angenommen_am: new Date().toISOString(),
      annahme_daten: annahme,
      updated_at: new Date().toISOString()
    });

    const warenwert = annahmePos.reduce((s, p) => s + (p.preis_pro_m2 != null ? p.preis_pro_m2 * p.menge_m2 : 0), 0);
    const lieferkosten = pa.angebot_gratis_lieferung ? 0 : (Number(pa.angebot_lieferkosten_netto) || 0);
    const brutto = Math.round((warenwert + lieferkosten) * 1.19 * 100) / 100;

    await vorgangEreignisPA(pa, 'angebot_angenommen', {
      text: `Angebot ${pa.pa_nummer} angenommen (${brutto.toFixed(2).replace('.', ',')} € brutto). VisioTrade erstellt nun die verbindliche Bestellung.`,
      meta: { pa_nummer: pa.pa_nummer, betrag: brutto, waehrung: 'EUR' },
      status: 'kundenantwort',
      idempotencyKey: `pa-${pa.id}:angenommen:${Date.now()}`
    });

    try {
      const zeilen = annahmePos.map(p => `<tr><td style="padding:3px 10px 3px 0;">${escapeHtml(p.produktname || '')}</td><td style="padding:3px 0;text-align:right;"><strong>${p.menge_m2} m²</strong>${p.preis_pro_m2 != null ? ' × ' + p.preis_pro_m2.toFixed(2).replace('.', ',') + ' €/m²' : ''}</td></tr>`).join('');
      const adrTxt = [lieferadresse.empfaenger, lieferadresse.strasse, [lieferadresse.plz, lieferadresse.ort].filter(Boolean).join(' '), lieferadresse.land].filter(Boolean).join(', ');
      const html = `<div style="font-family:Arial,sans-serif;color:#1F2937;max-width:640px;">
        <h2 style="color:#065F46;margin:0 0 6px;">✅ Angebot ${escapeHtml(pa.pa_nummer)} ANGENOMMEN</h2>
        <p style="color:#6B7280;font-size:13px;margin:0 0 12px;">${escapeHtml(pa.firma || '')} – bitte verbindliche Bestellung erstellen.</p>
        <table style="font-size:14px;border-collapse:collapse;">${zeilen}</table>
        ${adrTxt ? `<p style="font-size:13px;margin:12px 0 0;"><strong>Lieferadresse:</strong> ${escapeHtml(adrTxt)}</p>` : ''}
        ${hinweis ? `<p style="font-size:13px;margin:6px 0 0;"><strong>Hinweis:</strong> ${escapeHtml(hinweis)}</p>` : ''}
        <p style="font-size:13px;margin:6px 0 0;">Zahlungsart: <strong>${escapeHtml(pa.angebot_zahlungsart || '—')}</strong> · Gesamt ca. <strong>${brutto.toFixed(2).replace('.', ',')} €</strong> brutto</p>
      </div>`;
      await sendeMehrfachEmail(['visiotradegmbh@gmail.com'], `✅ Angebot ${pa.pa_nummer} angenommen – Bestellung erstellen`, html, [], pa.email || null);
    } catch (e) { console.warn('⚠️ PA-Annahme-Mail:', e?.message); }

    return res.json({ ok: true, status: 'angenommen', brutto });
  } catch (err) { console.error('❌ pa annehmen', err); return sendError(res, err); }
});

// Kunde lehnt das Angebot ab.
app.post('/api/b2b/preisanfragen/:id/ablehnen', strictOrderLimiter, async (req, res) => {
  try {
    const user = await getUserFromAuthHeader(req);
    const ctx = await ensureKundenprofilFuerAuthUser(user);
    if (!ctx?.profil) { const e = new Error('Nur für angemeldete B2B-Kunden.'); e.statusCode = 403; throw e; }
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const pa = await ladePreisanfrageFuerKunde(id, ctx, user.id);
    if (!pa) { const e = new Error('Diese Preisanfrage gehört nicht zu Ihrem Konto.'); e.statusCode = 403; throw e; }
    if (String(pa.status) === 'in_bestellung') { const e = new Error('Aus dieser Anfrage wurde bereits eine Bestellung erstellt.'); e.statusCode = 400; throw e; }
    const grund = String(req.body?.grund || '').trim().slice(0, 500) || null;
    await supabaseUpdate('preisanfragen', id, { status: 'abgelehnt', abgelehnt_am: new Date().toISOString(), updated_at: new Date().toISOString() });
    await vorgangEreignisPA(pa, 'angebot_abgelehnt', {
      text: `Angebot ${pa.pa_nummer} vom Kunden abgelehnt.${grund ? ' Grund: ' + grund : ''}`,
      meta: { pa_nummer: pa.pa_nummer, grund: grund || undefined }, status: 'kundenantwort',
      idempotencyKey: `pa-${pa.id}:abgelehnt-kunde:${Date.now()}`
    });
    try {
      const html = `<div style="font-family:Arial,sans-serif;color:#1F2937;"><h2 style="color:#991B1B;margin:0 0 6px;">Angebot ${escapeHtml(pa.pa_nummer)} abgelehnt</h2><p style="font-size:13px;">${escapeHtml(pa.firma || '')}${grund ? ' · Grund: ' + escapeHtml(grund) : ''}</p></div>`;
      await sendeMehrfachEmail(['visiotradegmbh@gmail.com'], `Angebot ${pa.pa_nummer} abgelehnt`, html, [], pa.email || null);
    } catch (_) {}
    return res.json({ ok: true, status: 'abgelehnt' });
  } catch (err) { console.error('❌ pa ablehnen', err); return sendError(res, err); }
});

// =============================================================================
// Inbound-E-Mail-Webhook: eingehende Antworten werden dem Thread zugeordnet
// und im Chat gespeichert (Kunde ⇄ Admin bleiben synchron).
// =============================================================================
// Konfiguration (Railway-ENV):
//   INBOUND_EMAIL_DOMAIN   z. B. inbound.visiotrade.shop  (MX → Mail-Anbieter)
//   INBOUND_WEBHOOK_SECRET geheimes Token; Provider ruft auf:
//     POST /api/inbound/email?key=<SECRET>
// Provider (z. B. Brevo Inbound Parsing) muss eingehende Mails als JSON posten.
// -----------------------------------------------------------------------------
function inboundFeldText(item) {
  // Bevorzugt den „nur neuen" Teil; sonst Plaintext.
  return item.ExtractedMarkdownMessage || item.RawTextBody || item.TextBody || item.text || item.body || '';
}
function inboundHeaderWert(item, name) {
  const h = item.Headers || item.headers || {};
  if (Array.isArray(h)) { const f = h.find(x => String(x.Name || x.name || '').toLowerCase() === name.toLowerCase()); return f ? (f.Value || f.value) : null; }
  return h[name] || h[name.toLowerCase()] || null;
}

app.post('/api/inbound/email', async (req, res) => {
  try {
    // Absicherung: ohne Secret nicht nutzbar.
    const secret = (process.env.INBOUND_WEBHOOK_SECRET || '').trim();
    if (!secret) return res.status(503).json({ ok: false, error: 'Inbound nicht konfiguriert.' });
    const key = (req.query?.key || req.headers['x-inbound-key'] || '').toString();
    if (!secretsGleich(key, secret)) return res.status(401).json({ ok: false, error: 'Unauthorized' });

    const items = Array.isArray(req.body?.items) ? req.body.items : [req.body || {}];
    let verarbeitet = 0;

    for (const item of items) {
      const from = normalizeEmail(item.From?.Address || item.From?.address || item.from || item.sender || '');
      const subject = item.Subject || item.subject || '';
      const toList = (Array.isArray(item.To) ? item.To : (item.to ? [item.to] : [])).map(t => (t.Address || t.address || t)).join(' ');
      const replyTo = item.ReplyTo?.Address || item.ReplyTo || item.replyTo || '';
      const messageId = inboundHeaderWert(item, 'Message-Id') || inboundHeaderWert(item, 'Message-ID') || item.MessageId || null;
      const inReplyTo = inboundHeaderWert(item, 'In-Reply-To') || item.InReplyTo || null;

      const token = extrahiereThreadToken({ to: toList, replyTo, subject });
      if (!token || !from) continue;

      const trows = await supabaseQuery('nachrichten_threads', `?email_thread_token=eq.${encodeURIComponent(token)}&limit=1`);
      const thread = Array.isArray(trows) ? trows[0] : null;
      if (!thread) { console.warn('Inbound: kein Thread für Token', token); continue; }

      // Dedup über Message-ID.
      if (messageId) {
        const dup = await supabaseQuery('nachrichten', `?email_message_id=eq.${encodeURIComponent(messageId)}&limit=1`);
        if (Array.isArray(dup) && dup[0]) { verarbeitet++; continue; }
      }

      const bestellung = await ladeBestellung(thread.bestellung_id);

      // Absender-Rolle bestimmen – nur bekannte Teilnehmer dürfen schreiben.
      let istAdmin = false, istIntern = false, rolle = null, absenderAuthId = null;
      if (from === normalizeEmail(LAGER_EMAIL)) {
        // Antwort vom Lager-Postfach → INTERNE Notiz (nicht kundensichtbar).
        istIntern = true; rolle = 'lager';
      } else {
        const adminRows = await supabaseQuery('admin_users', `?email=ilike.${encodeURIComponent(from)}&limit=1`);
        const adminRow = Array.isArray(adminRows) ? adminRows[0] : null;
        if (adminRow && adminRow.aktiv !== false) {
          istAdmin = true; rolle = adminRow.ist_super_admin ? 'superadmin' : 'admin'; absenderAuthId = adminRow.auth_user_id || null;
        } else {
          // Kundenseite: gehört die Absender-Adresse zu dieser Bestellung/Firma?
          const kundenMails = [thread.erstellt_von_email, bestellung.bestellt_von_email, bestellung.email].map(normalizeEmail).filter(Boolean);
          let gehoertDazu = kundenMails.includes(from);
          let mitglied = null;
          if (bestellung.kundenprofil_id) {
            const mrows = await supabaseQuery('kunden_mitarbeiter', `?kundenprofil_id=eq.${bestellung.kundenprofil_id}&email=ilike.${encodeURIComponent(from)}&limit=1`);
            mitglied = Array.isArray(mrows) ? mrows[0] : null;
            if (mitglied) gehoertDazu = true;
          }
          if (!gehoertDazu) { console.warn('Inbound: Absender gehört nicht zum Thread', from, token); continue; }
          rolle = mitglied?.rolle || 'kunde'; absenderAuthId = mitglied?.auth_user_id || null;
        }
      }

      const text = bereinigeEmailText(inboundFeldText(item));
      if (!text && !(Array.isArray(item.Attachments) && item.Attachments.length)) continue;

      // Anhänge (nur jpg/png/pdf) → in dateien-Form bringen. Brevo liefert i. d. R.
      // nur einen DownloadToken → Datei bei Brevo nachladen und base64-kodieren.
      const rawAtt = Array.isArray(item.Attachments) ? item.Attachments : (Array.isArray(item.attachments) ? item.attachments : []);
      const dateien = [];
      for (const att of rawAtt) {
        const name = att.Name || att.name || 'anhang';
        const typ = String(att.ContentType || att.contentType || att.mime_type || '').toLowerCase();
        let b64 = att.Content || att.content || att.ContentBytes || '';
        const tok = att.DownloadToken || att.downloadToken || null;
        if (!b64 && tok && process.env.BREVO_API_KEY) {
          try {
            const r = await fetchFn(`https://api.brevo.com/v3/inbound/attachments/${encodeURIComponent(tok)}`, { headers: { 'api-key': process.env.BREVO_API_KEY, Accept: 'application/octet-stream' } });
            if (r.ok) { const buf = await readResponseBuffer(r); if (buf && buf.length) b64 = buf.toString('base64'); }
          } catch (_) {}
        }
        if (b64) dateien.push({ name, typ, contentBase64: b64 });
      }

      // Status: Admin-Antwort → beantwortet; Kundenantwort → kundenantwort/offen.
      const warOffenStatus = ['beantwortet', 'erledigt', 'geschlossen'].includes(String(thread.status));
      // Interne (Lager-)Antwort ändert den Kunden-Status NICHT.
      const neuerStatus = istAdmin ? 'beantwortet' : (istIntern ? null : (warOffenStatus ? 'kundenantwort' : 'offen'));
      const sichtbarkeit = istIntern ? 'intern_admin' : 'kunde';

      await fuegeNachrichtHinzu(thread, bestellung, {
        text: text || '(nur Anhang)', dateien,
        absender: { authUserId: absenderAuthId, email: from, name: (item.From?.Name || item.from_name || from), rolle },
        istAdmin, sichtbarkeit, neuerStatus,
        quelle: 'email_inbound', emailMessageId: messageId, emailInReplyTo: inReplyTo
      });
      verarbeitet++;

      // Relay an die GEGENSEITE (geht nie an den Absender zurück → keine Schleife).
      try {
        const token2 = await ensureThreadToken(thread);
        if (istAdmin) {
          // Admin hat per E-Mail geantwortet → Kunde/Gast benachrichtigen.
          const ziel = kundenZielEmail(thread, bestellung);
          if (ziel) {
            const html = baueNachrichtMailHtml({ titel: 'Antwort vom VisioTrade Team', bestellung, absenderName: 'VisioTrade Team', absenderEmail: null, absenderRolle: 'Team', text, anzahlAnhaenge: dateien.length, fuerKunde: true, link: process.env.FRONTEND_URL || null });
            await sendeMehrfachEmail([ziel], betreffMitToken(`Antwort zu Ihrer Bestellung #${bestellung.id}`, token2), html, [], replyToToken(token2));
          }
        } else {
          // Kunde ODER Lager hat per E-Mail geantwortet → Admins benachrichtigen (nie an den Absender zurück).
          const empfaenger = await nachrichtEmpfaenger(bestellung.id);
          const titel = istIntern ? 'Interne Lager-Antwort' : 'Neue Kundennachricht';
          const html = baueNachrichtMailHtml({ titel, bestellung, absenderName: from, absenderEmail: from, absenderRolle: rolle, text, anzahlAnhaenge: dateien.length, fuerKunde: false });
          await sendeMehrfachEmail(empfaenger, betreffMitToken(`${istIntern ? '📦 Lager-Antwort' : '🛠 Kundenantwort'} zu Bestellung #${bestellung.id}`, token2), html, [], replyToToken(token2));
        }
      } catch (e) { console.error('❌ Inbound-Relay:', e.message); }
    }

    return res.json({ ok: true, verarbeitet });
  } catch (err) { console.error('❌ Inbound-Webhook', err); return res.status(200).json({ ok: false }); }
});

// POST: Kunde/Mitarbeiter schreibt eine Nachricht zu einer Bestellung (Thread-Chat).
app.post('/api/b2b/bestellungen/:id/nachricht', strictOrderLimiter, async (req, res) => {
  try {
    const user = await getUserFromAuthHeader(req);
    const ctx = await ensureKundenprofilFuerAuthUser(user);
    if (!ctx?.profil) { const e = new Error('Ihr Konto ist keinem Kundenkonto zugeordnet.'); e.statusCode = 403; throw e; }

    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const bestellung = await ladeBestellung(id);
    if (!darfBestellungSehen(ctx, bestellung, user.id)) {
      const e = new Error('Diese Bestellung gehört nicht zu Ihrem Konto.'); e.statusCode = 403; throw e;
    }

    // typ akzeptiert sowohl die neuen als auch die alten Schlüssel (Abwärtskompatibilität).
    let typRaw = String(req.body?.typ || req.body?.kategorie || 'nachricht').toLowerCase();
    if (typRaw === 'sonstiges' && req.body?.kategorie === 'sonstiges') typRaw = 'sonstiges';
    const typ = NACHRICHT_TYPEN.includes(typRaw) ? typRaw : 'nachricht';
    const text = String(req.body?.nachricht || req.body?.text || '').trim();
    if (!text) { const e = new Error('Bitte geben Sie eine Nachricht ein.'); e.statusCode = 400; throw e; }
    if (text.length > 5000) { const e = new Error('Nachricht ist zu lang (max. 5000 Zeichen).'); e.statusCode = 400; throw e; }

    // Akzeptiert sowohl das neue Feld `anhaenge` als auch das alte `fotos`.
    const dateien = Array.isArray(req.body?.anhaenge) ? req.body.anhaenge
      : (Array.isArray(req.body?.fotos) ? req.body.fotos : []);

    const absenderRolle = ctx.mitglied?.rolle || 'mitarbeiter';
    const absenderName = ctx.mitglied?.name || bestellung.kundenname || null;
    const absenderEmail = normalizeEmail(user.email) || bestellung.bestellt_von_email || null;

    const thread = await holeOderErstelleThread(bestellung, ctx, user, typ);
    // Antwortet der Kunde auf eine bereits beantwortete/erledigte Anfrage → wieder „Kundenantwort".
    const warBeantwortet = ['beantwortet', 'erledigt', 'geschlossen'].includes(String(thread.status));
    const neuerStatus = warBeantwortet ? 'kundenantwort' : 'offen';

    await fuegeNachrichtHinzu(thread, bestellung, {
      text, typ, dateien,
      absender: { authUserId: user.id, email: absenderEmail, name: absenderName, rolle: absenderRolle },
      istAdmin: false, neuerStatus, quelle: 'account_chat'
    });
    // Vorgangscenter: erstes Eröffnen einer Reklamation/Rücksendung als Systemereignis (einmalig je Vorgang).
    if (typ === 'reklamation') await vorgangEreignis(bestellung, 'reklamation_eroeffnet', { text: 'Reklamation eröffnet.' });
    else if (typ === 'ruecksendung') await vorgangEreignis(bestellung, 'ruecksendung', { text: 'Rücksendung erstellt.' });

    // E-Mail an Admins. Reply-To = Thread-Token (falls Inbound konfiguriert), damit eine
    // Antwort des Admins per E-Mail automatisch wieder im Thread landet – sonst Kunde als Reply-To.
    try {
      const token = await ensureThreadToken(thread);
      const empfaenger = await nachrichtEmpfaenger(id);
      const html = baueNachrichtMailHtml({
        titel: typLabelServer(typ), bestellung, absenderName, absenderEmail, absenderRolle,
        text, anzahlAnhaenge: Array.isArray(dateien) ? dateien.length : 0, fuerKunde: false
      });
      const replyTo = replyToToken(token) || absenderEmail || null;
      await sendeMehrfachEmail(empfaenger, betreffMitToken(`🛠 ${typLabelServer(typ)} zu Bestellung #${id}`, token), html, [], replyTo);
    } catch (e) { console.error('❌ Nachricht-Mail (Admin):', e.message); }

    try {
      const adminChat = process.env.TELEGRAM_ADMIN_CHAT_ID || process.env.TELEGRAM_CHAT_ID;
      if (adminChat) {
        await sendeTelegram(adminChat,
          `🛠 <b>${typLabelServer(typ)} zu Bestellung #${id}</b>\n👤 ${absenderName || '—'} (${absenderRolle})\n\n${text.slice(0, 500)}`);
      }
    } catch (_) {}

    const nachrichten = await ladeThreadVerlauf(thread.id);
    return res.json({ ok: true, thread_id: thread.id, nachrichten });
  } catch (err) { console.error('❌ Bestell-Nachricht senden', err); return sendError(res, err); }
});

// =============================================================================
// B2B: Mitarbeiter-Verwaltung + Einladungen (Einkaufsleiter)
// =============================================================================

// Supabase Auth Admin API (nutzt den geheimen Server-Key).
async function supabaseAuthAdmin(path, options = {}) {
  const url = requiredEnv('SUPABASE_URL');
  const key = getSupabaseKey();
  const res = await fetchFn(`${url}/auth/v1/${path}`, {
    ...options,
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      'Content-Type': 'application/json',
      ...(options.headers || {})
    }
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Supabase Auth Fehler ${res.status}: ${text}`);
  return text ? JSON.parse(text) : null;
}

// Liest einen Auth-User (für last_sign_in_at → „Einladung angenommen"). Fehlertolerant.
async function holeAuthUserAdmin(userId) {
  if (!userId) return null;
  try {
    return await supabaseAuthAdmin(`admin/users/${encodeURIComponent(userId)}`, { method: 'GET' });
  } catch (_) { return null; }
}

// Erzeugt einen sicheren Einladungslink (legt den Auth-User an, falls neu).
// Der Mitarbeiter setzt darüber selbst sein Passwort (Supabase Auth).
async function erzeugeEinladungsLink(email) {
  const redirect = `${requiredEnv('FRONTEND_URL')}?set_password=1`;
  const baue = (type) => supabaseAuthAdmin('admin/generate_link', {
    method: 'POST',
    body: JSON.stringify({ type, email, redirect_to: redirect })
  });
  let data;
  try {
    data = await baue('invite');
  } catch (e) {
    // Bereits registriert → Passwort-Setzen per Recovery-Link.
    if (/registered|exists|already/i.test(e.message)) data = await baue('recovery');
    else throw e;
  }
  return {
    link: data?.action_link || data?.properties?.action_link || null,
    user_id: data?.user?.id || data?.id || null
  };
}

// Stellt sicher, dass der eingeloggte Nutzer Einkaufsleiter eines Kundenkontos ist.
async function ladeKundenprofilFuerLeiter(authUser) {
  const ctx = await ladeKundenprofilFuerAuthUser(authUser);
  if (!ctx?.profil) {
    const e = new Error('Ihr Konto ist keinem Kundenkonto zugeordnet.'); e.statusCode = 403; throw e;
  }
  if (ctx.mitglied?.rolle !== 'einkaufsleiter') {
    const e = new Error('Nur der Einkaufsleiter darf Mitarbeiter verwalten.'); e.statusCode = 403; throw e;
  }
  if (ctx.mitglied?.aktiv === false) {
    const e = new Error('Ihr Zugang ist deaktiviert.'); e.statusCode = 403; throw e;
  }
  return ctx;
}

// Liste der Mitarbeiter des eigenen Kundenkontos (inkl. „hat bereits bestellt").
app.get('/api/b2b/mitarbeiter', async (req, res) => {
  try {
    const user = await getUserFromAuthHeader(req);
    const ctx = await ladeKundenprofilFuerLeiter(user);

    const mitarbeiter = await supabaseQuery('kunden_mitarbeiter', `?kundenprofil_id=eq.${ctx.profil.id}&order=id`);
    const best = await supabaseQuery('bestellungen', `?kundenprofil_id=eq.${ctx.profil.id}&select=bestellt_von_email`);
    const bestellerEmails = new Set((Array.isArray(best) ? best : []).map(b => normalizeEmail(b.bestellt_von_email)).filter(Boolean));

    const liste = await Promise.all((Array.isArray(mitarbeiter) ? mitarbeiter : []).map(async m => {
      let angenommen = m.einladung_angenommen_am;
      // Selbstheilung: hat sich der eingeladene Mitarbeiter bereits eingeloggt?
      // (Falls der Annahme-Stempel beim ersten Login noch nicht gesetzt wurde.)
      if (!angenommen && m.auth_user_id && m.rolle !== 'einkaufsleiter') {
        const authUser = await holeAuthUserAdmin(m.auth_user_id);
        const ersterLogin = authUser?.last_sign_in_at || null;
        if (ersterLogin) {
          angenommen = ersterLogin;
          try { await supabasePatchWhere('kunden_mitarbeiter', `?id=eq.${m.id}`, { einladung_angenommen_am: angenommen }); } catch (_) {}
        }
      }
      return {
        id: m.id, email: m.email, name: m.name, rolle: m.rolle, aktiv: m.aktiv,
        filiale: m.filiale || null,
        eingeladen_am: m.eingeladen_am, einladung_angenommen_am: angenommen,
        hat_bestellt: bestellerEmails.has(normalizeEmail(m.email)),
        rolle_typ: m.rolle_typ || 'einkaeufer',
        berechtigungen: (m.berechtigungen && typeof m.berechtigungen === 'object') ? m.berechtigungen : {}
      };
    }));

    return res.json({ ok: true, firma: ctx.profil.firma, mitarbeiter: liste });
  } catch (err) {
    console.error('❌ Mitarbeiter-Liste Fehler:', err);
    return sendError(res, err);
  }
});

// Mitarbeiter einladen (E-Mail + optional Name) → Einladungs-Mail mit Passwort-Link.
app.post('/api/b2b/mitarbeiter/einladen', paymentLimiter, async (req, res) => {
  try {
    const user = await getUserFromAuthHeader(req);
    const ctx = await ladeKundenprofilFuerLeiter(user);

    const email = normalizeEmail(req.body?.email);
    const name = String(req.body?.name || '').trim() || null;
    const filiale = String(req.body?.filiale || '').trim().slice(0, 120) || null;
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      const e = new Error('Bitte eine gültige E-Mail-Adresse angeben.'); e.statusCode = 400; throw e;
    }

    // Berechtigungen (gleiche Logik wie PATCH) – ohne Auswahl gilt die Standardrolle „Einkäufer".
    const ERLAUBTE_ROLLEN = ['administrator', 'einkaufsleiter', 'einkaeufer', 'buchhaltung', 'lager', 'individuell'];
    let rolle_typ = String(req.body?.rolle_typ || '').trim();
    if (!ERLAUBTE_ROLLEN.includes(rolle_typ)) rolle_typ = 'einkaeufer';
    const ERLAUBTE_RECHTE = [
      'bestellungen_ansehen', 'bestellungen_aufgeben', 'rechnungen_ansehen', 'rechnungen_herunterladen',
      'sendungsverfolgung_ansehen', 'nachrichten_lesen', 'nachrichten_schreiben', 'reklamationen_erstellen',
      'ruecksendungen_erstellen', 'firmendaten_bearbeiten', 'lieferadressen_bearbeiten', 'mitarbeiter_verwalten',
      'rabatt_ansehen', 'zahlungsarten_ansehen', 'preislisten_ansehen', 'sonderpreise_zugang', 'alle_funktionen'
    ];
    const eingehendeRechte = (req.body?.berechtigungen && typeof req.body.berechtigungen === 'object') ? req.body.berechtigungen : {};
    const berechtigungen = {};
    ERLAUBTE_RECHTE.forEach(k => { berechtigungen[k] = !!eingehendeRechte[k]; });

    const existing = await supabaseQuery('kunden_mitarbeiter', `?email=ilike.${encodeURIComponent(email)}&limit=1`);
    if (Array.isArray(existing) && existing[0]) {
      const e = new Error(existing[0].kundenprofil_id === ctx.profil.id
        ? 'Dieser Mitarbeiter ist bereits in Ihrem Kundenkonto.'
        : 'Diese E-Mail-Adresse ist bereits einem anderen Kundenkonto zugeordnet.');
      e.statusCode = 400; throw e;
    }

    const { link, user_id } = await erzeugeEinladungsLink(email);

    await supabaseInsert('kunden_mitarbeiter', {
      kundenprofil_id: ctx.profil.id,
      auth_user_id: user_id,
      email,
      name,
      filiale,
      rolle: 'mitarbeiter',
      rolle_typ,
      berechtigungen,
      aktiv: true,
      eingeladen_am: new Date().toISOString()
    });

    if (link) {
      const html = `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
          <div style="background:#3D2B1F;padding:20px;text-align:center;">
            <h1 style="color:#C49A2B;font-family:Georgia,serif;margin:0;">VisioTrade</h1>
            <p style="color:white;margin:5px 0 0;">Premium Parkett</p>
          </div>
          <div style="padding:30px;background:#FAF7F2;">
            <h2 style="color:#3D2B1F;">Sie wurden eingeladen</h2>
            <p>Hallo${name ? ' ' + escapeHtml(name) : ''},</p>
            <p>Sie wurden als Mitarbeiter für das Kundenkonto <strong>${escapeHtml(ctx.profil.firma || 'VisioTrade')}</strong> eingeladen und können künftig im VisioTrade-Shop für dieses Unternehmen bestellen.</p>
            <p>Bitte legen Sie über den folgenden Link Ihr persönliches Passwort fest:</p>
            <p style="text-align:center;margin:24px 0;">
              <a href="${link}" style="background:#C49A2B;color:#3D2B1F;text-decoration:none;font-weight:bold;padding:12px 24px;border-radius:8px;display:inline-block;">Passwort festlegen</a>
            </p>
            <p style="color:#6B7280;font-size:13px;">Falls der Button nicht funktioniert, kopieren Sie diesen Link in Ihren Browser:<br><span style="word-break:break-all;">${link}</span></p>
            <p style="color:#6B7280;font-size:13px;margin-top:30px;">VisioTrade GmbH</p>
          </div>
        </div>`;
      try {
        await sendeEmail(email, `Ihr Mitarbeiter-Zugang${ctx.profil.firma ? ' – ' + escapeHtml(ctx.profil.firma) : ''} | VisioTrade`, html, null);
      } catch (mailErr) {
        console.error('❌ Einladungs-Mail Fehler:', mailErr.message);
      }
    }

    return res.json({ ok: true, email });
  } catch (err) {
    console.error('❌ Mitarbeiter einladen Fehler:', err);
    return sendError(res, err);
  }
});

// Einladung erneut senden. Für offene Einladungen → neuer, sicherer Link (alter wird ungültig);
// für bereits registrierte Mitarbeiter → Benachrichtigung über aktualisierte Daten/Berechtigungen.
app.post('/api/b2b/mitarbeiter/:id/erneut-einladen', paymentLimiter, async (req, res) => {
  try {
    const user = await getUserFromAuthHeader(req);
    const ctx = await ladeKundenprofilFuerLeiter(user);

    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }

    const rows = await supabaseQuery('kunden_mitarbeiter', `?id=eq.${id}&limit=1`);
    const m = Array.isArray(rows) ? rows[0] : null;
    if (!m || m.kundenprofil_id !== ctx.profil.id) { const e = new Error('Mitarbeiter nicht gefunden.'); e.statusCode = 404; throw e; }
    if (m.rolle === 'einkaufsleiter') { const e = new Error('Der Einkaufsleiter kann nicht erneut eingeladen werden.'); e.statusCode = 400; throw e; }

    const firma = ctx.profil.firma || 'VisioTrade';
    const jetzt = new Date().toISOString();
    const kopf = `
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
        <div style="background:#3D2B1F;padding:20px;text-align:center;">
          <h1 style="color:#C49A2B;font-family:Georgia,serif;margin:0;">VisioTrade</h1>
          <p style="color:white;margin:5px 0 0;">Premium Parkett</p>
        </div>`;
    const istRegistriert = !!m.einladung_angenommen_am;
    let betreff, html;

    if (!istRegistriert) {
      // Frischen Einladungslink erzeugen – der bisherige verliert dadurch seine Gültigkeit.
      const { link, user_id } = await erzeugeEinladungsLink(m.email);
      if (!link) { const e = new Error('Einladungslink konnte nicht erstellt werden.'); e.statusCode = 502; throw e; }
      if (user_id && user_id !== m.auth_user_id) {
        try { await supabasePatchWhere('kunden_mitarbeiter', `?id=eq.${id}`, { auth_user_id: user_id }); } catch (_) {}
      }
      betreff = `Ihr Mitarbeiter-Zugang – ${firma} | VisioTrade`;
      html = `${kopf}
        <div style="padding:30px;background:#FAF7F2;">
          <h2 style="color:#3D2B1F;">Ihre Einladung (erneut)</h2>
          <p>Hallo${m.name ? ' ' + escapeHtml(m.name) : ''},</p>
          <p>Sie wurden als Mitarbeiter für das Kundenkonto <strong>${escapeHtml(firma)}</strong> eingeladen. Bitte legen Sie über den folgenden Link Ihr persönliches Passwort fest:</p>
          <p style="text-align:center;margin:24px 0;">
            <a href="${link}" style="background:#C49A2B;color:#3D2B1F;text-decoration:none;font-weight:bold;padding:12px 24px;border-radius:8px;display:inline-block;">Passwort festlegen</a>
          </p>
          <p style="color:#6B7280;font-size:13px;">Hinweis: Ein eventuell zuvor erhaltener Link ist nicht mehr gültig. Falls der Button nicht funktioniert, kopieren Sie diesen Link in Ihren Browser:<br><span style="word-break:break-all;">${link}</span></p>
          <p style="color:#6B7280;font-size:13px;margin-top:30px;">VisioTrade GmbH</p>
        </div>
      </div>`;
    } else {
      // Bereits registriert → Benachrichtigung (kein Passwort-Link nötig).
      const loginUrl = requiredEnv('FRONTEND_URL');
      betreff = `Aktualisierte Mitarbeiterdaten – ${firma} | VisioTrade`;
      html = `${kopf}
        <div style="padding:30px;background:#FAF7F2;">
          <h2 style="color:#3D2B1F;">Ihre Mitarbeiterdaten wurden aktualisiert</h2>
          <p>Hallo${m.name ? ' ' + escapeHtml(m.name) : ''},</p>
          <p>Ihre Mitarbeiterdaten bzw. Berechtigungen für das Kundenkonto <strong>${escapeHtml(firma)}</strong> wurden aktualisiert. Die Änderungen sind bei Ihrer nächsten Anmeldung aktiv.</p>
          <p style="text-align:center;margin:24px 0;">
            <a href="${loginUrl}" style="background:#C49A2B;color:#3D2B1F;text-decoration:none;font-weight:bold;padding:12px 24px;border-radius:8px;display:inline-block;">Zum Login</a>
          </p>
          <p style="color:#6B7280;font-size:13px;margin-top:30px;">VisioTrade GmbH</p>
        </div>
      </div>`;
    }

    try {
      await sendeEmail(m.email, betreff, html, null);
    } catch (mailErr) {
      console.error('❌ Erneute Einladung Mail Fehler:', mailErr.message);
      const e = new Error('Die E-Mail konnte nicht versendet werden: ' + mailErr.message); e.statusCode = 502; throw e;
    }

    // Protokoll aktualisieren: letzter Versand + Zähler; bei offener Einladung auch Einladungsdatum.
    const patch = { letzte_einladung_am: jetzt, einladung_anzahl: Number(m.einladung_anzahl || 0) + 1 };
    if (!istRegistriert) patch.eingeladen_am = jetzt;
    try { await supabasePatchWhere('kunden_mitarbeiter', `?id=eq.${id}`, patch); } catch (e) { console.warn('⚠️ Einladungs-Protokoll-Update fehlgeschlagen:', e.message); }

    return res.json({ ok: true, registriert: istRegistriert });
  } catch (err) {
    console.error('❌ Erneut einladen Fehler:', err);
    return sendError(res, err);
  }
});

// Mitarbeiter ändern (Name / aktiv). Einkaufsleiter-Zeile ist hier nicht änderbar.
app.patch('/api/b2b/mitarbeiter/:id', paymentLimiter, async (req, res) => {
  try {
    const user = await getUserFromAuthHeader(req);
    const ctx = await ladeKundenprofilFuerLeiter(user);

    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }

    const rows = await supabaseQuery('kunden_mitarbeiter', `?id=eq.${id}&limit=1`);
    const m = Array.isArray(rows) ? rows[0] : null;
    if (!m || m.kundenprofil_id !== ctx.profil.id) { const e = new Error('Mitarbeiter nicht gefunden.'); e.statusCode = 404; throw e; }
    if (m.rolle === 'einkaufsleiter') { const e = new Error('Der Einkaufsleiter kann hier nicht geändert werden.'); e.statusCode = 400; throw e; }

    const patch = {};
    if (typeof req.body?.name !== 'undefined') patch.name = String(req.body.name || '').trim() || null;
    if (typeof req.body?.aktiv !== 'undefined') patch.aktiv = !!req.body.aktiv;
    if (typeof req.body?.filiale !== 'undefined') patch.filiale = String(req.body.filiale || '').trim().slice(0, 120) || null;
    // E-Mail (Login-Adresse) ändern – Eindeutigkeit prüfen + Supabase-Auth mitziehen.
    if (typeof req.body?.email !== 'undefined') {
      const neueEmail = normalizeEmail(req.body.email);
      if (!neueEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(neueEmail)) { const e = new Error('Bitte eine gültige E-Mail-Adresse angeben.'); e.statusCode = 400; throw e; }
      if (neueEmail !== normalizeEmail(m.email)) {
        const dup = await supabaseQuery('kunden_mitarbeiter', `?email=ilike.${encodeURIComponent(neueEmail)}&id=neq.${id}&limit=1`);
        if (Array.isArray(dup) && dup[0]) { const e = new Error('Diese E-Mail-Adresse ist bereits vergeben.'); e.statusCode = 400; throw e; }
        if (m.auth_user_id) {
          try {
            await supabaseAuthAdmin(`admin/users/${encodeURIComponent(m.auth_user_id)}`, {
              method: 'PUT', body: JSON.stringify({ email: neueEmail, email_confirm: true })
            });
          } catch (authErr) {
            console.error('   ❌ Auth-E-Mail-Update fehlgeschlagen:', authErr?.message);
            const e = new Error('E-Mail konnte in der Anmeldung nicht aktualisiert werden: ' + (authErr?.message || 'unbekannt')); e.statusCode = 400; throw e;
          }
        }
        patch.email = neueEmail;
      }
    }
    // Rollen-Typ (6 Rollen) – nur erlaubte Werte.
    if (typeof req.body?.rolle_typ !== 'undefined') {
      const ERLAUBTE_ROLLEN = ['administrator', 'einkaufsleiter', 'einkaeufer', 'buchhaltung', 'lager', 'individuell'];
      const rt = String(req.body.rolle_typ || '').trim();
      if (!ERLAUBTE_ROLLEN.includes(rt)) { const e = new Error('Ungültige Rolle.'); e.statusCode = 400; throw e; }
      patch.rolle_typ = rt;
    }
    // Granulare Einzelrechte – ausschließlich bekannte Keys als saubere true/false-Map speichern.
    if (typeof req.body?.berechtigungen !== 'undefined') {
      const ERLAUBTE_RECHTE = [
        'bestellungen_ansehen', 'bestellungen_aufgeben', 'rechnungen_ansehen', 'rechnungen_herunterladen',
        'sendungsverfolgung_ansehen', 'nachrichten_lesen', 'nachrichten_schreiben', 'reklamationen_erstellen',
        'ruecksendungen_erstellen', 'firmendaten_bearbeiten', 'lieferadressen_bearbeiten', 'mitarbeiter_verwalten',
        'rabatt_ansehen', 'zahlungsarten_ansehen', 'preislisten_ansehen', 'sonderpreise_zugang', 'alle_funktionen'
      ];
      const eingehend = (req.body.berechtigungen && typeof req.body.berechtigungen === 'object') ? req.body.berechtigungen : {};
      const sauber = {};
      ERLAUBTE_RECHTE.forEach(k => { sauber[k] = !!eingehend[k]; });
      patch.berechtigungen = sauber;
    }
    if (!Object.keys(patch).length) { const e = new Error('Keine Änderungen angegeben.'); e.statusCode = 400; throw e; }

    await supabasePatchWhere('kunden_mitarbeiter', `?id=eq.${id}`, patch);
    return res.json({ ok: true });
  } catch (err) {
    console.error('❌ Mitarbeiter ändern Fehler:', err);
    return sendError(res, err);
  }
});

// Mitarbeiter löschen (nicht den Einkaufsleiter).
app.delete('/api/b2b/mitarbeiter/:id', paymentLimiter, async (req, res) => {
  try {
    const user = await getUserFromAuthHeader(req);
    const ctx = await ladeKundenprofilFuerLeiter(user);

    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }

    const rows = await supabaseQuery('kunden_mitarbeiter', `?id=eq.${id}&limit=1`);
    const m = Array.isArray(rows) ? rows[0] : null;
    if (!m || m.kundenprofil_id !== ctx.profil.id) { const e = new Error('Mitarbeiter nicht gefunden.'); e.statusCode = 404; throw e; }
    if (m.rolle === 'einkaufsleiter') { const e = new Error('Der Einkaufsleiter kann nicht gelöscht werden.'); e.statusCode = 400; throw e; }

    await supabaseRequest(`kunden_mitarbeiter?id=eq.${encodeURIComponent(id)}`, {
      method: 'DELETE',
      headers: { Prefer: 'return=minimal' }
    });
    return res.json({ ok: true });
  } catch (err) {
    console.error('❌ Mitarbeiter löschen Fehler:', err);
    return sendError(res, err);
  }
});

// =============================================================================
// Passwort vergessen / zurücksetzen (Reset-Link via Brevo, sicher)
// =============================================================================

async function erzeugeRecoveryLink(email) {
  const redirect = `${requiredEnv('FRONTEND_URL')}?set_password=1`;
  const data = await supabaseAuthAdmin('admin/generate_link', {
    method: 'POST',
    body: JSON.stringify({ type: 'recovery', email, redirect_to: redirect })
  });
  return { link: data?.action_link || data?.properties?.action_link || null };
}

app.post('/api/passwort-reset', paymentLimiter, async (req, res) => {
  // Immer dieselbe Antwort – verrät NICHT, ob ein Konto existiert.
  const generisch = {
    ok: true,
    message: 'Falls ein Konto mit dieser E-Mail-Adresse existiert, wurde ein Link zum Zurücksetzen des Passworts versendet.'
  };
  try {
    if (!(await pruefeTurnstile(req.body?.turnstileToken, clientIp(req)))) {
      return res.status(403).json({ ok: false, error: 'Bot-Verifizierung fehlgeschlagen. Bitte die Seite neu laden.' });
    }

    const email = normalizeEmail(req.body?.email);
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.json(generisch);
    }

    // Deaktivierte Mitarbeiter-Zugänge bekommen keinen Reset-Link.
    const m = await supabaseQuery('kunden_mitarbeiter', `?email=ilike.${encodeURIComponent(email)}&limit=1`);
    if (Array.isArray(m) && m[0] && m[0].aktiv === false) {
      return res.json(generisch);
    }

    // Recovery-Link erzeugen (schlägt fehl, wenn der Nutzer nicht existiert) und via Brevo senden.
    try {
      const { link } = await erzeugeRecoveryLink(email);
      if (link) {
        const html = `
          <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
            <div style="background:#3D2B1F;padding:20px;text-align:center;">
              <h1 style="color:#C49A2B;font-family:Georgia,serif;margin:0;">VisioTrade</h1>
              <p style="color:white;margin:5px 0 0;">Premium Parkett</p>
            </div>
            <div style="padding:30px;background:#FAF7F2;">
              <h2 style="color:#3D2B1F;">Passwort zurücksetzen</h2>
              <p>Sie haben angefordert, Ihr Passwort zurückzusetzen. Klicken Sie auf den folgenden Link und vergeben Sie ein neues Passwort:</p>
              <p style="text-align:center;margin:24px 0;">
                <a href="${link}" style="background:#C49A2B;color:#3D2B1F;text-decoration:none;font-weight:bold;padding:12px 24px;border-radius:8px;display:inline-block;">Neues Passwort festlegen</a>
              </p>
              <p style="color:#6B7280;font-size:13px;">Falls der Button nicht funktioniert, kopieren Sie diesen Link in Ihren Browser:<br><span style="word-break:break-all;">${link}</span></p>
              <p style="color:#6B7280;font-size:13px;">Der Link ist nur begrenzt gültig. Falls Sie kein neues Passwort angefordert haben, ignorieren Sie diese E-Mail einfach.</p>
              <p style="color:#6B7280;font-size:13px;margin-top:30px;">VisioTrade GmbH</p>
            </div>
          </div>`;
        await sendeEmail(email, 'Passwort zurücksetzen | VisioTrade', html, null);
      }
    } catch (e) {
      // Nutzer existiert evtl. nicht → bewusst still, keine Existenz-Preisgabe.
      console.warn('ℹ️ Passwort-Reset: kein Versand –', e.message);
    }

    return res.json(generisch);
  } catch (err) {
    console.error('❌ Passwort-Reset Fehler:', err);
    return res.json(generisch);
  }
});

// =============================================================================
// B2B: Lieferadressen (firmenbezogen, serverseitig geprüft)
// =============================================================================

async function ladeFirmenadressen(profilId) {
  const rows = await supabaseQuery('kunden_adressen', `?kundenprofil_id=eq.${encodeURIComponent(profilId)}&order=id.desc`);
  return Array.isArray(rows) ? rows : [];
}

async function ladeAdresseFuerProfil(adresseId, profilId) {
  const id = Number.parseInt(adresseId, 10);
  if (!Number.isInteger(id) || id <= 0) return null;
  const rows = await supabaseQuery('kunden_adressen', `?id=eq.${id}&kundenprofil_id=eq.${encodeURIComponent(profilId)}&limit=1`);
  return Array.isArray(rows) ? rows[0] || null : null;
}

function bereinigeAdresse(input) {
  const s = (v, max) => { const t = String(v == null ? '' : v).trim(); return t ? t.slice(0, max || 200) : null; };
  const b = v => (v === true || v === 'true' || v === 1) ? true : ((v === false || v === 'false' || v === 0) ? false : null);
  return {
    empfaenger: s(input?.empfaenger, 160),
    strasse: s(input?.strasse, 160),
    plz: s(input?.plz, 16),
    ort: s(input?.ort, 120),
    land: String(input?.land || 'DE').trim() || 'DE',
    telefon: s(input?.telefon, 40),
    // Anlieferungsdetails (Baustelle/Filiale)
    ansprechpartner: s(input?.ansprechpartner, 120),
    anlieferungscode: s(input?.anlieferungscode, 80),
    stapler: b(input?.stapler),
    hebebuehne: b(input?.hebebuehne),
    anlieferzeiten: s(input?.anlieferzeiten, 200),
    zufahrt_hinweis: s(input?.zufahrt_hinweis, 400),
    liefer_hinweise: s(input?.liefer_hinweise, 600)
  };
}

// Lieferadressen des eigenen Kundenkontos.
app.get('/api/b2b/adressen', async (req, res) => {
  try {
    const user = await getUserFromAuthHeader(req);
    const ctx = await ensureKundenprofilFuerAuthUser(user);
    if (!ctx?.profil) return res.json({ ok: true, adressen: [] });
    return res.json({ ok: true, adressen: await ladeFirmenadressen(ctx.profil.id) });
  } catch (err) {
    console.error('❌ Adressen-Liste Fehler:', err);
    return sendError(res, err);
  }
});

// Neue Lieferadresse für das eigene Kundenkonto speichern.
app.post('/api/b2b/adressen', paymentLimiter, async (req, res) => {
  try {
    const user = await getUserFromAuthHeader(req);
    const ctx = await ensureKundenprofilFuerAuthUser(user);
    if (!ctx?.profil) { const e = new Error('Kein Kundenkonto.'); e.statusCode = 403; throw e; }
    if (ctx.mitglied?.aktiv === false) { const e = new Error('Ihr Zugang ist deaktiviert.'); e.statusCode = 403; throw e; }

    const adr = bereinigeAdresse(req.body);
    if (!adr.strasse || !adr.plz || !adr.ort) { const e = new Error('Straße, PLZ und Ort sind erforderlich.'); e.statusCode = 400; throw e; }

    const rows = await supabaseInsert('kunden_adressen', { ...adr, kundenprofil_id: ctx.profil.id, user_id: user.id });
    return res.json({ ok: true, adresse: Array.isArray(rows) ? rows[0] : null });
  } catch (err) {
    console.error('❌ Adresse speichern Fehler:', err);
    return sendError(res, err);
  }
});

// Bestehende Lieferadresse des eigenen Kundenkontos bearbeiten.
app.put('/api/b2b/adressen/:id', paymentLimiter, async (req, res) => {
  try {
    const user = await getUserFromAuthHeader(req);
    const ctx = await ensureKundenprofilFuerAuthUser(user);
    if (!ctx?.profil) { const e = new Error('Kein Kundenkonto.'); e.statusCode = 403; throw e; }
    if (ctx.mitglied?.aktiv === false) { const e = new Error('Ihr Zugang ist deaktiviert.'); e.statusCode = 403; throw e; }

    const bestehend = await ladeAdresseFuerProfil(req.params.id, ctx.profil.id);
    if (!bestehend) { const e = new Error('Adresse nicht gefunden.'); e.statusCode = 404; throw e; }

    const adr = bereinigeAdresse(req.body);
    if (!adr.strasse || !adr.plz || !adr.ort) { const e = new Error('Straße, PLZ und Ort sind erforderlich.'); e.statusCode = 400; throw e; }

    const rows = await supabasePatchWhere('kunden_adressen', `?id=eq.${encodeURIComponent(bestehend.id)}`, adr);
    return res.json({ ok: true, adresse: Array.isArray(rows) ? rows[0] : null });
  } catch (err) {
    console.error('❌ Adresse bearbeiten Fehler:', err);
    return sendError(res, err);
  }
});

// Lieferadresse des eigenen Kundenkontos löschen.
app.delete('/api/b2b/adressen/:id', paymentLimiter, async (req, res) => {
  try {
    const user = await getUserFromAuthHeader(req);
    const ctx = await ensureKundenprofilFuerAuthUser(user);
    if (!ctx?.profil) { const e = new Error('Kein Kundenkonto.'); e.statusCode = 403; throw e; }

    const adr = await ladeAdresseFuerProfil(req.params.id, ctx.profil.id);
    if (!adr) { const e = new Error('Adresse nicht gefunden.'); e.statusCode = 404; throw e; }

    await supabaseRequest(`kunden_adressen?id=eq.${encodeURIComponent(adr.id)}`, {
      method: 'DELETE',
      headers: { Prefer: 'return=minimal' }
    });
    return res.json({ ok: true });
  } catch (err) {
    console.error('❌ Adresse löschen Fehler:', err);
    return sendError(res, err);
  }
});

app.post('/api/konto/gastbestellungen-verknuepfen', paymentLimiter, async (req, res) => {
  try {
    const user = await getUserFromAuthHeader(req);
    const email = normalizeEmail(user.email);

    if (!user.id || !email) {
      return res.status(400).json({ error: 'Konto konnte nicht ermittelt werden' });
    }

    const rows = await supabasePatchWhere(
      'bestellungen',
      `?user_id=is.null&email=ilike.${encodeURIComponent(email)}`,
      { user_id: user.id }
    );

    return res.json({
      ok: true,
      linked_count: Array.isArray(rows) ? rows.length : 0
    });
  } catch (err) {
    console.error('❌ Gastbestellungen verknüpfen Fehler:', err);
    return sendError(res, err);
  }
});

// -----------------------------------------------------------------------------
// Vorkasse / Überweisung: nur Zahlungsaufforderung, keine echte Rechnung
// -----------------------------------------------------------------------------

app.post('/api/vorkasse/bestellen', async (req, res) => {
  try {
    const { bestellung_id } = req.body;

    if (!bestellung_id) {
      return res.status(400).json({ error: 'bestellung_id fehlt' });
    }

    const bestellung = await ladeBestellung(bestellung_id);
    const user = await assertBestellungGehoertZuUser(req, bestellung);

    // Audit S2-04: Diese Route prüfte bisher nur die Eigentümerschaft, nicht die freigeschaltete
    // Zahlungsart – anders als alle /api/checkout/*-Routen. Damit ließ sich eine Bestellung, für
    // die nur Stripe erlaubt ist, nachträglich auf Vorkasse umstellen. Gastbestellungen sind
    // unberührt: pruefeCheckoutKontext liefert für sie { gast: true } statt eines Fehlers.
    await pruefeCheckoutKontext(user, 'vorkasse');

    const result = await verarbeiteVorkasseBestellung(bestellung_id, {
      kundenname: bestellung.kundenname,
      email: bestellung.email,
      user_id: user.id
    });

    return res.json(result);
  } catch (err) {
    console.error('❌ Vorkasse Error:', err);
    return sendError(res, err);
  }
});


// -----------------------------------------------------------------------------
// Kunde: offene Vorkasse-Bestellung stornieren
// -----------------------------------------------------------------------------

app.post('/api/vorkasse/stornieren', async (req, res) => {
  try {
    const { bestellung_id } = req.body;

    if (!bestellung_id) {
      return res.status(400).json({
        error: 'bestellung_id fehlt'
      });
    }

    const bestellungIdInt = Number.parseInt(bestellung_id, 10);

    if (!Number.isInteger(bestellungIdInt) || bestellungIdInt <= 0) {
      return res.status(400).json({
        error: 'Ungültige bestellung_id'
      });
    }

    const bestellung = await ladeBestellung(bestellungIdInt);
    const user = await assertBestellungGehoertZuUser(req, bestellung);

    if (bestellung.zahlungsart !== 'vorkasse') {
      return res.status(400).json({
        error: 'Nur Vorkasse-Bestellungen können über diese Funktion storniert werden.'
      });
    }

    if (bestellung.status !== 'warte_auf_zahlung') {
      return res.status(400).json({
        error: 'Nur offene Vorkasse-Bestellungen können storniert werden.'
      });
    }

    await gebeBestellReservierungenFrei(bestellungIdInt);

    await supabaseUpdate('bestellungen', bestellungIdInt, {
      status: 'storniert',
      reservierung_status: 'released'
    });

    // Vorgangscenter: Storno.
    await vorgangEreignis(bestellung, 'storniert', { text: 'Bestellung storniert.', meta: { status_neu: 'storniert' } });

    const adminId = process.env.ADMIN_TELEGRAM_ID || process.env.TELEGRAM_ADMIN_ID;

    if (adminId) {
      const tgText =
        `❌ <b>Vorkasse-Bestellung #${bestellungIdInt} wurde vom Kunden storniert</b>\n\n` +
        `👤 Kunde: ${escapeHtml(bestellung.kundenname || bestellung.firma || '—')}\n` +
        `🏢 Firma: ${escapeHtml(bestellung.firma || '—')}\n` +
        `📧 Email: ${escapeHtml(bestellung.email || user.email || '—')}\n` +
        `💰 Betrag brutto: ${euro(toNumber(bestellung.gesamt_brutto, toNumber(bestellung.gesamtbetrag, 0) * 1.19))}\n` +
        `🏦 Verwendungszweck: VT-${String(bestellungIdInt).padStart(4, '0')}\n` +
        `📦 Lagerreservierung wurde freigegeben.`;

      try {
        await sendeTelegram(adminId, tgText);
      } catch (tgErr) {
        console.warn('⚠️ Telegram-Stornohinweis fehlgeschlagen:', tgErr.message);
      }
    }

    console.log(`✅ Vorkasse-Bestellung ${bestellungIdInt} vom Kunden storniert`);

    return res.json({
      ok: true,
      bestellung_id: bestellungIdInt,
      status: 'storniert'
    });
  } catch (err) {
    console.error('❌ Vorkasse-Stornierung Fehler:', err);

    return sendError(res, err);
  }
});


// -----------------------------------------------------------------------------
// Admin-/Kunden-Auth-Guards (getUserFromAuthHeader, assertAdmin, assertAdmin-
// Permission, assertWarehouse, istNurLagerUser, verbieteNurLager, entferne-
// Geldfelder*, schreibeAuditLog …) sind nach lib/auth.js verschoben (Phase 3).
// Import siehe oben bei den lib-require-Zeilen.
// -----------------------------------------------------------------------------

// =============================================================================
// Admin-Rollensystem: Rechte-Katalog, Admin-Verwaltung, Audit-Log (Etappe 2)
// =============================================================================
const ADMIN_PERMISSION_KEYS = [
  'produkte.ansehen','produkte.erstellen','produkte.bearbeiten','produkte.loeschen','produkte.preise',
  'kategorien.ansehen','kategorien.erstellen','kategorien.bearbeiten','kategorien.loeschen',
  'bestellungen.ansehen','bestellungen.status','bestellungen.zahlungsstatus','bestellungen.vorkasse_bezahlt','bestellungen.tracking','bestellungen.stornieren','bestellungen.loeschen','orders.view_invoice_pdf',
  'warehouse.view_orders','warehouse.view_order_details','warehouse.mark_handed_to_carrier','warehouse.print_documents','warehouse.mark_ready','warehouse.request_spedition','warehouse.chat_view','warehouse.chat_write',
  'b2b.ansehen','b2b.bearbeiten','b2b.bonus','b2b.zahlungsarten','b2b.rechnung',
  'lieferkosten.ansehen','lieferkosten.bearbeiten',
  'messages.view','messages.reply_to_customer','messages.create_internal_note','messages.view_internal_notes','messages.create_superadmin_note','messages.view_superadmin_notes','messages.manage_visibility','messages.change_status','messages.view_attachments','messages.view_order_details',
  'messages.view_telegram_support','messages.reply_telegram_support','messages.view_whatsapp','messages.reply_whatsapp','messages.assign_thread','messages.manage_channels',
  'admin.ansehen','admin.einladen','admin.rechte','admin.deaktivieren'
];

// Setzt die Einzelrechte eines Admins neu (alte löschen, aktivierte schreiben).
async function setzeAdminRechte(email, perms) {
  const e = normalizeEmail(email);
  await supabaseRequest(`admin_permissions?admin_email=ilike.${encodeURIComponent(e)}`, {
    method: 'DELETE', headers: { Prefer: 'return=minimal' }
  });
  const rows = ADMIN_PERMISSION_KEYS.filter(k => perms && perms[k]).map(k => ({
    admin_email: e, permission_key: k, erlaubt: true
  }));
  if (rows.length) await supabaseInsert('admin_permissions', rows);
}

// Eigene Rolle + Rechte (für die Menüsteuerung im Admin-Panel).
app.get('/api/admin/me', async (req, res) => {
  try {
    const user = await assertAdmin(req);
    const a = user._admin;
    const istSuper = istLegacyAdmin(a) || a.ist_super_admin === true; // legacy = Vollzugriff
    // Einladung als angenommen markieren (erste eingeloggte Anfrage des Admins).
    if (!istLegacyAdmin(a) && a.eingeladen_am && !a.einladung_angenommen_am) {
      try { await supabasePatchWhere('admin_users', `?email=ilike.${encodeURIComponent(normalizeEmail(a.email))}`, { einladung_angenommen_am: new Date().toISOString() }); } catch (_) {}
    }
    const nurLager = istNurLagerUser(a);
    return res.json({
      ok: true,
      email: normalizeEmail(a.email),
      ist_super_admin: istSuper,
      rolle: nurLager ? 'lager' : (a.rolle || (istSuper ? 'super_admin' : 'admin')),
      nur_lager: nurLager,
      rechte: istSuper ? ADMIN_PERMISSION_KEYS : Array.from(a._perms),
      alle_rechte: ADMIN_PERMISSION_KEYS,
      // Test-Schutz sichtbar machen: solange gesetzt, gehen alle Mails nur an diese Adresse.
      mail_testmodus: !!process.env.MAIL_TEST_EMPFAENGER,
      mail_test_empfaenger: process.env.MAIL_TEST_EMPFAENGER || null
    });
  } catch (err) { console.error('❌ /api/admin/me', err); return sendError(res, err); }
});

// Admin-Liste inkl. Rechte (nur Super-Admin).
app.get('/api/admin/admins', async (req, res) => {
  try {
    await assertSuperAdmin(req);
    const admins = await supabaseQuery('admin_users', `?select=*&order=email`) || [];
    const perms = await supabaseQuery('admin_permissions', `?select=admin_email,permission_key,erlaubt`) || [];
    const permMap = {};
    (Array.isArray(perms) ? perms : []).forEach(p => {
      if (!p.erlaubt) return;
      const k = normalizeEmail(p.admin_email);
      (permMap[k] = permMap[k] || []).push(p.permission_key);
    });
    const liste = (Array.isArray(admins) ? admins : []).map(a => {
      const key = normalizeEmail(a.email);
      return {
        email: key, name: a.name || null,
        rolle: a.rolle || (a.ist_super_admin ? 'super_admin' : 'admin'),
        ist_super_admin: a.ist_super_admin === true,
        aktiv: a.aktiv !== false,
        eingeladen_am: a.eingeladen_am || null,
        einladung_angenommen_am: a.einladung_angenommen_am || null,
        rechte: a.ist_super_admin === true ? ADMIN_PERMISSION_KEYS : (permMap[key] || [])
      };
    });
    return res.json({ ok: true, admins: liste, alle_rechte: ADMIN_PERMISSION_KEYS });
  } catch (err) { console.error('❌ Admin-Liste', err); return sendError(res, err); }
});

// Admin einladen (nur Super-Admin) → eigene Login-Einladung, eigenes Passwort.
app.post('/api/admin/admins/einladen', paymentLimiter, async (req, res) => {
  try {
    await assertSuperAdmin(req);
    const email = normalizeEmail(req.body?.email);
    const name = String(req.body?.name || '').trim() || null;
    const perms = req.body?.rechte || {};
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      const e = new Error('Bitte eine gültige E-Mail-Adresse angeben.'); e.statusCode = 400; throw e;
    }
    if (await ladeAdmin(email)) { const e = new Error('Dieser Admin existiert bereits.'); e.statusCode = 400; throw e; }

    const { link, user_id } = await erzeugeEinladungsLink(email);
    await supabaseInsert('admin_users', {
      email, name, auth_user_id: user_id || null,
      rolle: 'admin', ist_super_admin: false, aktiv: true,
      eingeladen_am: new Date().toISOString()
    });
    await setzeAdminRechte(email, perms);

    if (link) {
      const html = `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
          <div style="background:#3D2B1F;padding:20px;text-align:center;">
            <h1 style="color:#C49A2B;font-family:Georgia,serif;margin:0;">VisioTrade</h1>
            <p style="color:white;margin:5px 0 0;">Admin-Bereich</p>
          </div>
          <div style="padding:30px;background:#FAF7F2;">
            <h2 style="color:#3D2B1F;">Admin-Zugang einrichten</h2>
            <p>Hallo${name ? ' ' + escapeHtml(name) : ''},</p>
            <p>Sie wurden als <strong>Admin-Mitarbeiter</strong> für den VisioTrade-Adminbereich eingeladen. Bitte legen Sie über den folgenden Link Ihr persönliches Passwort fest:</p>
            <p style="text-align:center;margin:24px 0;">
              <a href="${link}" style="background:#C49A2B;color:#3D2B1F;text-decoration:none;font-weight:bold;padding:12px 24px;border-radius:8px;display:inline-block;">Passwort festlegen</a>
            </p>
            <p style="color:#6B7280;font-size:13px;">Falls der Button nicht funktioniert:<br><span style="word-break:break-all;">${link}</span></p>
            <p style="color:#6B7280;font-size:13px;margin-top:30px;">VisioTrade GmbH</p>
          </div>
        </div>`;
      try { await sendeEmail(email, 'Ihr Admin-Zugang | VisioTrade', html, null); }
      catch (mailErr) { console.error('❌ Admin-Einladungs-Mail:', mailErr.message); }
    }

    await schreibeAuditLog(req, 'admin_eingeladen', 'admin_users', email, null,
      { rolle: 'admin', rechte: ADMIN_PERMISSION_KEYS.filter(k => perms[k]) });
    return res.json({ ok: true, email });
  } catch (err) { console.error('❌ Admin einladen', err); return sendError(res, err); }
});

// Einladung erneut senden (neuer gültiger Link) – nur Super-Admin.
app.post('/api/admin/admins/neu-einladen', paymentLimiter, async (req, res) => {
  try {
    await assertSuperAdmin(req);
    const email = normalizeEmail(req.body?.email);
    const target = await ladeAdmin(email);
    if (!target) { const e = new Error('Admin nicht gefunden'); e.statusCode = 404; throw e; }

    const { link, user_id } = await erzeugeEinladungsLink(email);
    if (user_id && !target.auth_user_id) {
      try { await supabasePatchWhere('admin_users', `?email=ilike.${encodeURIComponent(email)}`, { auth_user_id: user_id }); } catch (_) {}
    }
    if (link) {
      const html = `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
          <div style="background:#3D2B1F;padding:20px;text-align:center;">
            <h1 style="color:#C49A2B;font-family:Georgia,serif;margin:0;">VisioTrade</h1>
            <p style="color:white;margin:5px 0 0;">Admin-Bereich</p>
          </div>
          <div style="padding:30px;background:#FAF7F2;">
            <h2 style="color:#3D2B1F;">Admin-Zugang einrichten</h2>
            <p>Hallo${target.name ? ' ' + escapeHtml(target.name) : ''},</p>
            <p>Hier ist Ihr <strong>neuer</strong> Link, um Ihr persönliches Passwort für den VisioTrade-Adminbereich festzulegen:</p>
            <p style="text-align:center;margin:24px 0;">
              <a href="${link}" style="background:#C49A2B;color:#3D2B1F;text-decoration:none;font-weight:bold;padding:12px 24px;border-radius:8px;display:inline-block;">Passwort festlegen</a>
            </p>
            <p style="color:#6B7280;font-size:13px;">Falls der Button nicht funktioniert:<br><span style="word-break:break-all;">${link}</span></p>
            <p style="color:#6B7280;font-size:13px;margin-top:30px;">VisioTrade GmbH</p>
          </div>
        </div>`;
      await sendeEmail(email, 'Ihr Admin-Zugang (neuer Link) | VisioTrade', html, null);
    }
    await schreibeAuditLog(req, 'admin_einladung_erneut', 'admin_users', email, null, null);
    return res.json({ ok: true, email });
  } catch (err) { console.error('❌ Admin neu einladen', err); return sendError(res, err); }
});

// Self-Service: eingeladener Admin fordert selbst einen neuen Link an (KEINE Auth).
// Neutrale Antwort – verrät nie, ob die Adresse existiert.
app.post('/api/admin/request-new-invite', paymentLimiter, async (req, res) => {
  const NEUTRAL = { ok: true, message: 'Falls für diese E-Mail-Adresse eine aktive Admin-Einladung existiert, wurde eine neue Einladung versendet.' };
  try {
    const email = normalizeEmail(req.body?.email);
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.json(NEUTRAL);

    const admin = await ladeAdmin(email);
    // Nur an existierende, aktive Admins erneut senden – sonst still (kein Leak).
    if (admin && admin.aktiv !== false) {
      try {
        const { link, user_id } = await erzeugeEinladungsLink(email);
        if (user_id && !admin.auth_user_id) {
          try { await supabasePatchWhere('admin_users', `?email=ilike.${encodeURIComponent(email)}`, { auth_user_id: user_id }); } catch (_) {}
        }
        if (link) {
          const html = `
            <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
              <div style="background:#3D2B1F;padding:20px;text-align:center;">
                <h1 style="color:#C49A2B;font-family:Georgia,serif;margin:0;">VisioTrade</h1>
                <p style="color:white;margin:5px 0 0;">Admin-Bereich</p>
              </div>
              <div style="padding:30px;background:#FAF7F2;">
                <h2 style="color:#3D2B1F;">Admin-Zugang einrichten</h2>
                <p>Hallo${admin.name ? ' ' + escapeHtml(admin.name) : ''},</p>
                <p>Hier ist Ihr <strong>neuer</strong> Link, um Ihr persönliches Passwort für den VisioTrade-Adminbereich festzulegen:</p>
                <p style="text-align:center;margin:24px 0;">
                  <a href="${link}" style="background:#C49A2B;color:#3D2B1F;text-decoration:none;font-weight:bold;padding:12px 24px;border-radius:8px;display:inline-block;">Passwort festlegen</a>
                </p>
                <p style="color:#6B7280;font-size:13px;">Falls der Button nicht funktioniert:<br><span style="word-break:break-all;">${link}</span></p>
                <p style="color:#6B7280;font-size:13px;margin-top:30px;">VisioTrade GmbH</p>
              </div>
            </div>`;
          await sendeEmail(email, 'Ihr Admin-Zugang (neuer Link) | VisioTrade', html, null);
        }
      } catch (e) { console.error('❌ request-new-invite senden:', e.message); }
    }
    return res.json(NEUTRAL);
  } catch (err) {
    console.error('❌ request-new-invite', err);
    return res.json(NEUTRAL);
  }
});

// Admin ändern: aktiv / Super-Admin / Name / Rechte (nur Super-Admin, mit Schutzregeln).
app.patch('/api/admin/admins', paymentLimiter, async (req, res) => {
  try {
    const su = await assertSuperAdmin(req);
    const email = normalizeEmail(req.body?.email);
    if (!email) { const e = new Error('E-Mail fehlt'); e.statusCode = 400; throw e; }
    const target = await ladeAdmin(email);
    if (!target) { const e = new Error('Admin nicht gefunden'); e.statusCode = 404; throw e; }

    const patch = {};
    if (typeof req.body?.aktiv !== 'undefined') patch.aktiv = !!req.body.aktiv;
    if (typeof req.body?.ist_super_admin !== 'undefined') { patch.ist_super_admin = !!req.body.ist_super_admin; patch.rolle = patch.ist_super_admin ? 'super_admin' : 'admin'; }
    if (typeof req.body?.name !== 'undefined') patch.name = String(req.body.name || '').trim() || null;

    // Schutz: letzten/eigenen Super-Admin nicht aussperren.
    const istSelbst = normalizeEmail(su.email) === email;
    if (target.ist_super_admin && (patch.aktiv === false || patch.ist_super_admin === false)) {
      if (istSelbst) { const e = new Error('Sie können sich nicht selbst als Super-Admin entfernen oder deaktivieren.'); e.statusCode = 400; throw e; }
      const supers = await supabaseQuery('admin_users', `?ist_super_admin=eq.true&aktiv=eq.true&select=email`);
      if ((Array.isArray(supers) ? supers : []).length <= 1) { const e = new Error('Der letzte aktive Super-Admin kann nicht deaktiviert oder entmachtet werden.'); e.statusCode = 400; throw e; }
    }

    const altWert = { aktiv: target.aktiv, ist_super_admin: target.ist_super_admin, rechte: Array.from(target._perms) };
    if (Object.keys(patch).length) {
      patch.updated_at = new Date().toISOString();
      await supabasePatchWhere('admin_users', `?email=ilike.${encodeURIComponent(email)}`, patch);
    }
    if (typeof req.body?.rechte !== 'undefined') await setzeAdminRechte(email, req.body.rechte);

    const neu = await ladeAdmin(email);
    await schreibeAuditLog(req, 'admin_rechte_geaendert', 'admin_users', email, altWert,
      { aktiv: neu.aktiv, ist_super_admin: neu.ist_super_admin, rechte: Array.from(neu._perms) });
    return res.json({ ok: true });
  } catch (err) { console.error('❌ Admin ändern', err); return sendError(res, err); }
});

// Admin löschen (nur Super-Admin; nicht sich selbst, nicht einen Super-Admin).
app.delete('/api/admin/admins/:email', paymentLimiter, async (req, res) => {
  try {
    const su = await assertSuperAdmin(req);
    const email = normalizeEmail(decodeURIComponent(req.params.email || ''));
    const target = await ladeAdmin(email);
    if (!target) { const e = new Error('Admin nicht gefunden'); e.statusCode = 404; throw e; }
    if (target.ist_super_admin) { const e = new Error('Ein Super-Admin kann nicht gelöscht werden. Bitte zuerst die Super-Admin-Rolle entziehen.'); e.statusCode = 400; throw e; }
    if (normalizeEmail(su.email) === email) { const e = new Error('Sie können sich nicht selbst löschen.'); e.statusCode = 400; throw e; }

    await supabaseRequest(`admin_permissions?admin_email=ilike.${encodeURIComponent(email)}`, { method: 'DELETE', headers: { Prefer: 'return=minimal' } });
    await supabaseRequest(`admin_users?email=ilike.${encodeURIComponent(email)}`, { method: 'DELETE', headers: { Prefer: 'return=minimal' } });
    await schreibeAuditLog(req, 'admin_geloescht', 'admin_users', email, { rolle: target.rolle }, null);
    return res.json({ ok: true });
  } catch (err) { console.error('❌ Admin löschen', err); return sendError(res, err); }
});

// ENTFERNT (Security-Review 2026-07-14): POST /api/admin/audit erlaubte jedem
// aktiven Admin beliebige (aufrufer-gestempelte) Audit-Einträge. Sein einziger
// Aufrufer (admin.html auditLog(), für die alten Direkt-REST-Aktionen) war
// bereits tot — Audit-Einträge schreibt ausschließlich der Server selbst
// über schreibeAuditLog() in den jeweiligen Routen.

// Audit-Log lesen (jeder aktive Admin).
app.get('/api/admin/audit-log', async (req, res) => {
  try {
    await assertAdmin(req);
    const rows = await supabaseQuery('admin_audit_log', `?select=*&order=created_at.desc&limit=200`) || [];
    return res.json({ ok: true, eintraege: Array.isArray(rows) ? rows : [] });
  } catch (err) { return sendError(res, err); }
});

// =============================================================================
// Papierkorb (Soft-Delete) – nur Super-Admin. Nichts wird hart gelöscht.
// =============================================================================
app.post('/api/admin/bestellungen/:id/papierkorb', paymentLimiter, async (req, res) => {
  try {
    const su = await assertSuperAdmin(req);
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    await supabaseUpdate('bestellungen', id, {
      deleted_at: new Date().toISOString(),
      deleted_by_email: normalizeEmail(su.email),
      deleted_by_auth_user_id: su.id || null,
      delete_reason: String(req.body?.grund || '').trim() || null,
      restored_at: null, restored_by_auth_user_id: null
    });
    await schreibeAuditLog(req, 'bestellung_papierkorb', 'bestellungen', id, null, null);
    return res.json({ ok: true });
  } catch (err) { console.error('❌ Bestellung Papierkorb', err); return sendError(res, err); }
});

app.post('/api/admin/bestellungen/:id/wiederherstellen', paymentLimiter, async (req, res) => {
  try {
    const su = await assertSuperAdmin(req);
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    await supabaseUpdate('bestellungen', id, {
      deleted_at: null, deleted_by_email: null, deleted_by_auth_user_id: null,
      restored_at: new Date().toISOString(), restored_by_auth_user_id: su.id || null
    });
    await schreibeAuditLog(req, 'bestellung_wiederhergestellt', 'bestellungen', id, null, null);
    return res.json({ ok: true });
  } catch (err) { console.error('❌ Bestellung wiederherstellen', err); return sendError(res, err); }
});

// -----------------------------------------------------------------------------
// Admin: Bestellungen lesen/aktualisieren über RECHTE-GEPRÜFTE Endpoints.
// Ersetzt die früheren Supabase-Direktzugriffe (api('bestellungen'…)) im
// Admin-Panel, die an den granularen Adminrechten vorbeigingen.
// -----------------------------------------------------------------------------

// Liste, optional gefiltert nach Status/Zahlungsart. Recht: bestellungen.ansehen
app.get('/api/admin/bestellungen', async (req, res) => {
  try {
    await assertAdminPermission(req, 'bestellungen.ansehen');
    const status = String(req.query.status || '').trim();
    const zahlungsart = String(req.query.zahlungsart || '').trim();
    const filter = ['deleted_at=is.null'];
    if (status === 'in_bearbeitung') {
      filter.push('status=in.(bezahlt,auf_rechnung)');
      filter.push('lager_status=eq.in_bearbeitung');
    } else if (status) {
      filter.push(`status=eq.${encodeURIComponent(status)}`);
    }
    if (zahlungsart) filter.push(`zahlungsart=eq.${encodeURIComponent(zahlungsart)}`);
    const rows = await supabaseQuery('bestellungen', `?${filter.join('&')}&order=erstellt_am.desc&limit=2000`) || [];
    return res.json(rows);
  } catch (err) { console.error('❌ admin/bestellungen-liste', err); return sendError(res, err); }
});

// Anzahl offener (noch NICHT abgeschlossener) Bestellungen für das Nav-Badge – live
// aus der DB, KEIN lokaler Zähler. Abgeschlossen = status in
// (versendet, geliefert, storniert). 'abgeholt' ist technisch status='versendet'
// (Anzeige-Mapping) und damit ohnehin ausgeschlossen; zur Sicherheit mitgelistet.
app.get('/api/admin/bestellungen-offen-anzahl', async (req, res) => {
  try {
    await assertAdminPermission(req, 'bestellungen.ansehen');
    const rows = await supabaseQuery('bestellungen',
      `?deleted_at=is.null&status=not.in.(versendet,geliefert,storniert,abgeholt)&select=id`) || [];
    return res.json({ ok: true, anzahl: Array.isArray(rows) ? rows.length : 0 });
  } catch (err) { console.error('❌ bestellungen-offen-anzahl', err); return sendError(res, err); }
});

// Detail + Positionen in einem Aufruf. Recht: bestellungen.ansehen
app.get('/api/admin/bestellungen/:id/voll', async (req, res) => {
  try {
    await assertAdminPermission(req, 'bestellungen.ansehen');
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const rows = await supabaseQuery('bestellungen', `?id=eq.${id}&limit=1`);
    const bestellung = Array.isArray(rows) ? rows[0] : null;
    if (!bestellung) { const e = new Error('Bestellung nicht gefunden'); e.statusCode = 404; throw e; }
    const positionen = await supabaseQuery('bestellpositionen', `?bestellung_id=eq.${id}&order=id`) || [];
    return res.json({ bestellung, positionen });
  } catch (err) { console.error('❌ admin/bestellung-voll', err); return sendError(res, err); }
});

// Aktualisieren (Status/Tracking) – Feld-Whitelist + granulare Rechte je Feldgruppe.
// Audit R-06: 'storniert' ist hier BEWUSST NICHT enthalten. Ein Storno ist ein Vorgang, kein
// Statuswechsel – dazu gehören Reservierungsfreigabe, Kundenmail, Vorgangseintrag, Audit-Log und
// das Recht `bestellungen.stornieren`. Über diese generische Route lief davon NICHTS: Die Ware
// blieb `reserved` (dauerhaft blockiert), der Kunde erfuhr nichts, und das Storno-Recht war
// umgangen, weil hier nur `bestellungen.status` geprüft wird.
// Legitime Wege: offene Vorkasse → POST /api/admin/vorkasse/stornieren (prüft das Storno-Recht
// und gibt die Reservierung frei); Auto-Storno-Lauf → storniereAbgelaufeneVorkasseBestellungen.
// Für bereits bezahlte Stripe-/PayPal-Bestellungen fehlt ein Erstattungsprozess – bis der
// existiert, darf eine solche Bestellung hier gar nicht storniert werden (offener Punkt).
const BESTELL_STATUS_WHITELIST = ['offen', 'warte_auf_zahlung', 'bezahlt', 'bestaetigt', 'versendet', 'geliefert'];
app.patch('/api/admin/bestellungen/:id', async (req, res) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const b = req.body || {};
    const patch = {};

    if ('status' in b) {
      await assertAdminPermission(req, 'bestellungen.status');
      const status = String(b.status || '');
      // Eigene, sprechende Ablehnung für 'storniert' (statt der generischen Whitelist-Meldung),
      // damit im Admin-Panel klar wird, welcher Weg stattdessen zu nehmen ist.
      if (status === 'storniert') {
        const e = new Error('Stornieren ist über das Status-Feld nicht möglich. Offene Vorkasse-Bestellungen über die Schaltfläche „Stornieren" abwickeln (gibt die Reservierung frei und benachrichtigt den Kunden). Für bereits bezahlte Karten- oder PayPal-Zahlungen ist eine Erstattung erforderlich.');
        e.statusCode = 400; throw e;
      }
      if (!BESTELL_STATUS_WHITELIST.includes(status)) { const e = new Error(`Ungültiger Status "${status}". Erlaubt: ${BESTELL_STATUS_WHITELIST.join(', ')}.`); e.statusCode = 400; throw e; }
      patch.status = status;
      if ('geliefert_am' in b) {
        const d = new Date(String(b.geliefert_am || ''));
        if (Number.isNaN(d.getTime())) { const e = new Error('Ungültiges geliefert_am (ISO-Datum erwartet).'); e.statusCode = 400; throw e; }
        patch.geliefert_am = d.toISOString();
      }
      if ('tracking_status' in b) {
        if (b.tracking_status !== 'zugestellt') { const e = new Error('Ungültiger tracking_status (erlaubt: zugestellt).'); e.statusCode = 400; throw e; }
        patch.tracking_status = 'zugestellt';
      }
    }
    if ('tracking_nr' in b || 'spediteur' in b) {
      await assertAdminPermission(req, 'bestellungen.tracking');
      if ('tracking_nr' in b) patch.tracking_nr = String(b.tracking_nr || '').trim() || null;
      if ('spediteur' in b) patch.spediteur = String(b.spediteur || '').trim() || null;
    }

    if (!Object.keys(patch).length) { const e = new Error('Keine erlaubten Felder zum Aktualisieren'); e.statusCode = 400; throw e; }

    if ('status' in patch) {
      // SCHUTZ für Kauf auf Rechnung (B-14). Eine Bestellung im Status 'auf_rechnung'
      // hat den Bestand BEREITS direkt abgebucht und besitzt KEINE Reservierungszeile.
      // Würde dieses Feld sie auf einen anderen Status umschreiben, ginge zweierlei
      // verloren:
      //   * die Information „Forderung offen" – ersatzlos, es gibt kein zweites Feld dafür
      //   * der einzige Zustand, aus dem storniere_rechnungskauf zurückbuchen KANN
      // Ein Wechsel auf 'bezahlt' wäre zusätzlich ein Zahlungszustand ohne Zahlung.
      // Die Bedingung steht im WHERE, nicht in einer vorherigen Leseprüfung: Zwischen
      // Lesen und Schreiben liegen mehrere Netzwerkrunden (vgl. Vorkasse-Storno).
      //
      // `status=neq.storniert` sperrt zusätzlich die WIEDERBELEBUNG. Bisher war eine
      // stornierte Bestellung nur im Admin-HTML geschützt (deaktiviertes Auswahlfeld) –
      // ein direkter API-Aufruf konnte sie weiterhin auf 'bezahlt' setzen. Damit wäre
      // eine Bestellung „bezahlt", deren Ware längst freigegeben und deren Kunde bereits
      // über den Storno informiert wurde. Eine Sperre, die nur im Frontend existiert,
      // ist keine Sperre.
      const beansprucht = await supabasePatchWhere(
        'bestellungen',
        `?id=eq.${encodeURIComponent(id)}&status=neq.auf_rechnung&status=neq.storniert`,
        patch
      );
      if (!Array.isArray(beansprucht) || beansprucht.length === 0) {
        const aktuell = await ladeBestellung(id).catch(() => null);
        if (aktuell && aktuell.status === 'auf_rechnung') {
          const e = new Error('Der Status einer Rechnungsbestellung kann über dieses Feld nicht geändert werden. Der Bestand wurde bereits direkt abgebucht; zum Zurücknehmen die Schaltfläche „Rechnungskauf stornieren" verwenden (bucht den Bestand zurück). Der weitere Ablauf läuft über die Lager- und Versandaktionen.');
          e.statusCode = 400; throw e;
        }
        if (aktuell && aktuell.status === 'storniert') {
          const e = new Error('Eine stornierte Bestellung kann nicht über das Status-Feld wiederbelebt werden. Die Ware wurde freigegeben und der Kunde wurde informiert. Für eine erneute Bestellung bitte einen neuen Vorgang anlegen.');
          e.statusCode = 400; throw e;
        }
        const e = new Error(`Die Bestellung wurde zwischenzeitlich bearbeitet oder existiert nicht (Status: ${aktuell?.status || 'unbekannt'}). Es wurde nichts geändert.`);
        e.statusCode = 409; throw e;
      }
    } else {
      await supabaseUpdate('bestellungen', id, patch);
    }

    await schreibeAuditLog(req, 'bestellung_aktualisiert', 'bestellungen', id, null, patch);
    return res.json({ ok: true });
  } catch (err) { console.error('❌ admin/bestellung-patch', err); return sendError(res, err); }
});

// -----------------------------------------------------------------------------
// Admin: B2B-Kunden lesen/aktualisieren über RECHTE-GEPRÜFTE Endpoints.
// Ersetzt die früheren Supabase-Direktzugriffe api('kundenprofil'/'kunden_mitarbeiter').
// -----------------------------------------------------------------------------

// Liste: Profile + Mitarbeiter. Recht: b2b.ansehen
app.get('/api/admin/kunden', async (req, res) => {
  try {
    await assertAdminPermission(req, 'b2b.ansehen');
    const profile = await supabaseQuery('kundenprofil', '?deleted_at=is.null&order=firma') || [];
    const mitarbeiter = await supabaseQuery('kunden_mitarbeiter', '?select=id,kundenprofil_id,email,name,rolle,aktiv&order=id') || [];
    return res.json({ ok: true, profile, mitarbeiter });
  } catch (err) { console.error('❌ admin/kunden-liste', err); return sendError(res, err); }
});

// Profil aktualisieren – Feld-Whitelist + GRANULARE Rechte: Stammdaten via
// b2b.bearbeiten; bonus/rechnung/zahlungsarten werden NUR mit dem jeweiligen Recht
// angewendet (sonst still ignoriert, kein 403 → bricht Speichern für Teil-Admins nicht).
app.patch('/api/admin/kunden/:id', async (req, res) => {
  try {
    const user = await assertAdminPermission(req, 'b2b.bearbeiten');
    const a = user._admin || {};
    const hat = (k) => istLegacyAdmin(a) || a.ist_super_admin === true || (a._perms && a._perms.has(k));
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const b = req.body || {};
    const patch = {};

    const basis = ['firma', 'kontakt_name', 'telefon', 'ust_idnr', 'steuernummer',
      'rechnungsadresse_strasse', 'rechnungsadresse_plz', 'rechnungsadresse_ort', 'rechnungsadresse_land'];
    basis.forEach(k => { if (k in b) patch[k] = (typeof b[k] === 'string' ? (b[k].trim() || null) : b[k]); });
    if ('einkaufsleiter_email' in b) patch.einkaufsleiter_email = normalizeEmail(b.einkaufsleiter_email) || null;

    if ('bonus_prozent' in b && hat('b2b.bonus')) patch.bonus_prozent = toNumber(b.bonus_prozent, 0);
    if ('rechnung_erlaubt' in b && hat('b2b.rechnung')) patch.rechnung_erlaubt = !!b.rechnung_erlaubt;
    if ('erlaubte_zahlungsarten' in b && hat('b2b.zahlungsarten')) {
      const erlaubt = ['stripe', 'paypal', 'vorkasse'];
      patch.erlaubte_zahlungsarten = Array.isArray(b.erlaubte_zahlungsarten)
        ? b.erlaubte_zahlungsarten.filter(z => erlaubt.includes(z)) : [];
    }

    if (!Object.keys(patch).length) { const e = new Error('Keine erlaubten Felder zum Aktualisieren'); e.statusCode = 400; throw e; }
    await supabaseUpdate('kundenprofil', id, patch);
    await schreibeAuditLog(req, 'b2b_kunde_geaendert', 'kundenprofil', id, null, patch);
    return res.json({ ok: true });
  } catch (err) { console.error('❌ admin/kunde-patch', err); return sendError(res, err); }
});

// -----------------------------------------------------------------------------
// Admin: KATALOG (Produkte, Pakete, Kategorien) über rechte-geprüfte Endpoints.
// Ersetzt die früheren Supabase-Direktzugriffe api('produkte'/'pakete'/'kategorien').
// Rechte: produkte.ansehen/erstellen/bearbeiten/loeschen/preise, kategorien.*.
// Pakete haben KEIN eigenes Recht → laufen unter produkte.* (Preis-Feld unter produkte.preise).
// -----------------------------------------------------------------------------

// Produktliste + Paket-Bestände. Recht: produkte.ansehen
app.get('/api/admin/produkte', async (req, res) => {
  try {
    await assertAdminPermission(req, 'produkte.ansehen');
    const produkte = await supabaseQuery('produkte', '?select=*,kategorien(name)&order=id.asc') || [];
    const pakete = await supabaseQuery('pakete', '?select=produkt_id,verfuegbare_pakete') || [];
    return res.json({ ok: true, produkte, pakete });
  } catch (err) { console.error('❌ admin/produkte-liste', err); return sendError(res, err); }
});

// Einzelprodukt + zugehörige Pakete. Recht: produkte.ansehen
app.get('/api/admin/produkte/:id', async (req, res) => {
  try {
    await assertAdminPermission(req, 'produkte.ansehen');
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const rows = await supabaseQuery('produkte', `?id=eq.${id}`) || [];
    if (!rows.length) { const e = new Error('Produkt nicht gefunden'); e.statusCode = 404; throw e; }
    const pakete = await supabaseQuery('pakete', `?produkt_id=eq.${id}&order=menge_m2`) || [];
    return res.json({ ok: true, produkt: rows[0], pakete });
  } catch (err) { console.error('❌ admin/produkt-einzeln', err); return sendError(res, err); }
});

// Pakete eines Produkts. Recht: produkte.ansehen
app.get('/api/admin/produkte/:id/pakete', async (req, res) => {
  try {
    await assertAdminPermission(req, 'produkte.ansehen');
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const pakete = await supabaseQuery('pakete', `?produkt_id=eq.${id}&order=menge_m2`) || [];
    return res.json({ ok: true, pakete });
  } catch (err) { console.error('❌ admin/produkt-pakete', err); return sendError(res, err); }
});

// Produkt-Body aus Whitelist bauen; preis_pro_m2 nur mit produkte.preise.
function baueProduktPatch(b, darfPreise) {
  const felder = ['name', 'kategorie_id', 'beschreibung', 'holzart', 'oberflaeche', 'staerke_mm',
    'sortierung', 'breite_mm', 'laenge_mm', 'artikelnummer', 'gewicht_pro_paket_kg', 'bestand_pakete',
    'lagerort', 've_m2', 'm2_pro_palette', 'bild_urls', 'aktiv'];
  const patch = {};
  felder.forEach(k => { if (k in b) patch[k] = b[k]; });
  if ('preis_pro_m2' in b && darfPreise) patch.preis_pro_m2 = b.preis_pro_m2;
  return patch;
}

// Der Shop navigiert Kategorie → Arten → Sortierungen → Produkte und findet Produkte
// NUR über sortierung_id. Das Admin-Formular setzt aber nur kategorie_id (+ Freitext
// holzart/sortierung). Diese Funktion stellt – wie die SQL-Migrationen – die Kette sicher:
// Art (Name = holzart) unter der Kategorie, Sortierung (Name = sortierung-Text) unter der Art,
// und verknüpft das Produkt (art_id/sortierung_id). Nur nötig, wenn das Produkt noch keine
// sortierung_id hat (frisch angelegt) – bestehende Verknüpfungen bleiben unangetastet.
async function stelleKatalogHierarchieSicher(produktId, kategorieId, holzart, sortierungText) {
  const katId = Number.parseInt(kategorieId, 10);
  if (!Number.isInteger(katId)) return;
  const artName = (holzart && String(holzart).trim()) || 'Standard';
  const sortName = (sortierungText && String(sortierungText).trim()) || 'Standard';

  // Art finden oder anlegen
  let arten = await supabaseQuery('arten', `?kategorie_id=eq.${katId}&name=eq.${encodeURIComponent(artName)}&limit=1`) || [];
  let artId = arten[0] && arten[0].id;
  if (!artId) {
    const vorhandene = await supabaseQuery('arten', `?kategorie_id=eq.${katId}&select=id`) || [];
    const neu = await supabaseInsert('arten', { kategorie_id: katId, name: artName, reihenfolge: vorhandene.length + 1, aktiv: true });
    artId = Array.isArray(neu) ? (neu[0] && neu[0].id) : (neu && neu.id);
  }
  if (!artId) return;

  // Sortierung finden oder anlegen
  let sorts = await supabaseQuery('sortierungen', `?art_id=eq.${artId}&name=eq.${encodeURIComponent(sortName)}&limit=1`) || [];
  let sortId = sorts[0] && sorts[0].id;
  if (!sortId) {
    const vorhandene = await supabaseQuery('sortierungen', `?art_id=eq.${artId}&select=id`) || [];
    const neu = await supabaseInsert('sortierungen', { art_id: artId, name: sortName, reihenfolge: vorhandene.length + 1, aktiv: true });
    sortId = Array.isArray(neu) ? (neu[0] && neu[0].id) : (neu && neu.id);
  }
  if (!sortId) return;

  await supabaseUpdate('produkte', produktId, { art_id: artId, sortierung_id: sortId });
}

// Legt ein Paket an, falls das Produkt noch keins hat (sonst übernimmt die
// Bestandsverteilung die vorhandenen Pakete). Bestand & Preis leiten sich aus dem
// Produkt ab: menge_m2 = VE (m²/Paket), preis = preis_pro_m2 × VE (Netto-Paketpreis).
async function stellePaketSicher(produktId, veM2, preisProM2, bestand) {
  const vorhandene = await supabaseQuery('pakete', `?produkt_id=eq.${produktId}&select=id&limit=1`) || [];
  if (vorhandene.length) return false;
  const menge = Number.parseFloat(veM2) || 0;
  const ppm2 = Number.parseFloat(preisProM2) || 0;
  await supabaseInsert('pakete', {
    produkt_id: produktId,
    menge_m2: menge,
    preis: Math.round(menge * ppm2 * 100) / 100,
    verfuegbare_pakete: Number.parseInt(bestand, 10) || 0,
    aktiv: true
  });
  return true;
}

// Neues Produkt. Recht: produkte.erstellen (+ produkte.preise für Preis).
app.post('/api/admin/produkte', async (req, res) => {
  try {
    const user = await assertAdminPermission(req, 'produkte.erstellen');
    const a = user._admin || {};
    const darfPreise = istLegacyAdmin(a) || a.ist_super_admin === true || (a._perms && a._perms.has('produkte.preise'));
    const b = req.body || {};
    if (!b.name || !String(b.name).trim()) { const e = new Error('Name ist Pflichtfeld'); e.statusCode = 400; throw e; }
    const daten = baueProduktPatch(b, darfPreise);
    daten.name = String(b.name).trim();
    const neu = await supabaseInsert('produkte', daten);
    const row = Array.isArray(neu) ? neu[0] : neu;
    if (row && row.id) {
      // Shop-Sichtbarkeit + Bestand herstellen: Art/Sortierung verknüpfen + Paket anlegen.
      try { await stelleKatalogHierarchieSicher(row.id, row.kategorie_id, row.holzart, row.sortierung); }
      catch (e) { console.error('⚠️ Katalog-Hierarchie (POST) fehlgeschlagen:', e && e.message); }
      await stellePaketSicher(row.id, row.ve_m2, row.preis_pro_m2, row.bestand_pakete);
    }
    produktCacheLeeren();
    await schreibeAuditLog(req, 'produkt_erstellt', 'produkte', row && row.id, null, daten);
    return res.json({ ok: true, produkt: row });
  } catch (err) { console.error('❌ admin/produkt-erstellen', err); return sendError(res, err); }
});

// Produkt ändern (+ Pakete: menge_m2 aus ve_m2, Bestand verteilen). Recht: produkte.bearbeiten.
app.patch('/api/admin/produkte/:id', async (req, res) => {
  try {
    const user = await assertAdminPermission(req, 'produkte.bearbeiten');
    const a = user._admin || {};
    const darfPreise = istLegacyAdmin(a) || a.ist_super_admin === true || (a._perms && a._perms.has('produkte.preise'));
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const b = req.body || {};
    const patch = baueProduktPatch(b, darfPreise);
    if (Object.keys(patch).length) await supabaseUpdate('produkte', id, patch);

    // Aktuelle Produktzeile laden (für Hierarchie-Check + korrekte VE/Preis-Werte)
    const prodRows = await supabaseQuery('produkte', `?id=eq.${id}&limit=1`) || [];
    const prod = prodRows[0] || {};

    // Shop-Sichtbarkeit: Art/Sortierung verknüpfen, falls noch nicht geschehen.
    if (prod.sortierung_id == null) {
      try { await stelleKatalogHierarchieSicher(id, prod.kategorie_id, prod.holzart, prod.sortierung); }
      catch (e) { console.error('⚠️ Katalog-Hierarchie (PATCH) fehlgeschlagen:', e && e.message); }
    }

    const pakete = await supabaseQuery('pakete', `?produkt_id=eq.${id}&select=id&order=id`) || [];
    if (!pakete.length) {
      // Noch kein Paket → eins anlegen (Bestand/Preis aus dem Produkt).
      await stellePaketSicher(id, prod.ve_m2, prod.preis_pro_m2, b.bestand_pakete);
    } else {
      // (1) VE (m²/Paket) auf alle Pakete übertragen
      const veM2 = Number.parseFloat(b.ve_m2);
      if (Number.isFinite(veM2) && veM2 > 0) {
        await supabasePatchWhere('pakete', `?produkt_id=eq.${id}`, { menge_m2: veM2 });
      }
      // (2) Gesamtbestand gleichmäßig auf alle Pakete verteilen (nur wenn gesetzt)
      if (b.bestand_pakete !== undefined && b.bestand_pakete !== null && b.bestand_pakete !== '') {
        const gesamt = Number.parseInt(b.bestand_pakete, 10) || 0;
        const proPaket = Math.floor(gesamt / pakete.length);
        const rest = gesamt % pakete.length;
        for (let i = 0; i < pakete.length; i++) {
          await supabaseUpdate('pakete', pakete[i].id, { verfuegbare_pakete: proPaket + (i === 0 ? rest : 0) });
        }
      }
    }
    _produktCache.delete(String(id));
    await schreibeAuditLog(req, 'produkt_geaendert', 'produkte', id, null, patch);
    return res.json({ ok: true });
  } catch (err) { console.error('❌ admin/produkt-patch', err); return sendError(res, err); }
});

// Produkt löschen. Recht: produkte.loeschen
app.delete('/api/admin/produkte/:id', async (req, res) => {
  try {
    await assertAdminPermission(req, 'produkte.loeschen');
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    await supabaseRequest(`produkte?id=eq.${id}`, { method: 'DELETE', headers: { Prefer: 'return=minimal' } });
    _produktCache.delete(String(id));
    await schreibeAuditLog(req, 'produkt_geloescht', 'produkte', id, null, null);
    return res.json({ ok: true });
  } catch (err) { console.error('❌ admin/produkt-loeschen', err); return sendError(res, err); }
});

// Neues Paket. Recht: produkte.bearbeiten (Preis-Feld zusätzlich produkte.preise).
app.post('/api/admin/pakete', async (req, res) => {
  try {
    const user = await assertAdminPermission(req, 'produkte.bearbeiten');
    const a = user._admin || {};
    const darfPreise = istLegacyAdmin(a) || a.ist_super_admin === true || (a._perms && a._perms.has('produkte.preise'));
    const b = req.body || {};
    const produktId = Number.parseInt(b.produkt_id, 10);
    if (!Number.isInteger(produktId)) { const e = new Error('Ungültige Produkt-ID'); e.statusCode = 400; throw e; }
    if ('preis' in b && !darfPreise) { const e = new Error('Keine Berechtigung für Preise (produkte.preise).'); e.statusCode = 403; throw e; }
    const daten = {
      produkt_id: produktId,
      menge_m2: Number.parseFloat(b.menge_m2) || 0,
      verfuegbare_pakete: Number.parseInt(b.verfuegbare_pakete, 10) || 0,
      aktiv: b.aktiv !== false
    };
    if ('preis' in b) daten.preis = Number.parseFloat(b.preis) || 0;
    const neu = await supabaseInsert('pakete', daten);
    _produktCache.delete(String(produktId));
    await schreibeAuditLog(req, 'paket_erstellt', 'pakete', Array.isArray(neu) ? (neu[0] && neu[0].id) : null, null, daten);
    return res.json({ ok: true, paket: Array.isArray(neu) ? neu[0] : neu });
  } catch (err) { console.error('❌ admin/paket-erstellen', err); return sendError(res, err); }
});

// Paket ändern (Bestand/aktiv/menge_m2; Preis nur mit produkte.preise). Recht: produkte.bearbeiten.
app.patch('/api/admin/pakete/:id', async (req, res) => {
  try {
    const user = await assertAdminPermission(req, 'produkte.bearbeiten');
    const a = user._admin || {};
    const darfPreise = istLegacyAdmin(a) || a.ist_super_admin === true || (a._perms && a._perms.has('produkte.preise'));
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const b = req.body || {};
    const patch = {};
    if ('verfuegbare_pakete' in b) patch.verfuegbare_pakete = Number.parseInt(b.verfuegbare_pakete, 10) || 0;
    if ('aktiv' in b) patch.aktiv = !!b.aktiv;
    if ('menge_m2' in b) patch.menge_m2 = Number.parseFloat(b.menge_m2) || 0;
    if ('preis' in b && darfPreise) patch.preis = Number.parseFloat(b.preis) || 0;
    if (!Object.keys(patch).length) { const e = new Error('Keine erlaubten Felder'); e.statusCode = 400; throw e; }
    const rows = await supabaseQuery('pakete', `?id=eq.${id}&select=produkt_id`) || [];
    await supabaseUpdate('pakete', id, patch);
    if (rows[0] && rows[0].produkt_id != null) _produktCache.delete(String(rows[0].produkt_id));
    return res.json({ ok: true });
  } catch (err) { console.error('❌ admin/paket-patch', err); return sendError(res, err); }
});

// Paket löschen. Recht: produkte.bearbeiten
app.delete('/api/admin/pakete/:id', async (req, res) => {
  try {
    await assertAdminPermission(req, 'produkte.bearbeiten');
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const rows = await supabaseQuery('pakete', `?id=eq.${id}&select=produkt_id`) || [];
    await supabaseRequest(`pakete?id=eq.${id}`, { method: 'DELETE', headers: { Prefer: 'return=minimal' } });
    if (rows[0] && rows[0].produkt_id != null) _produktCache.delete(String(rows[0].produkt_id));
    await schreibeAuditLog(req, 'paket_geloescht', 'pakete', id, null, null);
    return res.json({ ok: true });
  } catch (err) { console.error('❌ admin/paket-loeschen', err); return sendError(res, err); }
});

// Kategorienliste. Recht: kategorien.ansehen
app.get('/api/admin/kategorien', async (req, res) => {
  try {
    await assertAdminPermission(req, 'kategorien.ansehen');
    const kategorien = await supabaseQuery('kategorien', '?order=reihenfolge') || [];
    return res.json({ ok: true, kategorien });
  } catch (err) { console.error('❌ admin/kategorien-liste', err); return sendError(res, err); }
});

// Kategorie anlegen. Recht: kategorien.erstellen
app.post('/api/admin/kategorien', async (req, res) => {
  try {
    await assertAdminPermission(req, 'kategorien.erstellen');
    const b = req.body || {};
    if (!b.name || !String(b.name).trim()) { const e = new Error('Name ist Pflichtfeld'); e.statusCode = 400; throw e; }
    const daten = { name: String(b.name).trim(), reihenfolge: Number.parseInt(b.reihenfolge, 10) || 1, aktiv: b.aktiv !== false };
    const neu = await supabaseInsert('kategorien', daten);
    produktCacheLeeren();
    await schreibeAuditLog(req, 'kategorie_erstellt', 'kategorien', Array.isArray(neu) ? (neu[0] && neu[0].id) : null, null, daten);
    return res.json({ ok: true, kategorie: Array.isArray(neu) ? neu[0] : neu });
  } catch (err) { console.error('❌ admin/kategorie-erstellen', err); return sendError(res, err); }
});

// Kategorie ändern. Recht: kategorien.bearbeiten
app.patch('/api/admin/kategorien/:id', async (req, res) => {
  try {
    await assertAdminPermission(req, 'kategorien.bearbeiten');
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const b = req.body || {};
    const patch = {};
    if ('name' in b) patch.name = String(b.name || '').trim();
    if ('reihenfolge' in b) patch.reihenfolge = Number.parseInt(b.reihenfolge, 10) || 1;
    if ('aktiv' in b) patch.aktiv = !!b.aktiv;
    if (!Object.keys(patch).length) { const e = new Error('Keine erlaubten Felder'); e.statusCode = 400; throw e; }
    await supabaseUpdate('kategorien', id, patch);
    produktCacheLeeren();
    await schreibeAuditLog(req, 'kategorie_geaendert', 'kategorien', id, null, patch);
    return res.json({ ok: true });
  } catch (err) { console.error('❌ admin/kategorie-patch', err); return sendError(res, err); }
});

// Kategorie löschen. Recht: kategorien.loeschen
app.delete('/api/admin/kategorien/:id', async (req, res) => {
  try {
    await assertAdminPermission(req, 'kategorien.loeschen');
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    await supabaseRequest(`kategorien?id=eq.${id}`, { method: 'DELETE', headers: { Prefer: 'return=minimal' } });
    produktCacheLeeren();
    await schreibeAuditLog(req, 'kategorie_geloescht', 'kategorien', id, null, null);
    return res.json({ ok: true });
  } catch (err) { console.error('❌ admin/kategorie-loeschen', err); return sendError(res, err); }
});

app.post('/api/admin/kunden/:id/papierkorb', paymentLimiter, async (req, res) => {
  try {
    const su = await assertSuperAdmin(req);
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    await supabaseUpdate('kundenprofil', id, {
      deleted_at: new Date().toISOString(),
      deleted_by_email: normalizeEmail(su.email),
      deleted_by_auth_user_id: su.id || null,
      aktiv: false,
      restored_at: null, restored_by_auth_user_id: null
    });
    await schreibeAuditLog(req, 'b2b_kunde_papierkorb', 'kundenprofil', id, null, null);
    return res.json({ ok: true });
  } catch (err) { console.error('❌ Kunde Papierkorb', err); return sendError(res, err); }
});

app.post('/api/admin/kunden/:id/wiederherstellen', paymentLimiter, async (req, res) => {
  try {
    const su = await assertSuperAdmin(req);
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    await supabaseUpdate('kundenprofil', id, {
      deleted_at: null, deleted_by_email: null, deleted_by_auth_user_id: null,
      aktiv: true, restored_at: new Date().toISOString(), restored_by_auth_user_id: su.id || null
    });
    await schreibeAuditLog(req, 'b2b_kunde_wiederhergestellt', 'kundenprofil', id, null, null);
    return res.json({ ok: true });
  } catch (err) { console.error('❌ Kunde wiederherstellen', err); return sendError(res, err); }
});

// Geschützte Rechnungs-PDF-Vorschau: liefert eine kurzlebige signierte URL.
// Zugriff: Admin (mit Recht) ODER Kunde/Firma der Bestellung. Serverseitig geprüft.
app.get('/api/orders/:id/invoice-pdf-url', async (req, res) => {
  try {
    const user = await getUserFromAuthHeader(req);
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }

    const rows = await supabaseQuery('bestellungen', `?id=eq.${id}&limit=1`);
    const bestellung = Array.isArray(rows) ? rows[0] : null;
    if (!bestellung) { const e = new Error('Bestellung nicht gefunden'); e.statusCode = 404; throw e; }

    // Berechtigung prüfen.
    let erlaubt = false;
    const admin = await ladeAdmin(user.email);
    if (admin && admin.aktiv !== false) {
      erlaubt = istLegacyAdmin(admin) || admin.ist_super_admin === true || admin._perms.has('orders.view_invoice_pdf');
    } else {
      const ctx = await ladeKundenprofilFuerAuthUser(user);
      const istEigene = String(bestellung.user_id || '') === String(user.id)
        || (normalizeEmail(bestellung.bestellt_von_email) && normalizeEmail(bestellung.bestellt_von_email) === normalizeEmail(user.email))
        || (normalizeEmail(bestellung.email) && normalizeEmail(bestellung.email) === normalizeEmail(user.email));
      const istFirma = ctx?.profil && bestellung.kundenprofil_id === ctx.profil.id;
      // Einkaufsleiter: ganze Firma; Mitarbeiter: nur eigene Bestellungen.
      erlaubt = (ctx?.mitglied?.rolle === 'einkaufsleiter') ? !!istFirma : !!istEigene;
    }
    if (!erlaubt) { const e = new Error('Sie haben keine Berechtigung, dieses Dokument anzusehen.'); e.statusCode = 403; throw e; }

    // PDF-Pfad sicherstellen (bei Altbestellungen lazy aus Lexoffice nachladen).
    let path = bestellung.rechnung_pdf_storage_path || null;
    if (!path && bestellung.lexoffice_id && process.env.LEXOFFICE_API_KEY) {
      const buf = await holeLexofficePdf(bestellung.lexoffice_id);
      if (buf) {
        path = `rechnung-${id}.pdf`;
        try {
          await speicherePdfInStorage(path, buf);
          const patch = { rechnung_pdf_storage_path: path, rechnung_pdf_gespeichert_am: new Date().toISOString() };
          if (!bestellung.rechnung_nummer) {
            const vn = await holeLexofficeVoucherNumber(bestellung.lexoffice_id);
            if (vn) patch.rechnung_nummer = vn;
          }
          await supabaseUpdate('bestellungen', id, patch);
        } catch (e) { console.error('❌ PDF lazy-speichern:', e.message); path = null; }
      }
    }
    if (!path) {
      return res.json({ ok: true, url: null, message: 'Für diese Bestellung wurde noch keine Rechnung als PDF gespeichert.' });
    }

    const url = await signierteRechnungUrl(path, 3600);
    return res.json({ ok: true, url });
  } catch (err) { console.error('❌ invoice-pdf-url', err); return sendError(res, err); }
});

// Generischer Dokument-Abruf: rechnung | auftragsbestaetigung | lieferschein.
// Liefert eine kurzlebige signierte URL; AB/Lieferschein werden bei Bedarf erzeugt.
app.get('/api/orders/:id/document/:typ', async (req, res) => {
  try {
    const user = await getUserFromAuthHeader(req);
    const id = Number.parseInt(req.params.id, 10);
    const typ = String(req.params.typ || '');
    if (!Number.isInteger(id) || !['rechnung', 'auftragsbestaetigung', 'lieferschein'].includes(typ)) {
      const e = new Error('Ungültige Anfrage'); e.statusCode = 400; throw e;
    }
    const rows = await supabaseQuery('bestellungen', `?id=eq.${id}&limit=1`);
    const bestellung = Array.isArray(rows) ? rows[0] : null;
    if (!bestellung) { const e = new Error('Bestellung nicht gefunden'); e.statusCode = 404; throw e; }
    let darfDoc = await bestellungZugriffErlaubt(user, bestellung);
    if (!darfDoc && typ === 'lieferschein') {
      // Lager-Mitarbeiter dürfen NUR den Lieferschein (preislos) öffnen – NIEMALS
      // Rechnung oder Auftragsbestätigung (die enthalten Preise/Beträge).
      const ladmin = await ladeAdmin(user.email);
      if (ladmin && ladmin.aktiv !== false && ladmin._perms && (ladmin._perms.has('warehouse.print_documents') || ladmin._perms.has('warehouse.view_orders'))) darfDoc = true;
    }
    if (!darfDoc) {
      const e = new Error('Sie haben keine Berechtigung, dieses Dokument anzusehen.'); e.statusCode = 403; throw e;
    }

    // Echte Rechnungsnummer (voucherNumber) nachtragen, falls noch nicht gespeichert.
    if (!bestellung.rechnung_nummer && bestellung.lexoffice_id && process.env.LEXOFFICE_API_KEY) {
      const vn = await holeLexofficeVoucherNumber(bestellung.lexoffice_id);
      if (vn) { try { await supabaseUpdate('bestellungen', id, { rechnung_nummer: vn }); bestellung.rechnung_nummer = vn; } catch (_) {} }
    }

    let path = null;
    if (typ === 'rechnung') {
      path = bestellung.rechnung_pdf_storage_path || null;
      if (!path && bestellung.lexoffice_id && process.env.LEXOFFICE_API_KEY) {
        const buf = await holeLexofficePdf(bestellung.lexoffice_id);
        if (buf) {
          path = `rechnung-${id}.pdf`;
          await speicherePdfInStorage(path, buf);
          const patch = { rechnung_pdf_storage_path: path, rechnung_pdf_gespeichert_am: new Date().toISOString() };
          if (!bestellung.rechnung_nummer) { const vn = await holeLexofficeVoucherNumber(bestellung.lexoffice_id); if (vn) patch.rechnung_nummer = vn; }
          await supabaseUpdate('bestellungen', id, patch);
        }
      }
      if (!path) return res.json({ ok: true, url: null, message: 'Für diese Bestellung wurde noch keine Rechnung als PDF gespeichert.' });
    } else {
      const feld = typ === 'auftragsbestaetigung' ? 'auftragsbestaetigung_pdf_path' : 'lieferschein_pdf_path';
      const verfuegbar = typ === 'auftragsbestaetigung' ? !!bestellung.auftragsbestaetigung_versendet_am : !!bestellung.lieferschein_versendet_am;
      path = bestellung[feld] || null;
      if (!path) {
        if (!verfuegbar) return res.json({ ok: true, url: null, message: 'Dieses Dokument ist noch nicht verfügbar.' });
        const positionen = await ladePositionen(id);
        const buf = typ === 'auftragsbestaetigung'
          ? await erzeugeProfiPdf('Auftragsbestätigung', bestellung, positionen, true)
          : await erzeugeProfiPdf('Lieferschein', bestellung, positionen, false);
        path = `${typ}-${id}.pdf`;
        await speicherePdfInStorage(path, buf);
        await supabaseUpdate('bestellungen', id, { [feld]: path });
      }
    }
    const url = await signierteRechnungUrl(path, 3600);
    return res.json({ ok: true, url });
  } catch (err) { console.error('❌ document', err); return sendError(res, err); }
});

// [DEPRECATED] Alter Direktweg „An Spedition übergeben" → Versendet + Rechnung.
// Vom Frontend NICHT mehr genutzt (neuer Weg: /versand/:id/versenden nach Rollenkette).
// Bleibt nur aus Kompatibilität; Lager-Benutzer dürfen den Direktversand NICHT (kein Bypass).
app.post('/api/admin/bestellungen/:id/an-spedition', paymentLimiter, async (req, res) => {
  try {
    const user = await assertAdminPermission(req, 'warehouse.mark_handed_to_carrier');
    verbieteNurLager(user, 'Der Direktversand');
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const bestellung = await ladeBestellung(id);
    assertLagerfaehig(bestellung, 'Die Übergabe an die Spedition');
    const tracking = String(req.body?.tracking_nr || req.body?.trackingnummer || '').trim() || null;
    const trackingUrl = String(req.body?.tracking_url || '').trim() || null;
    const spediteur = String(req.body?.spediteur || '').trim() || null;
    await supabaseUpdate('bestellungen', id, {
      status: 'versendet',
      versandstatus: 'an_spedition_uebergeben',
      lager_status: 'abgeschlossen',
      an_spedition_uebergeben_am: new Date().toISOString(),
      an_spedition_uebergeben_von: user.id || null,
      an_spedition_uebergeben_von_email: normalizeEmail(user.email) || null,
      ...(spediteur ? { spediteur } : {}),
      ...(tracking ? { tracking_nr: tracking } : {}),
      ...(trackingUrl ? { tracking_url: trackingUrl } : {})
    });
    await schreibeAuditLog(req, 'an_spedition_uebergeben', 'bestellungen', id,
      { status: 'bezahlt', lager_status: bestellung.lager_status || 'in_bearbeitung' },
      { status: 'versendet', lager_status: 'abgeschlossen', spediteur, tracking_nr: tracking });
    // Rechnung JETZT erzeugen + versenden (idempotent).
    let rechnung = null;
    try {
      rechnung = await erstelleUndVersendeRechnung(id);
      await schreibeAuditLog(req, 'rechnung_versendet', 'bestellungen', id, null, { lexoffice_id: rechnung?.lexoffice_id || null });
    } catch (e) { console.error('❌ Rechnung nach Spedition:', e.message); }
    // Vorgangscenter: Versand + Sendungsverfolgung + Rechnung.
    await vorgangEreignis(bestellung, 'versendet', { text: 'Ware an die Spedition übergeben.', meta: { spediteur, status_neu: 'versendet' } });
    if (tracking) await vorgangEreignis(bestellung, 'tracking_verfuegbar', { text: 'Sendungsverfolgung verfügbar.', meta: { tracking_nr: tracking, tracking_url: trackingUrl } });
    const reNr = rechnung?.rechnung_nummer || bestellung.rechnung_nummer || null;
    if (reNr) await vorgangEreignis(bestellung, 'rechnung_erstellt', { text: 'Rechnung erstellt.', meta: { rechnung_nummer: reNr, dok_typ: 'rechnung' } });
    return res.json({ ok: true, rechnung });
  } catch (err) { console.error('❌ an-spedition', err); return sendError(res, err); }
});

// =============================================================================
// LAGERBEREICH – Kommissionierung & Versandübergabe (eigene, schlanke Sicht).
// Lager sieht KEINE Preise/Bonus/Kundendaten über das Nötige hinaus.
// =============================================================================

// Liste der vorzubereitenden Bestellungen (bezahlt, noch nicht an Spedition
// übergeben – denn die Übergabe setzt status='versendet'). Lager-sichere Felder.
app.get('/api/admin/lager', async (req, res) => {
  try {
    await assertWarehouse(req);
    const felder = 'id,erstellt_am,kundenname,firma,telefon,lieferart,abweichende_lieferadresse,' +
      'lieferadresse_empfaenger,lieferadresse_strasse,lieferadresse_plz,lieferadresse_ort,lieferadresse_land,lieferadresse_telefon,' +
      'rechnungsadresse_strasse,rechnungsadresse_plz,rechnungsadresse_ort,rechnungsadresse_land,' +
      'spediteur,lieferkosten_spediteur,tracking_nr,tracking_url,status,zahlungsart,lager_status,versandstatus,lieferschein_versendet_am,' +
      'kommissioniert_am,kommissioniert_von_email,spedition_beauftragt_am,spedition_beauftragt_von_email,' +
      'abholdatum,paketanzahl,palettenanzahl,gewicht,versanddaten,an_disposition_am,abgeholt_am,abgeholt_von_email';
    const ordersRoh = await supabaseQuery('bestellungen',
      `?status=in.(bezahlt,auf_rechnung)&deleted_at=is.null&select=${felder}&order=erstellt_am.desc`) || [];
    const orders = ordersRoh.filter(istLagerfaehig);
    // Positionen (preislos) gebündelt nachladen.
    const ids = orders.map(o => o.id);
    let posMap = {};
    if (ids.length) {
      const pos = await supabaseQuery('bestellpositionen',
        `?bestellung_id=in.(${ids.join(',')})&select=bestellung_id,produktname,anzahl_pakete,menge_m2_gesamt`) || [];
      for (const p of pos) { (posMap[p.bestellung_id] = posMap[p.bestellung_id] || []).push(p); }
    }
    const liste = orders.map(o => ({
      ...o,
      phase: versandPhase(o),
      lieferschein_verfuegbar: !!o.lieferschein_versendet_am,
      positionen: posMap[o.id] || [],
      anzahl_positionen: (posMap[o.id] || []).length
    }));
    return res.json({ ok: true, bestellungen: liste });
  } catch (err) { console.error('❌ lager-liste', err); return sendError(res, err); }
});

// Schritt 1: „Kommissionierung fertig" → Material gepackt, aber NICHT versendet.
// lager_status='kommissioniert', versandstatus='bereit_zur_abholung'. KEINE Rechnung.
app.post('/api/admin/lager/:id/kommissioniert', async (req, res) => {
  try {
    const user = await assertAdminPermission(req, 'warehouse.mark_ready');
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const bestellung = await ladeBestellung(id);
    assertLagerfaehig(bestellung, 'Die Kommissionierung');
    await supabaseUpdate('bestellungen', id, {
      lager_status: 'kommissioniert',
      versandstatus: 'bereit_zur_abholung',
      kommissioniert_am: new Date().toISOString(),
      kommissioniert_von_auth_user_id: user.id || null,
      kommissioniert_von_email: normalizeEmail(user.email) || null
    });
    await schreibeAuditLog(req, 'lager_kommissioniert', 'bestellungen', id,
      { lager_status: bestellung.lager_status || 'in_bearbeitung' }, { lager_status: 'kommissioniert', versandstatus: 'bereit_zur_abholung' });
    // Vorgang: internes Ereignis (Admin/Lager sehen es, Kunde nicht).
    try {
      await vorgangEreignis(bestellung, 'kommissioniert', {
        text: `Ware kommissioniert (fertig gepackt) – bereit zur Abholung/Übergabe.${normalizeEmail(user.email) ? ' Erledigt von ' + normalizeEmail(user.email) + '.' : ''}`,
        sichtbarkeit: 'intern_admin',
        meta: { lager_status: 'kommissioniert', versandstatus: 'bereit_zur_abholung' }
      });
    } catch (_) {}
    return res.json({ ok: true, lager_status: 'kommissioniert', versandstatus: 'bereit_zur_abholung' });
  } catch (err) { console.error('❌ lager-kommissioniert', err); return sendError(res, err); }
});

// Schritt 2: „Spedition beauftragen / Abholung anmelden" → Ware fertig, Abholung
// angemeldet. NOCH NICHT versendet, KEINE Rechnung.
app.post('/api/admin/lager/:id/spedition-beauftragen', async (req, res) => {
  try {
    const user = await assertAdminPermission(req, 'warehouse.request_spedition');
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const bestellung = await ladeBestellung(id);
    assertLagerfaehig(bestellung, 'Die Speditionsbeauftragung');
    const b = req.body || {};
    const spediteur = String(b.spediteur || '').trim() || null;
    const abholdatum = String(b.abholdatum || '').trim() || null; // YYYY-MM-DD
    const paketanzahl = b.paketanzahl != null && b.paketanzahl !== '' ? Number.parseInt(b.paketanzahl, 10) : null;
    const palettenanzahl = b.palettenanzahl != null && b.palettenanzahl !== '' ? Number.parseInt(b.palettenanzahl, 10) : null;
    const gewicht = b.gewicht != null && b.gewicht !== '' ? toNumber(b.gewicht, null) : null;
    const tracking = String(b.tracking_nr || b.trackingnummer || '').trim() || null;
    const trackingUrl = String(b.tracking_url || '').trim() || null;
    await supabaseUpdate('bestellungen', id, {
      lager_status: 'fertig_gepackt',
      versandstatus: 'spedition_beauftragt',
      spedition_beauftragt_am: new Date().toISOString(),
      spedition_beauftragt_von_auth_user_id: user.id || null,
      spedition_beauftragt_von_email: normalizeEmail(user.email) || null,
      ...(spediteur ? { spediteur } : {}),
      ...(abholdatum ? { abholdatum } : {}),
      ...(Number.isInteger(paketanzahl) ? { paketanzahl } : {}),
      ...(Number.isInteger(palettenanzahl) ? { palettenanzahl } : {}),
      ...(gewicht != null ? { gewicht } : {}),
      ...(tracking ? { tracking_nr: tracking } : {}),
      ...(trackingUrl ? { tracking_url: trackingUrl } : {})
    });
    await schreibeAuditLog(req, 'lager_spedition_beauftragt', 'bestellungen', id, null,
      { versandstatus: 'spedition_beauftragt', spediteur, abholdatum, paketanzahl, palettenanzahl });
    // Vorgang: internes Ereignis (Admin/Lager sehen es, Kunde nicht).
    try {
      const _detail = [
        spediteur ? 'Spedition: ' + spediteur : '',
        abholdatum ? 'Abholung: ' + abholdatum : '',
        Number.isInteger(paketanzahl) ? paketanzahl + ' Paket(e)' : '',
        Number.isInteger(palettenanzahl) ? palettenanzahl + ' Palette(n)' : ''
      ].filter(Boolean).join(' · ');
      await vorgangEreignis(bestellung, 'spedition_beauftragt', {
        text: `Spedition beauftragt / Abholung angemeldet.${_detail ? ' ' + _detail : ''}${normalizeEmail(user.email) ? ' (von ' + normalizeEmail(user.email) + ')' : ''}`,
        sichtbarkeit: 'intern_admin',
        meta: { versandstatus: 'spedition_beauftragt', spediteur, abholdatum, paketanzahl, palettenanzahl }
      });
    } catch (_) {}
    return res.json({ ok: true, lager_status: 'fertig_gepackt', versandstatus: 'spedition_beauftragt' });
  } catch (err) { console.error('❌ lager-spedition-beauftragen', err); return sendError(res, err); }
});

// =============================================================================
// VERSANDPROZESS v3 – strikte Rollentrennung Lager ↔ Disposition/Büro mit
// serverseitig erzwungener Reihenfolge. Der technische `status` bleibt `bezahlt`
// bzw. beim Rechnungskauf `auf_rechnung` bis zum Versand; der Ablauf läuft intern
// über versandPhase(b).
// Kette: in_bearbeitung → an_disposition → spedition_beauftragt → abgeholt → versendet
//        (Sonderfall Abholung: an_disposition → abholbereit → versendet)
// =============================================================================

const VERSAND_PHASE_LABEL = {
  in_bearbeitung: 'in Bearbeitung (Lager kommissioniert)',
  an_disposition: 'an Disposition übergeben (wartet aufs Büro)',
  spedition_beauftragt: 'Spedition beauftragt (wartet auf Abholung durchs Lager)',
  abgeholt: 'abgeholt (wartet auf Versand durchs Büro)',
  abholbereit: 'abholbereit gemeldet',
  versendet: 'versendet',
  geliefert: 'geliefert',
  storniert: 'storniert'
};

// Kanonische Versandphase (Single Source of Truth). Wird auch im Frontend gespiegelt.
function versandPhase(b) {
  const s = String(b && b.status || '');
  if (s === 'storniert') return 'storniert';
  if (s === 'geliefert') return 'geliefert';
  if (s === 'versendet') return 'versendet';
  const vs = String(b && b.versandstatus || '');
  if (vs === 'abgeholt') return 'abgeholt';
  if (vs === 'abholbereit') return 'abholbereit';
  if (vs === 'spedition_beauftragt') return 'spedition_beauftragt';
  if (vs === 'an_disposition' || vs === 'bereit_zur_abholung') return 'an_disposition';
  return 'in_bearbeitung';
}

// Erzwingt die Schritt-Reihenfolge serverseitig (409 bei falschem Stand).
function assertVersandPhase(b, erwartet) {
  const p = versandPhase(b);
  const ok = Array.isArray(erwartet) ? erwartet.includes(p) : p === erwartet;
  if (!ok) { const e = new Error(`Aktion nicht möglich – aktueller Stand: ${VERSAND_PHASE_LABEL[p] || p}.`); e.statusCode = 409; throw e; }
}

// LAGER – Schritt 1 (NEU): Versanddaten erfassen → an Disposition weitergeben.
// Recht warehouse.mark_ready. KEINE Kundenmail, KEINE Rechnung.
app.post('/api/admin/lager/:id/an-disposition', async (req, res) => {
  try {
    const user = await assertAdminPermission(req, 'warehouse.mark_ready');
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const bestellung = await ladeBestellung(id);
    assertLagerfaehig(bestellung, 'Die Kommissionierung');
    assertVersandPhase(bestellung, 'in_bearbeitung');
    const b = req.body || {};
    const pakete = b.pakete != null && b.pakete !== '' ? Number.parseInt(b.pakete, 10) : null;
    const paletten = Array.isArray(b.paletten) ? b.paletten.map(p => ({
      laenge: toNumber(p && p.laenge, null), breite: toNumber(p && p.breite, null),
      hoehe: toNumber(p && p.hoehe, null), gewicht: toNumber(p && p.gewicht, null)
    })) : [];
    const gesamtgewicht = b.gesamtgewicht != null && b.gesamtgewicht !== '' ? toNumber(b.gesamtgewicht, null) : null;
    const bemerkungen = String(b.bemerkungen || '').trim() || null;
    const versanddaten = { pakete, paletten, gesamtgewicht, bemerkungen };
    await supabaseUpdate('bestellungen', id, {
      lager_status: 'kommissioniert',
      versandstatus: 'an_disposition',
      versanddaten,
      ...(Number.isInteger(pakete) ? { paketanzahl: pakete } : {}),
      ...(paletten.length ? { palettenanzahl: paletten.length } : {}),
      ...(gesamtgewicht != null ? { gewicht: gesamtgewicht } : {}),
      kommissioniert_am: new Date().toISOString(),
      kommissioniert_von_auth_user_id: user.id || null,
      kommissioniert_von_email: normalizeEmail(user.email) || null,
      an_disposition_am: new Date().toISOString(),
      an_disposition_von_email: normalizeEmail(user.email) || null
    });
    await schreibeAuditLog(req, 'lager_an_disposition', 'bestellungen', id,
      { versandstatus: bestellung.versandstatus || null }, { versandstatus: 'an_disposition', versanddaten });
    try {
      await vorgangEreignis(bestellung, 'an_disposition', {
        text: `Ware vollständig kommissioniert. Versanddaten wurden erfasst. Bitte Versand organisieren.${normalizeEmail(user.email) ? ' (Lager: ' + normalizeEmail(user.email) + ')' : ''}`,
        sichtbarkeit: 'intern_admin',
        meta: { versandstatus: 'an_disposition', pakete, paletten: paletten.length, gesamtgewicht }
      });
    } catch (_) {}
    return res.json({ ok: true, phase: 'an_disposition' });
  } catch (err) { console.error('❌ lager-an-disposition', err); return sendError(res, err); }
});

// BÜRO – Schritt 2 (NEU): Spedition beauftragen. Nicht-Lager-Admin (bestellungen.tracking).
app.post('/api/admin/versand/:id/spedition-beauftragen', async (req, res) => {
  try {
    const user = await assertAdminPermission(req, 'bestellungen.tracking');
    verbieteNurLager(user, 'Die Versandplanung');
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const bestellung = await ladeBestellung(id);
    assertLagerfaehig(bestellung, 'Die Speditionsbeauftragung');
    assertVersandPhase(bestellung, 'an_disposition');
    const b = req.body || {};
    const spediteur = String(b.spediteur || '').trim() || null;
    const abholdatum = String(b.abholdatum || '').trim() || null;
    const tracking = String(b.tracking_nr || b.trackingnummer || '').trim() || null;
    const trackingUrl = String(b.tracking_url || '').trim() || null;
    const notiz = String(b.notiz || '').trim();
    await supabaseUpdate('bestellungen', id, {
      versandstatus: 'spedition_beauftragt',
      spedition_beauftragt_am: new Date().toISOString(),
      spedition_beauftragt_von_auth_user_id: user.id || null,
      spedition_beauftragt_von_email: normalizeEmail(user.email) || null,
      ...(spediteur ? { spediteur } : {}),
      ...(abholdatum ? { abholdatum } : {}),
      ...(tracking ? { tracking_nr: tracking } : {}),
      ...(trackingUrl ? { tracking_url: trackingUrl } : {})
    });
    await schreibeAuditLog(req, 'versand_spedition_beauftragt', 'bestellungen', id, null,
      { versandstatus: 'spedition_beauftragt', spediteur, abholdatum });
    try {
      const _d = [spediteur ? 'Spedition: ' + spediteur : '', abholdatum ? 'Abholung: ' + abholdatum : '', notiz].filter(Boolean).join(' · ');
      await vorgangEreignis(bestellung, 'spedition_beauftragt', {
        text: `Spedition wurde beauftragt.${_d ? ' ' + _d : ''}${normalizeEmail(user.email) ? ' (Büro: ' + normalizeEmail(user.email) + ')' : ''}`,
        sichtbarkeit: 'intern_admin',
        meta: { versandstatus: 'spedition_beauftragt', spediteur, abholdatum }
      });
    } catch (_) {}
    return res.json({ ok: true, phase: 'spedition_beauftragt' });
  } catch (err) { console.error('❌ versand-spedition-beauftragen', err); return sendError(res, err); }
});

// LAGER – Schritt 3 (NEU): Bestellung abgeholt (tatsächliche Abholung bestätigen).
// Recht warehouse.mark_handed_to_carrier.
app.post('/api/admin/lager/:id/abgeholt', async (req, res) => {
  try {
    const user = await assertAdminPermission(req, 'warehouse.mark_handed_to_carrier');
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const bestellung = await ladeBestellung(id);
    assertLagerfaehig(bestellung, 'Die Abholbestätigung');
    assertVersandPhase(bestellung, 'spedition_beauftragt');
    await supabaseUpdate('bestellungen', id, {
      versandstatus: 'abgeholt',
      abgeholt_am: new Date().toISOString(),
      abgeholt_von_auth_user_id: user.id || null,
      abgeholt_von_email: normalizeEmail(user.email) || null
    });
    await schreibeAuditLog(req, 'lager_abgeholt', 'bestellungen', id,
      { versandstatus: 'spedition_beauftragt' }, { versandstatus: 'abgeholt' });
    try {
      await vorgangEreignis(bestellung, 'abgeholt', {
        text: `Bestellung wurde vom Lager als abgeholt bestätigt.${normalizeEmail(user.email) ? ' (Lager: ' + normalizeEmail(user.email) + ')' : ''}`,
        sichtbarkeit: 'intern_admin',
        meta: { versandstatus: 'abgeholt' }
      });
    } catch (_) {}
    return res.json({ ok: true, phase: 'abgeholt' });
  } catch (err) { console.error('❌ lager-abgeholt', err); return sendError(res, err); }
});

// BÜRO – Schritt 4 (NEU): Kunde informieren / in Versand setzen.
// → Versendet + Rechnung + EINE Kundenmail (Versandbestätigung mit Sendungsverfolgung).
app.post('/api/admin/versand/:id/versenden', paymentLimiter, async (req, res) => {
  try {
    const user = await assertAdminPermission(req, 'bestellungen.status');
    verbieteNurLager(user, 'Der Versand');
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const bestellung = await ladeBestellung(id);
    assertLagerfaehig(bestellung, 'Der Versand');
    assertVersandPhase(bestellung, ['abgeholt', 'abholbereit']);
    // Spedition/Tracking aus dem Versenden-Dialog übernehmen; Fallback auf bereits
    // erfasste Werte (spedition-beauftragen / versanddaten). In versanddaten (jsonb)
    // ablegen und die Einzelspalten additiv synchron halten (Kunden-Tracking liest sie).
    const _body = req.body || {};
    const _vdAlt = bestellung.versanddaten || {};
    const spedition = String(_body.spedition || '').trim() || _vdAlt.spedition || bestellung.spediteur || null;
    const trackingNummer = String(_body.tracking_nummer || _body.tracking_nr || '').trim() || _vdAlt.tracking_nummer || bestellung.tracking_nr || null;
    const trackingUrl = String(_body.tracking_url || '').trim() || _vdAlt.tracking_url || bestellung.tracking_url || null;
    const versanddaten = { ..._vdAlt, spedition, tracking_nummer: trackingNummer, tracking_url: trackingUrl };
    await supabaseUpdate('bestellungen', id, {
      status: 'versendet',
      versandstatus: 'an_spedition_uebergeben',
      lager_status: 'abgeschlossen',
      an_spedition_uebergeben_am: new Date().toISOString(),
      an_spedition_uebergeben_von: user.id || null,
      an_spedition_uebergeben_von_email: normalizeEmail(user.email) || null,
      versanddaten,
      ...(spedition ? { spediteur: spedition } : {}),
      ...(trackingNummer ? { tracking_nr: trackingNummer } : {}),
      ...(trackingUrl ? { tracking_url: trackingUrl } : {})
    });
    await schreibeAuditLog(req, 'versand_versendet', 'bestellungen', id, { status: bestellung.status }, { status: 'versendet' });
    // Abholung wurde bereits bei 'abholbereit' per E-Mail (inkl. Rechnung) informiert →
    // hier KEINE zweite Kundenmail. Nur Lieferung bekommt die Versandbestätigung.
    const istAbholung = String(bestellung.lieferart || '') === 'abholung';
    let rechnung = null;
    if (!istAbholung) {
      // EINE Kundenmail (Lieferung): Versandbestätigung + Sendungsverfolgung + Rechnung-PDF.
      // Exakter Wortlaut; ohne Tracking-Link entfällt nur die Sendungsverfolgungs-Zeile.
      const trackLinkZeile = trackingUrl
        ? `<p style="margin:6px 0;">Sendungsverfolgung: <a href="${escapeHtml(trackingUrl)}" style="color:#C49A2B;">${escapeHtml(trackingUrl)}</a></p>`
        : '';
      const introHtml =
        `<p style="font-weight:600;margin:0 0 10px;">Ihre Bestellung ist unterwegs!</p>` +
        `<p style="margin:0 0 6px;">Sie können den Versand hier jederzeit verfolgen:</p>` +
        trackLinkZeile +
        `<p style="margin:0 0 14px;">Versanddienstleister: ${escapeHtml(spedition || '—')} · Sendungsnummer: ${escapeHtml(trackingNummer || '—')}</p>` +
        `<p style="margin:0;">Die Rechnung zu Ihrer Bestellung finden Sie im Anhang dieser E-Mail.</p>`;
      try {
        rechnung = await erstelleUndVersendeRechnung(id, {
          mailSubject: `Ihre Bestellung #${id} wurde versendet | VisioTrade`,
          mailHeading: 'Versandbestätigung',
          mailIntroHtml: introHtml
        });
        await schreibeAuditLog(req, 'rechnung_versendet', 'bestellungen', id, null, { lexoffice_id: rechnung && rechnung.lexoffice_id || null });
      } catch (e) { console.error('❌ Rechnung/Versandmail:', e.message); }
    }
    if (istAbholung) {
      await vorgangEreignis(bestellung, 'versendet', { text: 'Abholung abgeschlossen. Der Kunde wurde bei „abholbereit" informiert.', sichtbarkeit: 'intern_admin', meta: { status_neu: 'versendet' } });
    } else {
      await vorgangEreignis(bestellung, 'versendet', { text: 'Ihre Bestellung wurde versendet.', meta: { spediteur: spedition || null, status_neu: 'versendet' } });
      if (trackingNummer) await vorgangEreignis(bestellung, 'tracking_verfuegbar', { text: 'Sendungsverfolgung verfügbar.', meta: { tracking_nr: trackingNummer, tracking_url: trackingUrl } });
      const reNr = (rechnung && rechnung.rechnung_nummer) || bestellung.rechnung_nummer || null;
      if (reNr) await vorgangEreignis(bestellung, 'rechnung_erstellt', { text: 'Rechnung erstellt.', meta: { rechnung_nummer: reNr, dok_typ: 'rechnung' } });
      try { await vorgangEreignis(bestellung, 'kunde_informiert', { text: `Kunde wurde über den Versand informiert.${normalizeEmail(user.email) ? ' (Büro: ' + normalizeEmail(user.email) + ')' : ''}`, sichtbarkeit: 'intern_admin', meta: {} }); } catch (_) {}
    }
    return res.json({ ok: true, phase: 'versendet', rechnung });
  } catch (err) { console.error('❌ versand-versenden', err); return sendError(res, err); }
});

// LAGER – Sonderfall Abholung (NEU): Abholbereit melden → Kunde benachrichtigen.
app.post('/api/admin/lager/:id/abholbereit', async (req, res) => {
  try {
    const user = await assertAdminPermission(req, 'warehouse.mark_ready');
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const bestellung = await ladeBestellung(id);
    assertLagerfaehig(bestellung, 'Die Abholbereitmeldung');
    if (String(bestellung.lieferart || '') !== 'abholung') { const e = new Error('Nur bei Selbstabholung möglich.'); e.statusCode = 400; throw e; }
    assertVersandPhase(bestellung, 'an_disposition');
    await supabaseUpdate('bestellungen', id, { versandstatus: 'abholbereit', abholbereit_am: new Date().toISOString() });
    await schreibeAuditLog(req, 'lager_abholbereit', 'bestellungen', id, null, { versandstatus: 'abholbereit' });
    // Abholung = einzige Kundenmail an DIESEM Punkt: „kann abgeholt werden" inkl. Rechnung-PDF.
    // (Der spätere versenden-Schritt schickt für Abholung KEINE zweite Mail.)
    let rechnung = null;
    try {
      const introHtml =
        `<p style="font-weight:600;margin:0 0 10px;">Ihre Bestellung kann ab sofort abgeholt werden.</p>` +
        `<p style="margin:0 0 14px;">Bitte halten Sie zur Abholung Ihre Bestellnummer #${id} bereit.</p>` +
        `<p style="margin:0;">Die Rechnung zu Ihrer Bestellung finden Sie im Anhang dieser E-Mail.</p>`;
      rechnung = await erstelleUndVersendeRechnung(id, {
        mailSubject: `Ihre Bestellung #${id} ist abholbereit | VisioTrade`,
        mailHeading: 'Ihre Bestellung ist abholbereit',
        mailIntroHtml: introHtml
      });
    } catch (e) { console.error('❌ Abholbereit-Mail/Rechnung:', e.message); }
    await vorgangEreignis(bestellung, 'abholbereit', { text: 'Ihre Bestellung kann ab sofort abgeholt werden.', meta: {} });
    const _reNr = (rechnung && rechnung.rechnung_nummer) || bestellung.rechnung_nummer || null;
    if (_reNr) { try { await vorgangEreignis(bestellung, 'rechnung_erstellt', { text: 'Rechnung erstellt.', meta: { rechnung_nummer: _reNr, dok_typ: 'rechnung' } }); } catch (_) {} }
    try { await vorgangEreignis(bestellung, 'abholbereit_intern', { text: 'Ware steht zur Abholung bereit. Kunde per E-Mail informiert (inkl. Rechnung).', sichtbarkeit: 'intern_admin', meta: {} }); } catch (_) {}
    return res.json({ ok: true, phase: 'abholbereit' });
  } catch (err) { console.error('❌ lager-abholbereit', err); return sendError(res, err); }
});

// BÜRO-Liste: Versandplanung (aktive Versandphasen). Nicht-Lager-Admin.
app.get('/api/admin/versandplanung', async (req, res) => {
  try {
    const user = await assertAdminPermission(req, 'bestellungen.ansehen');
    verbieteNurLager(user, 'Die Versandplanung');
    const felder = 'id,erstellt_am,kundenname,firma,telefon,lieferart,spediteur,abholdatum,' +
      'tracking_nr,tracking_url,status,zahlungsart,lager_status,versandstatus,kommissioniert_am,kommissioniert_von_email,' +
      'an_disposition_am,paketanzahl,palettenanzahl,gewicht,versanddaten,gesamtbetrag,rechnung_nummer';
    const ordersRoh = await supabaseQuery('bestellungen',
      `?status=in.(bezahlt,auf_rechnung)&deleted_at=is.null&versandstatus=in.(an_disposition,spedition_beauftragt,abgeholt,abholbereit)&select=${felder}&order=erstellt_am.asc`) || [];
    const orders = ordersRoh.filter(istLagerfaehig);
    const liste = orders.map(o => ({ ...o, phase: versandPhase(o) }));
    return res.json({ ok: true, bestellungen: liste });
  } catch (err) { console.error('❌ versandplanung', err); return sendError(res, err); }
});

// Sichtbarkeiten, die das Lager im internen Bestell-Chat sehen darf
// (Kunde-Kontext + interne Admin-Notizen, NIE reine Super-Admin-Notizen).
// Lager-interner Chat: NUR Staff-Notizen, KEINE Kundennachrichten ('kunde' bewusst raus).
const LAGER_CHAT_SICHT = ['intern_admin', 'intern_admin_freigegeben'];

// Interner Bestell-Chat des Lagers: NUR lesen.
app.get('/api/admin/lager/:id/notizen', async (req, res) => {
  try {
    await assertAdminPermission(req, 'warehouse.chat_view');
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const rows = await supabaseQuery('nachrichten_threads', `?bestellung_id=eq.${id}&limit=1`);
    const thread = Array.isArray(rows) ? rows[0] : null;
    const nachrichten = thread ? await ladeThreadVerlauf(thread.id, LAGER_CHAT_SICHT) : [];
    return res.json({ ok: true, nachrichten });
  } catch (err) { console.error('❌ lager-notizen', err); return sendError(res, err); }
});

// Interner Bestell-Chat des Lagers: schreiben – IMMER intern, NIE an Kunden.
// Sichtbarkeit ist serverseitig fix auf intern_admin gesetzt; es findet KEIN
// externer Versand (E-Mail/Telegram/WhatsApp) statt.
app.post('/api/admin/lager/:id/notiz', async (req, res) => {
  try {
    const user = await assertAdminPermission(req, 'warehouse.chat_write');
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const text = String(req.body?.nachricht || req.body?.text || '').trim();
    if (!text) { const e = new Error('Bitte geben Sie einen Text ein.'); e.statusCode = 400; throw e; }
    if (text.length > 5000) { const e = new Error('Text ist zu lang (max. 5000 Zeichen).'); e.statusCode = 400; throw e; }
    const dateien = Array.isArray(req.body?.anhaenge) ? req.body.anhaenge : [];
    const bestellung = await ladeBestellung(id); // 404, falls Bestellung fehlt → Bestellbezug Pflicht
    const thread = await holeOderErstelleThreadFuerBestellung(bestellung, { name: bestellung.kundenname });
    const a = user._admin || {};
    await fuegeNachrichtHinzu(thread, bestellung, {
      text, dateien,
      absender: { authUserId: user.id, email: normalizeEmail(user.email), name: a.name || normalizeEmail(user.email) || 'Lager', rolle: 'lager' },
      istAdmin: true,            // interne Staff-Nachricht (kein Kunden-Status-Wechsel)
      sichtbarkeit: 'intern_admin', // HART intern – Lager kann das nicht ändern
      quelle: 'lager_internal_chat',
      neuerStatus: null
    });
    await schreibeAuditLog(req, 'lager_interne_notiz', 'nachrichten_threads', thread.id, null, { bestellung_id: id });
    const nachrichten = await ladeThreadVerlauf(thread.id, LAGER_CHAT_SICHT);
    return res.json({ ok: true, nachrichten });
  } catch (err) { console.error('❌ lager-notiz', err); return sendError(res, err); }
});

// Rechnung erneut senden = KOPIE der bestehenden Rechnung (keine neue Rechnung).
app.post('/api/admin/bestellungen/:id/rechnung-senden', paymentLimiter, async (req, res) => {
  try {
    await assertSuperAdmin(req);
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    await versendeRechnungsKopie(id);
    await schreibeAuditLog(req, 'rechnung_kopie_versendet', 'bestellungen', id, null, null);
    return res.json({ ok: true });
  } catch (err) { console.error('❌ Rechnungskopie', err); return sendError(res, err); }
});

// Echte Rechnungsnummer (voucherNumber) für eine Bestellung sicherstellen/nachtragen.
// Wird vom Admin-Bestelldetail lazy aufgerufen, wenn die Nummer noch fehlt.
app.post('/api/admin/bestellungen/:id/rechnungsnummer-sync', async (req, res) => {
  try {
    await assertAdminPermission(req, 'bestellungen.ansehen');
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const bestellung = await ladeBestellung(id);
    const nummer = await backfillRechnungNummer(bestellung);
    return res.json({ ok: true, rechnung_nummer: nummer || bestellung.rechnung_nummer || null });
  } catch (err) { console.error('❌ rechnungsnummer-sync', err); return sendError(res, err); }
});

// --- Admin: Nachrichten-System (Threads/Chat) ----------------------------------

// Übersicht aller Threads (optional nach Status gefiltert) inkl. letzter SICHTBARER Nachricht.
app.get('/api/admin/nachrichten', async (req, res) => {
  try {
    const user = await assertAdminPermission(req, 'messages.view');
    const sicht = adminSichtbarkeiten(user);
    const nurLager = istNurLagerUser(user._admin);
    const status = String(req.query?.status || '').toLowerCase();
    const filter = NACHRICHT_STATUS.includes(status)
      ? `?status=eq.${status}&order=letzte_nachricht_am.desc&limit=300`
      : `?order=letzte_nachricht_am.desc&limit=300`;
    let threads = await supabaseQuery('nachrichten_threads', filter) || [];
    if (nurLager) threads = threads.filter(t => !t.preisanfrage_id); // Lager: keine Preisanfrage-Vorgänge
    const bIds = [...new Set(threads.map(t => t.bestellung_id).filter(Boolean))];
    const tIds = threads.map(t => t.id);

    let orders = [];
    if (bIds.length) orders = await supabaseQuery('bestellungen', `?id=in.(${bIds.join(',')})&select=id,firma,kundenname,rechnung_nummer,status`) || [];
    const omap = {}; orders.forEach(o => { omap[o.id] = nurLager ? (({ rechnung_nummer, ...rest }) => rest)(o) : o; });

    // Preisanfrage-Threads: Nummer + Status für die Übersicht.
    const paIds = [...new Set(threads.map(t => t.preisanfrage_id).filter(Boolean))];
    const pamap = {};
    if (paIds.length) {
      const pas = await supabaseQuery('preisanfragen', `?id=in.(${paIds.join(',')})&select=id,pa_nummer,status,firma`) || [];
      pas.forEach(p => { pamap[p.id] = p; });
    }

    // Nur für diesen Admin sichtbare Nachrichten in die Vorschau/Zähler aufnehmen.
    let msgs = [];
    if (tIds.length) msgs = await supabaseQuery('nachrichten', `?thread_id=in.(${tIds.join(',')})&sichtbarkeit=in.(${sicht.join(',')})&order=created_at.asc&select=id,thread_id,nachricht_text,ist_admin_antwort,absender_rolle,sichtbarkeit,created_at`) || [];
    const letzte = {}; const anzMsg = {};
    msgs.forEach(m => { letzte[m.thread_id] = m; anzMsg[m.thread_id] = (anzMsg[m.thread_id] || 0) + 1; });
    let anh = [];
    const msgIds = msgs.map(m => m.id);
    if (msgIds.length) anh = await supabaseQuery('nachrichten_anhaenge', `?nachricht_id=in.(${msgIds.join(',')})&select=nachricht_id`) || [];
    const msgThread = {}; msgs.forEach(m => { msgThread[m.id] = m.thread_id; });
    const anhCount = {}; anh.forEach(a => { const t = msgThread[a.nachricht_id]; if (t) anhCount[t] = (anhCount[t] || 0) + 1; });

    const ungelesen = await ungeleseneProBestellung(bIds, user.id, sicht);
    // ungelesen ist je Bestellung; auf Thread mappen.
    const threadUngelesen = {}; threads.forEach(t => { threadUngelesen[t.id] = ungelesen[t.bestellung_id] || 0; });

    const nachrichten = threads.map(t => ({
      ...t,
      bestellung: omap[t.bestellung_id] || null,
      pa_nummer: pamap[t.preisanfrage_id]?.pa_nummer || null,
      pa_status: pamap[t.preisanfrage_id]?.status || null,
      pa_firma: pamap[t.preisanfrage_id]?.firma || null,
      letzte_nachricht: letzte[t.id] ? { text: letzte[t.id].nachricht_text, ist_admin_antwort: letzte[t.id].ist_admin_antwort, absender_rolle: letzte[t.id].absender_rolle, sichtbarkeit: letzte[t.id].sichtbarkeit, created_at: letzte[t.id].created_at } : null,
      anzahl_nachrichten: anzMsg[t.id] || 0,
      anzahl_anhaenge: anhCount[t.id] || 0,
      ungelesen: threadUngelesen[t.id] || 0
    }));
    return res.json({ ok: true, nachrichten });
  } catch (err) { console.error('❌ admin/nachrichten', err); return sendError(res, err); }
});

// Gesamt-Anzahl ungelesener (für den Admin sichtbarer) Nachrichten – Sidebar-Badge.
app.get('/api/admin/nachrichten/anzahl', async (req, res) => {
  try {
    const user = await assertAdminPermission(req, 'messages.view');
    const sicht = adminSichtbarkeiten(user);
    const threads = await supabaseQuery('nachrichten_threads', `?select=bestellung_id`) || [];
    const ids = [...new Set(threads.map(t => t.bestellung_id).filter(Boolean))];
    const counts = await ungeleseneProBestellung(ids, user.id, sicht);
    const anzahl = Object.values(counts).reduce((s, n) => s + n, 0);
    return res.json({ ok: true, anzahl });
  } catch (err) { console.error('❌ admin/nachrichten-anzahl', err); return sendError(res, err); }
});

// Ungelesene Nachrichten je Bestellung (für die Badges an den Bestellkarten im Admin).
app.get('/api/admin/nachrichten/ungelesen', async (req, res) => {
  try {
    const user = await assertAdminPermission(req, 'messages.view');
    const sicht = adminSichtbarkeiten(user);
    const threads = await supabaseQuery('nachrichten_threads', `?select=bestellung_id`) || [];
    const ids = [...new Set(threads.map(t => t.bestellung_id).filter(Boolean))];
    const counts = await ungeleseneProBestellung(ids, user.id, sicht);
    return res.json({ ok: true, counts });
  } catch (err) { console.error('❌ admin/ungelesen', err); return sendError(res, err); }
});

// Vollständiger Thread: Bestelldetails + Dokumente + (sichtbarer) Chat-Verlauf.
app.get('/api/admin/threads/:id', async (req, res) => {
  try {
    const user = await assertAdminPermission(req, 'messages.view');
    const sicht = adminSichtbarkeiten(user);
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const rows = await supabaseQuery('nachrichten_threads', `?id=eq.${id}&limit=1`);
    const thread = Array.isArray(rows) ? rows[0] : null;
    if (!thread) { const e = new Error('Thread nicht gefunden'); e.statusCode = 404; throw e; }

    const a = user._admin || {};
    const isSuper = istLegacyAdmin(a) || a.ist_super_admin === true;
    const perms = a._perms || new Set();

    // Allgemeine Threads haben keine Bestellung (bestellung_id NULL).
    let bestellung = null, positionen = [], dokumente = { auftragsbestaetigung: false, lieferschein: false, rechnung: false, tracking: false };
    if (thread.bestellung_id) {
      bestellung = await ladeBestellung(thread.bestellung_id);
      try { await backfillRechnungNummer(bestellung); } catch (_) {}
      positionen = await supabaseQuery('bestellpositionen', `?bestellung_id=eq.${thread.bestellung_id}&order=id.asc`) || [];
      dokumente = {
        auftragsbestaetigung: !!bestellung.auftragsbestaetigung_versendet_am,
        lieferschein: !!bestellung.lieferschein_versendet_am,
        rechnung: !!(bestellung.lexoffice_id || bestellung.rechnung_pdf_storage_path),
        tracking: !!bestellung.tracking_nr
      };
    }
    // Preisanfrage-Thread (bestellung_id NULL, preisanfrage_id gesetzt): Kontext mitliefern.
    let preisanfrage = null;
    if (thread.preisanfrage_id) {
      try {
        const par = await supabaseQuery('preisanfragen', `?id=eq.${thread.preisanfrage_id}&limit=1`);
        const pa = Array.isArray(par) ? par[0] : null;
        if (pa) preisanfrage = { id: pa.id, pa_nummer: pa.pa_nummer, status: pa.status, status_label: paStatusLabel(pa.status), firma: pa.firma, bestellung_id: pa.bestellung_id };
      } catch (_) {}
    }
    const nachrichten = await ladeThreadVerlauf(id, sicht);
    // Anhänge nur mit Recht (Super-Admin immer).
    if (!(isSuper || perms.has('messages.view_attachments'))) nachrichten.forEach(m => { m.anhaenge = []; });
    await markiereThreadGelesen(id, user.id); // beim Öffnen als gelesen markieren
    // Welche Schreib-Modi darf dieser Admin? (für die UI)
    const modi = {
      kunde: isSuper || perms.has('messages.reply_to_customer'),
      intern_admin: isSuper || perms.has('messages.create_internal_note'),
      intern_superadmin: isSuper || perms.has('messages.create_superadmin_note'),
      intern_admin_freigegeben: isSuper || perms.has('messages.create_superadmin_note')
    };
    const darfFreigeben = isSuper || perms.has('messages.manage_visibility');

    // Lager-Benutzer: reine Preisanfrage-Vorgänge sind tabu; Geldfelder werden aus
    // Bestellung + Positionen entfernt, PA-Kontext nicht mitgeliefert (serverseitig).
    const nurLager = istNurLagerUser(a);
    if (nurLager && thread.preisanfrage_id && !thread.bestellung_id) {
      const e = new Error('Preisanfrage-Vorgänge sind für Lager-Benutzer nicht verfügbar.'); e.statusCode = 403; throw e;
    }
    const outBestellung = nurLager ? entferneGeldfelderBestellung(bestellung) : bestellung;
    const outPositionen = nurLager ? positionen.map(entferneGeldfelderPosition) : positionen;
    const outPreisanfrage = nurLager ? null : preisanfrage;
    return res.json({ ok: true, thread, bestellung: outBestellung, preisanfrage: outPreisanfrage, positionen: outPositionen, nachrichten, dokumente, modi, darf_freigeben: darfFreigeben });
  } catch (err) { console.error('❌ admin/thread', err); return sendError(res, err); }
});

// Thread zu einer Bestellung finden (für die Sektion im Bestelldetail).
app.get('/api/admin/bestellungen/:id/thread', async (req, res) => {
  try {
    const user = await assertAdminPermission(req, 'messages.view');
    const sicht = adminSichtbarkeiten(user);
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const rows = await supabaseQuery('nachrichten_threads', `?bestellung_id=eq.${id}&limit=1`);
    const thread = Array.isArray(rows) ? rows[0] : null;
    const nachrichten = thread ? await ladeThreadVerlauf(thread.id, sicht) : [];
    const a = user._admin || {};
    if (!(istLegacyAdmin(a) || a.ist_super_admin === true || (a._perms || new Set()).has('messages.view_attachments'))) nachrichten.forEach(m => { m.anhaenge = []; });
    return res.json({ ok: true, thread: thread || null, nachrichten });
  } catch (err) { console.error('❌ admin/bestellung-thread', err); return sendError(res, err); }
});

// Admin öffnet/erstellt den Thread einer Bestellung (z. B. um eine interne Notiz anzulegen).
app.post('/api/admin/bestellungen/:id/thread-oeffnen', async (req, res) => {
  try {
    const user = await assertAdminPermission(req, 'messages.view');
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const bestellung = await ladeBestellung(id);
    const rows = await supabaseQuery('nachrichten_threads', `?bestellung_id=eq.${id}&limit=1`);
    let thread = Array.isArray(rows) ? rows[0] : null;
    if (!thread) {
      const ins = await supabaseInsert('nachrichten_threads', {
        bestellung_id: id,
        kundenprofil_id: bestellung.kundenprofil_id || null,
        erstellt_von_email: normalizeEmail(user.email),
        erstellt_von_name: user._admin?.name || normalizeEmail(user.email),
        typ: 'nachricht',
        // 2c: Admin öffnet Thread (meist für interne Notiz) → neutral, nicht 'offen'.
        status: 'beantwortet',
        betreff: `Bestellung #${id}`,
        letzte_nachricht_am: new Date().toISOString()
      });
      thread = Array.isArray(ins) ? ins[0] : ins;
    }
    return res.json({ ok: true, thread_id: thread.id });
  } catch (err) { console.error('❌ admin/thread-oeffnen', err); return sendError(res, err); }
});

// Admin/Superadmin schreibt im Thread: an Kunden ODER als interne Notiz.
app.post('/api/admin/threads/:id/antwort', async (req, res) => {
  try {
    const user = await assertAdminPermission(req, 'messages.view');
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const rows = await supabaseQuery('nachrichten_threads', `?id=eq.${id}&limit=1`);
    const thread = Array.isArray(rows) ? rows[0] : null;
    if (!thread) { const e = new Error('Thread nicht gefunden'); e.statusCode = 404; throw e; }

    const text = String(req.body?.nachricht || req.body?.text || '').trim();
    if (!text) { const e = new Error('Bitte geben Sie einen Text ein.'); e.statusCode = 400; throw e; }
    if (text.length > 5000) { const e = new Error('Text ist zu lang (max. 5000 Zeichen).'); e.statusCode = 400; throw e; }
    const dateien = Array.isArray(req.body?.anhaenge) ? req.body.anhaenge : [];

    // Modus + Berechtigung bestimmen.
    const a = user._admin || {};
    const isSuper = istLegacyAdmin(a) || a.ist_super_admin === true;
    const perms = a._perms || new Set();
    const modus = String(req.body?.modus || 'kunde').toLowerCase();
    let sichtbarkeit, anKunde;
    if (modus === 'intern_superadmin') {
      if (!(isSuper || perms.has('messages.create_superadmin_note'))) { const e = new Error('Keine Berechtigung für Super-Admin-Notizen.'); e.statusCode = 403; throw e; }
      sichtbarkeit = 'intern_superadmin'; anKunde = false;
    } else if (modus === 'intern_admin_freigegeben') {
      if (!(isSuper || perms.has('messages.create_superadmin_note'))) { const e = new Error('Keine Berechtigung für Super-Admin-Notizen.'); e.statusCode = 403; throw e; }
      sichtbarkeit = 'intern_admin_freigegeben'; anKunde = false;
    } else if (modus === 'intern_admin') {
      if (!(isSuper || perms.has('messages.create_internal_note'))) { const e = new Error('Keine Berechtigung für interne Notizen.'); e.statusCode = 403; throw e; }
      sichtbarkeit = 'intern_admin'; anKunde = false;
    } else {
      if (!(isSuper || perms.has('messages.reply_to_customer'))) { const e = new Error('Keine Berechtigung, an den Kunden zu antworten.'); e.statusCode = 403; throw e; }
      sichtbarkeit = 'kunde'; anKunde = true;
    }

    const bestellung = thread.bestellung_id ? await ladeBestellung(thread.bestellung_id) : null;
    const adminName = a.name || normalizeEmail(user.email) || 'VisioTrade Team';

    await fuegeNachrichtHinzu(thread, bestellung, {
      text, dateien,
      absender: { authUserId: user.id, email: normalizeEmail(user.email), name: adminName, rolle: isSuper ? 'superadmin' : 'admin' },
      istAdmin: true, sichtbarkeit, quelle: 'admin_chat',
      neuerStatus: anKunde ? 'beantwortet' : null // interne Notiz ändert den Kunden-Status nicht
    });
    await schreibeAuditLog(req, anKunde ? 'nachricht_antwort' : 'nachricht_notiz', 'nachrichten_threads', id, null, { bestellung_id: thread.bestellung_id, sichtbarkeit, kanal: thread.kanal_letzte_nachricht });

    // Kundenantwort über den KANAL der letzten Kundennachricht zustellen (E-Mail/Telegram/…).
    // Interne Notizen werden NIE extern versendet.
    let zustellResultat = null;
    if (anKunde) {
      const attachments = [];
      for (const f of (Array.isArray(dateien) ? dateien.slice(0, NACHRICHT_MAX_ANHAENGE) : [])) {
        const mime = String(f?.typ || '').toLowerCase();
        if (!NACHRICHT_MIME[mime]) continue;
        const b64 = String(f?.contentBase64 || '').replace(/^data:[^;]+;base64,/, '');
        if (!b64) continue;
        try { const buf = Buffer.from(b64, 'base64'); if (buf.length && buf.length <= NACHRICHT_MAX_BYTES) attachments.push({ name: f?.name || `anhang.${NACHRICHT_MIME[mime]}`, content: buf.toString('base64') }); } catch (_) {}
      }
      try { zustellResultat = await dispatchKundenantwort(thread, bestellung, text, attachments); } catch (e) { console.error('❌ Antwort-Versand:', e.message); zustellResultat = { zugestellt: false, fehler: e.message }; }
    }

    const nachrichten = await ladeThreadVerlauf(id, adminSichtbarkeiten(user));
    // Dem Admin Rückmeldung geben, falls die externe Zustellung nicht klappte.
    let warnung = null;
    if (anKunde && zustellResultat && !zustellResultat.zugestellt) {
      warnung = zustellResultat.kanal === 'whatsapp'
        ? 'Hinweis: WhatsApp-Versand ist noch nicht aktiv – die Nachricht wurde im Verlauf gespeichert, aber nicht extern zugestellt.'
        : 'Achtung: Die Nachricht konnte nicht zugestellt werden (keine gültige Kunden-/Gast-Adresse oder Versandfehler). Sie ist im Verlauf gespeichert.';
    }
    return res.json({ ok: true, nachrichten, warnung });
  } catch (err) { console.error('❌ admin/thread-antwort', err); return sendError(res, err); }
});

// Status eines Threads setzen.
app.patch('/api/admin/threads/:id/status', async (req, res) => {
  try {
    await assertAdminPermission(req, 'messages.change_status');
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const status = String(req.body?.status || '').toLowerCase();
    if (!NACHRICHT_STATUS.includes(status)) { const e = new Error('Ungültiger Status'); e.statusCode = 400; throw e; }
    await supabaseUpdate('nachrichten_threads', id, { status, updated_at: new Date().toISOString() });
    await schreibeAuditLog(req, 'nachricht_status', 'nachrichten_threads', id, null, { status });
    return res.json({ ok: true });
  } catch (err) { console.error('❌ thread-status', err); return sendError(res, err); }
});

// Sichtbarkeit einer einzelnen Nachricht nachträglich ändern (z. B. Super-Admin-Notiz
// „für Admins freigeben"). Nur Super-Admin oder Recht messages.manage_visibility.
app.patch('/api/admin/nachrichten/:id/sichtbarkeit', async (req, res) => {
  try {
    const user = await assertAdminPermission(req, 'messages.view');
    const a = user._admin || {};
    const isSuper = istLegacyAdmin(a) || a.ist_super_admin === true;
    const perms = a._perms || new Set();
    if (!(isSuper || perms.has('messages.manage_visibility'))) {
      const e = new Error('Keine Berechtigung, die Sichtbarkeit zu ändern.'); e.statusCode = 403; throw e;
    }
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const ziel = String(req.body?.sichtbarkeit || '').toLowerCase();
    if (!['intern_admin', 'intern_superadmin', 'intern_admin_freigegeben'].includes(ziel)) {
      const e = new Error('Ungültige Sichtbarkeit.'); e.statusCode = 400; throw e;
    }
    const rows = await supabaseQuery('nachrichten', `?id=eq.${id}&limit=1`);
    const msg = Array.isArray(rows) ? rows[0] : null;
    if (!msg) { const e = new Error('Nachricht nicht gefunden'); e.statusCode = 404; throw e; }
    // Kundensichtbare Nachrichten werden hier NICHT internalisiert (Schutz vor Versehen).
    if (msg.sichtbarkeit === 'kunde') { const e = new Error('Kundensichtbare Nachrichten können hier nicht umklassifiziert werden.'); e.statusCode = 400; throw e; }
    await supabaseUpdate('nachrichten', id, { sichtbarkeit: ziel, ist_interne_notiz: ziel !== 'kunde' });
    await schreibeAuditLog(req, 'nachricht_sichtbarkeit', 'nachrichten', id, { sichtbarkeit: msg.sichtbarkeit }, { sichtbarkeit: ziel });
    return res.json({ ok: true });
  } catch (err) { console.error('❌ nachricht-sichtbarkeit', err); return sendError(res, err); }
});

// Als geliefert markieren (Super-Admin oder Lagerist mit Versand-Recht).
app.post('/api/admin/bestellungen/:id/geliefert', paymentLimiter, async (req, res) => {
  try {
    await assertAdminPermission(req, 'warehouse.mark_handed_to_carrier');
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }
    const bestellung = await ladeBestellung(id);
    if (bestellung.status !== 'versendet') { const e = new Error('Nur versendete Bestellungen können als geliefert markiert werden.'); e.statusCode = 400; throw e; }
    await supabaseUpdate('bestellungen', id, {
      status: 'geliefert',
      geliefert_am: new Date().toISOString(),
      tracking_status: 'zugestellt'
    });
    await schreibeAuditLog(req, 'als_geliefert_markiert', 'bestellungen', id, { status: 'versendet' }, { status: 'geliefert' });
    // Vorgangscenter: Zustellung.
    await vorgangEreignis(bestellung, 'geliefert', { text: 'Ware zugestellt.', meta: { status_neu: 'geliefert' } });
    return res.json({ ok: true });
  } catch (err) { console.error('❌ geliefert', err); return sendError(res, err); }
});

// Einmaliger Backfill: erzeugt für vorhandene Bestellungen die Timeline-Ereignisse aus
// bereits gespeicherten Daten/Zeitstempeln. Idempotent (mehrfach ausführbar). Bei >5000
// Bestellungen mit ?von=<letzte_id> weiter paginieren.
app.post('/api/admin/vorgangscenter/backfill', async (req, res) => {
  try {
    await assertAdminPermission(req, 'bestellungen.status');
    const von = Number.parseInt(req.query?.von || '0', 10) || 0;
    const felder = 'id,kundenname,bestellt_von_email,email,kundenprofil_id,gesamtbetrag,status,zahlungsart,' +
      'erstellt_am,bezahlt_am,auftragsbestaetigung_erstellt_am,rechnung_nummer,rechnung_versendet_am,' +
      'tracking_nr,tracking_url,spediteur,an_spedition_uebergeben_am,geliefert_am';
    const orders = await supabaseQuery('bestellungen',
      `?deleted_at=is.null&id=gt.${von}&select=${felder}&order=id.asc&limit=5000`) || [];
    let n = 0;
    for (const b of orders) {
      const ein = b.erstellt_am || null;
      await vorgangEreignis(b, 'bestellung_eingegangen', { text: 'Bestellung erfolgreich aufgenommen.', meta: { betrag: b.gesamtbetrag }, createdAt: ein });
      if (b.bezahlt_am)
        await vorgangEreignis(b, 'bezahlt', { text: 'Zahlung eingegangen.', meta: { betrag: b.gesamtbetrag }, createdAt: b.bezahlt_am });
      if (b.auftragsbestaetigung_erstellt_am)
        await vorgangEreignis(b, 'auftrag_bestaetigt', { text: 'Auftragsbestätigung erstellt.', meta: { dok_typ: 'auftragsbestaetigung' }, createdAt: b.auftragsbestaetigung_erstellt_am });
      else if (b.zahlungsart === 'rechnung')
        await vorgangEreignis(b, 'auftrag_bestaetigt', { text: 'Auftragsbestätigung erstellt (Kauf auf Rechnung).', meta: { dok_typ: 'auftragsbestaetigung' }, createdAt: ein });
      if (b.rechnung_nummer)
        await vorgangEreignis(b, 'rechnung_erstellt', { text: 'Rechnung erstellt.', meta: { rechnung_nummer: b.rechnung_nummer, dok_typ: 'rechnung' }, createdAt: b.rechnung_versendet_am || b.an_spedition_uebergeben_am || ein });
      if (b.an_spedition_uebergeben_am || b.tracking_nr || ['versendet', 'geliefert'].includes(b.status))
        await vorgangEreignis(b, 'versendet', { text: 'Ware an die Spedition übergeben.', meta: { spediteur: b.spediteur, status_neu: 'versendet' }, createdAt: b.an_spedition_uebergeben_am || ein });
      if (b.tracking_nr)
        await vorgangEreignis(b, 'tracking_verfuegbar', { text: 'Sendungsverfolgung verfügbar.', meta: { tracking_nr: b.tracking_nr, tracking_url: b.tracking_url }, createdAt: b.an_spedition_uebergeben_am || ein });
      if (b.geliefert_am || b.status === 'geliefert')
        await vorgangEreignis(b, 'geliefert', { text: 'Ware zugestellt.', meta: { status_neu: 'geliefert' }, createdAt: b.geliefert_am || ein });
      if (b.status === 'storniert')
        await vorgangEreignis(b, 'storniert', { text: 'Bestellung storniert.', meta: { status_neu: 'storniert' }, createdAt: ein });
      n++;
    }
    const letzteId = orders.length ? orders[orders.length - 1].id : von;
    return res.json({ ok: true, verarbeitet: n, letzte_id: letzteId, weiter: orders.length >= 5000 });
  } catch (err) { console.error('❌ vorgangscenter-backfill', err); return sendError(res, err); }
});

// Dashboard-Kennzahlen serverseitig berechnen (P1). Eine einzige DB-Funktion
// liefert Zähler + Umsatz + die letzten 8 Bestellungen – statt bis zu 1000
// Bestellungen in den Browser zu laden und dort zu zählen.
app.get('/api/admin/dashboard-stats', async (req, res) => {
  try {
    const user = await assertAdmin(req);
    // Reine Lager-Mitarbeiter sehen KEINE Umsatz-/Finanzdaten (serverseitig hart).
    if (istNurLagerUser(user._admin || {})) { const e = new Error('Kein Zugriff auf das Dashboard.'); e.statusCode = 403; throw e; }
    const stats = await supabaseRpc('dashboard_stats', {});
    return res.json(stats || { produkte: 0, bestellungen: 0, offen: 0, umsatz: 0, letzteBestellungen: [] });
  } catch (err) { console.error('❌ dashboard-stats', err); return sendError(res, err); }
});

app.get('/api/admin/papierkorb', async (req, res) => {
  try {
    await assertSuperAdmin(req);
    const bestellungen = await supabaseQuery('bestellungen', `?deleted_at=not.is.null&select=id,kundenname,firma,gesamtbetrag,zahlungsart,status,erstellt_am,deleted_at,deleted_by_email&order=deleted_at.desc`) || [];
    const kunden = await supabaseQuery('kundenprofil', `?deleted_at=not.is.null&select=id,firma,einkaufsleiter_email,deleted_at,deleted_by_email&order=deleted_at.desc`) || [];
    return res.json({ ok: true, bestellungen: Array.isArray(bestellungen) ? bestellungen : [], kunden: Array.isArray(kunden) ? kunden : [] });
  } catch (err) { console.error('❌ Papierkorb', err); return sendError(res, err); }
});

// -----------------------------------------------------------------------------
// Admin: Vorkasse Zahlung erhalten → echte Rechnung erstellen
// -----------------------------------------------------------------------------

app.post('/api/admin/vorkasse/zahlung-erhalten', async (req, res) => {
  try {
    await assertAdminPermission(req, 'bestellungen.vorkasse_bezahlt');

    const bestellungIdRoh = req.body?.bestellung_id;
    const bestellungIdText = (typeof bestellungIdRoh === 'string' || typeof bestellungIdRoh === 'number')
      ? String(bestellungIdRoh)
      : '';
    const bestellung_id = Number(bestellungIdText);

    if (!/^\d+$/.test(bestellungIdText)
        || !Number.isSafeInteger(bestellung_id)
        || bestellung_id <= 0) {
      return res.status(400).json({
        error: 'bestellung_id fehlt oder ist ungueltig'
      });
    }

    let bestellung = await ladeBestellung(bestellung_id);

    if (String(bestellung.zahlungsart || '').toLowerCase() !== 'vorkasse') {
      return res.status(400).json({ error: 'Nur Vorkasse-Bestellungen können hier als bezahlt gebucht werden.' });
    }

    // Vollständig erledigt: Zahlung UND Lagerbuchung sind dauerhaft bestätigt.
    // Eine nur als bezahlt markierte Bestellung darf hier NICHT aussteigen – genau
    // dieser Zustand ist der sichere Wiederholungsweg nach einem Lager-/Netzfehler.
    if (bestellung.status === 'bezahlt' && bestellung.reservierung_status === 'consumed') {
      return res.json({
        ok: true,
        already_processed: true,
        zahlung_erfasst: true,
        lagerbuchung_erfolgreich: true,
        message: 'Bestellung wurde bereits als bezahlt verarbeitet.'
      });
    }

    let zahlungNeuErfasst = false;
    if (bestellung.status !== 'bezahlt') {
      // Atomarer Zahlungs-Claim. Die Zahlung wird absichtlich VOR der Lagerbuchung
      // festgehalten: einen realen Geldeingang darf ein Lagerfehler nicht zurücknehmen.
      const beansprucht = await supabasePatchWhere(
        'bestellungen',
        `?id=eq.${encodeURIComponent(bestellung_id)}&status=neq.bezahlt&status=neq.storniert`,
        {
          status: 'bezahlt',
          zahlungs_id: `vorkasse-${bestellung_id}`,
          bezahlt_am: new Date().toISOString()
        }
      );

      if (!Array.isArray(beansprucht) || beansprucht.length === 0) {
        // Ein paralleler Lauf kann die Zahlung gerade beansprucht haben. Neu lesen:
        // bezahlt + nicht consumed ist ein Reparaturweg, storniert bleibt gesperrt.
        bestellung = await ladeBestellung(bestellung_id);
        if (bestellung.status !== 'bezahlt') {
          return res.status(409).json({
            error: 'Bestellung wurde zwischenzeitlich bearbeitet und kann nicht als bezahlt gebucht werden.'
          });
        }
        if (bestellung.reservierung_status === 'consumed') {
          return res.json({
            ok: true, already_processed: true, zahlung_erfasst: true,
            lagerbuchung_erfolgreich: true,
            message: 'Bestellung wurde bereits als bezahlt verarbeitet.'
          });
        }
      } else {
        zahlungNeuErfasst = true;
      }
    }

    let positionen = await ladePositionen(bestellung_id);
    let bestellungFixiert = bestellung;

    if (toNumber(bestellung.gesamtbetrag, 0) <= 0 || toNumber(bestellung.warenwert_netto, 0) <= 0) {
      const calc = await berechneUndFixiereBestellungServerseitig(bestellung_id, {
        pruefeBestand: false,
        fixiere: true
      });
      bestellungFixiert = calc.bestellung;
      positionen = calc.positionen;
    }

    const bestellungBezahlt = {
      ...bestellungFixiert,
      zahlungsart: 'vorkasse',
      status: 'bezahlt',
      zahlungs_id: `vorkasse-${bestellung_id}`
    };

    if (zahlungNeuErfasst) {
      await schreibeAuditLog(req, 'zahlung_erhalten', 'bestellungen', bestellung_id,
        { status: bestellung.status }, { status: 'bezahlt', zahlungsart: 'vorkasse' });
    }

    // EIN bestellungsbezogener DB-Aufruf entscheidet anhand der tatsächlichen
    // Reservierungszeilen. Er setzt reservierung_status erst zusammen mit der
    // erfolgreichen Lagerbuchung und ist bei verlorener Netzwerkantwort wiederholbar.
    let lagerErgebnis;
    try {
      lagerErgebnis = await bucheBezahlteBestellungLagerAtomar(bestellung_id);
      console.log(`✅ Lagerbuchung für Vorkasse #${bestellung_id}: ${lagerErgebnis.buchungsart}`);
    } catch (lagerErr) {
      // Zahlung bleibt korrekt auf bezahlt. Die Lagerbuchung bleibt dagegen sichtbar
      // offen und kann über denselben Endpunkt gefahrlos wiederholt werden.
      console.error(`🚨 Lagerbuchung für bezahlte Vorkasse-Bestellung ${bestellung_id} fehlgeschlagen:`, lagerErr.message);
      const auditOk = await schreibeAuditLog(
        req, 'vorkasse_lagerbuchung_fehlgeschlagen', 'bestellungen', bestellung_id,
        { status: bestellung.status, reservierung_status: bestellung.reservierung_status || null },
        { status: 'bezahlt', lagerbuchung: 'offen', fehler: String(lagerErr.message || lagerErr).slice(0, 500) }
      );
      sentry.captureException(lagerErr, {
        tags: { vorgang: 'vorkasse_lagerbuchung' },
        extra: { bestellung_id, audit_geschrieben: auditOk }
      });
      try {
        const adminId = process.env.ADMIN_TELEGRAM_ID || process.env.TELEGRAM_ADMIN_ID;
        if (adminId) {
          await sendeTelegram(
            adminId,
            `🚨 <b>Lagerbuchung fehlgeschlagen</b>\nBezahlte Vorkasse-Bestellung #${bestellung_id} konnte nicht vom Lager gebucht werden. Zahlung ist erfasst; Lagerbuchung muss wiederholt werden.`
          );
        }
      } catch (telegramErr) {
        console.warn(`⚠️ Telegram-Lageralarm für #${bestellung_id} fehlgeschlagen:`, telegramErr.message);
        await schreibeAuditLog(
          req, 'vorkasse_lageralarm_telegram_fehlgeschlagen', 'bestellungen', bestellung_id,
          null, { fehler: String(telegramErr.message || telegramErr).slice(0, 500) }
        );
      }

      return res.status(202).json({
        ok: true,
        bestellung_id,
        zahlung_erfasst: true,
        lagerbuchung_erfolgreich: false,
        wiederholung_noetig: true,
        audit_geschrieben: auditOk,
        message: 'Zahlung wurde erfasst, die Lagerbuchung ist jedoch noch offen. Bitte erneut ausführen.'
      });
    }

    // Ein paralleler Aufruf kann die atomare DB-Buchung zwischen unserem ersten
    // Lesen und dem RPC bereits abgeschlossen haben. Dann ist die Lagerseite sicher,
    // aber E-Mail, Telegram und Erfolgs-Audit duerfen nicht ein zweites Mal laufen.
    if (lagerErgebnis.bereits_gebucht) {
      return res.json({
        ok: true,
        already_processed: true,
        bestellung_id,
        zahlung_erfasst: true,
        lagerbuchung_erfolgreich: true,
        lagerbuchung: lagerErgebnis,
        message: 'Bestellung wurde parallel bereits vollständig verarbeitet.'
      });
    }

    // NEU: Auftragsbestätigung an Kunde + Lieferschein ans Lager (keine Rechnung).
    await nachZahlungAuftragUndLieferschein(bestellung_id, bestellungBezahlt, positionen);

    await sendeAdminBenachrichtigung({
      ...bestellungBezahlt,
      status: 'bezahlt'
    });

    await schreibeAuditLog(req, 'vorkasse_lagerbuchung_erfolgreich', 'bestellungen', bestellung_id,
      { reservierung_status: bestellung.reservierung_status || null },
      { reservierung_status: 'consumed', buchungsart: lagerErgebnis.buchungsart });

    return res.json({
      ok: true,
      bestellung_id,
      zahlung_erfasst: true,
      lagerbuchung_erfolgreich: true,
      lagerbuchung: lagerErgebnis,
      lager_status: 'in_bearbeitung'
    });
  } catch (err) {
    console.error('❌ Zahlung-erhalten Fehler:', err);

    return sendError(res, err);
  }
});


// -----------------------------------------------------------------------------
// Admin: offene Vorkasse-Bestellung stornieren → Reservierung freigeben
// -----------------------------------------------------------------------------

app.post('/api/admin/vorkasse/stornieren', async (req, res) => {
  try {
    await assertAdminPermission(req, 'bestellungen.stornieren');

    const { bestellung_id } = req.body;

    if (!bestellung_id) {
      return res.status(400).json({
        error: 'bestellung_id fehlt'
      });
    }

    const bestellungIdInt = Number.parseInt(bestellung_id, 10);

    if (!Number.isInteger(bestellungIdInt) || bestellungIdInt <= 0) {
      return res.status(400).json({
        error: 'Ungültige bestellung_id'
      });
    }

    const bestellung = await ladeBestellung(bestellungIdInt);

    if (bestellung.zahlungsart !== 'vorkasse') {
      return res.status(400).json({
        error: 'Nur Vorkasse-Bestellungen können über diese Funktion storniert werden.'
      });
    }

    if (bestellung.status !== 'warte_auf_zahlung') {
      return res.status(400).json({
        error: 'Nur offene Vorkasse-Bestellungen können storniert werden.'
      });
    }

    // Atomarer Claim – identisch zum automatischen Storno (storniereAbgelaufeneVorkasse-
    // Bestellungen). Vorher lief es genau andersherum: erst Reservierung freigeben, dann die
    // Bestellung BEDINGUNGSLOS auf 'storniert' setzen. Führt ein zweiter Admin im selben
    // Moment „Zahlung erhalten" aus, wurde damit eine BEZAHLTE Bestellung storniert und ihre
    // Ware freigegeben. Die Prüfung oben (status !== 'warte_auf_zahlung') schützt davor nicht –
    // zwischen Lesen und Schreiben liegen mehrere Netzwerkrunden.
    // Der Filter wird von Postgres unter Row-Lock erneut ausgewertet: Der Verlierer erhält 0 Zeilen.
    // Der Claim setzt NUR den Status – NICHT `reservierung_status`. Beides gemeinsam zu
    // schreiben, bevor die Ware tatsächlich freigegeben ist, wäre eine Lüge in der Datenbank:
    // Scheitert das RPC danach, stünde dort „released", während die Zeilen noch reserviert sind –
    // und ein zweiter Versuch prallt am Claim ab, weil der Status nicht mehr `warte_auf_zahlung`
    // ist. `reservierung_status` wird deshalb erst NACH erfolgreicher Freigabe nachgezogen.
    const beansprucht = await supabasePatchWhere(
      'bestellungen',
      `?id=eq.${encodeURIComponent(bestellungIdInt)}&status=eq.warte_auf_zahlung&zahlungsart=eq.vorkasse`,
      { status: 'storniert' }
    );
    if (!Array.isArray(beansprucht) || beansprucht.length === 0) {
      const aktuell = await ladeBestellung(bestellungIdInt).catch(() => null);
      const e = new Error(
        `Die Bestellung wurde zwischenzeitlich bearbeitet (Status: ${aktuell?.status || 'unbekannt'}). Es wurde nichts storniert und keine Ware freigegeben.`
      );
      e.statusCode = 409;
      throw e;
    }

    // Ware ERST nach erfolgreichem Claim freigeben – nie vorher.
    // ZWEI getrennte Wahrheiten: Ob die Ware tatsächlich frei ist (RPC), und ob das Feld in
    // der Bestellung nachgezogen werden konnte. Beides zusammenzufassen wäre irreführend –
    // gelingt das RPC und scheitert nur der Feld-Patch, ist die Ware frei, das Feld aber alt.
    let releaseResult = null;
    let reservierungFreigegeben = false;
    let reservierungStatusAktualisiert = false;
    try {
      releaseResult = await gebeBestellReservierungenFrei(bestellungIdInt);
      reservierungFreigegeben = true;
      try {
        await supabaseUpdate('bestellungen', bestellungIdInt, { reservierung_status: 'released' });
        reservierungStatusAktualisiert = true;
      } catch (feldErr) {
        // Harmlose Richtung: Ware ist frei, nur die Anzeige hinkt. Kein Kundenbezug.
        console.error(`⚠️ reservierung_status für Bestellung ${bestellungIdInt} nicht nachgezogen:`, feldErr.message);
      }
    } catch (relErr) {
      // Storno steht, Ware bleibt aber blockiert. `reservierung_status` bleibt bewusst auf dem
      // alten Wert – lieber „reserviert" (wahr, wenn auch unerwünscht) als ein falsches
      // „released". Der Admin kann über „Reservierungen freigeben" nachziehen; zusätzlich
      // greift die Frist-Freigabe des Auto-Laufs.
      console.error(`🚨 Reservierungsfreigabe für stornierte Bestellung ${bestellungIdInt} fehlgeschlagen:`, relErr.message);
      try {
        const alarmAn = process.env.ADMIN_TELEGRAM_ID || process.env.TELEGRAM_ADMIN_ID;
        if (alarmAn) {
          await sendeTelegram(
            alarmAn,
            `🚨 <b>Ware bleibt blockiert</b>\nBestellung #${bestellungIdInt} wurde storniert, die Lagerreservierung konnte aber NICHT freigegeben werden (${escapeHtml(String(relErr.message || relErr))}).\nBitte im Admin in den Bestelldetails „Reservierung erneut freigeben" ausführen – die allgemeine Schaltfläche „Reservierungen freigeben" hilft hier NICHT, sie räumt nur abgelaufene Reservierungen ab.`
          );
        }
      } catch (_) {}
    }

    // Vorgangscenter: Storno (Admin).
    await vorgangEreignis(bestellung, 'storniert', { text: 'Bestellung storniert.', meta: { status_neu: 'storniert' } });

    // Kunde informieren. Der AUTOMATISCHE Storno tut das seit jeher; beim manuellen fehlte es –
    // der Kunde erfuhr nur über den Vorgangsverlauf davon, wenn er dort nachsah.
    // sendeBestellEmail (statt sendeEmail) erreicht auch Besteller und Einkaufsleiter und hängt
    // den Thread-Token an, damit eine Antwort im richtigen Vorgang landet.
    let mailVersendet = false;
    try {
      const stornoHtml = `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
          <div style="background:#3D2B1F;padding:20px;text-align:center;">
            <h1 style="color:#C49A2B;font-family:Georgia,serif;margin:0;">VisioTrade</h1>
            <p style="color:white;margin:5px 0 0;">Premium Parkett</p>
          </div>
          <div style="padding:30px;background:#FAF7F2;">
            <h2 style="color:#3D2B1F;">Ihre Bestellung wurde storniert</h2>
            <p>Sehr geehrte/r ${escapeHtml(bestellung.kundenname || bestellung.firma || 'Kundin/Kunde')},</p>
            <p>Ihre Vorkasse-Bestellung <strong>#${bestellungIdInt}</strong> wurde storniert.${reservierungFreigegeben
              ? ' Die reservierte Ware haben wir wieder freigegeben.'
              : ''}</p>
            <p><strong>Bitte überweisen Sie den Betrag nicht mehr.</strong> Sollte Ihre Zahlung bereits unterwegs
            sein, melden Sie sich kurz bei uns – wir erstatten den Betrag zurück.</p>
            <p>Sie können jederzeit erneut bestellen.</p>
            <p style="color:#6B7280;font-size:13px;margin-top:30px;">Bei Fragen stehen wir Ihnen gerne zur Verfügung.<br>VisioTrade GmbH</p>
          </div>
        </div>`;
      const mailBericht = await sendeBestellEmail(bestellung, `Bestellung #${bestellungIdInt} storniert | VisioTrade`, stornoHtml);
      mailVersendet = mailVollstaendigZugestellt(mailBericht);
      if (!mailVersendet) {
        console.error(
          `🚨 Storno-Mail für Bestellung ${bestellungIdInt} nicht vollständig zugestellt:`,
          JSON.stringify({ empfaenger: mailBericht?.empfaenger || [], fehlgeschlagen: mailBericht?.fehlgeschlagen || [] })
        );
      }
    } catch (mailErr) {
      // Nicht abbrechen – der Storno ist bereits vollzogen. Aber auch NICHT verschlucken:
      // Der Admin erfährt es unten über `mail_versendet` in der Antwort.
      console.error(`🚨 Storno-E-Mail für Bestellung ${bestellungIdInt} fehlgeschlagen:`, mailErr.message);
    }

    const adminId = process.env.ADMIN_TELEGRAM_ID || process.env.TELEGRAM_ADMIN_ID;

    // Die reguläre Storno-Meldung NUR, wenn die Freigabe auch geklappt hat – ihr letzter Satz
    // lautet „Lagerreservierung wurde freigegeben". Beim Fehlschlag ist oben bereits der
    // Alarm „Ware bleibt blockiert" rausgegangen; zwei widersprüchliche Nachrichten wären
    // schlimmer als eine.
    if (adminId && reservierungFreigegeben) {
      const tgText =
        `❌ <b>Vorkasse-Bestellung #${bestellungIdInt} wurde im Admin storniert</b>\n\n` +
        `👤 Kunde: ${escapeHtml(bestellung.kundenname || bestellung.firma || '—')}\n` +
        `🏢 Firma: ${escapeHtml(bestellung.firma || '—')}\n` +
        `📧 Email: ${escapeHtml(bestellung.email || '—')}\n` +
        `💰 Betrag brutto: ${euro(toNumber(bestellung.gesamt_brutto, toNumber(bestellung.gesamtbetrag, 0) * 1.19))}\n` +
        `🏦 Verwendungszweck: VT-${String(bestellungIdInt).padStart(4, '0')}\n` +
        `📦 Lagerreservierung wurde freigegeben.`;

      try {
        await sendeTelegram(adminId, tgText);
      } catch (tgErr) {
        console.warn('⚠️ Telegram-Admin-Stornohinweis fehlgeschlagen:', tgErr.message);
      }
    }

    console.log(`✅ Vorkasse-Bestellung ${bestellungIdInt} im Admin storniert`);
    await schreibeAuditLog(req, 'bestellung_storniert', 'bestellungen', bestellungIdInt,
      { status: 'warte_auf_zahlung' }, { status: 'storniert' });

    return res.json({
      ok: true,
      bestellung_id: bestellungIdInt,
      status: 'storniert',
      mail_versendet: mailVersendet,
      reservierung_freigegeben: reservierungFreigegeben,
      reservierung_status_aktualisiert: reservierungStatusAktualisiert,
      release_result: releaseResult
    });
  } catch (err) {
    console.error('❌ Admin-Vorkasse-Stornierung Fehler:', err);

    return sendError(res, err);
  }
});


// -----------------------------------------------------------------------------
// Admin: Kauf auf Rechnung stornieren (B-14).
// -----------------------------------------------------------------------------
// Eigener Weg, weil Rechnungskauf sich von JEDEM anderen Zahlweg unterscheidet:
// Der Bestand wurde beim Bestellen SOFORT abgebucht (reduce_stock_bulk), es gibt
// KEINE Reservierungszeile. gebeBestellReservierungenFrei() fände hier nichts –
// der Bestand bliebe weg. Bis zu dieser Route existierte deshalb überhaupt kein
// Weg, eine Rechnungsbestellung mit Rückbuchung zurückzunehmen.
//
// Die gesamte Bestandslogik liegt in der DB-Funktion storniere_rechnungskauf
// (rechnungskauf_storno.sql) – Rückbuchung und Statuswechsel in EINER Transaktion,
// mit FOR UPDATE, Aggregation je Paket und Prüfung, dass jede Paketzeile wirklich
// aktualisiert wurde. Hier bleibt nur Rechteprüfung, Benachrichtigung, Protokoll.
app.post('/api/admin/bestellungen/:id/rechnungskauf-stornieren', async (req, res) => {
  try {
    await assertAdminPermission(req, 'bestellungen.stornieren');

    // STRIKTE Prüfung, nicht Number.parseInt(). parseInt liest nur den führenden
    // Zahlenteil: '159xyz' ergäbe 159, '159abc' ebenfalls. Bei einem destruktiven
    // Endpunkt darf eine ungenaue Eingabe nicht stillschweigend auf eine echte
    // Bestellung abgebildet werden – der Aufrufer bekäme einen Storno für eine
    // Bestellung, die er so nie adressiert hat.
    const idRoh = String(req.params.id || '');
    if (!/^\d+$/.test(idRoh)) {
      const e = new Error('Ungültige Bestell-ID: nur vollständige positive Ganzzahlen sind zulässig.');
      e.statusCode = 400; throw e;
    }
    const bestellungIdInt = Number(idRoh);
    if (!Number.isSafeInteger(bestellungIdInt) || bestellungIdInt <= 0) {
      const e = new Error('Ungültige Bestell-ID'); e.statusCode = 400; throw e;
    }

    // Kundendaten VOR dem Storno lesen – für die Mail. Der Storno ändert nur
    // `status`; Name, Firma und E-Mail bleiben, aber einmal lesen genügt.
    const bestellung = await ladeBestellung(bestellungIdInt);

    if (bestellung.zahlungsart !== 'rechnung') {
      const e = new Error('Nur Rechnungsbestellungen können über diese Funktion storniert werden.');
      e.statusCode = 400; throw e;
    }

    // Bestand + Status atomar. Wirft bei jedem unerwarteten Zustand und hat dann
    // NICHTS geschrieben.
    const rpc = await storniereRechnungskaufAtomar(bestellungIdInt);
    const zurueckgebucht = rpc.zurueckgebucht === true;
    const bereitsStorniert = rpc.bereits_storniert === true;

    // WIEDERHOLUNGSZWEIG – sofort und ohne jede Nebenwirkung antworten.
    // Geht die HTTP-Antwort des ersten, erfolgreichen Stornos verloren (Timeout,
    // Doppelklick, Retry), meldet die RPC beim zweiten Mal korrekt
    // bereits_storniert=true. Liefe die Route danach weiter, bekäme der Kunde eine
    // ZWEITE Storno-Mail, der Vorgang einen zweiten Eintrag und das Audit-Log einen
    // Zustandswechsel 'auf_rechnung' → 'storniert', den es nie gegeben hat.
    // Der Bestand bliebe zwar korrekt – die Außenwirkung nicht.
    //
    // Bewusste Abgrenzung: Ein fehlgeschlagener Mailversand wird hier NICHT
    // nachgeholt. Genau-einmal-Zustellung externer E-Mails ist ohne persistente
    // Versandmarkierung oder Outbox nicht garantierbar; ein Nachholversuch an
    // dieser Stelle wäre ein Versprechen, das die Architektur nicht einlöst.
    // Eine bewusste Wiederholung gehört in eine eigene Aktion (offener Punkt).
    if (bereitsStorniert) {
      console.log(`ℹ️ Rechnungskauf #${bestellungIdInt} war bereits storniert – keine zweite Rückbuchung, keine erneuten Benachrichtigungen`);
      return res.json({
        ok: true,
        bestellung_id: bestellungIdInt,
        status: 'storniert',
        bereits_storniert: true,
        zurueckgebucht: false,
        paketzeilen: 0,
        menge_gesamt: 0,
        mail_versendet: false,
        vorgang_geschrieben: false,
        audit_geschrieben: false
      });
    }

    console.log(`✅ Rechnungskauf #${bestellungIdInt} storniert, ${rpc.menge_gesamt} Paket(e) auf ${rpc.paketzeilen} Paketzeile(n) zurückgebucht`);

    // ------------------------------------------------------------------------
    // AB HIER IST DER STORNO VOLLZOGEN UND NICHT MEHR RÜCKGÄNGIG ZU MACHEN.
    // Bestand ist zurückgebucht, Status ist 'storniert' – beides committet.
    // Jede folgende Nebenwirkung (Vorgangseintrag, Mail, Telegram, Audit) MUSS
    // deshalb einzeln abgesichert werden und darf die Antwort NICHT auf 500
    // kippen. Sonst entstünde der schlimmste Zustand: Der Storno ist wirksam,
    // der Admin sieht einen Fehler, die Kundenmail wurde nie versucht – und nach
    // dem Neuladen ist der Knopf verschwunden, weil die Bestellung nicht mehr
    // 'auf_rechnung' ist. Jede Nebenwirkung bekommt ein eigenes Ergebnisfeld,
    // damit die Oberfläche ehrlich melden kann, was tatsächlich passiert ist.
    // Ein erneuter Aufruf dieser Route bleibt gefahrlos: storniere_rechnungskauf
    // bucht HÖCHSTENS EINMAL zurück.
    // ------------------------------------------------------------------------
    // ACHTUNG: vorgangEreignis() und schreibeAuditLog() WERFEN NIE – sie fangen
    // intern ab. Ein `try/catch` allein liefe hier ins Leere und meldete jeden
    // Fehlschlag als Erfolg. Maßgeblich ist deshalb der RÜCKGABEWERT; das
    // try/catch bleibt nur als Absicherung für künftige Änderungen.
    let vorgangGeschrieben = false;
    try {
      vorgangGeschrieben = (await vorgangEreignis(bestellung, 'storniert', { text: 'Bestellung storniert (Kauf auf Rechnung).', meta: { status_neu: 'storniert' } })) === true;
    } catch (vErr) {
      console.error(`⚠️ Vorgangseintrag für Rechnungskauf-Storno ${bestellungIdInt} fehlgeschlagen:`, vErr.message);
    }
    if (!vorgangGeschrieben) {
      console.error(`⚠️ Vorgangseintrag für Rechnungskauf-Storno ${bestellungIdInt} NICHT geschrieben`);
    }

    let mailVersendet = false;
    try {
      const stornoHtml = `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
          <div style="background:#3D2B1F;padding:20px;text-align:center;">
            <h1 style="color:#C49A2B;font-family:Georgia,serif;margin:0;">VisioTrade</h1>
            <p style="color:white;margin:5px 0 0;">Premium Parkett</p>
          </div>
          <div style="padding:30px;background:#FAF7F2;">
            <h2 style="color:#3D2B1F;">Ihre Bestellung wurde storniert</h2>
            <p>Sehr geehrte/r ${escapeHtml(bestellung.kundenname || bestellung.firma || 'Kundin/Kunde')},</p>
            <p>Ihre Bestellung <strong>#${bestellungIdInt}</strong> (Kauf auf Rechnung) wurde storniert.
            Der für diese Bestellung abgezogene Lagerbestand wurde wieder verfügbar gemacht.</p>
            <p><strong>Es entsteht keine Forderung.</strong> Eine Rechnung wurde für diese Bestellung nicht
            erstellt; sollten Sie dennoch eine erhalten haben, melden Sie sich bitte kurz bei uns.</p>
            <p>Sie können jederzeit erneut bestellen.</p>
            <p style="color:#6B7280;font-size:13px;margin-top:30px;">Bei Fragen stehen wir Ihnen gerne zur Verfügung.<br>VisioTrade GmbH</p>
          </div>
        </div>`;
      const mailBericht = await sendeBestellEmail(bestellung, `Bestellung #${bestellungIdInt} storniert | VisioTrade`, stornoHtml);
      mailVersendet = mailVollstaendigZugestellt(mailBericht);
      if (!mailVersendet) {
        console.error(
          `🚨 Storno-Mail (Rechnungskauf) für Bestellung ${bestellungIdInt} nicht vollständig zugestellt:`,
          JSON.stringify({ empfaenger: mailBericht?.empfaenger || [], fehlgeschlagen: mailBericht?.fehlgeschlagen || [] })
        );
      }
    } catch (mailErr) {
      console.error(`🚨 Storno-E-Mail (Rechnungskauf) für Bestellung ${bestellungIdInt} fehlgeschlagen:`, mailErr.message);
    }

    const adminId = process.env.ADMIN_TELEGRAM_ID || process.env.TELEGRAM_ADMIN_ID;
    if (adminId) {
      try {
        await sendeTelegram(
          adminId,
          `❌ <b>Rechnungsbestellung #${bestellungIdInt} wurde im Admin storniert</b>\n\n` +
          `👤 Kunde: ${escapeHtml(bestellung.kundenname || bestellung.firma || '—')}\n` +
          `🏢 Firma: ${escapeHtml(bestellung.firma || '—')}\n` +
          `📧 Email: ${escapeHtml(bestellung.email || '—')}\n` +
          `💰 Betrag brutto: ${euro(toNumber(bestellung.gesamt_brutto, toNumber(bestellung.gesamtbetrag, 0) * 1.19))}\n` +
          `📦 ${rpc.menge_gesamt} Paket(e) auf ${rpc.paketzeilen} Paketzeile(n) zurückgebucht.`
        );
      } catch (tgErr) {
        console.warn('⚠️ Telegram-Hinweis Rechnungskauf-Storno fehlgeschlagen:', tgErr.message);
      }
    }

    let auditGeschrieben = false;
    try {
      auditGeschrieben = (await schreibeAuditLog(req, 'rechnungskauf_storniert', 'bestellungen', bestellungIdInt,
        { status: 'auf_rechnung' }, { status: 'storniert', zurueckgebucht, paketzeilen: rpc.paketzeilen, menge_gesamt: rpc.menge_gesamt })) === true;
    } catch (aErr) {
      console.error(`⚠️ Audit-Eintrag für Rechnungskauf-Storno ${bestellungIdInt} fehlgeschlagen:`, aErr.message);
    }
    if (!auditGeschrieben) {
      console.error(`⚠️ Audit-Eintrag für Rechnungskauf-Storno ${bestellungIdInt} NICHT geschrieben`);
    }

    return res.json({
      ok: true,
      bestellung_id: bestellungIdInt,
      status: 'storniert',
      bereits_storniert: bereitsStorniert,
      zurueckgebucht,
      paketzeilen: rpc.paketzeilen,
      menge_gesamt: rpc.menge_gesamt,
      mail_versendet: mailVersendet,
      vorgang_geschrieben: vorgangGeschrieben,
      audit_geschrieben: auditGeschrieben
    });
  } catch (err) {
    console.error('❌ Rechnungskauf-Stornierung Fehler:', err);
    return sendError(res, err);
  }
});


// -----------------------------------------------------------------------------
// Admin: Reservierung EINER stornierten Bestellung gezielt freigeben (Wiederholung).
// -----------------------------------------------------------------------------
// Nötig, weil die allgemeine Schaltfläche „Reservierungen freigeben" ausschließlich
// ABGELAUFENE Reservierungen abräumt (release_expired_reservations). Eine soeben manuell
// stornierte Bestellung ist typischerweise noch lange nicht abgelaufen – schlägt bei ihr die
// Freigabe fehl, gäbe es ohne diesen Endpunkt keinen verlässlichen Reparaturweg, und die Ware
// bliebe bis zum Fristablauf blockiert.
// Idempotent: Sind die Zeilen bereits freigegeben, ist das RPC ein No-Op.
app.post('/api/admin/bestellungen/:id/reservierung-freigeben', paymentLimiter, async (req, res) => {
  try {
    await assertAdminPermission(req, 'bestellungen.stornieren');

    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id) || id <= 0) { const e = new Error('Ungültige ID'); e.statusCode = 400; throw e; }

    const bestellung = await ladeBestellung(id);
    // Schutz: Nur Bestellungen, die keine Ware mehr binden dürfen. Eine offene oder bezahlte
    // Bestellung darf ihre Reservierung auf diesem Weg NICHT verlieren.
    if (String(bestellung.status) !== 'storniert') {
      const e = new Error(`Nur stornierte Bestellungen können hier freigegeben werden (Status: ${bestellung.status}).`);
      e.statusCode = 400; throw e;
    }

    const releaseResult = await gebeBestellReservierungenFrei(id);
    let statusAktualisiert = false;
    try {
      await supabaseUpdate('bestellungen', id, { reservierung_status: 'released' });
      statusAktualisiert = true;
    } catch (feldErr) {
      console.error(`⚠️ reservierung_status für Bestellung ${id} nicht nachgezogen:`, feldErr.message);
    }

    await schreibeAuditLog(req, 'reservierung_freigegeben', 'bestellungen', id, null, { reservierung_status: 'released' });

    return res.json({
      ok: true,
      bestellung_id: id,
      reservierung_freigegeben: true,
      reservierung_status_aktualisiert: statusAktualisiert,
      release_result: releaseResult
    });
  } catch (err) {
    console.error('❌ Reservierung erneut freigeben:', err);
    return sendError(res, err);
  }
});

// -----------------------------------------------------------------------------
// Admin: abgelaufene Vorkasse-Reservierungen freigeben
// -----------------------------------------------------------------------------

app.post('/api/admin/reservierungen/freigeben', async (req, res) => {
  try {
    await assertAdmin(req);

    const result = await gebeAbgelaufeneReservierungenFrei();

    return res.json({
      ok: true,
      released_count: Array.isArray(result) && result[0] ? result[0].release_expired_reservations : result
    });
  } catch (err) {
    console.error('❌ Reservierungen-freigeben Fehler:', err);

    return sendError(res, err);
  }
});

// -----------------------------------------------------------------------------
// Automatische Stornierung abgelaufener, unbezahlter Vorkasse-Bestellungen
// -----------------------------------------------------------------------------

async function storniereAbgelaufeneVorkasseBestellungen() {
  try {
    const jetzt = new Date().toISOString();
    const abgelaufen = await supabaseQuery(
      'bestellungen',
      `?zahlungsart=eq.vorkasse&status=eq.warte_auf_zahlung&reserviert_bis=lt.${encodeURIComponent(jetzt)}`
    );

    if (!Array.isArray(abgelaufen) || abgelaufen.length === 0) {
      return { storniert: 0 };
    }

    console.log(`⏰ ${abgelaufen.length} abgelaufene Vorkasse-Bestellung(en) werden automatisch storniert.`);

    let storniert = 0;

    for (const b of abgelaufen) {
      try {
        // Atomarer Claim (Audit S2-03): Zwischen dem Lesen der Liste oben und diesem Schreiben
        // vergeht Zeit – pro Vorgänger-Iteration ein Mailversand (bis 20 s) und ein Telegram-Call
        // (bis 8 s). In diesem Fenster kann im Admin „Zahlung erhalten" gebucht werden. Ein Update
        // OHNE Statusbedingung würde die soeben bezahlte Bestellung auf 'storniert' überschreiben
        // und die Ware erneut freigeben → bezahlte Bestellung storniert, Bestand doppelt verkaufbar.
        // Der Filter wird von Postgres unter Row-Lock erneut ausgewertet; der Verlierer erhält
        // 0 Zeilen. Gleiches Muster wie in bestellungAbwickeln.
        // Nebeneffekt: Der Job ist damit auch mehrinstanz-fest (Audit B-05) – bei zwei parallel
        // laufenden Railway-Instanzen storniert nur eine, es gibt keine doppelten Storno-Mails.
        const beansprucht = await supabasePatchWhere(
          'bestellungen',
          `?id=eq.${encodeURIComponent(b.id)}&status=eq.warte_auf_zahlung`,
          { status: 'storniert' }
        );
        if (!Array.isArray(beansprucht) || beansprucht.length === 0) {
          console.log(`ℹ️ Bestellung ${b.id} wurde zwischenzeitlich bearbeitet (z. B. Zahlung eingegangen). Kein Auto-Storno.`);
          continue;
        }
        // Ware ERST nach erfolgreichem Claim freigeben – nie vorher, sonst würde eine
        // zwischenzeitlich bezahlte Bestellung ihre Reservierung verlieren.
        // `reservierung_status` wird ebenfalls erst DANACH gesetzt: Scheitert das RPC, stünde
        // sonst „released" in der Datenbank, während die Zeilen noch reserviert sind.
        let freigegeben = false;
        try {
          await gebeBestellReservierungenFrei(b.id);
          freigegeben = true;
          try {
            await supabaseUpdate('bestellungen', b.id, { reservierung_status: 'released' });
          } catch (feldErr) {
            console.error(`⚠️ Auto-Storno ${b.id}: reservierung_status nicht nachgezogen:`, feldErr.message);
            await schreibeAuditLog(
              null,
              'auto_storno_reservierungsstatus_nicht_nachgezogen',
              'bestellungen',
              b.id,
              { reservierung_status: b.reservierung_status || null },
              { reservierung_status: 'released', fehler: String(feldErr.message || feldErr).slice(0, 500) }
            );
          }
        } catch (relErr) {
          console.error(`🚨 Auto-Storno ${b.id}: Reservierungsfreigabe fehlgeschlagen:`, relErr.message);
          // Storno bleibt bestehen; die Frist-Freigabe des nächsten Laufs holt die Ware nach.
          await schreibeAuditLog(
            null,
            'auto_storno_reservierungsfreigabe_fehlgeschlagen',
            'bestellungen',
            b.id,
            { status: 'storniert', reservierung_status: b.reservierung_status || null },
            { lagerfreigabe: 'offen', fehler: String(relErr.message || relErr).slice(0, 500) }
          );
        }
        storniert += 1;

        // Kunde informieren
        if (b.email) {
          const html = `
            <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
              <div style="background:#3D2B1F;padding:20px;text-align:center;">
                <h1 style="color:#C49A2B;font-family:Georgia,serif;margin:0;">VisioTrade</h1>
                <p style="color:white;margin:5px 0 0;">Premium Parkett</p>
              </div>
              <div style="padding:30px;background:#FAF7F2;">
                <h2 style="color:#3D2B1F;">Bestellung automatisch storniert</h2>
                <p>Sehr geehrte/r ${escapeHtml(b.kundenname || b.firma || 'Kundin/Kunde')},</p>
                <p>für Ihre Vorkasse-Bestellung <strong>#${b.id}</strong> ist innerhalb der Reservierungsfrist von
                ${RESERVIERUNG_VORKASSE_STUNDEN} Stunden kein Zahlungseingang erfolgt. Die Bestellung wurde daher
                automatisch storniert.${freigegeben ? ' Die reservierte Ware haben wir wieder freigegeben.' : ''}</p>
                <p>Sie können jederzeit erneut bestellen. Wir empfehlen bei Vorkasse die <strong>Echtzeitüberweisung</strong>,
                damit Ihre Reservierung innerhalb der Frist bestätigt werden kann.</p>
                <p style="color:#6B7280;font-size:13px;margin-top:30px;">Bei Fragen stehen wir Ihnen gerne zur Verfügung.<br>VisioTrade GmbH</p>
              </div>
            </div>`;
          try {
            await sendeEmail(b.email, `Bestellung #${b.id} automatisch storniert | VisioTrade`, html, null);
          } catch (mailErr) {
            console.warn(`⚠️ Storno-E-Mail für #${b.id} fehlgeschlagen:`, mailErr.message);
          }
        }

        const adminId = process.env.ADMIN_TELEGRAM_ID || process.env.TELEGRAM_ADMIN_ID;
        if (adminId) {
          try {
            // Wie beim manuellen Storno: Die Zeile über die Freigabe darf nur stehen, wenn sie
            // auch stimmt. Sonst geht stattdessen eine Warnung raus – die Ware bleibt blockiert,
            // bis die Frist-Freigabe des nächsten Laufs greift oder jemand nachhilft.
            await sendeTelegram(
              adminId,
              freigegeben
                ? `⏰ <b>Vorkasse-Bestellung #${b.id} automatisch storniert</b>\n\n` +
                  `Kein Zahlungseingang innerhalb von ${RESERVIERUNG_VORKASSE_STUNDEN} Stunden.\n` +
                  `👤 Kunde: ${escapeHtml(b.kundenname || b.firma || '—')}\n` +
                  `📦 Lagerreservierung wurde freigegeben.`
                : `🚨 <b>Vorkasse-Bestellung #${b.id} storniert – WARE BLEIBT BLOCKIERT</b>\n\n` +
                  `Kein Zahlungseingang innerhalb von ${RESERVIERUNG_VORKASSE_STUNDEN} Stunden.\n` +
                  `👤 Kunde: ${escapeHtml(b.kundenname || b.firma || '—')}\n` +
                  `📦 Die Lagerreservierung konnte NICHT freigegeben werden. Bitte in der Bestellzeile „Reservierung erneut freigeben" ausführen.`
            );
          } catch (tgErr) {
            console.warn(`⚠️ Telegram-Storno-Hinweis für #${b.id} fehlgeschlagen:`, tgErr.message);
            await schreibeAuditLog(
              null,
              'auto_storno_telegram_fehlgeschlagen',
              'bestellungen',
              b.id,
              null,
              { fehler: String(tgErr.message || tgErr).slice(0, 500), lagerfreigabe: freigegeben }
            );
          }
        }

        console.log(`✅ Bestellung ${b.id} automatisch storniert.`);
      } catch (orderErr) {
        console.error(`❌ Auto-Storno für Bestellung ${b.id} fehlgeschlagen:`, orderErr.message);
        await schreibeAuditLog(
          null,
          'auto_storno_bestellung_fehlgeschlagen',
          'bestellungen',
          b.id,
          null,
          { fehler: String(orderErr.message || orderErr).slice(0, 500) }
        );
      }
    }

    return { storniert };
  } catch (err) {
    console.error('❌ Auto-Storno-Lauf fehlgeschlagen:', err.message);
    return { storniert: 0, error: err.message };
  }
}

// Manuell auslösbarer Admin-Trigger (zusätzlich zum automatischen Intervall)
// Beide Hintergrundpfade erhalten begrenzte Wiederholung, einen lokalen
// Ueberlappungsschutz und eine dauerhafte Auditspur. Telegram ist nur ein
// Zusatzkanal; eine fehlende Variable oder ein Telegram-Ausfall entfernt den
// Datenbankbeleg nicht.
const autoJobRunner = createAutoJobRunner({
  storniereAbgelaufeneVorkasseBestellungen,
  gebeAbgelaufeneReservierungenFrei,
  schreibeAuditLog,
  sendeTelegram,
  captureException: (err, context) => sentry.captureException(err, context),
  adminTelegramId: process.env.ADMIN_TELEGRAM_ID || process.env.TELEGRAM_ADMIN_ID || null
});

async function fuehreAutoLaufAus() {
  return autoJobRunner.run();
}

app.post('/api/admin/vorkasse/abgelaufene-stornieren', async (req, res) => {
  try {
    await assertAdmin(req);
    const result = await storniereAbgelaufeneVorkasseBestellungen();
    return res.json({ ok: true, ...result });
  } catch (err) {
    console.error('❌ Abgelaufene-stornieren Fehler:', err);
    return sendError(res, err);
  }
});

// -----------------------------------------------------------------------------
// Lieferkosten-Vorschau für den Shop (Anzeige = maßgeblicher Backend-Preis)
// -----------------------------------------------------------------------------

const frachtLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Zu viele Frachtabfragen. Bitte einen Moment warten.' }
});

app.post('/api/fracht/vorschau', frachtLimiter, async (req, res) => {
  try {
    const { plz, lieferart, positionen } = req.body || {};

    if (String(lieferart || '').toLowerCase() !== 'lieferung') {
      return res.json({ lieferung: false, lieferkosten_netto: 0, lieferkosten_brutto: 0 });
    }

    const plzStr = String(plz || '').trim();
    if (!/^\d{5}$/.test(plzStr)) {
      const err = new Error('Bitte eine gültige 5-stellige Liefer-PLZ angeben.');
      err.statusCode = 400;
      throw err;
    }

    if (!Array.isArray(positionen) || !positionen.length) {
      const err = new Error('Keine Positionen für die Frachtberechnung.');
      err.statusCode = 400;
      throw err;
    }

    const daten = await ermittleSendungsdatenAusPositionen(positionen);

    // Pseudo-Bestellung nur mit den frachtrelevanten Feldern – nichts wird gespeichert.
    const pseudoBestellung = { lieferart: 'lieferung', lieferadresse_plz: plzStr };

    let netto;
    try {
      const liefer = berechneLieferkostenServerseitig(
        pseudoBestellung,
        daten.gesamtGewichtKg,
        daten.warenwertNetto,
        daten.gesamtStellplaetze,
        daten.gesamtPaletten
      );
      netto = round2(liefer.lieferkostenNetto);
    } catch (calcErr) {
      // z. B. PLZ in keiner Frachtzone → für den Kunden „auf Anfrage" statt Fehler.
      console.warn('ℹ️ Fracht-Vorschau nicht berechenbar:', calcErr.message);
      return res.json({ lieferung: true, auf_anfrage: true, lieferkosten_netto: null });
    }

    // Bewusst KEINE internen Felder (Spediteur/Einkaufspreis) an den Client.
    return res.json({
      lieferung: true,
      lieferkosten_netto: netto,
      lieferkosten_brutto: round2(netto * 1.19)
    });
  } catch (err) {
    console.error('❌ Fracht-Vorschau Fehler:', err);
    return sendError(res, err);
  }
});

// -----------------------------------------------------------------------------
// Healthcheck
// -----------------------------------------------------------------------------

app.get('/', (req, res) => {
  res.json({
    status: 'VisioTrade Backend läuft ✅',
    time: new Date().toISOString(),
    allowedOrigins: ALLOWED_ORIGINS
  });
});

// Fallback-Fehler-Handler (Paket 5): fängt Fehler ab, die NICHT schon per
// try/catch → sendError behandelt wurden (z. B. synchron geworfene Route-Fehler).
// sendError meldet 5xx zentral ans Monitoring – dadurch genau EINE Sentry-Meldung
// pro Fehler, kein Doppel-Report. Muss NACH allen Routen registriert sein.
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  return sendError(res, err);
});

// Server + Hintergrund-Jobs nur beim DIREKTSTART (node server.js) hochfahren,
// NICHT wenn server.js aus Tests importiert wird (dann übernimmt node:test).
// Produktionsverhalten unverändert – auf Railway läuft es als Direktstart.
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`✅ VisioTrade Backend läuft auf Port ${PORT}`);

    // Automatischer Storno-Lauf: prüft regelmäßig auf abgelaufene, unbezahlte
    // Vorkasse-Bestellungen und storniert sie + gibt die Reservierung frei.
    const intervallMs = (Number.isInteger(STORNO_CHECK_MINUTEN) && STORNO_CHECK_MINUTEN > 0 ? STORNO_CHECK_MINUTEN : 15) * 60 * 1000;
    console.log(`⏱️ Auto-Storno aktiv: Prüfung alle ${STORNO_CHECK_MINUTEN} Min, Reservierungsfrist ${RESERVIERUNG_VORKASSE_STUNDEN} Std.`);

    // Einmal kurz nach Start, danach im Intervall.
    // Abgelaufene Stripe/PayPal-Checkout-Reservierungen global freigeben (Bestand
    // zurück in den Verkauf), zusätzlich zum Vorkasse-Storno.
    const autoLauf = () => {
      fuehreAutoLaufAus()
        .then((ergebnis) => {
          if (!ergebnis.ok && !ergebnis.uebersprungen) {
            console.error('Auto-Lauf nach allen Wiederholungen unvollstaendig. Auditspur wurde geschrieben.');
          }
        })
        .catch((e) => console.error('Unerwarteter Fehler im Auto-Job-Runner:', e));
    };
    setTimeout(autoLauf, 30 * 1000);
    setInterval(autoLauf, intervallMs);
  });
}

// Für Charakterisierungstests importierbar machen (Vorbereitung Modularisierung,
// KEINE Logikänderung – nur Export bestehender Funktionen).
module.exports = {
  // `app` wird NUR für Route-Tests exportiert (test/paypal-capture-route.test.js startet sie
  // auf einem freien Port). Der Server selbst wird davon nicht gestartet – das passiert weiter
  // unten ausschließlich unter `require.main === module`.
  app,
  // Für den Fehlerfall-Test des Auto-Storno-Laufs (test/vorkasse-storno-route.test.js):
  // direkt aufrufbar, ohne auf das 15-Minuten-Intervall zu warten.
  storniereAbgelaufeneVorkasseBestellungen,
  fuehreAutoLaufAus,
  euro, toNumber, normalizeEmail, secretsGleich, pruefeTurnstile,
  assertAdminPermission, supabaseQuery, supabaseInsert, supabaseUpdate,
  berechneUndFixiereBestellungServerseitig,
  stammdatenAusProfil, validateGuestCheckoutPayload,
  istLagerfaehig, assertLagerfaehig
};

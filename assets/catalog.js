'use strict';
// All filtering happens on the already reduced public DTO, never on raw rows.
(function (root) {
  const tables = ['produkte', 'pakete', 'kategorien', 'arten', 'sortierungen'];
  function filter(rows, params) {
    let result = rows.map(row => ({ ...row }));
    const query = new URLSearchParams(params);
    for (const [key, value] of query) {
      if (['select', 'order', 'limit'].includes(key)) continue;
      if (!['id', 'produkt_id', 'kategorie_id', 'art_id', 'sortierung_id', 'aktiv'].includes(key)) throw new Error('Katalogfilter nicht erlaubt');
      if (value === 'is.null') result = result.filter(r => r[key] == null);
      else if (value.startsWith('eq.')) result = result.filter(r => String(r[key]) === value.slice(3));
      else if (/^in\.\((\d+(,\d+)*)?\)$/.test(value)) {
        const ids = new Set(value.slice(4, -1).split(','));
        result = result.filter(r => ids.has(String(r[key])));
      } else throw new Error('Katalogfilter nicht erlaubt');
    }
    if (query.has('order')) {
      const [key, direction] = query.get('order').split('.');
      if (!['id', 'reihenfolge', 'menge_m2'].includes(key) || (direction && !['asc', 'desc'].includes(direction))) throw new Error('Katalogsortierung nicht erlaubt');
      result.sort((a, b) => ((Number(a[key]) || 0) - (Number(b[key]) || 0)) * (direction === 'desc' ? -1 : 1));
    }
    if (query.has('limit')) {
      if (!/^\d+$/.test(query.get('limit'))) throw new Error('Ungültige Kataloggrenze');
      result = result.slice(0, Number(query.get('limit')));
    }
    if (query.has('select')) {
      if (query.get('select') !== 'id,name') throw new Error('Katalogauswahl nicht erlaubt');
      result = result.map(({ id, name }) => ({ id, name }));
    }
    return result;
  }
  function create(base, fetcher = root.fetch.bind(root)) {
    let snapshot, expires = 0, pending;
    async function load() {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 10000);
      try {
        const response = await fetcher(base + '/api/katalog', { credentials: 'omit', cache: 'no-store', signal: controller.signal });
        if (!response.ok) throw new Error('Katalog nicht verfügbar');
        const data = await response.json();
        if (data.ok !== true || !tables.every(t => Array.isArray(data.katalog?.[t]))) throw new Error('Ungültiger Katalog');
        snapshot = data.katalog;
        expires = Date.now() + 15000;
      } finally { clearTimeout(timer); }
    }
    return async (table, params = '') => {
      if (!tables.includes(table)) throw new Error('Keine Katalogtabelle');
      if (!snapshot || Date.now() >= expires) {
        if (!pending) pending = load().finally(() => { pending = null; });
        await pending;
      }
      return filter(snapshot[table], params);
    };
  }
  root.VisioCatalog = { tables, create, filter };
})(typeof window === 'undefined' ? globalThis : window);

// GET /api/stoppages -> Trent & Mersey and Macclesfield Canal notices as JSON for the Wee Dram route page.
// Reads Canalplan's public copy of the Canal & River Trust notices, at most once an hour.
// Each item: [id, canal, from, to, startISO, endISO, description]
const { app } = require("@azure/functions");
const SRC = "https://canalplan.org.uk/utilities/stoppages.php";
const KEEP = /Trent and Mersey|Macclesfield/i;
let cache = { at: 0, body: null };

const strip = h => h.replace(/<br\s*\/?>/gi, " ").replace(/<[^>]+>/g, "").replace(/&amp;/g, "&").replace(/&nbsp;/g, " ")
  .replace(/&#39;|&rsquo;/g, "'").replace(/&quot;/g, '"').replace(/\s+/g, " ").trim();
const iso = s => { if (!/^\d{1,2} [A-Za-z]+ \d{4}$/.test(s || "")) return null; const d = new Date(s + " 12:00 UTC"); return isNaN(d) ? null : d.toISOString().slice(0, 10); };

function parse(html) {
  const out = new Map();
  for (const tr of html.match(/<tr[\s\S]*?<\/tr>/gi) || []) {
    const td = (tr.match(/<td[\s\S]*?<\/td>/gi) || []).map(strip);
    if (td.length < 7) continue;
    // Some rows carry a Type and Status column after the ID: [id, type, status, canal, from, to, start, end, desc, updated]
    let [id, canal, from, to, start, end, desc] = td.length >= 10 && !iso(td[4]) ? [td[0], td[3], td[4], td[5], td[6], td[7], `${td[1]}: ${td[8]}`] : td;
    if (!/^\d+$/.test(id) || !KEEP.test(canal)) continue;
    const s = iso(start), e = iso(end); if (!s || !e) continue;
    if (!out.has(id)) out.set(id, [id, canal, from, to, s, e, desc.slice(0, 600)]);
  }
  return [...out.values()];
}

app.http("stoppages", {
  methods: ["GET"],
  authLevel: "anonymous",
  handler: async () => {
    const headers = { "Access-Control-Allow-Origin": "*", "Cache-Control": "public, max-age=900" };
    if (!cache.body || Date.now() - cache.at > 60 * 60e3) {
      try {
        const r = await fetch(SRC, { headers: { "User-Agent": "WeeDram route page (personal use)" } });
        if (!r.ok) throw new Error("HTTP " + r.status);
        const items = parse(await r.text());
        if (items.length) cache = { at: Date.now(), body: { at: new Date().toISOString(), items } };
      } catch (e) { if (!cache.body) return { status: 502, headers, jsonBody: { error: "Couldn't reach the notices list" } }; }
    }
    return { headers, jsonBody: cache.body };
  }
});

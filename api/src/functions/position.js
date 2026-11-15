// GET  /api/position  -> latest shared boat position (for the #follow page)
// POST /api/position  -> update position; needs header x-share-key matching the SHARE_KEY app setting
// App settings: STORAGE_CONNECTION (storage account connection string), SHARE_KEY (any long random string)
const { app } = require("@azure/functions");
const { TableClient } = require("@azure/data-tables");

const table = () => TableClient.fromConnectionString(process.env.STORAGE_CONNECTION, "boatposition");

app.http("position", {
  methods: ["GET", "POST"],
  authLevel: "anonymous",
  handler: async (req, ctx) => {
    const t = table();
    await t.createTable().catch(() => {});
    if (req.method === "GET") {
      try {
        const e = await t.getEntity("boat", "latest");
        return { jsonBody: JSON.parse(e.data), headers: { "Cache-Control": "no-store" } };
      } catch { return { status: 404, jsonBody: { error: "No position shared yet" } }; }
    }
    if (!process.env.SHARE_KEY || req.headers.get("x-share-key") !== process.env.SHARE_KEY) return { status: 401, jsonBody: { error: "Bad share key" } };
    const b = await req.json();
    const clean = { trip: String(b.trip || "").slice(0, 4), lat: +b.lat, lon: +b.lon, miles: +b.miles,
      place: String(b.place || "").slice(0, 120), eta: String(b.eta || "").slice(0, 40), ts: Date.now() };
    if (!isFinite(clean.lat) || !isFinite(clean.lon) || !isFinite(clean.miles)) return { status: 400, jsonBody: { error: "Bad position" } };
    await t.upsertEntity({ partitionKey: "boat", rowKey: "latest", data: JSON.stringify(clean) }, "Replace");
    return { status: 204 };
  }
});

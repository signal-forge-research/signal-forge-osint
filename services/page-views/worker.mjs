const origins = new Set(["https://signalforgeresearch.com", "https://www.signalforgeresearch.com"]);
const assets = new Set(["signal-forge-icon-200.png", "signal-forge-logo-transparent.png", "signal-forge-logo.png"]);
const gif = Uint8Array.from(atob("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"), c => c.charCodeAt(0));
const increment = `INSERT INTO page_views (id, total, started_at) VALUES (1, 1, ?)
 ON CONFLICT(id) DO UPDATE SET total = total + 1 RETURNING total, started_at`;
const totalQuery = "SELECT total, started_at FROM page_views WHERE id = 1";
const clip = (value, max = 500) => typeof value === "string" ? value.slice(0, max) : "";
function sitePath(value) {
  try { const url = new URL(value, "https://signalforgeresearch.com"); return origins.has(url.origin) ? url.pathname.slice(0, 500) : ""; }
  catch { return ""; }
}
function cleanUrl(value) {
  try { const url = new URL(value); return ["https:", "http:"].includes(url.protocol) ? (url.origin + url.pathname).slice(0, 500) : ""; }
  catch { return ""; }
}
async function record(request, env, data) {
  if (request.headers.get("DNT") === "1" || request.headers.get("Sec-GPC") === "1") return null;
  const now = new Date().toISOString();
  const expiry = new Date(Date.now() - 90 * 86400000).toISOString();
  const insert = env.DB.prepare(`INSERT INTO analytics_events
    (occurred_at, event_type, target, page_path, referrer, session_id, ip_address, user_agent, country)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(now, data.type, clip(data.target), sitePath(data.page),
      cleanUrl(data.referrer), /^[a-f0-9-]{36}$/i.test(data.session || "") ? data.session : "",
      clip(request.headers.get("CF-Connecting-IP"), 64), clip(request.headers.get("User-Agent")), clip(request.cf?.country, 8));
  const statements = [env.DB.prepare("DELETE FROM analytics_events WHERE occurred_at < ?").bind(expiry), insert];
  if (data.type === "pageview") statements.push(env.DB.prepare(increment).bind(now));
  // Batch writes and count changes are committed together.
  const results = await env.DB.batch(statements);
  return data.type === "pageview" ? results.at(-1).results[0] : null;
}
function json(data, headers, status = 200) { return new Response(JSON.stringify(data), { status, headers }); }
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const common = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer" };
    const pixel = /^\/pixel\/([a-f0-9]{32})\.gif$/.exec(url.pathname);
    if (pixel && request.method === "GET") {
      // A request is only a possible open: mail proxies can prefetch/cache images.
      try { await record(request, env, { type: "pixel_request", target: pixel[1] }); }
      catch { return new Response(gif, { status: 503, headers: { ...common, "Content-Type": "image/gif" } }); }
      return new Response(gif, { headers: { ...common, "Content-Type": "image/gif" } });
    }
    if (url.pathname.startsWith("/asset/") && request.method === "GET") {
      const name = url.pathname.slice(7);
      if (!assets.has(name)) return new Response("Not found", { status: 404 });
      try {
        const upstream = await fetch(`https://signalforgeresearch.com/assets/${name}`, { redirect: "error" });
        if (!upstream.ok) return new Response("Asset unavailable", { status: 502 });
        await record(request, env, { type: "asset_request", target: `/assets/${name}`, referrer: request.headers.get("Referer") });
        return new Response(upstream.body, { headers: { ...common, "Content-Type": "image/png" } });
      } catch { return new Response("Asset unavailable", { status: 503 }); }
    }
    if (!["/views", "/event"].includes(url.pathname)) return new Response("Not found", { status: 404 });
    const origin = request.headers.get("Origin");
    if (!origins.has(origin)) return new Response("Forbidden", { status: 403 });
    const headers = { ...common, "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type",
      "Content-Type": "application/json; charset=utf-8", "Vary": "Origin" };
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers });
    try {
      if (url.pathname === "/views" && request.method === "GET") {
        const row = await env.DB.prepare(totalQuery).first();
        return json({ total: row?.total ?? 0, startedAt: row?.started_at ?? null }, headers);
      }
      if (url.pathname === "/event" && request.method === "POST") {
        if (!request.headers.get("Content-Type")?.startsWith("application/json")) return json({ error: "JSON required" }, headers, 415);
        // Stream with a hard size limit; never buffer an unbounded request body.
        const reader = request.body?.getReader();
        if (!reader) return json({ error: "Missing event" }, headers, 400);
        const chunks = []; let size = 0;
        while (true) {
          const { value, done } = await reader.read(); if (done) break;
          size += value.byteLength;
          if (size > 4096) { await reader.cancel(); return json({ error: "Event too large" }, headers, 413); }
          chunks.push(value);
        }
        const bytes = new Uint8Array(size); let offset = 0;
        for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
        let data;
        try { data = JSON.parse(new TextDecoder().decode(bytes)); } catch { return json({ error: "Invalid JSON" }, headers, 400); }
        if (!data || !["pageview", "download_click", "outbound_click"].includes(data.type) || !sitePath(data.page)) return json({ error: "Invalid event" }, headers, 400);
        data.target = data.type === "pageview" ? sitePath(data.page) : cleanUrl(data.target);
        const row = await record(request, env, data);
        return json({ accepted: true, ...(row ? { total: row.total, startedAt: row.started_at } : {}) }, headers);
      }
      return json({ error: "Method not allowed" }, { ...headers, Allow: url.pathname === "/views" ? "GET, OPTIONS" : "POST, OPTIONS" }, 405);
    } catch { return json({ error: "Analytics unavailable" }, headers, 503); }
  },
};

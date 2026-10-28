const origins = new Set([
  "https://signalforgeresearch.com",
  "https://www.signalforgeresearch.com",
]);

export default {
  async fetch(request, env) {
    if (new URL(request.url).pathname !== "/views") return new Response("Not found", { status: 404 });
    const origin = request.headers.get("Origin");
    if (!origins.has(origin)) return new Response("Forbidden", { status: 403 });
    const headers = {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Cache-Control": "no-store",
      "Content-Type": "application/json; charset=utf-8",
      "Vary": "Origin",
      "X-Content-Type-Options": "nosniff",
    };
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers });
    if (!["GET", "POST"].includes(request.method)) {
      return new Response(JSON.stringify({ error: "Method not allowed" }), {
        status: 405, headers: { ...headers, Allow: "GET, POST, OPTIONS" },
      });
    }
    try {
      // A single SQL statement increments atomically, even with concurrent visits.
      // Store aggregate numbers only: no IPs, URLs, user agents, or visitor IDs.
      const row = request.method === "POST"
        ? await env.DB.prepare(`
            INSERT INTO page_views (id, total, started_at) VALUES (1, 1, ?)
            ON CONFLICT(id) DO UPDATE SET total = total + 1
            RETURNING total, started_at
          `).bind(new Date().toISOString()).first()
        : await env.DB.prepare("SELECT total, started_at FROM page_views WHERE id = 1").first();
      return new Response(JSON.stringify({ total: row?.total ?? 0, startedAt: row?.started_at ?? null }), { headers });
    } catch {
      return new Response(JSON.stringify({ error: "Counter unavailable" }), { status: 503, headers });
    }
  },
};

import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import worker from "./worker.mjs";

const origin = "https://signalforgeresearch.com";
function database() {
  const sql = new DatabaseSync(":memory:");
  sql.exec(readFileSync(new URL("migrations/0001_page_views.sql", import.meta.url), "utf8"));
  return {
    sql,
    DB: { prepare(query) {
      let args = [];
      return {
        bind(...values) { args = values; return this; },
        async first() { return sql.prepare(query).get(...args); },
      };
    } },
  };
}
function request(method = "GET", site = origin, path = "/views") {
  return new Request(`https://counter.example${path}`, { method, headers: { Origin: site } });
}

test("reads do not count; writes persist a shared total and original start date", async () => {
  const env = database();
  try {
    assert.deepEqual(await (await worker.fetch(request(), env)).json(), { total: 0, startedAt: null });
    const first = await (await worker.fetch(request("POST"), env)).json();
    assert.equal(first.total, 1);
    assert.ok(Number.isFinite(Date.parse(first.startedAt)));
    await Promise.all(Array.from({ length: 20 }, () => worker.fetch(request("POST"), env)));
    const response = await worker.fetch(request(), env);
    assert.deepEqual(await response.json(), { total: 21, startedAt: first.startedAt });
    assert.equal(response.headers.get("Cache-Control"), "no-store");
    assert.equal(response.headers.get("Access-Control-Allow-Origin"), origin);
    assert.equal(env.sql.prepare("SELECT count(*) AS n FROM page_views").get().n, 1);
  } finally { env.sql.close(); }
});

test("disallowed origins, paths, methods and preflight do not write", async () => {
  const env = database();
  try {
    for (const [req, expected] of [
      [request("POST", "https://other.example"), 403],
      [request("POST", "null"), 403],
      [request("POST", origin, "/pixel/example.gif"), 404],
      [request("DELETE"), 405], [request("OPTIONS"), 204],
    ]) assert.equal((await worker.fetch(req, env)).status, expected);
    assert.equal((await (await worker.fetch(request(), env)).json()).total, 0);
    assert.equal((await worker.fetch(request("POST", "https://www.signalforgeresearch.com"), env)).status, 200);
    assert.equal((await worker.fetch(request("POST"), {})).status, 503);
  } finally { env.sql.close(); }
});

const browserSource = readFileSync(new URL("../../docs/assets/page-views.js", import.meta.url), "utf8");
async function browser({ enabled = true, navigator = {}, failing = false } = {}) {
  const calls = [];
  const label = { textContent: "" };
  const element = { hidden: true, querySelector: () => label };
  const code = enabled ? browserSource.replace('const endpoint = "";', 'const endpoint = "https://counter.example";') : browserSource;
  await vm.runInNewContext(code, {
    URL, AbortSignal, navigator, location: { hostname: "signalforgeresearch.com" },
    document: { querySelectorAll: () => [element] },
    fetch: async (url, options) => {
      calls.push({ url: url.href, ...options });
      if (failing) throw new Error("Blocked");
      return { ok: true, json: async () => ({ total: 42, startedAt: "2026-10-27T00:00:00Z" }) };
    },
  });
  return { calls, element, label };
}

test("browser sends no credentials, updates the label, respects opt-out and fails quietly", async () => {
  const normal = await browser();
  assert.equal(normal.calls[0].method, "POST");
  assert.equal(normal.calls[0].credentials, "omit");
  assert.equal(normal.calls[0].referrerPolicy, "no-referrer");
  assert.equal(normal.label.textContent, "42");
  assert.equal(normal.element.hidden, false);
  for (const navigator of [{ doNotTrack: "1" }, { globalPrivacyControl: true }]) {
    assert.equal((await browser({ navigator })).calls[0].method, "GET");
  }
  assert.equal((await browser({ enabled: false })).calls.length, 0);
  assert.equal((await browser({ failing: true })).element.hidden, true);
});

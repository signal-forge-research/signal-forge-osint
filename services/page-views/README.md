# Website analytics and separate email-pixel log

GitHub Pages serves the website. A Cloudflare Worker and D1 database store a public
page-view total and private detailed events. No email inbox access is involved.

## Records

- `pageview`: server UTC timestamp, page path, available referring URL, temporary
  session UUID, connecting IP, User-Agent, and approximate Cloudflare country.
- `download_click` and `outbound_click`: same information plus the clicked URL.
  This records a click, not a completed transfer.
- `asset_request`: a successful response for an allowlisted image routed through
  `/asset/FILENAME`. Direct requests to GitHub Pages cannot be observed here.
- `pixel_request`: requests to `/pixel/RANDOM_32_HEX_TOKEN.gif`. Independent of
  website visits. Mail proxies/prefetch/caching make these only possible opens.

Raw event records are private to the Cloudflare account, never returned by the
public API. They expire after 90 days and are purged on the next recorded event.
The all-time page-view total is separate. URL queries/fragments are omitted. Raw
IPs identify connecting networks/proxies, not necessarily people. Approximate
visits are distinct temporary tab-session IDs; this is not a unique-person count.

## Activate

Use Node.js with npm. In this directory:

```sh
npx wrangler@4 login
npx wrangler@4 d1 create signalforge-analytics
```

Replace `REPLACE_WITH_D1_DATABASE_ID` in `wrangler.jsonc` with the returned ID,
keeping the binding name `DB`. Decline any offer to add a duplicate binding.

```sh
npx wrangler@4 d1 migrations apply signalforge-analytics --remote
npx wrangler@4 deploy
```

Set `endpoint` in `docs/assets/page-views.js` to the deployed HTTPS base URL. For
image request logging, change the homepage logo `src` to
`https://YOUR-WORKER.workers.dev/asset/signal-forge-logo-transparent.png`. Other
allowlisted assets can use the same endpoint. Deploy the GitHub Pages changes.
No DNS changes are required. API keys and account tokens never belong in the site.

Dashboard alternative: create a Worker and D1 database in Cloudflare, paste
`worker.mjs` into the Worker's code editor, run both migration files in the D1 SQL
console, and bind the database to the Worker as `DB`. Then deploy and set the URL.
Do not enable public database access.

Before activation the counter stays hidden. If the service is unavailable, the
counter stays hidden and page navigation remains functional. If image delivery is
unavailable, restore the logo's original GitHub Pages URL. Clear `endpoint` to
stop browser tracking. Browser Do Not Track / Global Privacy Control skip event
submission and session storage; their read-only total request does not count.
Cloudflare Worker observability remains enabled for service diagnostics. Cloudflare
also processes requests as the provider. Review the account's plan limits before use.

## View private metrics

Open Cloudflare > Storage & databases > D1 > signalforge-analytics > Console.
Queries below are read-only. Timestamps use UTC; convert in your report as needed.

```sql
-- Recent activity, including connecting IP and image/pixel events.
SELECT * FROM analytics_events ORDER BY id DESC LIMIT 100;

-- Daily totals by event type.
SELECT substr(occurred_at,1,10) AS day, event_type, count(*) AS events
FROM analytics_events GROUP BY day,event_type ORDER BY day DESC,event_type;

-- Daily approximate tab sessions (not people); sessions with blocked storage omitted.
SELECT substr(occurred_at,1,10) AS day, count(DISTINCT session_id) AS sessions
FROM analytics_events WHERE event_type='pageview' AND session_id<>'' GROUP BY day ORDER BY day DESC;

-- Popular pages.
SELECT page_path, count(*) AS views FROM analytics_events WHERE event_type='pageview'
GROUP BY page_path ORDER BY views DESC;

-- Possible email opens, grouped by opaque token; never include email addresses in URLs.
SELECT target AS pixel_token, min(occurred_at) AS first_request,
max(occurred_at) AS last_request, count(*) AS requests
FROM analytics_events WHERE event_type='pixel_request' GROUP BY target ORDER BY last_request DESC;
```

These queries only cover the retained event history. The public total lives in
`page_views` and persists beyond it. No historic GitHub website traffic can be
recovered. Origin restrictions are not authentication; automated callers can
spoof them or repeat events. Counts are approximate, not an audit of human visits.

## Include a pixel in a future send-only client

Generate a separate cryptographically random 16-byte token for each message and
recipient, and keep the token-to-message mapping privately in the sender's log:

```sh
node -e 'console.log(require("node:crypto").randomBytes(16).toString("hex"))'
```

```html
<img src="https://YOUR-WORKER.workers.dev/pixel/RANDOM_32_HEX_TOKEN.gif" width="1" height="1" alt="">
```

No scripts execute inside the email. A client loads the image URL and the server
records that request. Nothing here guarantees delivery, identifies a reader, or
proves that anyone read the message. This change does not send any emails.

## Verify

```sh
node --test counter.test.mjs
```

Requires Node.js 22.13+ for the SQLite-backed tests.
References: [D1](https://developers.cloudflare.com/d1/worker-api/d1-database/),
[Wrangler](https://developers.cloudflare.com/workers/wrangler/configuration/).

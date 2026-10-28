# Website page-view counter

GitHub Pages continues to serve the website. A Cloudflare Worker and D1 database
store one aggregate count across the three HTML pages. No inbox access is involved.
This service does not implement email pixels or count image requests.

## Activate

Use a supported Node.js version with npm installed and sign in to your own
Cloudflare account. From this directory:

```sh
npx wrangler@4 login
npx wrangler@4 d1 create signalforge-page-views
```

Copy the returned database ID into `wrangler.jsonc`, replacing
`REPLACE_WITH_D1_DATABASE_ID` in the existing `DB` binding. If Wrangler offers to
add another binding, decline; edit the existing binding instead.

```sh
npx wrangler@4 d1 migrations apply signalforge-page-views --remote
npx wrangler@4 deploy
```

Paste the deployed HTTPS Worker base URL (such as
`https://signalforge-page-views.YOUR-SUBDOMAIN.workers.dev`) into `endpoint` in
`docs/assets/page-views.js`. Commit that change and publish the GitHub Pages files
using the repository's existing publishing settings. No DNS changes are needed.
The Worker URL and database ID are not passwords; never commit account tokens.

Check the live site and reload: the footer should show an increasing "Page views"
total. All three pages share it. To inspect without incrementing:

```sh
curl -H 'Origin: https://signalforgeresearch.com' https://YOUR-WORKER.workers.dev/views
```

Before activation, or when the service is blocked or unavailable, the counter stays
hidden. It never substitutes a fabricated total or starts a separate local count.
To disable it, clear `endpoint` and publish that change.

## Meaning and limitations

- Counts successful requests from page loads after activation, including refreshes
  and repeat visits. It cannot recover past website traffic or count unique people.
- JavaScript blockers, privacy settings, network errors, and failed database writes
  can prevent counts. Do Not Track and Global Privacy Control skip increments.
- Automated traffic can inflate totals. The Origin allowlist blocks accidental
  browser use on other sites, but is not authentication: non-browser callers can
  spoof it. This is an approximate public counter, not an audited traffic report.
- Storage contains only the total and first-count timestamp, with no cookies,
  local storage, IP addresses, or per-visitor history. Cloudflare still processes
  requests as the hosting provider. Worker application observability is disabled.
- Only the homepage displays the total; visits to either catalog page contribute.
- Email pixels need a separate endpoint with separate records, never this total.
  A pixel request would still indicate only a possible open.

Cloudflare plan limits and billing apply to Workers and D1; inspect the account's
current limits before deployment. Database records can be inspected in Cloudflare's
D1 console. There is no public reset or administrative endpoint.

## Verify locally

Node.js 22.13 or newer is required for the SQLite-backed checks:

```sh
node --test counter.test.mjs
```

References: [D1 bindings](https://developers.cloudflare.com/d1/worker-api/d1-database/),
[Wrangler configuration](https://developers.cloudflare.com/workers/wrangler/configuration/).

// After deploying services/page-views, paste its HTTPS base URL here.
// This is a public service URL, never an API key or password.
const endpoint = "";

(async () => {
  if (!endpoint || !["signalforgeresearch.com", "www.signalforgeresearch.com"].includes(location.hostname)) return;
  try {
    const base = new URL(endpoint);
    if (base.protocol !== "https:") return;
    // Respect browser privacy preferences: display the total without incrementing.
    const optOut = navigator.doNotTrack === "1" || navigator.globalPrivacyControl === true;
    const response = await fetch(new URL("/views", base), {
      method: optOut ? "GET" : "POST",
      mode: "cors",
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) return;
    const { total, startedAt } = await response.json();
    if (!Number.isSafeInteger(total) || total < 0) return;
    for (const element of document.querySelectorAll("[data-site-views]")) {
      element.querySelector("[data-site-views-value]").textContent = total.toLocaleString();
      element.title = "Recorded page loads across this site; repeat visits count. No cookies or IP addresses stored by the counter."
        + (startedAt ? ` Counting began ${startedAt.slice(0, 10)} (UTC).` : "");
      element.hidden = false;
    }
  } catch {
    // A blocked or unavailable counter must not interrupt the website.
  }
})();

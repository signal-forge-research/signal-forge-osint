// Public Worker base URL; never put account tokens or passwords in this file.
const endpoint = "https://signalforge-analytics.vbz92whs5n.workers.dev";
const allowed = ["signalforgeresearch.com", "www.signalforgeresearch.com"];
if (endpoint && allowed.includes(location.hostname)) {
  const optOut = navigator.doNotTrack === "1" || navigator.globalPrivacyControl === true;
  let session = "";
  if (!optOut) {
    try {
      session = sessionStorage.getItem("signalforge-analytics-session") || crypto.randomUUID();
      sessionStorage.setItem("signalforge-analytics-session", session);
    } catch { /* Page views work without session storage; visit estimates may be lower. */ }
  }
  const base = new URL(endpoint);
  const show = ({ total, startedAt }) => {
    if (!Number.isSafeInteger(total) || total < 0) return;
    for (const element of document.querySelectorAll("[data-site-views]")) {
      element.querySelector("[data-site-views-value]").textContent = total.toLocaleString();
      element.title = "Recorded page loads across this site, including repeat visits."
        + (startedAt ? ` Counting began ${startedAt.slice(0, 10)} (UTC).` : "");
      element.hidden = false;
    }
  };
  const send = async (type, target = "") => {
    try {
      const response = await fetch(new URL("/event", base), {
        method: "POST", mode: "cors", credentials: "omit", cache: "no-store",
        referrerPolicy: "no-referrer", keepalive: true, signal: AbortSignal.timeout(5000),
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type, target, page: location.pathname, referrer: document.referrer, session }),
      });
      if (response.ok && type === "pageview") show(await response.json());
    } catch { /* Analytics must not interrupt the website. */ }
  };
  if (base.protocol === "https:") {
    if (optOut) {
      fetch(new URL("/views", base), { credentials: "omit", cache: "no-store", referrerPolicy: "no-referrer" })
        .then(r => r.ok ? r.json() : null).then(data => data && show(data)).catch(() => {});
    } else {
      send("pageview");
      document.addEventListener("click", event => {
        const link = event.target.closest?.("a[href]");
        if (!link) return;
        const url = new URL(link.href, location.href);
        if (!["https:", "http:"].includes(url.protocol)) return;
        const target = url.origin + url.pathname;
        if (link.hasAttribute("download") || /\.(pdf|zip|csv|xlsx?|docx?|pptx?|png|jpe?g|gif|webp|txt)$/i.test(url.pathname)) send("download_click", target);
        else if (!allowed.includes(url.hostname)) send("outbound_click", target);
      });
    }
  }
}

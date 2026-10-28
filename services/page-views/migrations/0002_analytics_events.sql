CREATE TABLE IF NOT EXISTS analytics_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  occurred_at TEXT NOT NULL,
  event_type TEXT NOT NULL CHECK (event_type IN ('pageview', 'download_click', 'outbound_click', 'asset_request', 'pixel_request')),
  target TEXT NOT NULL DEFAULT '',
  page_path TEXT NOT NULL DEFAULT '',
  referrer TEXT NOT NULL DEFAULT '',
  session_id TEXT NOT NULL DEFAULT '',
  ip_address TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT '',
  country TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS analytics_events_time ON analytics_events(occurred_at);
CREATE INDEX IF NOT EXISTS analytics_events_type_time ON analytics_events(event_type, occurred_at);

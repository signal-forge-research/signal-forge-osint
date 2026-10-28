CREATE TABLE IF NOT EXISTS page_views (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  total INTEGER NOT NULL CHECK (total >= 0),
  started_at TEXT NOT NULL
);

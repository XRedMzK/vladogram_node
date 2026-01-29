CREATE TABLE IF NOT EXISTS user_epochs (
  user_id INTEGER PRIMARY KEY,
  epoch INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS apocalypse (
  username TEXT NOT NULL,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  stamp TIMESTAMP WITH TIME ZONE,
  PRIMARY KEY (username, key)
);

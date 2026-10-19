CREATE TABLE bloodhound_targets (
  id            INTEGER PRIMARY KEY,
  kind          TEXT NOT NULL CHECK (kind IN ('Computer', 'User')),
  identity      TEXT NOT NULL COLLATE NOCASE,
  host_id       INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
  state         TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'synced', 'error')),
  error         TEXT NOT NULL DEFAULT '',
  object_id     TEXT NOT NULL DEFAULT '',
  resolved_name TEXT NOT NULL DEFAULT '',
  updated_at    INTEGER NOT NULL,
  synced_at     INTEGER NOT NULL DEFAULT 0,
  CHECK ((kind = 'Computer' AND host_id IS NOT NULL) OR (kind = 'User' AND host_id IS NULL)),
  UNIQUE (kind, identity)
);
CREATE UNIQUE INDEX bloodhound_target_host ON bloodhound_targets(host_id) WHERE kind = 'Computer';
CREATE INDEX bloodhound_target_state ON bloodhound_targets(state);

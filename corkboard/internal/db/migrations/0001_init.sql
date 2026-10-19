CREATE TABLE meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE runs (
  id           INTEGER PRIMARY KEY,
  kind         TEXT NOT NULL CHECK (kind IN ('nmap','masscan','nxc','gowitness','nuclei','manual')),
  uploaded_by  TEXT NOT NULL,
  uploaded_at  INTEGER NOT NULL,
  started_at   INTEGER,
  finished_at  INTEGER,
  command      TEXT,
  source_name  TEXT,
  source_sha256 TEXT,
  stages       TEXT NOT NULL DEFAULT '[]',
  stats        TEXT NOT NULL DEFAULT '{}'
);
CREATE UNIQUE INDEX runs_sha ON runs(source_sha256) WHERE source_sha256 IS NOT NULL;

CREATE TABLE hosts (
  id          INTEGER PRIMARY KEY,
  ip          TEXT NOT NULL UNIQUE,
  ip_sort     BLOB NOT NULL,
  os          TEXT,
  os_accuracy INTEGER,
  domain      TEXT,
  mac         TEXT,
  mac_vendor  TEXT,
  status      TEXT NOT NULL DEFAULT 'untouched'
              CHECK (status IN ('untouched','in_progress','done','compromised','locked')),
  scope_zone  TEXT NOT NULL DEFAULT 'unknown'
              CHECK (scope_zone IN ('in','caution','out','unknown')),
  owner       TEXT,
  claimed_at  INTEGER,
  priority    INTEGER NOT NULL DEFAULT 3,
  first_seen  INTEGER NOT NULL,
  last_seen   INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);
CREATE INDEX hosts_ip_sort ON hosts(ip_sort);
CREATE INDEX hosts_status ON hosts(status);

CREATE TABLE hostnames (
  host_id  INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  name     TEXT NOT NULL COLLATE NOCASE,
  source   TEXT NOT NULL,
  first_seen INTEGER NOT NULL,
  PRIMARY KEY (host_id, name)
);
CREATE INDEX hostnames_name ON hostnames(name);

CREATE TABLE host_tags (
  host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  tag     TEXT NOT NULL COLLATE NOCASE,
  source  TEXT NOT NULL,
  PRIMARY KEY (host_id, tag)
);
CREATE INDEX host_tags_tag ON host_tags(tag);

CREATE TABLE host_attrs (
  host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  key     TEXT NOT NULL,
  value   TEXT NOT NULL,
  source  TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (host_id, key)
);

CREATE TABLE services (
  id         INTEGER PRIMARY KEY,
  host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  proto      TEXT NOT NULL CHECK (proto IN ('tcp','udp','sctp')),
  port       INTEGER NOT NULL CHECK (port BETWEEN 0 AND 65535),
  state      TEXT NOT NULL DEFAULT 'open',
  name       TEXT,
  product    TEXT,
  version    TEXT,
  extrainfo  TEXT,
  tunnel     TEXT,
  cpe        TEXT,
  first_seen INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL,
  UNIQUE (host_id, proto, port)
);
CREATE INDEX services_port ON services(port, proto);

CREATE TABLE service_scripts (
  service_id INTEGER REFERENCES services(id) ON DELETE CASCADE,
  host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  script_id  TEXT NOT NULL,
  output     TEXT NOT NULL,
  run_id     INTEGER NOT NULL REFERENCES runs(id),
  updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX service_scripts_uniq ON service_scripts(host_id, IFNULL(service_id, 0), script_id);

CREATE TABLE observations (
  id         INTEGER PRIMARY KEY,
  run_id     INTEGER NOT NULL REFERENCES runs(id),
  host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  service_id INTEGER REFERENCES services(id) ON DELETE CASCADE,
  what       TEXT NOT NULL,
  detail     TEXT NOT NULL DEFAULT '{}',
  at         INTEGER NOT NULL
);
CREATE INDEX observations_host ON observations(host_id, at);

CREATE TABLE run_coverage (
  run_id  INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  stage   TEXT NOT NULL,
  PRIMARY KEY (run_id, host_id, stage)
);
CREATE INDEX run_coverage_host ON run_coverage(host_id, stage);

CREATE TABLE web_results (
  id            INTEGER PRIMARY KEY,
  service_id    INTEGER REFERENCES services(id) ON DELETE SET NULL,
  host_id       INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
  url           TEXT NOT NULL UNIQUE,
  final_url     TEXT,
  status_code   INTEGER,
  title         TEXT,
  technologies  TEXT NOT NULL DEFAULT '[]',
  tls_subject   TEXT,
  tls_sans      TEXT NOT NULL DEFAULT '[]',
  screenshot    TEXT,
  thumb         TEXT,
  failed        INTEGER NOT NULL DEFAULT 0,
  failed_reason TEXT,
  run_id        INTEGER NOT NULL REFERENCES runs(id),
  probed_at     INTEGER
);

CREATE TABLE creds (
  id          INTEGER PRIMARY KEY,
  domain      TEXT NOT NULL DEFAULT '' COLLATE NOCASE,
  username    TEXT NOT NULL COLLATE NOCASE,
  secret      TEXT NOT NULL,
  secret_type TEXT NOT NULL CHECK (secret_type IN ('password','ntlm','aes','ssh_key','ticket','hash_uncracked','other')),
  source      TEXT NOT NULL,
  notes       TEXT,
  added_by    TEXT NOT NULL,
  added_at    INTEGER NOT NULL,
  UNIQUE (domain, username, secret, secret_type)
);

CREATE TABLE cred_access (
  cred_id   INTEGER NOT NULL REFERENCES creds(id) ON DELETE CASCADE,
  host_id   INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  protocol  TEXT NOT NULL,
  level     TEXT NOT NULL CHECK (level IN ('invalid','valid','admin')),
  source    TEXT NOT NULL,
  observed_at INTEGER NOT NULL,
  PRIMARY KEY (cred_id, host_id, protocol)
);

CREATE TABLE shares (
  id       INTEGER PRIMARY KEY,
  host_id  INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  name     TEXT NOT NULL,
  remark   TEXT,
  cred_id  INTEGER REFERENCES creds(id) ON DELETE SET NULL,
  can_read INTEGER NOT NULL DEFAULT 0,
  can_write INTEGER NOT NULL DEFAULT 0,
  observed_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX shares_uniq ON shares(host_id, name, IFNULL(cred_id, 0));

CREATE TABLE tasks (
  id          INTEGER PRIMARY KEY,
  dedupe_key  TEXT NOT NULL UNIQUE,
  rule_id     TEXT,
  host_id     INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
  service_id  INTEGER REFERENCES services(id) ON DELETE CASCADE,
  title       TEXT NOT NULL,
  body        TEXT NOT NULL DEFAULT '',
  commands    TEXT NOT NULL DEFAULT '[]',
  priority    INTEGER NOT NULL DEFAULT 3,
  state       TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open','claimed','blocked','done','wontdo')),
  owner       TEXT,
  claimed_at  INTEGER,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,
  closed_note TEXT
);
CREATE INDEX tasks_state ON tasks(state, priority);

CREATE TABLE findings (
  id           INTEGER PRIMARY KEY,
  dedupe_key   TEXT NOT NULL UNIQUE,
  title        TEXT NOT NULL,
  severity     TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
  source       TEXT NOT NULL,
  state        TEXT NOT NULL DEFAULT 'candidate' CHECK (state IN ('candidate','confirmed','rejected','reported')),
  gw_library_title TEXT,
  gw_finding_id INTEGER,
  description  TEXT NOT NULL DEFAULT '',
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL
);

CREATE TABLE finding_hosts (
  id         INTEGER PRIMARY KEY,
  finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  service_id INTEGER REFERENCES services(id) ON DELETE CASCADE,
  evidence   TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX finding_hosts_uniq ON finding_hosts(finding_id, host_id, IFNULL(service_id, 0));

CREATE TABLE compromises (
  id        INTEGER PRIMARY KEY,
  host_id   INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  level     TEXT NOT NULL CHECK (level IN ('user','admin','system','domain_admin')),
  via_finding_id INTEGER REFERENCES findings(id) ON DELETE SET NULL,
  via_cred_id    INTEGER REFERENCES creds(id) ON DELETE SET NULL,
  via_text  TEXT NOT NULL DEFAULT '',
  by_user   TEXT NOT NULL,
  at        INTEGER NOT NULL
);

CREATE TABLE notes (
  id       INTEGER PRIMARY KEY,
  host_id  INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  author   TEXT NOT NULL,
  body     TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE events (
  id       INTEGER PRIMARY KEY,
  at       INTEGER NOT NULL,
  actor    TEXT NOT NULL,
  kind     TEXT NOT NULL,
  host_id  INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
  ref_id   INTEGER,
  summary  TEXT NOT NULL,
  data     TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX events_at ON events(at);

CREATE TABLE alerts_sent (
  key  TEXT PRIMARY KEY,
  at   INTEGER NOT NULL
);

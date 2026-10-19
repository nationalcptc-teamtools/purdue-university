ALTER TABLE runs ADD COLUMN vantage TEXT NOT NULL DEFAULT '';
CREATE TABLE scan_evidence (
  run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  ip TEXT NOT NULL,
  host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
  vantage TEXT NOT NULL DEFAULT '',
  observed_at INTEGER NOT NULL,
  run_json TEXT NOT NULL,
  host_json TEXT NOT NULL,
  PRIMARY KEY(run_id, ip)
);
CREATE INDEX scan_evidence_host ON scan_evidence(host_id, observed_at);
CREATE TABLE service_views (
  host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  proto TEXT NOT NULL,
  port INTEGER NOT NULL,
  vantage TEXT NOT NULL,
  run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  observed_at INTEGER NOT NULL,
  state TEXT NOT NULL,
  method TEXT NOT NULL DEFAULT '',
  confidence INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(host_id, proto, port, vantage)
);
ALTER TABLE run_coverage ADD COLUMN status TEXT NOT NULL DEFAULT 'attempted';
UPDATE run_coverage SET status = 'completed' WHERE run_id IN
  (SELECT id FROM runs WHERE kind NOT IN ('nmap','masscan'));
INSERT OR IGNORE INTO host_attrs(host_id,key,value,source,updated_at)
 SELECT host_id,'legacy_port_state','Inferred closures predate scan evidence','migration',MAX(last_seen)
 FROM services WHERE state='closed' GROUP BY host_id;

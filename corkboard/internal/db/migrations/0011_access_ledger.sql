CREATE TABLE vantages (
 name TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('operator','foothold','network')),
 host_id INTEGER REFERENCES hosts(id), note TEXT NOT NULL DEFAULT '',
 created_by TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE tunnels (
 id INTEGER PRIMARY KEY, owner TEXT NOT NULL, via_host_id INTEGER NOT NULL REFERENCES hosts(id),
 listener TEXT NOT NULL DEFAULT '', destination TEXT NOT NULL DEFAULT '',
 vantage TEXT NOT NULL REFERENCES vantages(name),
 state TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active','ended','unknown')),
 started_at INTEGER, ended_at INTEGER, end_reason TEXT NOT NULL DEFAULT '',
 note TEXT NOT NULL DEFAULT '', recorded_at INTEGER NOT NULL
);
CREATE TABLE access_edges (
 id INTEGER PRIMARY KEY,
 kind TEXT NOT NULL CHECK(kind IN ('reach','auth','shell','cred_found','cred_used')),
 src TEXT, dst TEXT NOT NULL,
 level TEXT NOT NULL DEFAULT '',
 via_edge_id INTEGER REFERENCES access_edges(id),
 cred_id INTEGER REFERENCES creds(id), finding_id INTEGER REFERENCES findings(id),
 evidence_id INTEGER REFERENCES evidence(id), compromise_id INTEGER REFERENCES compromises(id),
 note TEXT NOT NULL DEFAULT '', actor TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'manual',
 occurred_at INTEGER, recorded_at INTEGER NOT NULL,
 ended_at INTEGER, ended_recorded_at INTEGER, end_reason TEXT NOT NULL DEFAULT '', ended_by TEXT NOT NULL DEFAULT '',
 corrects INTEGER UNIQUE REFERENCES access_edges(id), correction_reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX access_edges_dst ON access_edges(dst);
CREATE INDEX access_edges_src ON access_edges(src);

INSERT INTO access_edges(kind,src,dst,level,cred_id,finding_id,compromise_id,note,actor,source,occurred_at,recorded_at)
 SELECT 'shell',NULL,'host:'||host_id,level,via_cred_id,via_finding_id,id,via_text,by_user,'migration',at,at FROM compromises;

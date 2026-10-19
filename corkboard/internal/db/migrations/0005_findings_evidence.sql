CREATE TABLE applications (
 id INTEGER PRIMARY KEY, origin TEXT NOT NULL, realm TEXT NOT NULL DEFAULT '',
 host_id INTEGER REFERENCES hosts(id), service_id INTEGER REFERENCES services(id),
 created_at INTEGER NOT NULL, UNIQUE(origin,realm)
);
CREATE TABLE work_targets (
 id INTEGER PRIMARY KEY,
 host_id INTEGER UNIQUE REFERENCES hosts(id),
 service_id INTEGER UNIQUE REFERENCES services(id),
 application_id INTEGER UNIQUE REFERENCES applications(id),
 task_id INTEGER UNIQUE REFERENCES tasks(id),
 CHECK ((host_id IS NOT NULL)+(service_id IS NOT NULL)+(application_id IS NOT NULL)+(task_id IS NOT NULL)=1)
);
CREATE VIEW target_details AS
 SELECT t.id,
 CASE WHEN t.host_id IS NOT NULL THEN 'host' WHEN t.service_id IS NOT NULL THEN 'service' WHEN t.application_id IS NOT NULL THEN 'application' ELSE 'task' END kind,
 COALESCE(t.host_id,t.service_id,t.application_id,t.task_id) ref_id,
 COALESCE(t.host_id,s.host_id,a.host_id,ats.host_id,k.host_id) host_id,
 COALESCE(t.service_id,a.service_id,k.service_id) service_id,
 CASE WHEN t.host_id IS NOT NULL THEN h.ip WHEN t.service_id IS NOT NULL THEN h.ip||':'||s.port||'/'||s.proto WHEN t.application_id IS NOT NULL THEN a.origin||' '||a.realm ELSE k.title END label
 FROM work_targets t LEFT JOIN services s ON s.id=t.service_id
 LEFT JOIN applications a ON a.id=t.application_id LEFT JOIN services ats ON ats.id=a.service_id
 LEFT JOIN tasks k ON k.id=t.task_id LEFT JOIN hosts h ON h.id=COALESCE(t.host_id,s.host_id,a.host_id,ats.host_id,k.host_id);
CREATE TABLE finding_assets (
 finding_id INTEGER NOT NULL REFERENCES findings(id), target_id INTEGER NOT NULL REFERENCES work_targets(id),
 evidence TEXT NOT NULL DEFAULT '', needs_review INTEGER NOT NULL DEFAULT 1,
 PRIMARY KEY(finding_id,target_id)
);
ALTER TABLE findings ADD COLUMN operator_edited INTEGER NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN merged_into INTEGER REFERENCES findings(id);
ALTER TABLE findings ADD COLUMN report_ref TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN report_update INTEGER NOT NULL DEFAULT 0;
CREATE TABLE finding_history (
 id INTEGER PRIMARY KEY, finding_id INTEGER NOT NULL REFERENCES findings(id), actor TEXT NOT NULL,
 occurred_at INTEGER, recorded_at INTEGER NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL
);
CREATE TABLE evidence (
 id INTEGER PRIMARY KEY, sha TEXT NOT NULL DEFAULT '', media_type TEXT NOT NULL,
 caption TEXT NOT NULL DEFAULT '', external_ref TEXT NOT NULL DEFAULT '', actor TEXT NOT NULL,
 occurred_at INTEGER, recorded_at INTEGER NOT NULL, run_id INTEGER REFERENCES runs(id)
);
CREATE TABLE evidence_links (
 id INTEGER PRIMARY KEY, evidence_id INTEGER NOT NULL REFERENCES evidence(id),
 finding_id INTEGER REFERENCES findings(id), target_id INTEGER REFERENCES work_targets(id),
 CHECK(finding_id IS NOT NULL OR target_id IS NOT NULL)
);
CREATE INDEX evidence_finding ON evidence_links(finding_id);
INSERT OR IGNORE INTO work_targets(service_id) SELECT DISTINCT service_id FROM finding_hosts WHERE service_id IS NOT NULL;
INSERT OR IGNORE INTO work_targets(host_id) SELECT DISTINCT host_id FROM finding_hosts WHERE service_id IS NULL;
INSERT OR IGNORE INTO finding_assets(finding_id,target_id,evidence,needs_review)
 SELECT f.finding_id,t.id,f.evidence,CASE WHEN n.state IN ('confirmed','reported') THEN 0 ELSE 1 END
 FROM finding_hosts f JOIN findings n ON n.id=f.finding_id JOIN work_targets t
 ON (f.service_id IS NOT NULL AND t.service_id=f.service_id) OR (f.service_id IS NULL AND t.host_id=f.host_id);

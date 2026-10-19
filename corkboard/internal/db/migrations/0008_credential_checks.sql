ALTER TABLE applications ADD COLUMN retired INTEGER NOT NULL DEFAULT 0;
CREATE TABLE credential_profiles (
 cred_id INTEGER PRIMARY KEY REFERENCES creds(id), retired INTEGER NOT NULL DEFAULT 0,
 scope_kind TEXT NOT NULL DEFAULT 'unknown' CHECK(scope_kind IN ('unknown','domain','local','target','all')),
 scope_value TEXT NOT NULL DEFAULT '', protocols TEXT NOT NULL DEFAULT '[]',
 revision_of INTEGER REFERENCES creds(id), cracked_from INTEGER REFERENCES creds(id), updated_at INTEGER NOT NULL
);
INSERT INTO credential_profiles(cred_id,scope_kind,scope_value,updated_at)
 SELECT id,CASE WHEN domain<>'' AND domain<>'.' THEN 'domain' ELSE 'unknown' END,lower(domain),added_at FROM creds;
CREATE TABLE credential_support (
 secret_type TEXT NOT NULL, protocol TEXT NOT NULL, PRIMARY KEY(secret_type,protocol)
);
INSERT INTO credential_support VALUES
 ('password','ssh'),('password','smb'),('password','winrm'),('password','rdp'),('password','ldap'),('password','mssql'),('password','ftp'),('password','mysql'),('password','postgres'),('password','web'),('password','kerberos'),
 ('ssh_key','ssh'),('ntlm','smb'),('ntlm','winrm'),('ntlm','ldap'),('ntlm','mssql'),
 ('aes','kerberos'),('aes','smb'),('aes','ldap'),('aes','winrm'),('ticket','kerberos'),('ticket','smb'),('ticket','ldap');
CREATE TABLE auth_endpoints (
 id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL REFERENCES work_targets(id), protocol TEXT NOT NULL,
 vantage TEXT NOT NULL DEFAULT '', generation INTEGER NOT NULL DEFAULT 1, identity TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('open','closed')), changed_at INTEGER NOT NULL, identity_at INTEGER NOT NULL DEFAULT 0,
 UNIQUE(target_id,protocol,vantage)
);
CREATE TABLE endpoint_history (
 id INTEGER PRIMARY KEY, endpoint_id INTEGER NOT NULL REFERENCES auth_endpoints(id), generation INTEGER NOT NULL,
 state TEXT NOT NULL, identity TEXT NOT NULL, reason TEXT NOT NULL, occurred_at INTEGER, recorded_at INTEGER NOT NULL
);
CREATE TABLE check_applicability (
 cred_id INTEGER NOT NULL REFERENCES creds(id), endpoint_id INTEGER NOT NULL REFERENCES auth_endpoints(id),
 decision TEXT NOT NULL CHECK(decision IN ('eligible','excluded')), reason TEXT NOT NULL,
 actor TEXT NOT NULL, recorded_at INTEGER NOT NULL, PRIMARY KEY(cred_id,endpoint_id)
);
CREATE TABLE check_work (
 id INTEGER PRIMARY KEY, cred_id INTEGER NOT NULL REFERENCES creds(id), endpoint_id INTEGER NOT NULL REFERENCES auth_endpoints(id),
 generation INTEGER NOT NULL, state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','claimed','blocked','completed','waived')),
 owner TEXT NOT NULL DEFAULT '', reason TEXT NOT NULL DEFAULT '', current_result_id INTEGER REFERENCES check_results(id), updated_at INTEGER NOT NULL,
 UNIQUE(cred_id,endpoint_id,generation)
);
CREATE TABLE check_results (
 id INTEGER PRIMARY KEY, work_id INTEGER NOT NULL REFERENCES check_work(id),
 result TEXT NOT NULL CHECK(result IN ('invalid','valid','admin','inconclusive','waived','recheck')),
 actor TEXT NOT NULL, occurred_at INTEGER, recorded_at INTEGER NOT NULL, source TEXT NOT NULL,
 run_id INTEGER REFERENCES runs(id), accepted_current INTEGER NOT NULL DEFAULT 0,
 confirmed_loss INTEGER NOT NULL DEFAULT 0, detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX check_results_work ON check_results(work_id,id);
CREATE TABLE access_observations (
 id INTEGER PRIMARY KEY, cred_id INTEGER NOT NULL REFERENCES creds(id), host_id INTEGER NOT NULL REFERENCES hosts(id),
 protocol TEXT NOT NULL, result TEXT NOT NULL, vantage TEXT NOT NULL DEFAULT '',
 endpoint_id INTEGER REFERENCES auth_endpoints(id), occurred_at INTEGER, recorded_at INTEGER NOT NULL,
 actor TEXT NOT NULL, source TEXT NOT NULL, run_id INTEGER REFERENCES runs(id),
 association_reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX access_observations_identity ON access_observations(cred_id,host_id,protocol,id);
CREATE VIEW credential_pairs AS
 SELECT c.id cred_id,c.domain||CASE WHEN c.domain='' THEN '' ELSE '\' END||c.username identity,c.secret_type,
 e.id endpoint_id,e.target_id,e.protocol,e.vantage,e.generation,e.changed_at,t.kind,t.ref_id,t.host_id,t.label,
 CASE WHEN x.decision IS NOT NULL THEN x.decision WHEN p.scope_kind='all' THEN 'eligible'
 WHEN p.scope_kind='target' AND p.scope_value=t.kind||':'||t.ref_id THEN 'eligible'
 WHEN p.scope_kind='local' AND p.scope_value=h.ip AND t.kind<>'application' THEN 'eligible'
 WHEN p.scope_kind='domain' AND lower(p.scope_value)=lower(e.identity) AND t.kind<>'application' THEN 'eligible'
 WHEN p.scope_kind='target' THEN 'excluded'
 WHEN p.scope_kind='local' AND h.ip IS NOT NULL AND p.scope_value<>h.ip THEN 'excluded'
 WHEN t.kind='application' THEN 'unknown'
 WHEN p.scope_kind='domain' AND e.identity<>'' AND lower(p.scope_value)<>lower(e.identity) THEN 'excluded'
 ELSE 'unknown' END applicability,
 COALESCE(w.state,'pending') state,COALESCE(w.owner,'') owner,
 CASE WHEN COALESCE(w.reason,'')<>'' THEN w.reason WHEN c.added_at>e.changed_at THEN 'new credential revision' ELSE COALESCE((SELECT reason FROM endpoint_history WHERE endpoint_id=e.id ORDER BY id DESC LIMIT 1),'new endpoint') END reason,
 COALESCE(r.result,'') current_result,r.occurred_at current_occurred_at,r.recorded_at current_recorded_at,
 COALESCE(w.id,0) work_id
 FROM creds c JOIN credential_profiles p ON p.cred_id=c.id
 JOIN auth_endpoints e ON e.state='open'
 JOIN credential_support support ON support.secret_type=c.secret_type AND support.protocol=e.protocol
 JOIN target_details t ON t.id=e.target_id LEFT JOIN hosts h ON h.id=t.host_id
 LEFT JOIN check_applicability x ON x.cred_id=c.id AND x.endpoint_id=e.id
 LEFT JOIN check_work w ON w.cred_id=c.id AND w.endpoint_id=e.id AND w.generation=e.generation
 LEFT JOIN check_results r ON r.id=w.current_result_id
 WHERE p.retired=0 AND (p.protocols='[]' OR e.protocol IN (SELECT value FROM json_each(p.protocols)));

INSERT INTO access_observations(cred_id,host_id,protocol,result,recorded_at,actor,source,association_reason)
 SELECT cred_id,host_id,protocol,level,observed_at,'migration',source,'legacy host/protocol access; endpoint/time unknown' FROM cred_access;
INSERT OR IGNORE INTO work_targets(service_id) SELECT id FROM services;
INSERT OR IGNORE INTO work_targets(application_id) SELECT id FROM applications;
INSERT INTO auth_endpoints(target_id,protocol,vantage,identity,state,changed_at)
 SELECT t.id,CASE s.port WHEN 22 THEN 'ssh' WHEN 139 THEN 'smb' WHEN 445 THEN 'smb' WHEN 3389 THEN 'rdp' WHEN 5985 THEN 'winrm' WHEN 5986 THEN 'winrm' WHEN 389 THEN 'ldap' WHEN 636 THEN 'ldap' WHEN 3268 THEN 'ldap' WHEN 3269 THEN 'ldap' WHEN 1433 THEN 'mssql' WHEN 88 THEN 'kerberos' WHEN 21 THEN 'ftp' WHEN 3306 THEN 'mysql' WHEN 5432 THEN 'postgres' ELSE '' END,COALESCE(v.vantage,''),lower(COALESCE(h.domain,'')),COALESCE(v.state,s.state),CAST(unixepoch('subsec')*1000 AS INTEGER)
 FROM services s JOIN hosts h ON h.id=s.host_id JOIN work_targets t ON t.service_id=s.id
 LEFT JOIN service_views v ON v.host_id=s.host_id AND v.proto=s.proto AND v.port=s.port
 WHERE (CASE s.port WHEN 22 THEN 'ssh' WHEN 139 THEN 'smb' WHEN 445 THEN 'smb' WHEN 3389 THEN 'rdp' WHEN 5985 THEN 'winrm' WHEN 5986 THEN 'winrm' WHEN 389 THEN 'ldap' WHEN 636 THEN 'ldap' WHEN 3268 THEN 'ldap' WHEN 3269 THEN 'ldap' WHEN 1433 THEN 'mssql' WHEN 88 THEN 'kerberos' WHEN 21 THEN 'ftp' WHEN 3306 THEN 'mysql' WHEN 5432 THEN 'postgres' ELSE '' END)<>'' AND COALESCE(v.state,s.state) IN ('open','closed') AND (s.proto='tcp' OR (s.proto='udp' AND s.port=88));
INSERT INTO auth_endpoints(target_id,protocol,vantage,identity,state,changed_at)
 SELECT t.id,'web','',a.origin||'|'||a.realm,CASE WHEN a.retired THEN 'closed' ELSE 'open' END,CAST(unixepoch('subsec')*1000 AS INTEGER)
 FROM applications a JOIN work_targets t ON t.application_id=a.id;
INSERT INTO endpoint_history(endpoint_id,generation,state,identity,reason,recorded_at)
 SELECT id,generation,state,identity,'legacy endpoint inventory; prior authentication history unknown',changed_at FROM auth_endpoints;

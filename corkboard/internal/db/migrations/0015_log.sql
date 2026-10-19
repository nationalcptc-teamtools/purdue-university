ALTER TABLE notes ADD COLUMN service_id INTEGER REFERENCES services(id) ON DELETE SET NULL;
ALTER TABLE notes ADD COLUMN outcome TEXT NOT NULL DEFAULT '';
ALTER TABLE notes ADD COLUMN command TEXT NOT NULL DEFAULT '';
ALTER TABLE notes ADD COLUMN output TEXT NOT NULL DEFAULT '';
CREATE INDEX notes_host_service ON notes(host_id, service_id, created_at);

INSERT INTO notes(host_id, service_id, author, body, outcome, command, output, created_at)
 SELECT t.host_id, CASE WHEN t.kind = 'service' THEN t.ref_id END, a.actor,
  a.title
   || CASE WHEN a.next_action <> '' THEN char(10) || 'Next: ' || a.next_action ELSE '' END
   || CASE WHEN a.recipient <> '' THEN char(10) || 'Handed to ' || a.recipient ELSE '' END,
  CASE a.outcome WHEN 'successful' THEN 'worked' WHEN 'unsuccessful' THEN 'failed' ELSE '' END,
  a.command, a.result, COALESCE(a.occurred_at, a.recorded_at)
 FROM attempts a JOIN target_details t ON t.id = a.target_id
 WHERE t.host_id IS NOT NULL
 ORDER BY a.id;
DELETE FROM attempt_evidence WHERE attempt_id IN
 (SELECT a.id FROM attempts a JOIN target_details t ON t.id = a.target_id WHERE t.host_id IS NOT NULL);
DELETE FROM attempts WHERE id IN
 (SELECT a.id FROM attempts a JOIN target_details t ON t.id = a.target_id WHERE t.host_id IS NOT NULL);

DROP VIEW search_documents;
CREATE VIEW search_documents AS
 SELECT 'host' kind,CAST(h.id AS TEXT) id,h.ip title,
 COALESCE(h.os,'')||' '||COALESCE(h.domain,'')||' '||COALESCE((SELECT group_concat(name,' ') FROM hostnames WHERE host_id=h.id),'')||' '||COALESCE((SELECT group_concat(tag,' ') FROM host_tags WHERE host_id=h.id),'') body,
 '/hosts/'||h.ip link,h.ip asset FROM hosts h
 UNION ALL SELECT 'service',CAST(s.id AS TEXT),h.ip||':'||s.port||'/'||s.proto,
 COALESCE(s.name,'')||' '||COALESCE(s.product,'')||' '||COALESCE(s.version,'')||' '||s.state,'/hosts/'||h.ip||'#svc-'||s.id,h.ip FROM services s JOIN hosts h ON h.id=s.host_id
 UNION ALL SELECT 'script',x.host_id||':'||COALESCE(x.service_id,0)||':'||x.script_id,x.script_id,x.output,'/hosts/'||h.ip,h.ip FROM service_scripts x JOIN hosts h ON h.id=x.host_id
 UNION ALL SELECT 'note',CAST(n.id AS TEXT),'Log by '||n.author,n.body||' '||n.command||' '||n.output,'/hosts/'||h.ip||'#log',h.ip FROM notes n JOIN hosts h ON h.id=n.host_id
 UNION ALL SELECT 'task',CAST(k.id AS TEXT),k.title,k.body||' '||k.commands||' '||COALESCE(k.closed_note,''),COALESCE('/hosts/'||h.ip||'#tasks','/tasks'),COALESCE(h.ip,'') FROM tasks k LEFT JOIN hosts h ON h.id=k.host_id
 UNION ALL SELECT 'finding',CAST(f.id AS TEXT),f.title,f.description||' '||COALESCE((SELECT group_concat(evidence,' ') FROM finding_assets WHERE finding_id=f.id),'')||' '||COALESCE((SELECT group_concat(evidence,' ') FROM finding_hosts WHERE finding_id=f.id),''),'/findings/'||f.id,substr(COALESCE((SELECT group_concat(DISTINCT h.ip) FROM finding_hosts fh JOIN hosts h ON h.id=fh.host_id WHERE fh.finding_id=f.id),''),1,160) FROM findings f WHERE f.merged_into IS NULL
 UNION ALL SELECT 'evidence',CAST(e.id AS TEXT),COALESCE(NULLIF(e.caption,''),'Evidence #'||e.id),e.external_ref,'/evidence/'||e.id,'' FROM evidence e
 UNION ALL SELECT 'application',CAST(a.id AS TEXT),a.origin,a.realm,COALESCE('/hosts/'||h.ip,'/web'),COALESCE(h.ip,'') FROM applications a LEFT JOIN hosts h ON h.id=a.host_id
 UNION ALL SELECT 'credential',CAST(c.id AS TEXT),c.domain||CASE WHEN c.domain='' THEN '' ELSE '\' END||c.username,c.source,'/creds#cred-'||c.id,'' FROM creds c;

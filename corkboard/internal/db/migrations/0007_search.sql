CREATE VIEW search_documents AS
 SELECT 'host' kind,CAST(h.id AS TEXT) id,h.ip title,
 COALESCE(h.os,'')||' '||COALESCE(h.domain,'')||' '||COALESCE((SELECT group_concat(name,' ') FROM hostnames WHERE host_id=h.id),'')||' '||COALESCE((SELECT group_concat(tag,' ') FROM host_tags WHERE host_id=h.id),'') body,
 '/hosts/'||h.ip link,h.ip asset FROM hosts h
 UNION ALL SELECT 'service',CAST(s.id AS TEXT),h.ip||':'||s.port||'/'||s.proto,
 COALESCE(s.name,'')||' '||COALESCE(s.product,'')||' '||COALESCE(s.version,'')||' '||s.state,'/work?target=service:'||s.id,h.ip FROM services s JOIN hosts h ON h.id=s.host_id
 UNION ALL SELECT 'script',x.host_id||':'||COALESCE(x.service_id,0)||':'||x.script_id,x.script_id,x.output,'/hosts/'||h.ip,h.ip FROM service_scripts x JOIN hosts h ON h.id=x.host_id
 UNION ALL SELECT 'note',CAST(n.id AS TEXT),'Note by '||n.author,n.body,'/hosts/'||h.ip,h.ip FROM notes n JOIN hosts h ON h.id=n.host_id
 UNION ALL SELECT 'attempt',CAST(a.id AS TEXT),a.title,a.command||' '||a.result||' '||a.next_action||' '||a.recipient||' '||a.outcome,
 '/work?target='||t.kind||':'||t.ref_id||'#attempt-'||a.id,t.label FROM attempts a JOIN target_details t ON t.id=a.target_id
 UNION ALL SELECT 'task',CAST(k.id AS TEXT),k.title,k.body||' '||k.commands||' '||COALESCE(k.closed_note,''),'/work?target=task:'||k.id,COALESCE(h.ip,'') FROM tasks k LEFT JOIN hosts h ON h.id=k.host_id
 UNION ALL SELECT 'finding',CAST(f.id AS TEXT),f.title,f.description||' '||COALESCE((SELECT group_concat(evidence,' ') FROM finding_assets WHERE finding_id=f.id),'')||' '||COALESCE((SELECT group_concat(evidence,' ') FROM finding_hosts WHERE finding_id=f.id),''),'/findings/'||f.id,substr(COALESCE((SELECT group_concat(DISTINCT h.ip) FROM finding_hosts fh JOIN hosts h ON h.id=fh.host_id WHERE fh.finding_id=f.id),''),1,160) FROM findings f WHERE f.merged_into IS NULL
 UNION ALL SELECT 'evidence',CAST(e.id AS TEXT),COALESCE(NULLIF(e.caption,''),'Evidence #'||e.id),e.external_ref,'/evidence/'||e.id,'' FROM evidence e
 UNION ALL SELECT 'application',CAST(a.id AS TEXT),a.origin,a.realm,'/work?target=application:'||a.id,COALESCE(h.ip,'') FROM applications a LEFT JOIN hosts h ON h.id=a.host_id
 UNION ALL SELECT 'credential',CAST(c.id AS TEXT),c.domain||CASE WHEN c.domain='' THEN '' ELSE '\' END||c.username,c.source,'/creds#cred-'||c.id,'' FROM creds c;

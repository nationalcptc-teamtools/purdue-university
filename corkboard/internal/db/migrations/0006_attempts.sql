CREATE TABLE attempts (
 id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL REFERENCES work_targets(id),
 title TEXT NOT NULL, command TEXT NOT NULL DEFAULT '', outcome TEXT NOT NULL CHECK(outcome IN ('successful','unsuccessful','inconclusive','blocked')),
 result TEXT NOT NULL DEFAULT '', next_action TEXT NOT NULL DEFAULT '', recipient TEXT NOT NULL DEFAULT '',
 cred_id INTEGER REFERENCES creds(id), vantage TEXT NOT NULL DEFAULT '', actor TEXT NOT NULL,
 occurred_at INTEGER, recorded_at INTEGER NOT NULL, corrects INTEGER UNIQUE REFERENCES attempts(id), correction_reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX attempts_target ON attempts(target_id,id);
CREATE TABLE attempt_evidence (
 attempt_id INTEGER NOT NULL REFERENCES attempts(id), evidence_id INTEGER NOT NULL REFERENCES evidence(id),
 PRIMARY KEY(attempt_id,evidence_id)
);
CREATE INDEX events_host_actor_at ON events(host_id,actor,at);

CREATE TABLE target_claims (
 target_id INTEGER PRIMARY KEY REFERENCES work_targets(id),
 owner TEXT NOT NULL, claimed_at INTEGER NOT NULL
);
CREATE INDEX target_claims_owner ON target_claims(owner);

CREATE TABLE IF NOT EXISTS application_policies (
 namespace TEXT NOT NULL,
 id TEXT NOT NULL CHECK (id='application_access'),
 revision INTEGER NOT NULL CHECK (revision > 0),
 policy_json TEXT NOT NULL,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 PRIMARY KEY(namespace,id)
);
PRAGMA user_version=6;

CREATE TABLE IF NOT EXISTS consent_records (
 namespace TEXT NOT NULL, id TEXT NOT NULL, client_id TEXT NOT NULL, client_name TEXT NOT NULL,
 session_id TEXT NOT NULL, scope_json TEXT NOT NULL, modes_json TEXT NOT NULL, purpose TEXT NOT NULL,
 duration_seconds INTEGER NOT NULL, created_at INTEGER NOT NULL, request_expires_at INTEGER NOT NULL,
 request_state TEXT NOT NULL, decision TEXT NOT NULL, grant_id TEXT NOT NULL, grant_created_at INTEGER NOT NULL,
 grant_expires_at INTEGER NOT NULL, grant_state TEXT NOT NULL, revocation_state TEXT NOT NULL,
 revision INTEGER NOT NULL, PRIMARY KEY(namespace,id), UNIQUE(namespace,grant_id)
);
CREATE TABLE IF NOT EXISTS consent_audit (
 namespace TEXT NOT NULL, id TEXT NOT NULL, request_id TEXT NOT NULL, kind TEXT NOT NULL,
 actor_id TEXT NOT NULL, created_at INTEGER NOT NULL, payload_json TEXT NOT NULL,
 PRIMARY KEY(namespace,id), FOREIGN KEY(namespace,request_id) REFERENCES consent_records(namespace,id)
);
PRAGMA user_version=3;

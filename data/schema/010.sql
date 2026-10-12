CREATE TABLE IF NOT EXISTS credential_delivery_attempts (
 namespace TEXT NOT NULL, client_id TEXT NOT NULL, session_id TEXT NOT NULL,
 attempt_id TEXT NOT NULL CHECK(length(attempt_id)=64 AND attempt_id NOT GLOB '*[^0-9a-f]*'),
 selection_id TEXT NOT NULL CHECK(length(selection_id)=64 AND selection_id NOT GLOB '*[^0-9a-f]*'),
 selected_revision TEXT NOT NULL CHECK(length(selected_revision)=64 AND selected_revision NOT GLOB '*[^0-9a-f]*'),
 grant_id TEXT NOT NULL, origin TEXT NOT NULL,
 profile_channel TEXT NOT NULL, browser_instance TEXT NOT NULL,
 document_id TEXT NOT NULL, document_generation INTEGER NOT NULL CHECK(document_generation>0),
 tab_id INTEGER NOT NULL CHECK(tab_id>0),
 broker_epoch TEXT NOT NULL, channel_epoch TEXT NOT NULL, scope_hash TEXT NOT NULL,
 renderer_lease_id TEXT NOT NULL, renderer_lease_generation INTEGER NOT NULL CHECK(renderer_lease_generation>0),
 chrome_start_token TEXT NOT NULL, native_host_start_token TEXT NOT NULL,
 dispatch_state TEXT NOT NULL CHECK(dispatch_state IN ('unknown','dispatched','notDispatched')),
 protection_state TEXT NOT NULL CHECK(protection_state IN ('held','closed')),
 revision INTEGER NOT NULL CHECK(revision>0), created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 PRIMARY KEY(namespace,client_id,attempt_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS credential_delivery_active_owner ON credential_delivery_attempts(namespace) WHERE protection_state='held' OR dispatch_state='unknown';
CREATE TABLE IF NOT EXISTS credential_delivery_audit (
 namespace TEXT NOT NULL, client_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision>0), dispatch_state TEXT NOT NULL,
 protection_state TEXT NOT NULL, created_at TEXT NOT NULL,
 PRIMARY KEY(namespace,client_id,attempt_id,revision),
 FOREIGN KEY(namespace,client_id,attempt_id) REFERENCES credential_delivery_attempts(namespace,client_id,attempt_id)
);
PRAGMA user_version=10;

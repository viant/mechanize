-- Preserve dispatch knowledge and every audit; retire only protection after verified process exit.
DROP TRIGGER credential_delivery_siblings_keep_lineage;
DROP TRIGGER credential_preparation_excludes_active_child;
DROP TRIGGER credential_delivery_requires_exact_preparation;
DROP TRIGGER credential_preparation_close_only;
DROP TRIGGER credential_delivery_close_keeps_dispatch;
CREATE TEMP TABLE credential_delivery_audit_copy AS SELECT * FROM credential_delivery_audit;
DROP TABLE credential_delivery_audit;
CREATE TABLE credential_delivery_attempts_next (
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
 protection_state TEXT NOT NULL CHECK(protection_state IN ('held','closed','retired')),
 revision INTEGER NOT NULL CHECK(revision>0), created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 purpose_hash TEXT,
 PRIMARY KEY(namespace,client_id,attempt_id)
);
INSERT INTO credential_delivery_attempts_next SELECT * FROM credential_delivery_attempts;
DROP TABLE credential_delivery_attempts;
ALTER TABLE credential_delivery_attempts_next RENAME TO credential_delivery_attempts;
CREATE TABLE IF NOT EXISTS credential_delivery_audit (
 namespace TEXT NOT NULL, client_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision>0), dispatch_state TEXT NOT NULL,
 protection_state TEXT NOT NULL, created_at TEXT NOT NULL,
 PRIMARY KEY(namespace,client_id,attempt_id,revision),
 FOREIGN KEY(namespace,client_id,attempt_id) REFERENCES credential_delivery_attempts(namespace,client_id,attempt_id)
);
INSERT INTO credential_delivery_audit SELECT * FROM credential_delivery_audit_copy;
DROP TABLE credential_delivery_audit_copy;
CREATE TRIGGER IF NOT EXISTS credential_delivery_siblings_keep_lineage
BEFORE INSERT ON credential_delivery_attempts
WHEN EXISTS(SELECT 1 FROM credential_delivery_attempts a WHERE a.namespace=NEW.namespace
 AND (a.protection_state='held' OR (a.dispatch_state='unknown' AND a.protection_state<>'retired')) AND ((a.dispatch_state='unknown' AND a.protection_state<>'retired') OR (
 a.client_id<>NEW.client_id OR a.session_id<>NEW.session_id OR a.selection_id<>NEW.selection_id
 OR a.selected_revision<>NEW.selected_revision OR a.grant_id<>NEW.grant_id
 OR a.purpose_hash IS NULL OR a.purpose_hash<>NEW.purpose_hash OR a.origin<>NEW.origin
 OR a.profile_channel<>NEW.profile_channel OR a.browser_instance<>NEW.browser_instance
 OR a.tab_id<>NEW.tab_id OR a.broker_epoch<>NEW.broker_epoch OR a.channel_epoch<>NEW.channel_epoch
 OR a.scope_hash<>NEW.scope_hash OR a.chrome_start_token<>NEW.chrome_start_token
 OR a.native_host_start_token<>NEW.native_host_start_token)))
BEGIN SELECT RAISE(ABORT,'private delivery lineage mismatch'); END;
CREATE TRIGGER credential_preparation_excludes_active_child BEFORE INSERT ON credential_delivery_preparations
WHEN NEW.protection_state<>'held' OR NEW.revision<>1 OR EXISTS(SELECT 1 FROM credential_delivery_attempts a WHERE a.namespace=NEW.namespace AND (a.protection_state='held' OR (a.dispatch_state='unknown' AND a.protection_state<>'retired')))
BEGIN SELECT RAISE(ABORT,'private preparation conflicts with unresolved delivery'); END;
CREATE TRIGGER credential_delivery_requires_exact_preparation BEFORE INSERT ON credential_delivery_attempts
WHEN NOT EXISTS(SELECT 1 FROM credential_delivery_preparations p WHERE p.namespace=NEW.namespace AND p.client_id=NEW.client_id AND p.session_id=NEW.session_id AND p.preparation_id=NEW.selection_id AND p.grant_id=NEW.grant_id AND p.purpose_hash=NEW.purpose_hash AND p.origin=NEW.origin AND p.selected_revision=NEW.selected_revision AND p.protection_state='held')
BEGIN SELECT RAISE(ABORT,'private delivery preparation mismatch'); END;
CREATE TRIGGER credential_preparation_close_only BEFORE UPDATE ON credential_delivery_preparations
WHEN OLD.protection_state<>'held' OR NEW.protection_state<>'closed' OR NEW.revision<>OLD.revision+1
 OR NEW.namespace<>OLD.namespace OR NEW.client_id<>OLD.client_id OR NEW.session_id<>OLD.session_id OR NEW.preparation_id<>OLD.preparation_id OR NEW.grant_id<>OLD.grant_id OR NEW.purpose_hash<>OLD.purpose_hash OR NEW.origin<>OLD.origin OR NEW.selected_revision<>OLD.selected_revision OR NEW.created_at<>OLD.created_at
 OR EXISTS(SELECT 1 FROM credential_delivery_attempts a WHERE a.namespace=OLD.namespace AND a.selection_id=OLD.preparation_id AND (a.protection_state='held' OR (a.dispatch_state='unknown' AND a.protection_state<>'retired')))
BEGIN SELECT RAISE(ABORT,'private preparation cleanup is unconfirmed'); END;
CREATE TRIGGER credential_delivery_close_keeps_dispatch BEFORE UPDATE ON credential_delivery_attempts
WHEN NEW.protection_state='closed' AND (OLD.protection_state<>'held' OR OLD.dispatch_state='unknown' OR NEW.dispatch_state<>OLD.dispatch_state OR NEW.revision<>OLD.revision+1)
BEGIN SELECT RAISE(ABORT,'private cleanup cannot resolve or rewrite input'); END;
CREATE TRIGGER credential_delivery_retire_keeps_unknown BEFORE UPDATE ON credential_delivery_attempts
WHEN NEW.protection_state='retired' AND (OLD.protection_state<>'held' OR OLD.dispatch_state<>'unknown' OR NEW.dispatch_state<>'unknown' OR NEW.revision<>OLD.revision+1)
BEGIN SELECT RAISE(ABORT,'private retirement cannot resolve or rewrite input'); END;
PRAGMA user_version=14;

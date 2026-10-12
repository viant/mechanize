-- Old schema010 rows have no authenticated purpose hash. NULL is retained as
-- unknown legacy metadata; new private writes require a complete correlated prep.
ALTER TABLE credential_delivery_attempts ADD COLUMN purpose_hash TEXT;
CREATE TABLE IF NOT EXISTS credential_delivery_preparations (
 namespace TEXT NOT NULL, client_id TEXT NOT NULL, session_id TEXT NOT NULL,
 preparation_id TEXT NOT NULL CHECK(length(preparation_id)=64 AND preparation_id NOT GLOB '*[^0-9a-f]*'),
 grant_id TEXT NOT NULL,
 purpose_hash TEXT NOT NULL CHECK(length(purpose_hash)=64 AND purpose_hash NOT GLOB '*[^0-9a-f]*'),
 origin TEXT NOT NULL,
 selected_revision TEXT NOT NULL CHECK(length(selected_revision)=64 AND selected_revision NOT GLOB '*[^0-9a-f]*'),
 protection_state TEXT NOT NULL CHECK(protection_state='held'),
 revision INTEGER NOT NULL CHECK(revision=1), created_at TEXT NOT NULL,
 PRIMARY KEY(namespace,client_id,preparation_id), UNIQUE(namespace)
);
CREATE TRIGGER IF NOT EXISTS credential_preparation_excludes_active_child
BEFORE INSERT ON credential_delivery_preparations
WHEN EXISTS(SELECT 1 FROM credential_delivery_attempts a WHERE a.namespace=NEW.namespace AND (a.protection_state='held' OR a.dispatch_state='unknown'))
BEGIN SELECT RAISE(ABORT,'private preparation conflicts with unresolved delivery'); END;
CREATE TRIGGER IF NOT EXISTS credential_delivery_requires_exact_preparation
BEFORE INSERT ON credential_delivery_attempts
WHEN NOT EXISTS(SELECT 1 FROM credential_delivery_preparations p WHERE
 p.namespace=NEW.namespace AND p.client_id=NEW.client_id AND p.session_id=NEW.session_id
 AND p.preparation_id=NEW.selection_id AND p.grant_id=NEW.grant_id
 AND p.purpose_hash=NEW.purpose_hash AND p.origin=NEW.origin
 AND p.selected_revision=NEW.selected_revision AND p.protection_state='held')
BEGIN SELECT RAISE(ABORT,'private delivery preparation mismatch'); END;
PRAGMA user_version=11;

DROP TRIGGER credential_preparation_excludes_active_child;
DROP TRIGGER credential_delivery_requires_exact_preparation;
CREATE TABLE credential_delivery_preparations_next (
 namespace TEXT NOT NULL,client_id TEXT NOT NULL,session_id TEXT NOT NULL,
 preparation_id TEXT NOT NULL CHECK(length(preparation_id)=64 AND preparation_id NOT GLOB '*[^0-9a-f]*'),
 grant_id TEXT NOT NULL,purpose_hash TEXT NOT NULL CHECK(length(purpose_hash)=64 AND purpose_hash NOT GLOB '*[^0-9a-f]*'),
 origin TEXT NOT NULL,selected_revision TEXT NOT NULL CHECK(length(selected_revision)=64 AND selected_revision NOT GLOB '*[^0-9a-f]*'),
 protection_state TEXT NOT NULL CHECK(protection_state IN ('held','closed')),
 revision INTEGER NOT NULL CHECK((protection_state='held' AND revision=1) OR (protection_state='closed' AND revision=2)),created_at TEXT NOT NULL,
 PRIMARY KEY(namespace,client_id,preparation_id)
);
INSERT INTO credential_delivery_preparations_next SELECT * FROM credential_delivery_preparations;
DROP TABLE credential_delivery_preparations;
ALTER TABLE credential_delivery_preparations_next RENAME TO credential_delivery_preparations;
CREATE UNIQUE INDEX credential_preparation_active_namespace ON credential_delivery_preparations(namespace) WHERE protection_state='held';
CREATE TABLE credential_preparation_audit (
 namespace TEXT NOT NULL,client_id TEXT NOT NULL,preparation_id TEXT NOT NULL,revision INTEGER NOT NULL,protection_state TEXT NOT NULL,
 PRIMARY KEY(namespace,client_id,preparation_id,revision),FOREIGN KEY(namespace,client_id,preparation_id) REFERENCES credential_delivery_preparations(namespace,client_id,preparation_id)
);
INSERT INTO credential_preparation_audit SELECT namespace,client_id,preparation_id,revision,protection_state FROM credential_delivery_preparations;
CREATE TRIGGER credential_preparation_excludes_active_child BEFORE INSERT ON credential_delivery_preparations
WHEN NEW.protection_state<>'held' OR NEW.revision<>1 OR EXISTS(SELECT 1 FROM credential_delivery_attempts a WHERE a.namespace=NEW.namespace AND (a.protection_state='held' OR a.dispatch_state='unknown'))
BEGIN SELECT RAISE(ABORT,'private preparation conflicts with unresolved delivery'); END;
CREATE TRIGGER credential_delivery_requires_exact_preparation BEFORE INSERT ON credential_delivery_attempts
WHEN NOT EXISTS(SELECT 1 FROM credential_delivery_preparations p WHERE p.namespace=NEW.namespace AND p.client_id=NEW.client_id AND p.session_id=NEW.session_id AND p.preparation_id=NEW.selection_id AND p.grant_id=NEW.grant_id AND p.purpose_hash=NEW.purpose_hash AND p.origin=NEW.origin AND p.selected_revision=NEW.selected_revision AND p.protection_state='held')
BEGIN SELECT RAISE(ABORT,'private delivery preparation mismatch'); END;
CREATE TRIGGER credential_preparation_close_only BEFORE UPDATE ON credential_delivery_preparations
WHEN OLD.protection_state<>'held' OR NEW.protection_state<>'closed' OR NEW.revision<>OLD.revision+1
 OR NEW.namespace<>OLD.namespace OR NEW.client_id<>OLD.client_id OR NEW.session_id<>OLD.session_id OR NEW.preparation_id<>OLD.preparation_id OR NEW.grant_id<>OLD.grant_id OR NEW.purpose_hash<>OLD.purpose_hash OR NEW.origin<>OLD.origin OR NEW.selected_revision<>OLD.selected_revision OR NEW.created_at<>OLD.created_at
 OR EXISTS(SELECT 1 FROM credential_delivery_attempts a WHERE a.namespace=OLD.namespace AND a.selection_id=OLD.preparation_id AND (a.protection_state='held' OR a.dispatch_state='unknown'))
BEGIN SELECT RAISE(ABORT,'private preparation cleanup is unconfirmed'); END;
CREATE TRIGGER credential_preparation_audit_insert AFTER INSERT ON credential_delivery_preparations
BEGIN INSERT INTO credential_preparation_audit VALUES(NEW.namespace,NEW.client_id,NEW.preparation_id,NEW.revision,NEW.protection_state); END;
CREATE TRIGGER credential_preparation_audit_close AFTER UPDATE ON credential_delivery_preparations
BEGIN INSERT INTO credential_preparation_audit VALUES(NEW.namespace,NEW.client_id,NEW.preparation_id,NEW.revision,NEW.protection_state); END;
CREATE TRIGGER credential_delivery_close_keeps_dispatch BEFORE UPDATE ON credential_delivery_attempts
WHEN NEW.protection_state='closed' AND (OLD.protection_state<>'held' OR OLD.dispatch_state='unknown' OR NEW.dispatch_state<>OLD.dispatch_state OR NEW.revision<>OLD.revision+1)
BEGIN SELECT RAISE(ABORT,'private cleanup cannot resolve or rewrite input'); END;
PRAGMA user_version=13;

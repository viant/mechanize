CREATE TABLE IF NOT EXISTS credential_protection_scopes (
 namespace TEXT NOT NULL, client_id TEXT NOT NULL,
 preparation_id TEXT NOT NULL CHECK(length(preparation_id)=64 AND preparation_id NOT GLOB '*[^0-9a-f]*'),
 origin TEXT NOT NULL, profile_channel TEXT NOT NULL, browser_instance TEXT NOT NULL,
 tab_id INTEGER NOT NULL CHECK(tab_id>0), frame_id INTEGER NOT NULL CHECK(frame_id=0),
 document_id TEXT NOT NULL, document_generation INTEGER NOT NULL CHECK(document_generation>0),
 chrome_start_token TEXT NOT NULL, broker_epoch TEXT NOT NULL, channel_epoch TEXT NOT NULL,
 scope_hash TEXT NOT NULL CHECK(length(scope_hash)=64 AND scope_hash NOT GLOB '*[^0-9a-f]*'),
 login_route_sha256 TEXT NOT NULL CHECK(length(login_route_sha256)=64 AND login_route_sha256 NOT GLOB '*[^0-9a-f]*'),
 created_at TEXT NOT NULL,
 PRIMARY KEY(namespace,client_id,preparation_id), UNIQUE(namespace,preparation_id),
 FOREIGN KEY(namespace,client_id,preparation_id) REFERENCES credential_delivery_preparations(namespace,client_id,preparation_id)
);
CREATE TRIGGER IF NOT EXISTS credential_protection_scope_requires_preparation BEFORE INSERT ON credential_protection_scopes
WHEN NOT EXISTS(SELECT 1 FROM credential_delivery_preparations p WHERE p.namespace=NEW.namespace AND p.client_id=NEW.client_id AND p.preparation_id=NEW.preparation_id AND p.origin=NEW.origin AND p.protection_state='held')
BEGIN SELECT RAISE(ABORT,'private source requires held preparation'); END;
CREATE TRIGGER IF NOT EXISTS credential_protection_scope_immutable_update BEFORE UPDATE ON credential_protection_scopes
BEGIN SELECT RAISE(ABORT,'private source scope is immutable'); END;
CREATE TRIGGER IF NOT EXISTS credential_protection_scope_immutable_delete BEFORE DELETE ON credential_protection_scopes
BEGIN SELECT RAISE(ABORT,'private source history is retained'); END;
PRAGMA user_version=15;

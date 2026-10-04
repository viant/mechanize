CREATE TABLE IF NOT EXISTS chrome_retirements (
 namespace TEXT NOT NULL,
 id TEXT NOT NULL,
 client_id TEXT NOT NULL,
 request_id TEXT NOT NULL,
 profile_channel TEXT NOT NULL,
 browser_instance TEXT NOT NULL,
 trust_scope TEXT NOT NULL CHECK (trust_scope IN ('profile','desktop')),
 old_broker_epoch TEXT NOT NULL,
 old_channel_epoch TEXT NOT NULL,
 old_scope_hash TEXT NOT NULL,
 process_evidence_json TEXT NOT NULL,
 policy_evidence_json TEXT NOT NULL,
 evidence_digest TEXT NOT NULL CHECK (length(evidence_digest)=64 AND evidence_digest NOT GLOB '*[^0-9a-f]*'),
 phase TEXT NOT NULL CHECK (phase IN ('intended','prepared','released','adopted')),
 revision INTEGER NOT NULL CHECK (revision > 0),
 manifest_digest TEXT CHECK (manifest_digest IS NULL OR (length(manifest_digest)=64 AND manifest_digest NOT GLOB '*[^0-9a-f]*')),
 manifest_count INTEGER CHECK (manifest_count IS NULL OR manifest_count BETWEEN 0 AND 64),
 receipt_count INTEGER CHECK (receipt_count IS NULL OR receipt_count BETWEEN 0 AND 4096),
 adoption_evidence_json TEXT,
 adoption_digest TEXT CHECK (adoption_digest IS NULL OR (length(adoption_digest)=64 AND adoption_digest NOT GLOB '*[^0-9a-f]*')),
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 PRIMARY KEY(namespace,id),
 UNIQUE(namespace,client_id,profile_channel,browser_instance,request_id),
 UNIQUE(namespace,old_broker_epoch,old_channel_epoch,old_scope_hash),
 CHECK ((phase='intended' AND manifest_digest IS NULL AND manifest_count IS NULL AND receipt_count IS NULL)
     OR (phase!='intended' AND manifest_digest IS NOT NULL AND manifest_count IS NOT NULL AND receipt_count IS NOT NULL)),
 CHECK ((phase='adopted' AND adoption_evidence_json IS NOT NULL AND adoption_digest IS NOT NULL)
     OR (phase!='adopted' AND adoption_evidence_json IS NULL AND adoption_digest IS NULL))
);

CREATE TABLE IF NOT EXISTS chrome_retirement_manifests (
 namespace TEXT NOT NULL,
 transition_id TEXT NOT NULL,
 id TEXT NOT NULL,
 document_identity_json TEXT NOT NULL,
 receipt_revision INTEGER NOT NULL CHECK (receipt_revision >= 0),
 receipt_count INTEGER NOT NULL CHECK (receipt_count BETWEEN 0 AND 512),
 canonical_manifest_json TEXT NOT NULL CHECK (length(CAST(canonical_manifest_json AS BLOB)) <= 262144),
 manifest_digest TEXT NOT NULL CHECK (length(manifest_digest)=64 AND manifest_digest NOT GLOB '*[^0-9a-f]*'),
 created_at TEXT NOT NULL,
 PRIMARY KEY(namespace,transition_id,id),
 UNIQUE(namespace,transition_id,document_identity_json),
 FOREIGN KEY(namespace,transition_id) REFERENCES chrome_retirements(namespace,id)
);

CREATE TABLE IF NOT EXISTS chrome_retirement_audit (
 namespace TEXT NOT NULL,
 id TEXT NOT NULL,
 transition_id TEXT NOT NULL,
 phase TEXT NOT NULL CHECK (phase IN ('intended','prepared','released','adopted')),
 prior_revision INTEGER NOT NULL CHECK (prior_revision >= 0),
 sequence INTEGER NOT NULL CHECK (sequence > 0),
 request_id TEXT NOT NULL,
 payload_json TEXT NOT NULL CHECK (length(CAST(payload_json AS BLOB)) <= 262144),
 created_at TEXT NOT NULL,
 PRIMARY KEY(namespace,id),
 UNIQUE(namespace,transition_id,sequence),
 UNIQUE(namespace,transition_id,phase),
 FOREIGN KEY(namespace,transition_id) REFERENCES chrome_retirements(namespace,id)
);
PRAGMA user_version=7;

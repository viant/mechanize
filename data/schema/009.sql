-- Legacy review data schema retained for existing databases. Active video-analysis components now belong to Videoz.
CREATE TABLE IF NOT EXISTS workflow_review_requests (
 namespace TEXT NOT NULL,
 client_id TEXT NOT NULL CHECK(length(client_id) BETWEEN 0 AND 256),
 request_id TEXT NOT NULL CHECK(length(request_id) BETWEEN 1 AND 256),
 request_hash TEXT NOT NULL CHECK(length(request_hash)=64 AND request_hash NOT GLOB '*[^0-9a-f]*'),
 operation TEXT NOT NULL CHECK(operation IN ('begin','propose')),
 result_id TEXT NOT NULL CHECK(length(result_id)=32 AND result_id NOT GLOB '*[^0-9a-f]*'),
 key_reference TEXT NOT NULL CHECK(length(key_reference) BETWEEN 1 AND 256),
 state TEXT NOT NULL CHECK(state IN ('pending','published')),
 revision INTEGER NOT NULL CHECK(revision>0),
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 PRIMARY KEY(namespace,client_id,request_id),
 UNIQUE(namespace,result_id)
);
PRAGMA user_version=9;

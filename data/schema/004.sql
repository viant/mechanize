-- Immutable reusable scenario revisions are separate from durable run plans.
CREATE TABLE IF NOT EXISTS scenario_revisions (
 namespace TEXT NOT NULL, scenario_id TEXT NOT NULL, revision TEXT NOT NULL,
 content_hash TEXT NOT NULL, objective_hash TEXT NOT NULL, content_json TEXT NOT NULL,
 publication_state TEXT NOT NULL CHECK(publication_state = 'draft'), created_at TEXT NOT NULL,
 PRIMARY KEY(namespace,scenario_id,revision)
);
CREATE INDEX IF NOT EXISTS scenario_objective ON scenario_revisions(namespace,objective_hash);
PRAGMA user_version=4;

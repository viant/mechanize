CREATE TABLE IF NOT EXISTS repair_workflow_budgets (
 namespace TEXT NOT NULL,run_id TEXT NOT NULL,revision INTEGER NOT NULL,
 max_repairs INTEGER NOT NULL,used_repairs INTEGER NOT NULL,max_elapsed_ms INTEGER NOT NULL,elapsed_ms INTEGER NOT NULL,
 PRIMARY KEY(namespace,run_id),FOREIGN KEY(namespace,run_id) REFERENCES runs(namespace,id)
);
CREATE TABLE IF NOT EXISTS repair_incident_budgets (
 namespace TEXT NOT NULL,run_id TEXT NOT NULL,id TEXT NOT NULL,revision INTEGER NOT NULL,
 max_repairs INTEGER NOT NULL,used_repairs INTEGER NOT NULL,max_elapsed_ms INTEGER NOT NULL,elapsed_ms INTEGER NOT NULL,
 PRIMARY KEY(namespace,run_id,id),FOREIGN KEY(namespace,run_id) REFERENCES runs(namespace,id)
);
CREATE TABLE IF NOT EXISTS repair_revisions (
 namespace TEXT NOT NULL,id TEXT NOT NULL,run_id TEXT NOT NULL,parent_plan_id TEXT NOT NULL,new_plan_id TEXT NOT NULL,
 parent_content_hash TEXT NOT NULL,parent_plan_hash TEXT NOT NULL,plan_hash TEXT NOT NULL,objective_hash TEXT NOT NULL,
 patch_hash TEXT NOT NULL,evidence_json TEXT NOT NULL,policy_hash TEXT NOT NULL,completed_steps INTEGER NOT NULL,
 incident_id TEXT NOT NULL,run_revision INTEGER NOT NULL,admitted_at TEXT NOT NULL,
 PRIMARY KEY(namespace,id),UNIQUE(namespace,new_plan_id),
 FOREIGN KEY(namespace,run_id) REFERENCES runs(namespace,id),
 FOREIGN KEY(namespace,parent_plan_id) REFERENCES plan_revisions(namespace,id),
 FOREIGN KEY(namespace,new_plan_id) REFERENCES plan_revisions(namespace,id)
);
CREATE TABLE IF NOT EXISTS repair_lineage (
 namespace TEXT NOT NULL,id TEXT NOT NULL,run_id TEXT NOT NULL,repair_id TEXT NOT NULL,new_plan_id TEXT NOT NULL,
 step_id TEXT NOT NULL,step_index INTEGER NOT NULL,original_plan_id TEXT NOT NULL,original_step_id TEXT NOT NULL,
 attempt_id TEXT NOT NULL,effect_id TEXT NOT NULL,business_key TEXT NOT NULL,result_hash TEXT NOT NULL,state TEXT NOT NULL,
 PRIMARY KEY(namespace,id),UNIQUE(namespace,new_plan_id,attempt_id),
 FOREIGN KEY(namespace,repair_id) REFERENCES repair_revisions(namespace,id),
 FOREIGN KEY(namespace,new_plan_id) REFERENCES plan_revisions(namespace,id),
 FOREIGN KEY(namespace,original_plan_id) REFERENCES plan_revisions(namespace,id),
 FOREIGN KEY(namespace,attempt_id) REFERENCES attempts(namespace,id),
 FOREIGN KEY(namespace,effect_id) REFERENCES effects(namespace,id)
);
PRAGMA user_version=5;

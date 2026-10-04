SELECT r.*,p.objective_id FROM runs r JOIN plan_revisions p ON p.namespace=r.namespace AND p.id=r.plan_id WHERE r.namespace=:Namespace AND r.id=:RunID

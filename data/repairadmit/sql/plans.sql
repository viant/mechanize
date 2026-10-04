SELECT * FROM (SELECT r.* FROM plan_revisions r WHERE r.namespace=:Namespace AND r.parent_id=:ParentPlanID
) plans
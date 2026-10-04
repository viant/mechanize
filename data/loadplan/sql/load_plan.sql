SELECT records.* FROM  (SELECT r.* FROM plan_revisions r WHERE r.namespace = :Namespace AND r.id = :PlanID
)  records
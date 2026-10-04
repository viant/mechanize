SELECT records.* FROM  (SELECT r.* FROM scenario_revisions r WHERE r.namespace = :Namespace
)  records
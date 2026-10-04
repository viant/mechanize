SELECT * FROM (SELECT r.* FROM run_variables r WHERE r.namespace=:Namespace
) variables
SELECT * FROM (SELECT r.* FROM attempts r WHERE r.namespace=:Namespace
) attempts
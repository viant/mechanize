SELECT * FROM (SELECT r.* FROM events r WHERE r.namespace=:Namespace
) events
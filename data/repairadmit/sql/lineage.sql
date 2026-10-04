SELECT * FROM (SELECT r.* FROM repair_lineage r WHERE r.namespace=:Namespace
) lineage
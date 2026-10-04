SELECT * FROM  (SELECT r.namespace,r.id,r.status,r.revision FROM runs r WHERE r.namespace = :Namespace
)  records
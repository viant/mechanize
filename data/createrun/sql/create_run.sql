SELECT records.* FROM  (SELECT r.* FROM runs r WHERE r.namespace = :Namespace
)  records
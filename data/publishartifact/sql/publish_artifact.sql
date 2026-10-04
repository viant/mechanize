SELECT records.* FROM  (SELECT r.* FROM artifacts r WHERE r.namespace = :Namespace
)  records
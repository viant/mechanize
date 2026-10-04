SELECT records.* FROM  (SELECT r.* FROM runs r WHERE r.namespace = :Namespace ORDER BY r.created_at DESC
)  records
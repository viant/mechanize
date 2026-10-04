SELECT * FROM  (SELECT r.* FROM consent_records r WHERE r.namespace = :Namespace
)  records
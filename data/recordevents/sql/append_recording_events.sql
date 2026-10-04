SELECT records.* FROM  (SELECT r.* FROM recorded_events r WHERE r.namespace = :Namespace
)  records
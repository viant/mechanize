SELECT records.* FROM  (SELECT r.* FROM checkpoints r WHERE r.namespace = :Namespace AND r.run_id = :RunID
)  records
SELECT r.* FROM events r WHERE r.namespace = :Namespace AND r.run_id = :RunID ORDER BY r.sequence

SELECT e.* FROM effects e WHERE e.namespace = :Namespace AND e.state IN ('intent','unknown')

SELECT a.namespace, a.id, a.lease_epoch FROM attempts a
WHERE a.namespace = :Namespace AND a.lease_epoch = :LeaseEpoch
LIMIT 1

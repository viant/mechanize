SELECT r.* FROM consent_records r WHERE r.namespace = :Namespace AND (:RecordID = '*' OR r.id = :RecordID OR r.grant_id = :RecordID) ORDER BY r.created_at DESC

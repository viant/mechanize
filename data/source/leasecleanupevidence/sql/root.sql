SELECT a.namespace, a.id, a.run_id, a.lease_epoch,
 CAST((SELECT COUNT(*) FROM attempts c WHERE c.namespace = :Namespace AND c.lease_epoch = :LeaseEpoch) AS INTEGER) AS total_attempts,
 f.id AS effect_id, f.state AS effect_state, f.revision AS effect_revision, f.evidence_json,
 i.id AS intent_event_id, i.sequence AS intent_sequence,
 o.id AS outcome_event_id, o.sequence AS outcome_sequence, o.payload_json AS outcome_payload_json
FROM attempts a
LEFT JOIN effects f ON f.namespace = a.namespace AND f.attempt_id = a.id AND f.run_id = a.run_id
LEFT JOIN events i ON i.namespace = a.namespace AND i.run_id = a.run_id AND i.attempt_id = a.id AND i.kind = 'intent'
LEFT JOIN events o ON o.namespace = a.namespace AND o.run_id = a.run_id AND o.attempt_id = a.id AND o.kind = 'outcome'
WHERE a.namespace = :Namespace AND a.lease_epoch = :LeaseEpoch
ORDER BY a.id
LIMIT 4097

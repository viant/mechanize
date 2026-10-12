SELECT r.*, CASE WHEN EXISTS (SELECT 1 FROM consent_audit a WHERE a.namespace = r.namespace AND a.request_id = r.id AND a.kind = 'revoke' AND a.actor_id = r.client_id)
AND NOT EXISTS (SELECT 1 FROM consent_audit a WHERE a.namespace = r.namespace AND a.request_id = r.id AND a.kind = 'revoke' AND a.actor_id <> r.client_id)
THEN 1 ELSE 0 END AS cleanup_machine_only FROM consent_records r
WHERE r.namespace = :Namespace AND r.client_id = :ClientID
AND r.decision = 'allow_until_revoked' AND r.grant_state = 'active'
AND r.grant_expires_at = 0 AND r.revocation_state IN ('', 'cleanupUnknown')
ORDER BY r.created_at DESC, r.id LIMIT 257

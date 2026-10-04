SELECT records.* FROM  (SELECT r.* FROM consent_records r
WHERE r.namespace = :Namespace AND r.client_id = :ClientID
AND r.decision = 'allow_until_revoked' AND r.grant_state = 'active'
AND r.grant_expires_at = 0 AND r.revocation_state = ''
ORDER BY r.created_at DESC, r.id LIMIT 257
)  records
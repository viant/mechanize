SELECT a.dispatch_state,a.protection_state,a.chrome_start_token,a.purpose_hash,a.revision,
 (SELECT COUNT(*) FROM credential_delivery_audit d WHERE d.namespace=:Namespace) AS audit_count,
 (SELECT COUNT(*) FROM credential_delivery_attempts d WHERE d.namespace=:Namespace AND (d.protection_state='held' OR (d.dispatch_state='unknown' AND d.protection_state<>'retired'))) AS blocked_count
FROM credential_delivery_attempts a WHERE a.namespace=:Namespace ORDER BY a.attempt_id

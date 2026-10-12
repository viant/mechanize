SELECT (SELECT COUNT(*) FROM credential_delivery_audit WHERE namespace=:Namespace) AS deliveries,
 (SELECT COUNT(*) FROM credential_preparation_audit WHERE namespace=:Namespace) AS preparations

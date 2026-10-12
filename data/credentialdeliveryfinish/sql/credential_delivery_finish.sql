SELECT * FROM  (SELECT d.* FROM credential_delivery_attempts d WHERE d.namespace=:Namespace AND d.client_id=:ClientID AND d.attempt_id=:AttemptID
)  deliveries
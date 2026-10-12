SELECT preparations.* FROM  (SELECT p.* FROM credential_delivery_preparations p WHERE p.namespace=:Namespace AND p.client_id=:ClientID AND p.preparation_id=:PreparationID
)  preparations
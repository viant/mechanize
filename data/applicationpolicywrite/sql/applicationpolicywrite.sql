SELECT records.* FROM  (SELECT p.* FROM application_policies p WHERE p.namespace=:Namespace AND p.id='application_access'
)  records
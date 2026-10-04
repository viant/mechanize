SELECT * FROM (SELECT r.* FROM repair_incident_budgets r WHERE r.namespace=:Namespace
) incidents
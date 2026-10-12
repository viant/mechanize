SELECT state.* FROM  (SELECT v.user_version AS version, f.foreign_keys AS foreign_keys, j.journal_mode AS journal_mode,
 s.synchronous AS synchronous,
 (SELECT COUNT(*) FROM sqlite_schema WHERE type IN ('table','index','trigger')) AS object_count,
 (SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='run_variables') AS variables_table,
 (SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name IN ('chrome_retirements','chrome_retirement_manifests','chrome_retirement_audit')) AS retirement_tables,
 (SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='chrome_attempt_bindings') AS attempt_bindings_table,
 (SELECT COUNT(*) FROM sqlite_schema WHERE type='index' AND name='chrome_attempt_bindings_fence') AS attempt_fence_index,
 (SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='workflow_review_requests') AS workflow_reviews_table,
 (SELECT COUNT(*) FROM pragma_table_info('credential_delivery_attempts') WHERE name='purpose_hash') AS purpose_columns,
 (SELECT COUNT(*) FROM sqlite_schema WHERE type='trigger' AND name IN ('credential_preparation_excludes_active_child','credential_delivery_requires_exact_preparation')) AS lineage_triggers,
 (SELECT COUNT(*) FROM pragma_foreign_key_check) AS foreign_key_violations
FROM pragma_user_version v CROSS JOIN pragma_foreign_keys f CROSS JOIN pragma_journal_mode j CROSS JOIN pragma_synchronous s
)  state
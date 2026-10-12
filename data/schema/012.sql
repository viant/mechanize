-- A credential session needs distinct non-replayed fill/submit attempts. Keep
-- the single namespace-owned preparation and exact-parent trigger from 011;
-- replace the single-child index with immutable sibling lineage enforcement.
-- No row, protection state, unknown dispatch or audit history is modified.
DROP INDEX IF EXISTS credential_delivery_active_owner;
CREATE TRIGGER IF NOT EXISTS credential_delivery_siblings_keep_lineage
BEFORE INSERT ON credential_delivery_attempts
WHEN EXISTS(SELECT 1 FROM credential_delivery_attempts a WHERE a.namespace=NEW.namespace
 AND (a.protection_state='held' OR a.dispatch_state='unknown') AND (a.dispatch_state='unknown' OR (
 a.client_id<>NEW.client_id OR a.session_id<>NEW.session_id OR a.selection_id<>NEW.selection_id
 OR a.selected_revision<>NEW.selected_revision OR a.grant_id<>NEW.grant_id
 OR a.purpose_hash IS NULL OR a.purpose_hash<>NEW.purpose_hash OR a.origin<>NEW.origin
 OR a.profile_channel<>NEW.profile_channel OR a.browser_instance<>NEW.browser_instance
 OR a.tab_id<>NEW.tab_id OR a.broker_epoch<>NEW.broker_epoch OR a.channel_epoch<>NEW.channel_epoch
 OR a.scope_hash<>NEW.scope_hash OR a.chrome_start_token<>NEW.chrome_start_token
 OR a.native_host_start_token<>NEW.native_host_start_token)))
BEGIN SELECT RAISE(ABORT,'private delivery lineage mismatch'); END;
PRAGMA user_version=12;

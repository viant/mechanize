package mcp

import "github.com/viant/mechanize/backend/chrome"

// Every canonical registration must have an explicit browser transport policy.
// TestControllerCanonicalExposurePolicy rejects new unclassified registrations.
type controllerToolPolicy struct {
	Exposed  bool
	Contract string
}

var controllerToolPolicies = map[string]controllerToolPolicy{
	"mechanize_browser_activate_tab":         {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_browser_location_matches":     {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_browser_open_origin":          {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_browser_status":               {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_browser_tab_location_matches": {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_browser_tabs":                 {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_capabilities":                 {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_capture":                      {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_capture_window_frame":         {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_capture_windows":              {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_credential_apply":             {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_credential_prepare":           {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_credential_recover":           {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_credential_resume_manual":     {true, "Owned immutable credential preparation, current grant and private redactor qualification; closed credential status only."},
	"mechanize_credential_status":            {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_credential_submit":            {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_describe":                     {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_observe":                      {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_operation_cancel":             {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_operation_outputs":            {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_operation_status":             {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_permission_request":           {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_permission_status":            {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_record_pause":                 {true, "Exact namespace/client/session recording ownership; bounded finite status only, never events or export."},
	"mechanize_record_status":                {true, "Exact namespace/client/session recording ownership; bounded finite status only, never events or export."},
	"mechanize_record_stop":                  {true, "Exact namespace/client/session recording ownership; bounded finite status only, never events or export."},
	"mechanize_resource_read":                {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_script_run":                   {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_script_validate":              {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_session_close":                {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_session_open":                 {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_step_run":                     {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"skill_get":                              {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"skill_list":                             {true, "Authenticated controller identity, canonical authorization and closed typed projection; owned session where required."},
	"mechanize_extension_reload":             {false, "Local native-client maintenance only; authenticated owned session and enrolled extension, never a website controller."},
	"mechanize_extension_reload_status":      {false, "Local native-client maintenance observation only; original owned session and request, never a website controller."},
	"mechanize_effect_reconcile":             {false, "Needs exact client-owned durable run and stored-plan authority-target screening."},
	"mechanize_record_export":                {false, "Export includes recorded action values and editable plans; no safe controller projection."},
	"mechanize_record_start":                 {false, "Capture target needs controller-specific protected-console screening."},
	"mechanize_recovery_admit":               {false, "Recovery patches need client-owned run and protected-target screening."},
	"mechanize_recovery_context":             {false, "Recovery context needs client-owned run and private-value projection."},
	"mechanize_scenario_list":                {false, "Namespace catalogue includes entity values, inputs and surfaces."},
	"mechanize_scenario_publish":             {false, "Namespace catalogue mutation requires controller ownership and value screening."},
	"mechanize_scenario_select":              {false, "Selection can return an unscreened stored plan and private values."},
	"mechanize_state_get":                    {false, "Namespace-scoped state includes variables, progress and checkpoints."},
	"mechanize_state_patch":                  {false, "Namespace-scoped mutation returns unprojected state; needs exact client-owned run."},
	"mechanize_state_pause":                  {false, "Namespace-scoped mutation returns unprojected state; needs exact client-owned run."},
	"mechanize_state_resume":                 {false, "Stored-plan execution needs exact client-owned run and protected-target screening."},
	"mechanize_state_stop_boundary":          {false, "Needs exact client-owned durable run and stored-plan authority-target screening."},
}

var controllerTools = func() map[string]bool {
	result := make(map[string]bool)
	for name, policy := range controllerToolPolicies {
		if policy.Exposed {
			result[name] = true
		}
	}
	return result
}()

// Preserve the complete pre-0.1.63 catalog on installed 32-tool receivers.
// Tools introduced with the larger catalog remain available on newer sessions.
func controllerCatalogLimit(id chrome.ControllerIdentity) int {
	if id.CatalogToolLimit == 64 {
		return 64
	}
	return 32
}
func controllerToolAvailable(id chrome.ControllerIdentity, name string) bool {
	if !controllerTools[name] {
		return false
	}
	if controllerCatalogLimit(id) == 64 {
		return true
	}
	switch name {
	case "mechanize_credential_resume_manual", "mechanize_record_pause", "mechanize_record_status", "mechanize_record_stop":
		return false
	}
	return true
}

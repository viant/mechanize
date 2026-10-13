package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mcp/client"
	server "github.com/viant/mcp/server"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/engine/durable"
	"github.com/viant/mechanize/engine/recording"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

// The controller uses the same registered MCP handlers, runtime, host policy and
// human consent as local clients. This is a transport adapter, not another engine.
type ControllerDispatcher struct {
	server  *server.Server
	runtime *automation.Runtime
	mu      sync.Mutex
	clients map[string]*controllerClient
}
type controllerClient struct {
	initialized      *schema.InitializeResult
	client           client.Interface
	mu               sync.Mutex
	sessions         map[string]bool
	closed           bool
	catalogToolLimit int
}

func NewControllerDispatcher(s *server.Server, r *automation.Runtime) (*ControllerDispatcher, error) {
	if s == nil || r == nil {
		return nil, errors.New("canonical MCP server and runtime required")
	}
	return &ControllerDispatcher{server: s, runtime: r, clients: map[string]*controllerClient{}}, nil
}

func (d *ControllerDispatcher) clientFor(ctx context.Context, id chrome.ControllerIdentity) (*controllerClient, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	p, err := auth.FromContext(ctx)
	if err != nil || p.Namespace != id.Principal.Namespace || p.ClientID != id.Principal.ClientID || !strings.HasPrefix(p.ClientID, "controller:") || id.ConversationID == "" || auth.NativeHuman(ctx) {
		return nil, auth.ErrUnauthorized
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if c := d.clients[p.ClientID]; c != nil {
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		if closed || c.catalogToolLimit != controllerCatalogLimit(id) {
			return nil, auth.ErrUnauthorized
		}
		return c, nil
	}
	c := &controllerClient{client: d.server.AsClient(auth.WithPrincipal(context.Background(), p)), sessions: map[string]bool{}, catalogToolLimit: controllerCatalogLimit(id)}
	if c.initialized, err = c.client.Initialize(ctx); err != nil {
		return nil, errors.New("controller MCP unavailable")
	}
	d.clients[p.ClientID] = c
	return c, nil
}
func (d *ControllerDispatcher) ListTools(ctx context.Context, id chrome.ControllerIdentity) (*schema.ListToolsResult, error) {
	c, err := d.clientFor(ctx, id)
	if err != nil {
		return nil, err
	}
	listed, err := c.client.ListTools(ctx, nil)
	if err != nil {
		return nil, errors.New("controller catalog unavailable")
	}
	result := &schema.ListToolsResult{Tools: []schema.Tool{}}
	for _, tool := range listed.Tools {
		if controllerToolAvailable(id, tool.Name) {
			result.Tools = append(result.Tools, tool)
		}
	}
	if len(result.Tools) > controllerCatalogLimit(id) {
		return nil, errors.New("controller catalog capacity exceeded")
	}
	return result, nil
}

type controllerArgumentError string

func (e controllerArgumentError) Error() string { return string(e) }

func decodeControllerArgs(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > 49152 {
		return controllerArgumentError("invalidArguments")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return controllerArgumentError("invalidArguments")
	}
	return nil
}
func controllerArgs(name string, raw json.RawMessage) (map[string]any, string, error) {
	var typed any
	switch name {
	case "mechanize_capture_windows":
		typed = &CaptureWindowsInput{}
	case "mechanize_capture", "mechanize_capture_window_frame":
		typed = &CaptureWindowInput{}
	case "skill_list":
		typed = &Empty{}
	case "skill_get", "mechanize_resource_read":
		typed = &SkillRef{}
	case "mechanize_credential_recover":
		typed = &CredentialRecoverInput{}
	case "mechanize_credential_prepare":
		typed = &CredentialPrepareInput{}
	case "mechanize_credential_apply", "mechanize_credential_submit", "mechanize_credential_status", "mechanize_credential_resume_manual":
		typed = &CredentialRefInput{}
	case "mechanize_capabilities", "mechanize_describe", "mechanize_browser_status":
		typed = &Empty{}
	case "mechanize_record_pause", "mechanize_record_status", "mechanize_record_stop":
		typed = &RecordingRef{}
	case "mechanize_session_open":
		typed = &SessionInput{}
	case "mechanize_session_close":
		typed = &SessionRef{}
	case "mechanize_permission_request":
		typed = &ConsentRequestInput{}
	case "mechanize_permission_status":
		typed = &ConsentStatusInput{}
	case "mechanize_observe":
		typed = &ObserveInput{}
	case "mechanize_script_validate":
		typed = &SourceInput{}
	case "mechanize_script_run", "mechanize_step_run":
		typed = &RunInput{}
	case "mechanize_operation_status", "mechanize_operation_cancel":
		typed = &OperationInput{}
	case "mechanize_operation_outputs":
		typed = &OperationOutputsInput{}
	case "mechanize_browser_tabs":
		typed = &BrowserTabsInput{}
	case "mechanize_browser_open_origin":
		typed = &BrowserOpenOriginInput{}
	case "mechanize_browser_activate_tab":
		typed = &BrowserActivateTabInput{}
	case "mechanize_browser_location_matches":
		typed = &BrowserLocationMatchesInput{}
	case "mechanize_browser_tab_location_matches":
		typed = &BrowserTabLocationMatchesInput{}
	default:
		return nil, "", errors.New("controller tool unavailable")
	}
	if err := decodeControllerArgs(raw, typed); err != nil {
		return nil, "", err
	}
	switch v := typed.(type) {
	case *CaptureWindowsInput:
		if !controllerSurfaceAllowed(v.Surface) {
			return nil, "", errors.New("native authority surface unavailable")
		}
	case *CaptureWindowInput:
		if !controllerSurfaceAllowed(v.Surface) {
			return nil, "", errors.New("native authority surface unavailable")
		}
	case *CredentialPrepareInput:
		if !controllerSurfaceAllowed(v.Surface) {
			return nil, "", errors.New("native authority surface unavailable")
		}
	case *ObserveInput:
		if !controllerSurfaceAllowed(v.Surface) {
			return nil, "", errors.New("native authority surface unavailable")
		}
		if !observeSurfaceIdentityValid(v.Surface) {
			return nil, "", controllerArgumentError("invalidSurface")
		}
	case *ConsentRequestInput:
		if err := consentArgumentValidation(v); err != nil {
			return nil, "", err
		}
		if !controllerSurfaceAllowed(model.Surface{BundleID: v.Scope.BundleID}) {
			return nil, "", errors.New("native authority surface unavailable")
		}
	case *RunInput:
		if len(v.Source) > 32768 || len(v.ClientRequestID) > 128 {
			return nil, "", errors.New("bounded script required")
		}
		plan, err := compileSource(v.Source, v.Format)
		if err != nil {
			var invalid *model.MechanizeError
			if errors.As(err, &invalid) && invalid.Code == "invalidPredicate" && invalid.DispatchState == "notDispatched" && invalid.EffectState == "none" {
				return nil, "", controllerArgumentError("invalidPredicate")
			}
			return nil, "", errors.New("invalid or authority-protected script")
		}
		if !controllerPlanAllowed(plan) {
			return nil, "", errors.New("invalid or authority-protected script")
		}
		// Credentials use the private native Vault delivery channel. Ordinary
		// script inputs must not turn declared sensitive values into page bytes.
		for _, def := range plan.Inputs {
			if def.Sensitive {
				return nil, "", errors.New("sensitive script input requires private local delivery")
			}
		}
	case *SourceInput:
		if len(v.Source) > 32768 {
			return nil, "", errors.New("bounded script required")
		}
		plan, err := compileSource(v.Source, v.Format)
		if err != nil {
			var invalid *model.MechanizeError
			if errors.As(err, &invalid) && invalid.Code == "invalidPredicate" && invalid.DispatchState == "notDispatched" && invalid.EffectState == "none" {
				return nil, "", controllerArgumentError("invalidPredicate")
			}
			return nil, "", errors.New("invalid or authority-protected script")
		}
		if !controllerPlanAllowed(plan) {
			return nil, "", errors.New("invalid or authority-protected script")
		}
		for _, def := range plan.Inputs {
			if def.Sensitive {
				return nil, "", errors.New("sensitive script input requires private local delivery")
			}
		}
	case *SessionInput:
		if len(v.Name) > 128 {
			return nil, "", errors.New("bounded session name required")
		}
	}
	var args map[string]any
	if json.Unmarshal(raw, &args) != nil {
		return nil, "", errors.New("arguments object required")
	}
	session, _ := args["sessionId"].(string)
	if name != "mechanize_session_open" && name != "mechanize_capabilities" && name != "mechanize_describe" && name != "mechanize_browser_status" && name != "mechanize_script_validate" && name != "skill_list" && name != "skill_get" && name != "mechanize_resource_read" && session == "" {
		return nil, "", controllerArgumentError("sessionRequired")
	}
	return args, session, nil
}
func controllerRejected(dispatch string, codes ...string) *schema.CallToolResult {
	if dispatch != "notDispatched" && dispatch != "dispatched" {
		dispatch = "unknown"
	}
	yes := true
	code := "controllerToolRejected"
	if len(codes) > 0 {
		switch codes[0] {
		case "invalidPredicate", "permissionRequired", "permissionExpired", "permissionDenied", "secureDocumentRequired", "staleGeneration", "staleAuthority", "unknownEffect", "targetNotFound", "ambiguousTarget", "invalidArguments", "sessionRequired", "sessionNotOwned", "invalidScopeKind", "invalidConsentScope", "unsupportedMode", "invalidSurface", "invalidScope", "browserInventoryUnavailable", "privateDOMUnavailable", "protectionMetadataUnavailable", "publicReadIdentityChanged", "publicReadInventoryUnavailable", "publicReadBusy", "publicReadLimit", "publicReadUnavailable":
			code = codes[0]
		}
	}
	message := "Tool request unavailable; review local permissions and operation status."
	if code == "invalidPredicate" {
		message = "Invalid verification contract. For web.valueEquals use observational authority and typed origin, strategy, selector, attribute and expected inputs; use strategy id plus selector for an element ID."
	}
	if code == "invalidSurface" {
		message = invalidSurfaceMessage
	}
	if code == "privateDOMUnavailable" {
		message = privateDOMMessage
	}
	if code == "invalidScope" {
		message = "Use an exact discovered scope. Native window observation requires surface.processId and surface.processStartToken plus a discovered window title. For screenshots, discover windows with mechanize_capture_windows and capture the returned window instead."
	}
	switch code {
	case "protectionMetadataUnavailable":
		message = "Browser protection metadata is unavailable; inspect its metadata phase and cause."
	case "publicReadIdentityChanged":
		message = "Public document identity changed during read qualification; select the current tab and observe again."
	case "publicReadInventoryUnavailable":
		message = "Current browser tab or frame metadata is unavailable for this read."
	case "publicReadBusy":
		message = "A current browser exchange prevents this read; wait for its receipt."
	case "publicReadLimit":
		message = "Public document read proof capacity is exhausted."
	case "publicReadUnavailable":
		message = "Public document read proof is unavailable; inspect current browser connection metadata."
	}
	body := map[string]any{"code": code, "message": message, "dispatchState": dispatch}
	raw, _ := json.Marshal(body)
	return &schema.CallToolResult{IsError: &yes, StructuredContent: body, Content: []schema.CallToolResultContentElem{schema.TextContent{Type: "text", Text: string(raw)}}}
}
func controllerProtectionMetadataRejected(dispatch string, structured map[string]any) *schema.CallToolResult {
	phase, _ := structured["metadataPhase"].(string)
	cause, _ := structured["metadataCause"].(string)
	phase, cause = durable.ClosedProtectionMetadataDiagnostic(&durable.ProtectionMetadataFailure{Phase: phase, Cause: cause})
	rejected := controllerRejected(dispatch, "protectionMetadataUnavailable")
	body := rejected.StructuredContent.(map[string]any)
	body["metadataPhase"], body["metadataCause"] = phase, cause
	raw, _ := json.Marshal(body)
	rejected.Content = []schema.CallToolResultContentElem{schema.TextContent{Type: "text", Text: string(raw)}}
	return rejected
}

func (d *ControllerDispatcher) CallTool(ctx context.Context, id chrome.ControllerIdentity, call chrome.ControllerToolCall) (*schema.CallToolResult, error) {
	if !controllerToolAvailable(id, call.Name) {
		return controllerRejected("notDispatched"), nil
	}
	args, session, err := controllerArgs(call.Name, call.Arguments)
	if err != nil {
		var closed controllerArgumentError
		if errors.As(err, &closed) {
			return controllerRejected("notDispatched", string(closed)), nil
		}
		return controllerRejected("notDispatched"), nil
	}
	c, err := d.clientFor(ctx, id)
	if err != nil {
		return nil, err
	}
	if call.Name == "mechanize_session_open" {
		c.mu.Lock()
		full := c.closed || len(c.sessions) >= 8
		c.mu.Unlock()
		if full {
			return controllerRejected("notDispatched"), nil
		}
	}
	if session != "" {
		c.mu.Lock()
		owned := c.sessions[session] && !c.closed
		c.mu.Unlock()
		if !owned {
			return controllerRejected("notDispatched", "sessionNotOwned"), nil
		}
	}
	answer, err := c.client.CallTool(ctx, &schema.CallToolRequestParams{Name: call.Name, Arguments: args})
	if err != nil || answer == nil {
		return controllerRejected("unknown"), nil
	}
	if answer.ResultType != "" && answer.ResultType != "complete" {
		// This connection does not implement July input-required continuations.
		// Do not turn a pending upstream operation into a completed tool result.
		return nil, errors.New("controller result continuation unavailable")
	}
	var structured map[string]any
	encoded, encodeErr := json.Marshal(answer.StructuredContent)
	if encodeErr != nil || len(encoded) > 192*1024 || json.Unmarshal(encoded, &structured) != nil || structured == nil {
		return controllerRejected("unknown"), nil
	}
	if answer.IsError != nil && *answer.IsError {
		dispatch, _ := structured["dispatchState"].(string)
		code, _ := structured["code"].(string)
		if code == "protectionMetadataUnavailable" {
			return controllerProtectionMetadataRejected(dispatch, structured), nil
		}
		return controllerRejected(dispatch, code), nil
	}
	if call.Name == "mechanize_session_open" {
		opened, _ := structured["sessionId"].(string)
		if opened == "" || len(opened) > 256 {
			return controllerRejected("unknown"), nil
		}
		c.mu.Lock()
		closed := c.closed
		if !closed {
			c.sessions[opened] = true
		}
		c.mu.Unlock()
		if closed || ctx.Err() != nil {
			cleanup, cancel := context.WithTimeout(auth.WithPrincipal(context.Background(), id.Principal), 3*time.Second)
			defer cancel()
			_ = d.runtime.Close(cleanup, opened)
			return controllerRejected("unknown"), nil
		}
	}
	if call.Name == "mechanize_session_close" {
		c.mu.Lock()
		delete(c.sessions, session)
		c.mu.Unlock()
	}
	// Canonical structured data is authoritative. Never forward arbitrary text,
	// resource links or an exception dump from a tool implementation.
	if answer.StructuredContent == nil {
		return controllerRejected("unknown"), nil
	}
	body := structured
	if call.Name == "mechanize_script_validate" {
		projected, _ := result(Validation{Valid: true, Plan: nil, Explanation: "Validated locally; source and compiled plan are withheld from the controller response."})
		return projected, nil
	}
	if call.Name == "mechanize_operation_outputs" {
		var output automation.OperationOutputs
		if json.Unmarshal(encoded, &output) != nil {
			return controllerRejected("unknown"), nil
		}
		for _, v := range output.Outputs {
			if v.Kind == model.ReferenceValue {
				return controllerRejected("unknown"), nil
			}
		}
		projected, _ := result(output)
		return projected, nil
	}
	if call.Name == "mechanize_script_run" || call.Name == "mechanize_step_run" || call.Name == "mechanize_operation_status" || call.Name == "mechanize_operation_cancel" {
		raw, _ := json.Marshal(body)
		var operation Operation
		if json.Unmarshal(raw, &operation) != nil {
			return controllerRejected("unknown"), nil
		}
		operation.Error = ""
		if operation.ExecutionFailure != nil && !operation.ExecutionFailure.Valid() {
			operation.ExecutionFailure = nil
		}
		operation.VerificationReason = ""
		if operation.Objective != nil {
			operation.Objective.Reason = ""
			for i := range operation.Objective.Evidence {
				operation.Objective.Evidence[i].BusinessKey = ""
			}
		}
		projected, _ := result(operation)
		return projected, nil
	}
	if call.Name == "mechanize_capture" || call.Name == "mechanize_capture_window_frame" {
		return projectControllerCapture(ctx, call.Name, encoded, answer)
	}
	var safe any
	switch call.Name {
	case "mechanize_capture_windows":
		safe = &native.CaptureWindowList{}
	case "skill_list":
		safe = &SkillCatalog{}
	case "skill_get":
		safe = &SkillGuide{}
	case "mechanize_resource_read":
		safe = &schema.ReadResourceResult{}

	case "mechanize_credential_recover", "mechanize_credential_prepare", "mechanize_credential_apply", "mechanize_credential_submit", "mechanize_credential_status", "mechanize_credential_resume_manual":
		safe = &CredentialResult{}
	case "mechanize_record_pause", "mechanize_record_status", "mechanize_record_stop":
		safe = &recording.Status{}
	case "mechanize_session_open":
		safe = &SessionRef{}
	case "mechanize_session_close":
		safe = &Empty{}
	case "mechanize_capabilities", "mechanize_describe":
		safe = &Discovery{}
	case "mechanize_permission_request":
		safe = &PermissionRequired{}
	case "mechanize_permission_status":
		safe = &consent.RequestStatus{}
	case "mechanize_observe":
		safe = &model.Observation{}
	case "mechanize_browser_status":
		safe = &chrome.BrowserStatus{}
	case "mechanize_browser_tabs":
		safe = &chrome.TabHandleInventory{}
	case "mechanize_browser_open_origin":
		safe = &BrowserOpenOriginResult{}
	case "mechanize_browser_activate_tab":
		safe = &BrowserActivateTabResult{}
	case "mechanize_browser_location_matches":
		safe = &chrome.FocusedOriginMatch{}
	case "mechanize_browser_tab_location_matches":
		safe = &chrome.TabLocationMatch{}
	default:
		return controllerRejected("unknown"), nil
	}
	if json.Unmarshal(encoded, safe) != nil {
		return controllerRejected("unknown"), nil
	}
	if status, ok := safe.(*recording.Status); ok && !validControllerRecordingStatus(*status) {
		return controllerRejected("unknown"), nil
	}
	if discovery, ok := safe.(*Discovery); ok {
		// Origin comes from the broker-verified Chrome sender, never tool args.
		// Keep page URLs, document/profile IDs and native process identity private.
		discovery.ControllerContext = nil
		if chrome.OrdinaryWebsiteOrigin(id.Origin) {
			discovery.ControllerContext = &ControllerContext{Kind: "web", Origin: id.Origin}
		}
	}
	projected, rpcError := result(safe)
	if rpcError != nil {
		return nil, errors.New("controller result unavailable")
	}
	return projected, nil
}
func (d *ControllerDispatcher) CloseController(ctx context.Context, id chrome.ControllerIdentity) error {
	d.mu.Lock()
	c := d.clients[id.Principal.ClientID]
	delete(d.clients, id.Principal.ClientID)
	d.mu.Unlock()
	if c == nil {
		return nil
	}
	c.mu.Lock()
	c.closed = true
	sessions := make([]string, 0, len(c.sessions))
	for session := range c.sessions {
		sessions = append(sessions, session)
	}
	c.mu.Unlock()
	ctx = auth.WithPrincipal(ctx, id.Principal)
	var failed bool
	for _, session := range sessions {
		if d.runtime.Close(ctx, session) != nil {
			failed = true
		}
	}
	if failed {
		return errors.New("controller session cleanup requires local reconciliation")
	}
	return nil
}

func (d *ControllerDispatcher) Initialize(ctx context.Context, id chrome.ControllerIdentity) (*schema.InitializeResult, error) {
	c, err := d.clientFor(ctx, id)
	if err != nil {
		return nil, err
	}
	// The bridge is an explicit 2025-11-25 boundary, independent of the canonical
	// server's negotiated version. Only complete results and tool methods are
	// projected; July input-required continuations and host-only metadata are not.
	return &schema.InitializeResult{ProtocolVersion: "2025-11-25", ServerInfo: c.initialized.ServerInfo, Capabilities: schema.ServerCapabilities{Tools: &schema.ServerCapabilitiesTools{}}}, nil
}

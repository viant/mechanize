// Package mcp exposes Mechanize's compact LLM gateway using viant/mcp.
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	protocol "github.com/viant/mcp-protocol/server"
	server "github.com/viant/mcp/server"
	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
	"github.com/viant/mechanize/engine/recording"
	repairs "github.com/viant/mechanize/engine/recovery"
	scenarios "github.com/viant/mechanize/engine/scenario"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
	"github.com/viant/mechanize/script"
)

type ObserveNativeWindow func(context.Context, auth.Principal, model.Surface, string, string) (model.Observation, error)
type ObserveNativeRoot func(context.Context, auth.Principal, model.Surface, string) (model.Observation, error)
type Observe func(context.Context, auth.Principal, model.Surface) (model.Observation, error)
type Policy func(context.Context, auth.Principal) (script.Policy, error)
type StateGet func(context.Context, auth.Principal, string) (durable.State, error)
type StatePause func(context.Context, auth.Principal, string, int) (durable.State, error)
type StatePatch func(context.Context, auth.Principal, string, int, map[string]model.Value) (durable.State, error)
type StateResume func(context.Context, auth.Principal, string, string, int, string, string) (*automation.ResumeResult, error)
type CaptureWindow func(context.Context, auth.Principal, model.Surface, int32, uint32) (data.ArtifactReference, native.CapturedImage, error)
type CaptureWindows func(context.Context, auth.Principal, model.Surface, int) (native.CaptureWindowList, error)
type CaptureWindowFrame func(context.Context, auth.Principal, model.Surface, int32, uint32) (data.ArtifactReference, data.ArtifactReference, native.WindowFrameCapture, error)
type Dependencies struct {
	BrowserStatus       BrowserStatus
	StateStopBoundary   func(context.Context, auth.Principal, durable.StopBoundaryRequest) (durable.StopBoundaryResult, error)
	EffectReconcile     func(context.Context, auth.Principal, durable.EffectReconcileRequest) (durable.EffectReconcileResult, error)
	Recovery            *repairs.Service
	Scenarios           *scenarios.Service
	CaptureWindow       CaptureWindow
	CaptureWindows      CaptureWindows
	CaptureWindowFrame  CaptureWindowFrame
	StateResume         StateResume
	PermissionRequest   ConsentRequest
	PermissionStatus    ConsentStatus
	Recording           *recording.Service
	StatePause          StatePause
	StateGet            StateGet
	StatePatch          StatePatch
	Runtime             *automation.Runtime
	ObserveNativeWindow ObserveNativeWindow
	ObserveNativeRoot   ObserveNativeRoot
	Observe             Observe
	Policy              Policy
	Version             string
}
type Empty struct{}
type SessionInput struct {
	Name string `json:"name,omitempty"`
}
type SessionRef struct {
	SessionID string `json:"sessionId"`
}
type SourceInput struct {
	Source string `json:"source"`
	Format string `json:"format,omitempty"`
}
type RunInput struct {
	GrantID         string                 `json:"grantId,omitempty"`
	Purpose         string                 `json:"purpose,omitempty"`
	SessionID       string                 `json:"sessionId"`
	ClientRequestID string                 `json:"clientRequestId"`
	Source          string                 `json:"source"`
	Format          string                 `json:"format,omitempty"`
	Inputs          map[string]model.Value `json:"inputs,omitempty"`
}
type OperationInput struct {
	SessionID   string `json:"sessionId"`
	OperationID string `json:"operationId"`
}
type ObserveWindowScope struct {
	Title string `json:"title" description:"Exact unique window title within the named native process."`
	Role  string `json:"role,omitempty" choice:"window" choice:"AXWindow"`
}

func (s *ObserveWindowScope) UnmarshalJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	type plain ObserveWindowScope
	var parsed plain
	if err := decoder.Decode(&parsed); err != nil {
		return errors.New("closed exact window scope required")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("single exact window scope required")
	}
	*s = ObserveWindowScope(parsed)
	return nil
}

type ObserveInput struct {
	WindowScope *ObserveWindowScope `json:"windowScope,omitempty" description:"Exact native window subtree; requires PID/birth identity and never falls back to whole-app state."`
	NativeRoot  string              `json:"nativeRoot,omitempty" choice:"menuBar" choice:"focusedElement" description:"Explicit app-owned native subtree; requires helper support and never falls back to the whole app."`
	SessionID   string              `json:"sessionId,omitempty"`
	GrantID     string              `json:"grantId,omitempty"`
	Purpose     string              `json:"purpose,omitempty"`
	Surface     model.Surface       `json:"surface"`
}
type Validation struct {
	Valid       bool        `json:"valid"`
	Plan        *model.Plan `json:"plan"`
	Explanation string      `json:"explanation"`
}
type Discovery struct {
	SchemaVersion       int                 `json:"schemaVersion"`
	Methods             []script.Definition `json:"methods"`
	Capabilities        map[string]bool     `json:"capabilities"`
	CapabilityReasons   map[string]string   `json:"capabilityReasons,omitempty"`
	BusinessReliability string              `json:"businessReliability"`
	SourceFormats       []string            `json:"sourceFormats,omitempty"`
	WorkflowSchema      map[string]any      `json:"workflowSchema,omitempty"`
}
type Operation struct {
	RunID              string            `json:"runId,omitempty"`
	ID                 string            `json:"operationId"`
	SessionID          string            `json:"sessionId"`
	ExecutionStatus    string            `json:"executionStatus"`
	BusinessStatus     string            `json:"businessStatus"`
	VerificationState  string            `json:"verificationState"`
	Objective          *objective.Result `json:"objective,omitempty"`
	VerificationReason string            `json:"verificationReason,omitempty"`
	Error              string            `json:"error,omitempty"`
}

// Execution completion and business completion have separate evidence. A
// pending or unavailable durable verification must never inherit UI success.
func operationResult(ctx context.Context, runtime *automation.Runtime, operation Operation) (*schema.CallToolResult, *jsonrpc.Error) {
	verified, err := runtime.Result(ctx, operation.SessionID, operation.ID)
	if err != nil {
		operation.BusinessStatus = "unverified"
		operation.VerificationState = "unknown"
		operation.VerificationReason = "business outcome mapping unavailable"
	} else {
		operation.BusinessStatus = verified.BusinessStatus
		operation.VerificationState = verified.VerificationState
		operation.Objective = verified.Objective
		operation.VerificationReason = verified.Reason
	}
	return result(operation)
}

func New(deps Dependencies) (*server.Server, error) {
	if deps.Runtime == nil || deps.Policy == nil {
		return nil, errors.New("Endly runtime and explicit gateway policy are required")
	}
	if deps.Version == "" {
		deps.Version = "0.1.0-dev"
	}
	handler := protocol.WithDefaultHandler(context.Background(), func(base *protocol.DefaultHandler) error { return register(base, deps) })
	return server.New(server.WithImplementation(schema.Implementation{Name: "mechanize", Version: deps.Version}), server.WithNewHandler(handler), server.WithStreamableURI("/mcp"), server.WithRequestContext(func(ctx context.Context) (context.Context, error) {
		if _, err := auth.FromContext(ctx); err != nil {
			return nil, err
		}
		return ctx, nil
	}))
}
func result(value any) (*schema.CallToolResult, *jsonrpc.Error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, jsonrpc.NewInternalError("cannot encode gateway result", nil)
	}
	structured := map[string]any{}
	if err = json.Unmarshal(encoded, &structured); err != nil {
		structured = map[string]any{"data": value}
	}
	return &schema.CallToolResult{Content: []schema.CallToolResultContentElem{schema.TextContent{Type: "text", Text: string(encoded)}}, StructuredContent: structured}, nil
}
func failure(err error) (*schema.CallToolResult, *jsonrpc.Error) {
	yes := true
	body := map[string]any{"code": "operationRejected", "message": err.Error(), "dispatchState": "notDispatched"}
	var typed *model.MechanizeError
	if errors.As(err, &typed) {
		body = map[string]any{"code": typed.Code, "message": typed.Message, "stage": typed.Stage, "dispatchState": typed.DispatchState, "effectState": typed.EffectState}
	}
	var committed *durable.StatePatchCommittedError
	if errors.As(err, &committed) {
		body = map[string]any{"code": "stateCommittedNeedsAttention", "message": "Durable state committed; runtime bindings require attention before continuing", "dispatchState": "notDispatched", "committed": true, "state": committed.CommittedState()}
	}
	encoded, _ := json.Marshal(body)
	return &schema.CallToolResult{IsError: &yes, Content: []schema.CallToolResultContentElem{schema.TextContent{Type: "text", Text: string(encoded)}}, StructuredContent: body}, nil
}
func register(base *protocol.DefaultHandler, d Dependencies) error {
	if err := registerBrowserStatus(base, d.BrowserStatus); err != nil {
		return err
	}
	if err := registerRecovery(base, d.Recovery, d.Runtime); err != nil {
		return err
	}
	if err := registerScenarios(base, d.Scenarios); err != nil {
		return err
	}
	if err := registerCapture(base, d); err != nil {
		return err
	}
	if err := registerWindowFrameCapture(base, d.CaptureWindowFrame); err != nil {
		return err
	}
	if err := RegisterConsentStatus(base, d.PermissionStatus); err != nil {
		return err
	}
	if err := RegisterConsent(base, d.PermissionRequest); err != nil {
		return err
	}
	if err := RegisterRecording(base, d.Recording); err != nil {
		return err
	}
	if err := registerState(base, d); err != nil {
		return err
	}
	if err := registerStopBoundary(base, d); err != nil {
		return err
	}
	if err := registerEffectReconciliation(base, d); err != nil {
		return err
	}
	if err := registerOperationOutputs(base, d.Runtime); err != nil {
		return err
	}
	if err := registerResume(base, d); err != nil {
		return err
	}
	if err := registerSkills(base); err != nil {
		return err
	}
	if err := protocol.RegisterTool[*Empty, *Discovery](base.Registry, "mechanize_capabilities", "Discover supported surfaces and shared macOS/Chrome methods. Inspect before selecting an action.", func(ctx context.Context, _ *Empty) (*schema.CallToolResult, *jsonrpc.Error) {
		p, err := auth.FromContext(ctx)
		if err != nil {
			return failure(err)
		}
		policy, err := d.Policy(ctx, p)
		if err != nil {
			return failure(err)
		}
		return result(Discovery{SchemaVersion: 1, Methods: (script.Registry{}).Describe(), Capabilities: policy.Capabilities, CapabilityReasons: policy.CapabilityReasons, BusinessReliability: "unmeasured"})
	}); err != nil {
		return err
	}
	if err := protocol.RegisterTool[*Empty, *Discovery](base.Registry, "mechanize_describe", "Get shared DSL method signatures, effect rules and strict JSON/YAML workflow envelope schema. Descriptions do not grant permission or enroll adapters.", func(ctx context.Context, _ *Empty) (*schema.CallToolResult, *jsonrpc.Error) {
		p, err := auth.FromContext(ctx)
		if err != nil {
			return failure(err)
		}
		policy, err := d.Policy(ctx, p)
		if err != nil {
			return failure(err)
		}
		return result(Discovery{SchemaVersion: 1, Methods: (script.Registry{}).Describe(), Capabilities: policy.Capabilities, CapabilityReasons: policy.CapabilityReasons, BusinessReliability: "unmeasured", SourceFormats: []string{"dsl", "json", "yaml"}, WorkflowSchema: script.EnvelopeSchema()})
	}); err != nil {
		return err
	}
	if err := protocol.RegisterTool[*SessionInput, *SessionRef](base.Registry, "mechanize_session_open", "Open a user-scoped Endly automation session; use the returned ID in later calls.", func(ctx context.Context, input *SessionInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if input == nil {
			input = &SessionInput{}
		}
		s, err := d.Runtime.Open(ctx, input.Name)
		if err != nil {
			return failure(err)
		}
		return result(SessionRef{s.SessionID})
	}); err != nil {
		return err
	}
	if err := protocol.RegisterTool[*SessionRef, *Empty](base.Registry, "mechanize_session_close", "Cancel/close the owned automation session. This does not delete durable effects or close employee applications.", func(ctx context.Context, input *SessionRef) (*schema.CallToolResult, *jsonrpc.Error) {
		if input == nil || input.SessionID == "" {
			return failure(errors.New("sessionId required"))
		}
		if err := d.Runtime.Close(ctx, input.SessionID); err != nil {
			return failure(err)
		}
		return result(Empty{})
	}); err != nil {
		return err
	}
	if err := protocol.RegisterTool[*SourceInput, *Validation](base.Registry, "mechanize_script_validate", "Validate source without executing: format dsl (default), json or yaml. Workflow envelopes support typed inputs and business objectives.", func(ctx context.Context, input *SourceInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if input == nil {
			return failure(errors.New("source required"))
		}
		plan, err := compileSource(input.Source, input.Format)
		if err != nil {
			return failure(err)
		}
		return result(Validation{true, plan, (script.Explainer{}).Explain(plan)})
	}); err != nil {
		return err
	}
	for _, spec := range []struct {
		name, description string
		single            bool
	}{{"mechanize_step_run", "Run exactly one typed native/Chrome action through Endly; mutations are policy-gated and never transparently retried.", true}, {"mechanize_script_run", "Run source in format dsl (default), json or yaml through Endly. Use a workflow envelope to declare the business objective; inspect separate execution and business verification status.", false}} {
		single := spec.single
		if err := protocol.RegisterTool[*RunInput, *Operation](base.Registry, spec.name, spec.description, func(ctx context.Context, input *RunInput) (*schema.CallToolResult, *jsonrpc.Error) {
			if input == nil || input.SessionID == "" || input.ClientRequestID == "" {
				return failure(errors.New("sessionId and clientRequestId required"))
			}
			plan, err := compileSource(input.Source, input.Format)
			if err != nil {
				return failure(err)
			}
			if single && len(plan.Steps) != 1 {
				return failure(errors.New("step_run requires exactly one execution step"))
			}
			p, err := auth.FromContext(ctx)
			if err != nil {
				return failure(err)
			}
			policy, err := d.Policy(ctx, p)
			if err != nil {
				return failure(err)
			}
			if err = (script.Validator{}).CheckPolicy(plan, policy); err != nil {
				return failure(err)
			}
			// Request identity is scoped to principal/session and persisted as the run ID;
			// replay is never permission to repeat an uncertain external effect.
			ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{GrantID: input.GrantID, SessionID: input.SessionID, Purpose: input.Purpose})
			operation, err := d.Runtime.StartPlanWithRequest(ctx, input.SessionID, input.ClientRequestID, *plan, input.Inputs)
			if err != nil {
				return failure(err)
			}
			runID, _ := d.Runtime.RunReference(ctx, operation.SessionID, operation.ID)
			return operationResult(ctx, d.Runtime, Operation{RunID: runID, ID: operation.ID, SessionID: operation.SessionID, ExecutionStatus: operation.Status})
		}); err != nil {
			return err
		}
	}
	if err := protocol.RegisterTool[*OperationInput, *Operation](base.Registry, "mechanize_operation_status", "Inspect owned Endly execution status and separate business verification status.", func(ctx context.Context, input *OperationInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if input == nil {
			return failure(errors.New("operation reference required"))
		}
		o, err := d.Runtime.Status(ctx, input.SessionID, input.OperationID)
		if err != nil {
			return failure(err)
		}
		runID, _ := d.Runtime.RunReference(ctx, o.SessionID, o.ID)
		return operationResult(ctx, d.Runtime, Operation{RunID: runID, ID: o.ID, SessionID: o.SessionID, ExecutionStatus: o.Status, Error: o.Error})
	}); err != nil {
		return err
	}
	if err := protocol.RegisterTool[*OperationInput, *Operation](base.Registry, "mechanize_operation_cancel", "Request cancellation of the owned Endly operation; already-dispatched effects still require reconciliation.", func(ctx context.Context, input *OperationInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if input == nil {
			return failure(errors.New("operation reference required"))
		}
		o, err := d.Runtime.Cancel(ctx, input.SessionID, input.OperationID)
		if err != nil {
			return failure(err)
		}
		runID, _ := d.Runtime.RunReference(ctx, o.SessionID, o.ID)
		return operationResult(ctx, d.Runtime, Operation{RunID: runID, ID: o.ID, SessionID: o.SessionID, ExecutionStatus: o.Status, Error: o.Error})
	}); err != nil {
		return err
	}
	if d.Observe != nil || d.ObserveNativeRoot != nil || d.ObserveNativeWindow != nil {
		if err := registerObserve(base, d); err != nil {
			return err
		}
	}
	return nil
}

func registerObserve(base *protocol.DefaultHandler, d Dependencies) error {
	return protocol.RegisterTool[*ObserveInput, *model.Observation](base.Registry, "mechanize_observe", "Read bounded current semantic state of an authorized native app or Chrome surface; use fresh refs and declared locators.", func(ctx context.Context, input *ObserveInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if input == nil {
			return failure(errors.New("surface required"))
		}
		p, err := auth.FromContext(ctx)
		if err != nil {
			return failure(err)
		}
		policy, err := d.Policy(ctx, p)
		if err != nil {
			return failure(err)
		}
		var key string
		switch input.Surface.Kind {
		case "native":
			key = input.Surface.BundleID
			if key == "" {
				return failure(fmt.Errorf("native surface bundleId required"))
			}
			if !policy.AllowAllNative && !policy.AllowedSurfaces[key] {
				return failure(fmt.Errorf("surface outside authorized scope"))
			}
		case "web":
			key = input.Surface.Origin
			if key == "" {
				return failure(fmt.Errorf("web surface origin required"))
			}
			if !policy.AllowAllWeb && !policy.AllowedSurfaces[key] {
				return failure(fmt.Errorf("surface outside authorized scope"))
			}
		default:
			return failure(fmt.Errorf("surface outside authorized scope"))
		}
		if input.NativeRoot != "" && (input.Surface.Kind != "native" || (input.NativeRoot != "menuBar" && input.NativeRoot != "focusedElement")) {
			return failure(errors.New("supported native observation root required"))
		}
		if input.WindowScope != nil {
			if input.NativeRoot != "" {
				return failure(errors.New("nativeRoot and windowScope are mutually exclusive"))
			}
			if err := native.ValidateNativeWindowRequest(input.Surface, input.WindowScope.Title, input.WindowScope.Role); err != nil {
				return failure(err)
			}
		}
		ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{GrantID: input.GrantID, SessionID: input.SessionID, Purpose: input.Purpose})
		var observed model.Observation
		if input.WindowScope != nil {
			if d.ObserveNativeWindow == nil {
				return failure(errors.New("exact native window observation unavailable"))
			}
			observed, err = d.ObserveNativeWindow(ctx, p, input.Surface, input.WindowScope.Title, input.WindowScope.Role)
		} else if input.NativeRoot != "" {
			if d.ObserveNativeRoot == nil {
				return failure(errors.New("scoped native observation unavailable"))
			}
			observed, err = d.ObserveNativeRoot(ctx, p, input.Surface, input.NativeRoot)
		} else {
			if d.Observe == nil {
				return failure(errors.New("observation unavailable"))
			}
			observed, err = d.Observe(ctx, p, input.Surface)
		}
		if err != nil {
			return failure(err)
		}
		if input.WindowScope != nil {
			if err := native.ValidateNativeWindowObservation(observed, input.Surface, input.WindowScope.Title, input.WindowScope.Role); err != nil {
				return failure(err)
			}
		} else if input.Surface.Kind == "native" && (observed.NativeRoot != input.NativeRoot || len(observed.WindowScope) != 0 || observed.WindowRootsOnly) {
			return failure(errors.New("native observation root does not match request"))
		}
		if input.NativeRoot != "" && (observed.NativeRoot != input.NativeRoot || observed.Surface != input.Surface) {
			return failure(errors.New("scoped native observation identity mismatch"))
		}
		return result(observed)
	})
}

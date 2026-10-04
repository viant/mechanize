package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	protocol "github.com/viant/mcp-protocol/server"
	"github.com/viant/mechanize/auth"
	repairs "github.com/viant/mechanize/engine/recovery"
	integration "github.com/viant/mechanize/integration/endly"
)

type RecoveryContextInput struct {
	SessionID string `json:"sessionId"`
	Purpose   string `json:"purpose"`
	repairs.ContextRequest
}

type RecoveryAdmissionInput struct {
	SessionID string `json:"sessionId"`
	Purpose   string `json:"purpose"`
	repairs.AdmissionRequest
}

func recoveryInput(request *schema.CallToolRequest, input any, limit int) error {
	if request == nil {
		return errors.New("bounded closed recovery input required")
	}
	raw, err := json.Marshal(request.Params.Arguments)
	if err != nil || len(raw) > limit {
		return errors.New("bounded closed recovery input required")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(input) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("closed recovery references required; caller proof is not accepted")
	}
	return nil
}

func recoveryContext(ctx context.Context, runtime *integration.Runtime, session, purpose string) (context.Context, auth.Principal, error) {
	if session == "" || len(session) > 256 || purpose == "" || len(purpose) > 4000 {
		return ctx, auth.Principal{}, errors.New("owned recovery session and bounded purpose required")
	}
	p, err := auth.FromContext(ctx)
	if err != nil {
		return ctx, p, err
	}
	if runtime == nil {
		return ctx, p, errors.New("owned recovery runtime unavailable")
	}
	if err = runtime.CheckSession(ctx, p, session); err != nil {
		return ctx, p, err
	}
	return auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: session, Purpose: purpose}), p, nil
}

func registerRecovery(base *protocol.DefaultHandler, service *repairs.Service, runtime *integration.Runtime) error {
	if service == nil {
		return nil
	}
	register := func(name, description string, inputType, outputType any, handler func(context.Context, *schema.CallToolRequest) (*schema.CallToolResult, *jsonrpc.Error)) error {
		var input schema.ToolInputSchema
		if err := input.Load(inputType); err != nil {
			return err
		}
		extra, ok := input.AdditionalProperties.(map[string]any)
		if !ok {
			extra = map[string]any{}
		}
		extra["additionalProperties"] = false
		input.AdditionalProperties = extra
		var output schema.ToolOutputSchema
		if err := output.Load(outputType); err != nil {
			return err
		}
		base.Registry.RegisterToolWithSchema(name, description, input, &output, handler)
		return nil
	}
	if err := register("mechanize_recovery_context", "Inspect a stopped owned run at its exact plan/revision under owned session consent and obtain bounded redacted repair context only from trusted fresh evidence/contracts. Unknown effects or unavailable authority return needsAttention. No execution or budget admission.", (*RecoveryContextInput)(nil), (*repairs.ContextResult)(nil), func(ctx context.Context, request *schema.CallToolRequest) (*schema.CallToolResult, *jsonrpc.Error) {
		var in *RecoveryContextInput
		if err := recoveryInput(request, &in, 8192); err != nil {
			return failure(err)
		}
		if in == nil {
			return failure(errors.New("exact owned recovery references required"))
		}
		ctx, p, err := recoveryContext(ctx, runtime, in.SessionID, in.Purpose)
		if err != nil {
			return failure(err)
		}
		planning, err := service.Context(ctx, p, in.ContextRequest)
		if err != nil {
			return failure(errors.New("owned recovery context unavailable"))
		}
		return result(planning)
	}); err != nil {
		return err
	}
	return register("mechanize_recovery_admit", "Validate strict objective-preserving patch under owned session consent against trusted context, CAS-persist immutable revision/lineage and finite budgets before any resume. No scheduler, grant or automatic effect replay. Only confirmed admission with readyToResume may be explicitly resumed under consent.", (*RecoveryAdmissionInput)(nil), (*repairs.AdmissionResult)(nil), func(ctx context.Context, request *schema.CallToolRequest) (*schema.CallToolResult, *jsonrpc.Error) {
		var in *RecoveryAdmissionInput
		if err := recoveryInput(request, &in, 256*1024); err != nil {
			return failure(err)
		}
		if in == nil {
			return failure(errors.New("exact owned recovery references and strict patch required"))
		}
		ctx, p, err := recoveryContext(ctx, runtime, in.SessionID, in.Purpose)
		if err != nil {
			return failure(err)
		}
		admitted, err := service.Admit(ctx, p, in.AdmissionRequest)
		if err != nil {
			if admitted.Reference != nil {
				r, rpcErr := result(admitted)
				bad := true
				r.IsError = &bad
				return r, rpcErr
			}
			return failure(errors.New("owned recovery admission rejected"))
		}
		return result(admitted)
	})
}

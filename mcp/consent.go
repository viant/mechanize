package mcp

import (
	"context"
	"errors"
	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	protocol "github.com/viant/mcp-protocol/server"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
)

type ConsentRequest func(context.Context, auth.Principal, string, consent.RequestInput) (consent.Request, error)
type ConsentRequestInput struct {
	SessionID       string         `json:"sessionId"`
	Scope           consent.Scope  `json:"scope"`
	Modes           []consent.Mode `json:"modes"`
	Purpose         string         `json:"purpose"`
	DurationSeconds int            `json:"durationSeconds"`
}
type PermissionRequired struct {
	Code          string `json:"code"`
	RequestID     string `json:"requestID"`
	DispatchState string `json:"dispatchState"`
}

// RegisterConsent exposes request submission only. Human decisions and grant
// revocation are private native-console operations, never requester tools.
func RegisterConsent(base *protocol.DefaultHandler, request ConsentRequest) error {
	if request == nil {
		return nil
	}
	return protocol.RegisterTool[*ConsentRequestInput, *PermissionRequired](base.Registry, "mechanize_permission_request", "Request bounded consent from the verified human console. Returns permissionRequired and requestID; submission does not grant permission or dispatch an action.", func(ctx context.Context, in *ConsentRequestInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if in == nil || in.SessionID == "" {
			return failure(errors.New("owned session and consent scope required"))
		}
		p, e := auth.FromContext(ctx)
		if e != nil {
			return failure(e)
		}
		r, e := request(ctx, p, in.SessionID, consent.RequestInput{Scope: in.Scope, Modes: in.Modes, Purpose: in.Purpose, DurationSeconds: in.DurationSeconds})
		if e != nil {
			return failure(e)
		}
		return result(PermissionRequired{Code: "permissionRequired", RequestID: r.ID, DispatchState: "notDispatched"})
	})
}

type ConsentStatus func(context.Context, auth.Principal, string, string) (consent.RequestStatus, error)
type ConsentStatusInput struct {
	SessionID string `json:"sessionId"`
	RequestID string `json:"requestID"`
}

func RegisterConsentStatus(base *protocol.DefaultHandler, status ConsentStatus) error {
	if status == nil {
		return nil
	}
	return protocol.RegisterTool[*ConsentStatusInput, *consent.RequestStatus](base.Registry, "mechanize_permission_status", "Inspect only your client/session's permission request and approved grant reference. Cannot approve, deny or change access.", func(ctx context.Context, input *ConsentStatusInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if input == nil || input.SessionID == "" || input.RequestID == "" {
			return failure(errors.New("sessionId and requestID required"))
		}
		p, err := auth.FromContext(ctx)
		if err != nil {
			return failure(err)
		}
		value, err := status(ctx, p, input.SessionID, input.RequestID)
		if err != nil {
			return failure(err)
		}
		return result(value)
	})
}

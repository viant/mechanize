package durable

import (
	"context"
	"encoding/json"
	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/credentialdeliveryfinish"
	"github.com/viant/mechanize/data/credentialdeliveryget"
	"github.com/viant/mechanize/data/credentialdeliveryreserve"
	"github.com/viant/xdatly/handler"
)

func credentialDeliveryTarget(pkg, name, method string) exec.ComponentTarget {
	return exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/" + pkg, Name: name}, Route: spec.RouteRef{Method: method, Path: "/internal/data/" + pkg}}
}

// ReadCredentialDelivery is private exact metadata readback, not a public catalog.
func (b *Builder) ReadCredentialDelivery(ctx context.Context, p auth.Principal) (data.CredentialDeliveryRecord, error) {
	a, e := data.RequireCredentialDeliveryAuthority(ctx)
	if e != nil {
		return data.CredentialDeliveryRecord{}, data.ErrCredentialDeliveryAuthority
	}
	in := &credentialdeliveryget.CredentialDeliveryGetInput{}
	in.SetNamespace(a.Record.Namespace)
	in.SetClientID(a.Record.ClientID)
	in.SetAttemptID(a.Record.AttemptID)
	value, e := b.invokeCredentialDeliveryComponent(ctx, p, exec.ComponentRequest{Target: credentialDeliveryTarget("credentialdeliveryget", "CredentialDeliveryGet", "GET"), Input: in})
	if e != nil {
		return data.CredentialDeliveryRecord{}, data.ErrCredentialDeliveryAuthority
	}
	out, ok := value.(*credentialdeliveryget.CredentialDeliveryGetOutput)
	if !ok || len(out.Data) != 1 {
		return data.CredentialDeliveryRecord{}, data.ErrCredentialDeliveryAuthority
	}
	raw, e := json.Marshal(out.Data[0])
	if e != nil {
		return data.CredentialDeliveryRecord{}, data.ErrCredentialDeliveryAuthority
	}
	var r data.CredentialDeliveryRecord
	if json.Unmarshal(raw, &r) != nil {
		return r, data.ErrCredentialDeliveryAuthority
	}
	return r, nil
}

// ReserveCredentialDelivery requires confirmed generated commit AND matching
// readback before the host may privately encode credentials. No browser I/O here.
func (b *Builder) ReserveCredentialDelivery(ctx context.Context, p auth.Principal) error {
	a, e := data.RequireCredentialDeliveryAuthority(ctx)
	if e != nil {
		return data.ErrCredentialDeliveryAuthority
	}
	r := a.Record
	if a.Before != nil {
		return data.ErrCredentialDeliveryAuthority
	}
	row := &credentialdeliveryreserve.Delivery{}
	row.SetPurposeHash(&r.PurposeHash)
	row.SetNamespace(&r.Namespace)
	row.SetClientId(&r.ClientID)
	row.SetSessionId(&r.SessionID)
	row.SetAttemptId(&r.AttemptID)
	row.SetSelectionId(&r.SelectionID)
	row.SetSelectedRevision(&r.SelectedRevision)
	row.SetGrantId(&r.GrantID)
	row.SetOrigin(&r.Origin)
	row.SetProfileChannel(&r.ProfileChannel)
	row.SetBrowserInstance(&r.BrowserInstance)
	row.SetDocumentId(&r.DocumentID)
	row.SetDocumentGeneration(&r.DocumentGeneration)
	row.SetTabId(&r.TabID)
	row.SetBrokerEpoch(&r.BrokerEpoch)
	row.SetChannelEpoch(&r.ChannelEpoch)
	row.SetScopeHash(&r.ScopeHash)
	row.SetRendererLeaseId(&r.RendererLeaseID)
	row.SetRendererLeaseGeneration(&r.RendererLeaseGeneration)
	row.SetChromeStartToken(&r.ChromeStartToken)
	row.SetNativeHostStartToken(&r.NativeHostStartToken)
	row.SetDispatchState(&r.DispatchState)
	row.SetProtectionState(&r.ProtectionState)
	row.SetRevision(&r.Revision)
	row.SetCreatedAt(&r.CreatedAt)
	row.SetUpdatedAt(&r.UpdatedAt)
	audit := &credentialdeliveryreserve.Audit{}
	audit.SetNamespace(&r.Namespace)
	audit.SetClientId(&r.ClientID)
	audit.SetAttemptId(&r.AttemptID)
	audit.SetRevision(&r.Revision)
	audit.SetDispatchState(&r.DispatchState)
	audit.SetProtectionState(&r.ProtectionState)
	audit.SetCreatedAt(&r.UpdatedAt)
	row.SetAudit([]*credentialdeliveryreserve.Audit{audit})
	in := &credentialdeliveryreserve.CredentialDeliveryReserveInput{}
	in.SetNamespace(r.Namespace)
	in.SetClientID(r.ClientID)
	in.SetAttemptID(r.AttemptID)
	in.SetCredentialDeliveryReserve([]*credentialdeliveryreserve.Delivery{row})
	committed := false
	_, e = b.invokeCredentialDeliveryComponent(ctx, p, exec.ComponentRequest{Target: credentialDeliveryTarget("credentialdeliveryreserve", "CredentialDeliveryReserve", "POST"), Input: in, Completion: func(o handler.Outcome) { committed = o.CommitConfirmed() }})
	if e != nil || !committed {
		return data.ErrCredentialDeliveryAuthority
	}
	actual, e := b.ReadCredentialDelivery(ctx, p)
	if e != nil || actual != r {
		return data.ErrCredentialDeliveryAuthority
	}
	return nil
}

func (b *Builder) FinishCredentialDelivery(ctx context.Context, p auth.Principal) error {
	a, e := data.RequireCredentialDeliveryAuthority(ctx)
	if e != nil {
		return data.ErrCredentialDeliveryAuthority
	}
	r := a.Record
	if a.Before == nil {
		return data.ErrCredentialDeliveryAuthority
	}
	row := &credentialdeliveryfinish.Delivery{}
	row.SetRevision(&r.Revision)
	row.SetPurposeHash(&r.PurposeHash)
	row.SetNamespace(&r.Namespace)
	row.SetClientId(&r.ClientID)
	row.SetSessionId(&r.SessionID)
	row.SetAttemptId(&r.AttemptID)
	row.SetSelectionId(&r.SelectionID)
	row.SetSelectedRevision(&r.SelectedRevision)
	row.SetGrantId(&r.GrantID)
	row.SetOrigin(&r.Origin)
	row.SetProfileChannel(&r.ProfileChannel)
	row.SetBrowserInstance(&r.BrowserInstance)
	row.SetDocumentId(&r.DocumentID)
	row.SetDocumentGeneration(&r.DocumentGeneration)
	row.SetTabId(&r.TabID)
	row.SetBrokerEpoch(&r.BrokerEpoch)
	row.SetChannelEpoch(&r.ChannelEpoch)
	row.SetScopeHash(&r.ScopeHash)
	row.SetRendererLeaseId(&r.RendererLeaseID)
	row.SetRendererLeaseGeneration(&r.RendererLeaseGeneration)
	row.SetChromeStartToken(&r.ChromeStartToken)
	row.SetNativeHostStartToken(&r.NativeHostStartToken)
	row.SetDispatchState(&r.DispatchState)
	row.SetProtectionState(&r.ProtectionState)
	row.SetCreatedAt(&r.CreatedAt)
	row.SetUpdatedAt(&r.UpdatedAt)
	row.SetRevision(&a.Before.Revision)
	audit := &credentialdeliveryfinish.Audit{}
	audit.SetNamespace(&r.Namespace)
	audit.SetClientId(&r.ClientID)
	audit.SetAttemptId(&r.AttemptID)
	audit.SetRevision(&r.Revision)
	audit.SetDispatchState(&r.DispatchState)
	audit.SetProtectionState(&r.ProtectionState)
	audit.SetCreatedAt(&r.UpdatedAt)
	row.SetAudit([]*credentialdeliveryfinish.Audit{audit})
	in := &credentialdeliveryfinish.CredentialDeliveryFinishInput{}
	in.SetNamespace(r.Namespace)
	in.SetClientID(r.ClientID)
	in.SetAttemptID(r.AttemptID)
	in.SetCredentialDeliveryFinish([]*credentialdeliveryfinish.Delivery{row})
	committed := false
	_, e = b.invokeCredentialDeliveryComponent(ctx, p, exec.ComponentRequest{Target: credentialDeliveryTarget("credentialdeliveryfinish", "CredentialDeliveryFinish", "PATCH"), Input: in, Completion: func(o handler.Outcome) { committed = o.CommitConfirmed() }})
	if e != nil || !committed {
		return data.ErrCredentialDeliveryAuthority
	}
	actual, e := b.ReadCredentialDelivery(ctx, p)
	if e != nil || actual != r {
		return data.ErrCredentialDeliveryAuthority
	}
	return nil
}

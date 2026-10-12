package durable

import (
	"context"
	"encoding/json"
	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/credentialpreparationget"
	"github.com/viant/mechanize/data/credentialpreparationreserve"
	"github.com/viant/xdatly/handler"
)

// ReserveCredentialPreparation must complete before Pin or any private probe.
// It requires actual generated commit confirmation and exact metadata readback.
func (b *Builder) ReserveCredentialPreparation(ctx context.Context, p auth.Principal) error {
	r, e := data.RequireCredentialPreparationAuthority(ctx)
	if e != nil {
		return data.ErrCredentialDeliveryAuthority
	}
	row := &credentialpreparationreserve.Preparation{}
	row.SetNamespace(&r.Namespace)
	row.SetClientId(&r.ClientID)
	row.SetSessionId(&r.SessionID)
	row.SetPreparationId(&r.PreparationID)
	row.SetGrantId(&r.GrantID)
	row.SetPurposeHash(&r.PurposeHash)
	row.SetOrigin(&r.Origin)
	row.SetSelectedRevision(&r.SelectedRevision)
	row.SetProtectionState(&r.ProtectionState)
	row.SetRevision(&r.Revision)
	row.SetCreatedAt(&r.CreatedAt)
	in := &credentialpreparationreserve.CredentialPreparationReserveInput{}
	in.SetNamespace(r.Namespace)
	in.SetClientID(r.ClientID)
	in.SetPreparationID(r.PreparationID)
	in.SetCredentialPreparationReserve([]*credentialpreparationreserve.Preparation{row})
	committed := false
	_, e = b.invokeCredentialDeliveryComponent(ctx, p, exec.ComponentRequest{Target: credentialDeliveryTarget("credentialpreparationreserve", "CredentialPreparationReserve", "POST"), Input: in, Completion: func(o handler.Outcome) { committed = o.CommitConfirmed() }})
	if e != nil || !committed {
		return data.ErrCredentialDeliveryAuthority
	}
	actual, e := b.ReadCredentialPreparation(ctx, p)
	if e != nil || actual != r {
		return data.ErrCredentialDeliveryAuthority
	}
	return nil
}
func (b *Builder) ReadCredentialPreparation(ctx context.Context, p auth.Principal) (data.CredentialPreparationRecord, error) {
	r, e := data.RequireCredentialPreparationAuthority(ctx)
	if e != nil {
		return data.CredentialPreparationRecord{}, data.ErrCredentialDeliveryAuthority
	}
	in := &credentialpreparationget.CredentialPreparationGetInput{}
	in.SetNamespace(r.Namespace)
	in.SetClientID(r.ClientID)
	in.SetPreparationID(r.PreparationID)
	value, e := b.invokeCredentialDeliveryComponent(ctx, p, exec.ComponentRequest{Target: credentialDeliveryTarget("credentialpreparationget", "CredentialPreparationGet", "GET"), Input: in})
	if e != nil {
		return data.CredentialPreparationRecord{}, data.ErrCredentialDeliveryAuthority
	}
	out, ok := value.(*credentialpreparationget.CredentialPreparationGetOutput)
	if !ok || len(out.Data) != 1 {
		return data.CredentialPreparationRecord{}, data.ErrCredentialDeliveryAuthority
	}
	raw, e := json.Marshal(out.Data[0])
	if e != nil {
		return data.CredentialPreparationRecord{}, data.ErrCredentialDeliveryAuthority
	}
	var actual data.CredentialPreparationRecord
	if json.Unmarshal(raw, &actual) != nil {
		return actual, data.ErrCredentialDeliveryAuthority
	}
	return actual, nil
}

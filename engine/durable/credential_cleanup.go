package durable

import (
	"context"
	"encoding/json"

	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/credentialpreparationfinish"
	"github.com/viant/mechanize/data/credentialrecoveryload"
	"github.com/viant/xdatly/handler"
)

// LoadCredentialRecovery is an internal metadata reader under the actual user
// lock. It never reads the Vault or returns data directly to a tool caller.
func (b *Builder) LoadCredentialRecovery(ctx context.Context, p auth.Principal, id string) (data.CredentialPreparationRecord, []data.CredentialDeliveryRecord, error) {
	clientID := p.ClientID
	if scope, ok := data.CredentialPreflightLifecycleScope(ctx); ok {
		if scope.Namespace != p.Namespace || scope.PreparationID != id {
			return data.CredentialPreparationRecord{}, nil, data.ErrCredentialDeliveryAuthority
		}
		// This value selects metadata only. Invocation retains the actual principal.
		clientID = scope.ClientID
	}
	if scope, ok := data.CredentialSourceLifecycleScope(ctx); ok {
		if scope.Namespace != p.Namespace || scope.PreparationID != id {
			return data.CredentialPreparationRecord{}, nil, data.ErrCredentialDeliveryAuthority
		}
		clientID = scope.ClientID // Metadata selector only; actual actor remains unchanged.
	}
	return readCredentialRecoveryClient(ctx, p.Namespace, clientID, id, func(c context.Context, r exec.ComponentRequest) (any, error) {
		return b.invokeCredentialDeliveryComponent(c, p, r)
	})
}

func readCredentialRecovery(ctx context.Context, p auth.Principal, id string, invoke func(context.Context, exec.ComponentRequest) (any, error)) (data.CredentialPreparationRecord, []data.CredentialDeliveryRecord, error) {
	return readCredentialRecoveryClient(ctx, p.Namespace, p.ClientID, id, invoke)
}
func readCredentialRecoveryClient(ctx context.Context, namespace, clientID, id string, invoke func(context.Context, exec.ComponentRequest) (any, error)) (data.CredentialPreparationRecord, []data.CredentialDeliveryRecord, error) {
	in := &credentialrecoveryload.CredentialRecoveryLoadInput{}
	in.SetNamespace(namespace)
	in.SetClientID(clientID)
	in.SetPreparationID(id)
	value, e := invoke(ctx, exec.ComponentRequest{Target: credentialDeliveryTarget("credentialrecoveryload", "CredentialRecoveryLoad", "GET"), Input: in})
	if e != nil {
		return data.CredentialPreparationRecord{}, nil, e
	}
	out, ok := value.(*credentialrecoveryload.CredentialRecoveryLoadOutput)
	if !ok || len(out.Data) != 1 {
		return data.CredentialPreparationRecord{}, nil, data.ErrCredentialDeliveryAuthority
	}
	raw, e := json.Marshal(out.Data[0])
	if e != nil {
		return data.CredentialPreparationRecord{}, nil, e
	}
	var snapshot struct {
		data.CredentialPreparationRecord
		Deliveries []data.CredentialDeliveryRecord `json:"deliveries"`
	}
	if json.Unmarshal(raw, &snapshot) != nil || snapshot.Namespace != namespace || snapshot.ClientID != clientID || snapshot.PreparationID != id || len(snapshot.Deliveries) > 512 {
		return data.CredentialPreparationRecord{}, nil, data.ErrCredentialDeliveryAuthority
	}
	return snapshot.CredentialPreparationRecord, snapshot.Deliveries, nil
}

// CloseCredentialPreparation CAS-closes the final parent only after the caller
// supplies a sealed cleanup authority and all child protections are closed.
// Its SQL audit trigger shares the generated transaction. No history is deleted.
func (b *Builder) CloseCredentialPreparation(ctx context.Context, p auth.Principal) error {
	r, e := data.RequireCredentialPreparationAuthority(ctx)
	if e != nil || r.ProtectionState != "closed" || r.Revision != 2 {
		return data.ErrCredentialDeliveryAuthority
	}
	if before, preflight, err := data.CredentialPreflightCleanupPreparation(ctx); err != nil {
		return err
	} else if preflight {
		actual, children, err := b.LoadCredentialRecovery(ctx, p, r.PreparationID)
		if err != nil || actual != before || len(children) != 0 {
			return data.ErrCredentialDeliveryAuthority
		}
	}
	row := &credentialpreparationfinish.Preparation{}
	row.SetNamespace(&r.Namespace)
	row.SetClientId(&r.ClientID)
	row.SetSessionId(&r.SessionID)
	row.SetPreparationId(&r.PreparationID)
	row.SetGrantId(&r.GrantID)
	row.SetPurposeHash(&r.PurposeHash)
	row.SetOrigin(&r.Origin)
	row.SetSelectedRevision(&r.SelectedRevision)
	row.SetProtectionState(&r.ProtectionState)
	row.SetCreatedAt(&r.CreatedAt)
	previous := r.Revision - 1
	row.SetRevision(&previous)
	in := &credentialpreparationfinish.CredentialPreparationFinishInput{}
	in.SetNamespace(r.Namespace)
	in.SetClientID(r.ClientID)
	in.SetPreparationID(r.PreparationID)
	in.SetCredentialPreparationFinish([]*credentialpreparationfinish.Preparation{row})
	committed := false
	_, e = b.invokeCredentialDeliveryComponent(ctx, p, exec.ComponentRequest{Target: credentialDeliveryTarget("credentialpreparationfinish", "CredentialPreparationFinish", "PATCH"), Input: in, Completion: func(o handler.Outcome) { committed = o.CommitConfirmed() }})
	if e != nil || !committed {
		return data.ErrCredentialDeliveryAuthority
	}
	actual, e := b.ReadCredentialPreparation(ctx, p)
	if e != nil || actual != r {
		return data.ErrCredentialDeliveryAuthority
	}
	return nil
}

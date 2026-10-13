package durable

import (
	"context"
	"encoding/json"
	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/credentialprotectionscopeget"
	"github.com/viant/mechanize/data/credentialprotectionscopelegacy"
	"github.com/viant/mechanize/data/credentialprotectionscopelist"
	"github.com/viant/mechanize/data/credentialprotectionscopereserve"
	"github.com/viant/xdatly/handler"
)

func (b *Builder) ReserveCredentialProtectionScope(ctx context.Context, p auth.Principal) error {
	r, e := data.RequireCredentialProtectionScopeAuthority(ctx)
	if e != nil {
		return e
	}
	row := &credentialprotectionscopereserve.ProtectionScope{}
	row.SetNamespace(&r.Namespace)
	row.SetClientId(&r.ClientID)
	row.SetPreparationId(&r.PreparationID)
	row.SetOrigin(&r.Origin)
	row.SetProfileChannel(&r.ProfileChannel)
	row.SetBrowserInstance(&r.BrowserInstance)
	row.SetTabId(&r.TabID)
	row.SetFrameId(&r.FrameID)
	row.SetDocumentId(&r.DocumentID)
	row.SetDocumentGeneration(&r.DocumentGeneration)
	row.SetChromeStartToken(&r.ChromeStartToken)
	row.SetBrokerEpoch(&r.BrokerEpoch)
	row.SetChannelEpoch(&r.ChannelEpoch)
	row.SetScopeHash(&r.ScopeHash)
	row.SetLoginRouteSha256(&r.LoginRouteSHA256)
	row.SetCreatedAt(&r.CreatedAt)

	in := &credentialprotectionscopereserve.CredentialProtectionScopeReserveInput{}
	in.SetNamespace(r.Namespace)
	in.SetClientID(r.ClientID)
	in.SetPreparationID(r.PreparationID)
	in.SetCredentialProtectionScopeReserve([]*credentialprotectionscopereserve.ProtectionScope{row})
	committed := false
	_, e = b.invokeCredentialDeliveryComponent(ctx, p, exec.ComponentRequest{Target: credentialDeliveryTarget("credentialprotectionscopereserve", "CredentialProtectionScopeReserve", "POST"), Input: in, Completion: func(o handler.Outcome) { committed = o.CommitConfirmed() }})
	if e != nil || !committed {
		return data.ErrCredentialDeliveryAuthority
	}
	read := &credentialprotectionscopeget.CredentialProtectionScopeGetInput{}
	read.SetNamespace(r.Namespace)
	read.SetClientID(r.ClientID)
	read.SetPreparationID(r.PreparationID)
	value, e := b.invokeCredentialDeliveryComponent(ctx, p, exec.ComponentRequest{Target: credentialDeliveryTarget("credentialprotectionscopeget", "CredentialProtectionScopeGet", "GET"), Input: read})
	if e != nil {
		return e
	}
	out, ok := value.(*credentialprotectionscopeget.CredentialProtectionScopeGetOutput)
	if !ok || len(out.Data) != 1 {
		return data.ErrCredentialDeliveryAuthority
	}
	raw, e := json.Marshal(out.Data[0])
	var actual data.CredentialProtectionScopeRecord
	if e != nil || json.Unmarshal(raw, &actual) != nil || actual != r {
		return data.ErrCredentialDeliveryAuthority
	}
	return nil
}

// CredentialProtection is host-only metadata. Legacy owned attempts remain
// available for independently proving absence; no exposure authority is stored.
type CredentialProtection struct {
	Scope        data.CredentialProtectionScopeRecord
	Preparation  data.CredentialPreparationRecord
	Attempts     []data.CredentialDeliveryRecord
	LegacySource *data.CredentialProtectionScopeRecord
}

// CredentialProtectionScopes retains the same user-lock ordering as the old
// namespace barrier. Every held preparation/unknown attempt is represented;
// absent exact scope stays an origin-only barrier, including for another client.
func (b *Builder) CredentialProtectionScopes(ctx context.Context, p auth.Principal, legacyOrigin ...string) ([]CredentialProtection, error) {
	actual, e := auth.FromContext(ctx)
	if b == nil || e != nil || actual.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || p.ClientID == "" || !actual.HasScope("desktop:control") && !actual.HasScope("desktop:observe") {
		return nil, protectionMetadataFailure("identity", auth.ErrUnauthorized)
	}
	user, release, held, e := b.heldInvocation(ctx, p)
	if e != nil {
		return nil, protectionMetadataFailure("heldContext", e)
	}
	if held {
		defer release()
	} else {
		ctx, user, e = b.bound(ctx, p, 0)
		if e != nil {
			return nil, protectionMetadataFailure("bind", e)
		}
		user.mu.Lock()
		defer user.mu.Unlock()
	}
	if user == nil || user.server == nil {
		return nil, protectionMetadataFailure("bind", data.ErrCredentialDeliveryAuthority)
	}
	return readCredentialProtectionProjection(ctx, p, legacyOrigin, func(c context.Context, r exec.ComponentRequest) (any, error) {
		return user.server.InvokeComponent(c, r)
	})
}

func readCredentialProtectionProjection(ctx context.Context, p auth.Principal, legacyOrigin []string, invoke func(context.Context, exec.ComponentRequest) (any, error)) ([]CredentialProtection, error) {
	in := &credentialprotectionscopelist.CredentialProtectionScopeListInput{}
	in.SetNamespace(p.Namespace)
	value, e := invoke(ctx, exec.ComponentRequest{Target: credentialDeliveryTarget("credentialprotectionscopelist", "CredentialProtectionScopeList", "GET"), Input: in})
	if e != nil {
		return nil, protectionMetadataFailure("scopeList", e)
	}
	out, ok := value.(*credentialprotectionscopelist.CredentialProtectionScopeListOutput)
	if !ok || out == nil {
		return nil, protectionMetadataFailure("projection", data.ErrCredentialDeliveryAuthority)
	}
	if len(out.Data) > 512 {
		return nil, protectionMetadataFailure("projection", errProtectionMetadataCapacity)
	}
	result := make([]CredentialProtection, 0, len(out.Data))
	for _, row := range out.Data {
		raw, e := json.Marshal(row)
		var r data.CredentialProtectionScopeRecord
		if e != nil || json.Unmarshal(raw, &r) != nil || r.Namespace != p.Namespace || r.ClientID == "" || !r.ValidOrigin() || r.PreparationID == "" {
			return nil, protectionMetadataFailure("projection", data.ErrCredentialDeliveryAuthority)
		}
		if r.Exact() {
			if r.Validate() != nil {
				return nil, protectionMetadataFailure("projection", data.ErrCredentialDeliveryAuthority)
			}
		} else {
			minimal := data.CredentialProtectionScopeRecord{Namespace: r.Namespace, ClientID: r.ClientID, PreparationID: r.PreparationID, Origin: r.Origin}
			if r != minimal {
				return nil, protectionMetadataFailure("projection", data.ErrCredentialDeliveryAuthority)
			}
		}
		snapshot := CredentialProtection{Scope: r}

		result = append(result, snapshot)
	}
	// One narrow metadata projection for all relevant legacy sources, never an
	// N+1 full delivery-history read on ordinary operation admission.
	if len(legacyOrigin) == 1 {
		needed := false
		for _, r := range result {
			needed = needed || r.Scope.ClientID == p.ClientID && r.Scope.Origin == legacyOrigin[0] && !r.Scope.Exact()
		}
		if needed {
			in := &credentialprotectionscopelegacy.CredentialProtectionScopeLegacyInput{}
			in.SetNamespace(p.Namespace)
			in.SetClientID(p.ClientID)
			in.SetOrigin(legacyOrigin[0])
			value, e := invoke(ctx, exec.ComponentRequest{Target: credentialDeliveryTarget("credentialprotectionscopelegacy", "CredentialProtectionScopeLegacy", "GET"), Input: in})
			if e != nil {
				return nil, protectionMetadataFailure("legacyList", e)
			}
			rows, ok := value.(*credentialprotectionscopelegacy.CredentialProtectionScopeLegacyOutput)
			if !ok || rows == nil {
				return nil, protectionMetadataFailure("legacyProjection", data.ErrCredentialDeliveryAuthority)
			}
			if len(rows.Data) > 512 {
				return nil, protectionMetadataFailure("legacyProjection", errProtectionMetadataCapacity)
			}
			seen := map[string]bool{}
			for _, row := range rows.Data {
				raw, e := json.Marshal(row)
				var source data.CredentialProtectionScopeRecord
				if e != nil || json.Unmarshal(raw, &source) != nil || source.Namespace != p.Namespace || source.ClientID != p.ClientID || source.Origin != legacyOrigin[0] || source.DocumentID == "" || source.TabID <= 0 || source.DocumentGeneration < 1 || source.ChromeStartToken == "" || seen[source.PreparationID] {
					return nil, protectionMetadataFailure("legacyProjection", data.ErrCredentialDeliveryAuthority)
				}
				seen[source.PreparationID] = true
				for i := range result {
					if result[i].Scope.PreparationID == source.PreparationID && result[i].Scope.ClientID == p.ClientID && !result[i].Scope.Exact() {
						copy := source
						result[i].LegacySource = &copy
					}
				}
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, protectionMetadataFailure("context", err)
	}
	return result, nil
}

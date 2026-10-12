package durable

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	get "github.com/viant/mechanize/data/browseractivationbindingget"
)

// BrowserActivationBinding reads original immutable metadata; it does not mint
// reconciliation evidence, change a receipt or acquire an input capability.
func (b *Builder) BrowserActivationBinding(ctx context.Context, p auth.Principal, browserAttempt string) (data.BrowserActivationBindingAuthority, error) {
	var record data.BrowserActivationBindingAuthority
	actual, e := auth.FromContext(ctx)
	if e != nil || p.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || p.ClientID == "" {
		return record, auth.ErrUnauthorized
	}
	ctx, user, e := b.bound(ctx, p, 0)
	if e != nil {
		return record, e
	}
	user.mu.Lock()
	defer user.mu.Unlock()
	in := &get.LoadBrowserActivationBindingInput{}
	in.SetNamespace(p.Namespace)
	in.SetClientID(p.ClientID)
	in.SetBrowserAttemptID(browserAttempt)
	value, e := invoke(ctx, user.server, "browseractivationbindingget", "LoadBrowserActivationBinding", "GET", in, false)
	if e != nil {
		return record, e
	}
	out, ok := value.(*get.LoadBrowserActivationBindingOutput)
	if !ok || out == nil || len(out.Data) != 1 || out.Data[0] == nil {
		return record, errors.New("original activation binding unavailable")
	}
	raw, e := json.Marshal(out.Data[0])
	if e != nil || json.Unmarshal(raw, &record) != nil || record.Validate() != nil || record.Namespace != p.Namespace || record.ClientID != p.ClientID || record.BrowserAttemptID != browserAttempt {
		return data.BrowserActivationBindingAuthority{}, errors.New("original activation binding mismatch")
	}
	return record, nil
}

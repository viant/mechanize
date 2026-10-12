package data

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/viant/mechanize/auth"
)

// CredentialPreparationRecord is created BEFORE any private browser probe. It
// deliberately has no document, renderer lease, account alias or Vault reference.
type CredentialPreparationRecord struct {
	Namespace        string `json:"namespace"`
	ClientID         string `json:"clientId"`
	SessionID        string `json:"sessionId"`
	PreparationID    string `json:"preparationId"`
	GrantID          string `json:"grantId"`
	PurposeHash      string `json:"purposeHash"`
	Origin           string `json:"origin"`
	SelectedRevision string `json:"selectedRevision"`
	ProtectionState  string `json:"protectionState"`
	Revision         int    `json:"revision"`
	CreatedAt        string `json:"createdAt"`
}
type credentialPreparationKey struct{}
type credentialPreparationAuthority struct {
	record CredentialPreparationRecord
	guard  func(context.Context) error
	active atomic.Bool
}

func validateCredentialPreparation(ctx context.Context, r CredentialPreparationRecord) error {
	if cleanupPreparationAllowed(ctx, r) {
		return nil
	}
	p, e := auth.FromContext(ctx)
	c, ok := auth.ConsentBindingFromContext(ctx)
	if e != nil || p.Validate() != nil || ctx.Err() != nil || !p.HasScope("desktop:control") || p.ClientID == "" || p.Namespace != r.Namespace || p.ClientID != r.ClientID || !ok || c.SessionID != r.SessionID || c.GrantID != r.GrantID || c.Purpose == "" || CredentialDeliveryPurposeHash(c.Purpose) != r.PurposeHash {
		return ErrCredentialDeliveryAuthority
	}
	if _, e = RequireScope(ctx, r.Namespace); e != nil {
		return ErrCredentialDeliveryAuthority
	}
	for _, v := range []string{r.Namespace, r.PreparationID, r.PurposeHash, r.SelectedRevision} {
		if !deliveryHex.MatchString(v) {
			return ErrCredentialDeliveryAuthority
		}
	}
	for _, v := range []string{r.ClientID, r.SessionID, r.GrantID} {
		if v == "" || len(v) > 256 || strings.ContainsAny(v, "\x00\r\n") {
			return ErrCredentialDeliveryAuthority
		}
	}
	u, e := url.Parse(r.Origin)
	if e != nil || len(r.Origin) > 2048 || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != r.Origin || u.Host != strings.ToLower(u.Host) || strings.HasSuffix(u.Host, ":443") || strings.HasSuffix(u.Hostname(), ".") {
		return ErrCredentialDeliveryAuthority
	}
	created, e := time.Parse(time.RFC3339Nano, r.CreatedAt)
	if e != nil || created.After(time.Now().Add(time.Minute)) || r.ProtectionState != "held" || r.Revision != 1 {
		return ErrCredentialDeliveryAuthority
	}
	return nil
}

// WithCredentialPreparationAuthority is a trusted host seam, not a caller claim.
// Guard must recheck the real original consent and exclusive pre-admission lease.
func WithCredentialPreparationAuthority(ctx context.Context, r CredentialPreparationRecord, guard func(context.Context) error) (context.Context, func(), error) {
	if validateCredentialPreparation(ctx, r) != nil || !credentialDeliveryGuard(ctx, guard) {
		return nil, nil, ErrCredentialDeliveryAuthority
	}
	a := &credentialPreparationAuthority{record: r, guard: guard}
	a.active.Store(true)
	return context.WithValue(ctx, credentialPreparationKey{}, a), func() { a.active.Store(false) }, nil
}
func RequireCredentialPreparationAuthority(ctx context.Context) (CredentialPreparationRecord, error) {
	a, ok := ctx.Value(credentialPreparationKey{}).(*credentialPreparationAuthority)
	if !ok || !a.active.Load() || validateCredentialPreparation(ctx, a.record) != nil || !credentialDeliveryGuard(ctx, a.guard) {
		return CredentialPreparationRecord{}, ErrCredentialDeliveryAuthority
	}
	return a.record, nil
}
func ValidateCredentialPreparationRow(ctx context.Context, row any) error {
	expected, e := RequireCredentialPreparationAuthority(ctx)
	if e != nil {
		return e
	}
	raw, e := json.Marshal(row)
	if e != nil {
		return ErrCredentialDeliveryAuthority
	}
	var actual CredentialPreparationRecord
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&actual) != nil || actual != expected {
		return ErrCredentialDeliveryAuthority
	}
	return nil
}

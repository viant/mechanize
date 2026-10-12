package data

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/viant/mechanize/auth"
)

var ErrCredentialDeliveryAuthority = errors.New("private credential delivery authority unavailable")
var deliveryHex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// CredentialDeliveryRecord is metadata only. It has no Vault reference, Target
// account, credential hash, raw payload, error message or arbitrary JSON column.
type CredentialDeliveryRecord struct {
	PurposeHash             string `json:"purposeHash"`
	SelectedRevision        string `json:"selectedRevision"`
	Namespace               string `json:"namespace"`
	ClientID                string `json:"clientId"`
	SessionID               string `json:"sessionId"`
	AttemptID               string `json:"attemptId"`
	SelectionID             string `json:"selectionId"`
	GrantID                 string `json:"grantId"`
	Origin                  string `json:"origin"`
	ProfileChannel          string `json:"profileChannel"`
	BrowserInstance         string `json:"browserInstance"`
	DocumentID              string `json:"documentId"`
	DocumentGeneration      int    `json:"documentGeneration"`
	TabID                   int    `json:"tabId"`
	BrokerEpoch             string `json:"brokerEpoch"`
	ChannelEpoch            string `json:"channelEpoch"`
	ScopeHash               string `json:"scopeHash"`
	RendererLeaseID         string `json:"rendererLeaseId"`
	RendererLeaseGeneration int    `json:"rendererLeaseGeneration"`
	ChromeStartToken        string `json:"chromeStartToken"`
	NativeHostStartToken    string `json:"nativeHostStartToken"`
	DispatchState           string `json:"dispatchState"`
	ProtectionState         string `json:"protectionState"`
	Revision                int    `json:"revision"`
	CreatedAt               string `json:"createdAt"`
	UpdatedAt               string `json:"updatedAt"`
}
type CredentialDeliveryAuthority struct {
	Before *CredentialDeliveryRecord
	Record CredentialDeliveryRecord
}
type deliveryAuthorityKey struct{}
type deliveryAuthority struct {
	value  CredentialDeliveryAuthority
	guard  func(context.Context) error
	active atomic.Bool
}

// WithCredentialDeliveryAuthority is a trusted in-process producer seam, never
// a transport endpoint. The caller must hold the actual delivery protection and
// consent lease; guard revalidates those concrete capabilities on every access.
// No default guard, NativeHuman conversion or caller readiness boolean exists.
func WithCredentialDeliveryAuthority(ctx context.Context, a CredentialDeliveryAuthority, guard func(context.Context) error) (context.Context, func(), error) {
	if guard == nil || validateDelivery(ctx, a) != nil || !credentialDeliveryGuard(ctx, guard) {
		return nil, nil, ErrCredentialDeliveryAuthority
	}
	if a.Before != nil {
		copy := *a.Before
		a.Before = &copy
	}
	seal := &deliveryAuthority{value: a, guard: guard}
	seal.active.Store(true)
	return context.WithValue(ctx, deliveryAuthorityKey{}, seal), func() { seal.active.Store(false) }, nil
}
func RequireCredentialDeliveryAuthority(ctx context.Context) (CredentialDeliveryAuthority, error) {
	seal, ok := ctx.Value(deliveryAuthorityKey{}).(*deliveryAuthority)
	if !ok || !seal.active.Load() || validateDelivery(ctx, seal.value) != nil || !credentialDeliveryGuard(ctx, seal.guard) {
		return CredentialDeliveryAuthority{}, ErrCredentialDeliveryAuthority
	}
	a := seal.value
	if a.Before != nil {
		copy := *a.Before
		a.Before = &copy
	}
	return a, nil
}
func validateDelivery(ctx context.Context, a CredentialDeliveryAuthority) error {
	if cleanupDeliveryAllowed(ctx, a) {
		return nil
	}
	p, e := auth.FromContext(ctx)
	r := a.Record
	binding, ok := auth.ConsentBindingFromContext(ctx)
	if e != nil || ctx.Err() != nil || !p.HasScope("desktop:control") || p.Namespace != r.Namespace || p.ClientID == "" || p.ClientID != r.ClientID || !ok || binding.SessionID != r.SessionID || binding.GrantID != r.GrantID || binding.Purpose == "" || r.PurposeHash != CredentialDeliveryPurposeHash(binding.Purpose) {
		return ErrCredentialDeliveryAuthority
	}
	if _, e = RequireScope(ctx, r.Namespace); e != nil {
		return ErrCredentialDeliveryAuthority
	}
	for _, v := range []string{r.Namespace, r.AttemptID, r.SelectionID, r.SelectedRevision, r.ScopeHash} {
		if !deliveryHex.MatchString(v) {
			return ErrCredentialDeliveryAuthority
		}
	}
	for _, v := range []string{r.ClientID, r.SessionID, r.GrantID, r.ProfileChannel, r.BrowserInstance, r.DocumentID, r.BrokerEpoch, r.ChannelEpoch, r.RendererLeaseID, r.ChromeStartToken, r.NativeHostStartToken} {
		if len(v) < 1 || len(v) > 256 || strings.ContainsAny(v, "\x00\r\n") {
			return ErrCredentialDeliveryAuthority
		}
	}
	u, e := url.Parse(r.Origin)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Opaque != "" || len(r.Origin) > 2048 || u.Fragment != "" || u.String() != r.Origin || u.Host != strings.ToLower(u.Host) || strings.HasSuffix(u.Host, ":443") || strings.HasSuffix(u.Hostname(), ".") {
		return ErrCredentialDeliveryAuthority
	}
	if r.DocumentGeneration < 1 || r.DocumentGeneration > 9007199254740991 || r.TabID < 1 || r.TabID > 2147483647 || r.RendererLeaseGeneration < 1 || r.RendererLeaseGeneration > 9007199254740991 || r.Revision < 1 || r.ProtectionState != "held" {
		return ErrCredentialDeliveryAuthority
	}
	created, e := time.Parse(time.RFC3339Nano, r.CreatedAt)
	if e != nil {
		return ErrCredentialDeliveryAuthority
	}
	updated, e := time.Parse(time.RFC3339Nano, r.UpdatedAt)
	if e != nil || updated.Before(created) || updated.After(time.Now().Add(time.Minute)) {
		return ErrCredentialDeliveryAuthority
	}
	if a.Before == nil {
		if r.Revision != 1 || r.DispatchState != "unknown" || r.CreatedAt != r.UpdatedAt {
			return ErrCredentialDeliveryAuthority
		}
		return nil
	}
	old := *a.Before
	oldUpdated, parseErr := time.Parse(time.RFC3339Nano, old.UpdatedAt)
	if parseErr != nil || updated.Before(oldUpdated) {
		return ErrCredentialDeliveryAuthority
	}
	normalized := r
	normalized.DispatchState = old.DispatchState
	normalized.UpdatedAt = old.UpdatedAt
	normalized.Revision = old.Revision
	if normalized != old || old.ProtectionState != "held" || old.DispatchState != "unknown" || r.Revision != old.Revision+1 || (r.DispatchState != "unknown" && r.DispatchState != "dispatched" && r.DispatchState != "notDispatched") {
		return ErrCredentialDeliveryAuthority
	}
	return nil
}

// ValidateCredentialDeliveryRow compares the generated entity to detached
// server-owned metadata and requires exactly one matching append-only audit.
func ValidateCredentialDeliveryRow(ctx context.Context, row any, previous any, finish bool) error {
	a, e := RequireCredentialDeliveryAuthority(ctx)
	if e != nil {
		return e
	}
	if finish != (a.Before != nil) {
		return ErrCredentialDeliveryAuthority
	}
	raw, e := json.Marshal(row)
	if e != nil {
		return ErrCredentialDeliveryAuthority
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return ErrCredentialDeliveryAuthority
	}
	auditRaw := fields["audit"]
	delete(fields, "audit")
	raw, _ = json.Marshal(fields)
	var record CredentialDeliveryRecord
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&record) != nil || record != a.Record {
		return ErrCredentialDeliveryAuthority
	}
	var audits []map[string]any
	if json.Unmarshal(auditRaw, &audits) != nil || len(audits) != 1 {
		return ErrCredentialDeliveryAuthority
	}
	expected := map[string]any{"namespace": record.Namespace, "clientId": record.ClientID, "attemptId": record.AttemptID, "revision": float64(record.Revision), "dispatchState": record.DispatchState, "protectionState": record.ProtectionState, "createdAt": record.UpdatedAt}
	if !reflect.DeepEqual(audits[0], expected) {
		return ErrCredentialDeliveryAuthority
	}
	if finish {
		oldRaw, e := json.Marshal(previous)
		if e != nil {
			return ErrCredentialDeliveryAuthority
		}
		var oldFields map[string]json.RawMessage
		if json.Unmarshal(oldRaw, &oldFields) != nil {
			return ErrCredentialDeliveryAuthority
		}
		delete(oldFields, "audit")
		oldRaw, _ = json.Marshal(oldFields)
		var old CredentialDeliveryRecord
		if json.Unmarshal(oldRaw, &old) != nil || old != *a.Before {
			return ErrCredentialDeliveryAuthority
		}
	}
	return nil
}

func credentialDeliveryGuard(ctx context.Context, guard func(context.Context) error) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return guard != nil && guard(ctx) == nil
}

func CredentialDeliveryPurposeHash(purpose string) string {
	digest := sha256.Sum256([]byte(purpose))
	return hex.EncodeToString(digest[:])
}

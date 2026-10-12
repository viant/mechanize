package data

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// CredentialProtectionScopeRecord supplements a preparation only after trusted
// browser admission. It is immutable provenance, never an exposure capability.
// The route hash excludes query/fragment; no URL, content or Vault bytes exist here.
type CredentialProtectionScopeRecord struct {
	Namespace          string `json:"namespace"`
	ClientID           string `json:"clientId"`
	PreparationID      string `json:"preparationId"`
	Origin             string `json:"origin"`
	ProfileChannel     string `json:"profileChannel"`
	BrowserInstance    string `json:"browserInstance"`
	TabID              int    `json:"tabId"`
	FrameID            int    `json:"frameId"`
	DocumentID         string `json:"documentId"`
	DocumentGeneration int    `json:"documentGeneration"`
	ChromeStartToken   string `json:"chromeStartToken"`
	BrokerEpoch        string `json:"brokerEpoch"`
	ChannelEpoch       string `json:"channelEpoch"`
	ScopeHash          string `json:"scopeHash"`
	LoginRouteSHA256   string `json:"loginRouteSha256"`
	CreatedAt          string `json:"createdAt"`
}

func (r CredentialProtectionScopeRecord) Exact() bool { return r.DocumentID != "" }
func (r CredentialProtectionScopeRecord) Validate() error {
	if !r.ValidOrigin() {
		return ErrCredentialDeliveryAuthority
	}
	for _, v := range []string{r.Namespace, r.PreparationID, r.ScopeHash, r.LoginRouteSHA256} {
		if !deliveryHex.MatchString(v) {
			return ErrCredentialDeliveryAuthority
		}
	}
	for _, v := range []string{r.ClientID, r.ProfileChannel, r.BrowserInstance, r.DocumentID, r.ChromeStartToken, r.BrokerEpoch, r.ChannelEpoch} {
		if v == "" || len(v) > 256 || strings.ContainsAny(v, "\x00\r\n") {
			return ErrCredentialDeliveryAuthority
		}
	}
	if r.TabID < 1 || r.TabID > 2147483647 || r.FrameID != 0 || r.DocumentGeneration < 1 || r.DocumentGeneration > 9007199254740991 {
		return ErrCredentialDeliveryAuthority
	}
	if _, err := time.Parse(time.RFC3339Nano, r.CreatedAt); err != nil {
		return ErrCredentialDeliveryAuthority
	}
	return nil
}

type protectionScopeAuthorityKey struct{}
type protectionScopeAuthority struct {
	record CredentialProtectionScopeRecord
	active atomic.Bool
}

// Existing preparation authority rechecks original consent and real protection
// guard for every generated row/read; scope cannot be claimed from tool JSON.
func WithCredentialProtectionScopeAuthority(ctx context.Context, r CredentialProtectionScopeRecord) (context.Context, func(), error) {
	p, e := RequireCredentialPreparationAuthority(ctx)
	if e != nil || r.Validate() != nil || r.Namespace != p.Namespace || r.ClientID != p.ClientID || r.PreparationID != p.PreparationID || r.Origin != p.Origin {
		return nil, nil, ErrCredentialDeliveryAuthority
	}
	a := &protectionScopeAuthority{record: r}
	a.active.Store(true)
	return context.WithValue(ctx, protectionScopeAuthorityKey{}, a), func() { a.active.Store(false) }, nil
}
func RequireCredentialProtectionScopeAuthority(ctx context.Context) (CredentialProtectionScopeRecord, error) {
	a, ok := ctx.Value(protectionScopeAuthorityKey{}).(*protectionScopeAuthority)
	p, e := RequireCredentialPreparationAuthority(ctx)
	if !ok || !a.active.Load() || e != nil || a.record.Validate() != nil || a.record.Namespace != p.Namespace || a.record.ClientID != p.ClientID || a.record.PreparationID != p.PreparationID || a.record.Origin != p.Origin {
		return CredentialProtectionScopeRecord{}, ErrCredentialDeliveryAuthority
	}
	return a.record, nil
}
func ValidateCredentialProtectionScopeRow(ctx context.Context, row any) error {
	expected, e := RequireCredentialProtectionScopeAuthority(ctx)
	if e != nil {
		return e
	}
	raw, e := json.Marshal(row)
	if e != nil {
		return ErrCredentialDeliveryAuthority
	}
	var actual CredentialProtectionScopeRecord
	if json.Unmarshal(raw, &actual) != nil || actual != expected {
		return ErrCredentialDeliveryAuthority
	}
	return nil
}

func (r CredentialProtectionScopeRecord) ValidOrigin() bool {
	u, e := url.Parse(r.Origin)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.String() != r.Origin || len(r.Origin) > 2048 {
		return false
	}

	return true
}

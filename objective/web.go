package objective

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

// WebIdentity names one original enrolled root document, including transport
// epochs. Generation is a minimum: DOM changes may advance it, navigation cannot
// replace the document. Host code compares this with its opaque pre-effect pin.
type WebIdentity struct {
	ProfileChannel  string `json:"profileChannel"`
	BrowserInstance string `json:"browserInstance"`
	Origin          string `json:"origin"`
	TabID           int    `json:"tabId"`
	FrameID         int    `json:"frameId"`
	DocumentID      string `json:"documentId"`
	Generation      uint64 `json:"documentGeneration"`
	ExtensionOrigin string `json:"extensionOrigin"`
	BrokerEpoch     string `json:"brokerEpoch"`
	ChannelEpoch    string `json:"channelEpoch"`
	ScopeHash       string `json:"scopeHash"`
}
type WebEvidence struct {
	Owner      string
	ClientID   string
	Identity   WebIdentity
	RequestID  string
	ObservedAt time.Time
}
type WebRead func(context.Context, auth.Principal, model.Selector, string, WebIdentity) (model.Value, WebEvidence, error)

// WebIdentityResolver supplies the original private pre-effect document pin.
// It must fail when no dispatched, safely retired step owns that capability;
// it cannot select a document from the requested origin.
type WebIdentityResolver func(context.Context, auth.Principal, string) (WebIdentity, error)
type WebOptions struct {
	Read            WebRead
	ResolveIdentity WebIdentityResolver
}
type WebAdapter struct {
	read            WebRead
	resolveIdentity WebIdentityResolver
}

func NewWeb(read WebRead) (*WebAdapter, error) {
	return NewWebWithOptions(WebOptions{Read: read})
}
func NewWebWithOptions(options WebOptions) (*WebAdapter, error) {
	if options.Read == nil {
		return nil, errors.New("qualified protected web read required")
	}
	return &WebAdapter{read: options.Read, resolveIdentity: options.ResolveIdentity}, nil
}
func (a *WebAdapter) Enrollment() Enrollment {
	return Enrollment{Adapter: a, MaximumAuthority: Observational, AllowedPredicates: map[string]bool{"valueEquals": true}}
}
func webBounded(value model.Value, max int, empty bool) (string, error) {
	if value.Kind != model.StringValue || value.Validate() != nil || len(value.String) > max || (!empty && strings.TrimSpace(value.String) == "") {
		return "", errors.New("bounded typed web string required")
	}
	for _, r := range value.String {
		if unicode.IsControl(r) {
			return "", errors.New("web input control character rejected")
		}
	}
	return value.String, nil
}
func webNumber(value model.Value, min, max int64) (int64, error) {
	if value.Kind != model.NumberValue || value.Validate() != nil || value.Number < min || value.Number > max {
		return 0, errors.New("bounded typed web identity number required")
	}
	return value.Number, nil
}
func webSameIdentity(a, b WebIdentity) bool { a.Generation = 0; b.Generation = 0; return a == b }

// Evaluate can only request a protected value/text/name read. It cannot acquire
// control, inject JavaScript, reselect a replacement document or claim business
// authority. Equality follows the existing DOM-normalized string read semantics.
func (a *WebAdapter) Evaluate(ctx context.Context, p auth.Principal, name string, inputs map[string]model.Value) (Result, error) {
	actual, err := auth.FromContext(ctx)
	if err != nil || p.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID {
		return Result{}, auth.ErrUnauthorized
	}
	if a == nil || a.read == nil || name != "valueEquals" {
		return Result{}, errors.New("qualified web.valueEquals predicate required")
	}
	allowed := map[string]bool{"profileChannel": true, "browserInstance": true, "origin": true, "tabId": true, "frameId": true, "documentId": true, "documentGeneration": true, "extensionOrigin": true, "brokerEpoch": true, "channelEpoch": true, "scopeHash": true, "strategy": true, "selector": true, "name": true, "attribute": true, "expected": true}
	for key := range inputs {
		if !allowed[key] {
			return Result{}, errors.New("unsupported web predicate input")
		}
	}
	text := func(key string, max int) (string, error) { return webBounded(inputs[key], max, false) }
	id := WebIdentity{}
	if a.resolveIdentity != nil {
		origin, err := text("origin", 2048)
		if err != nil {
			return Result{}, err
		}
		parsed, err := url.Parse(origin)
		if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Scheme+"://"+parsed.Host != origin || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && (parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "localhost"))) {
			return Result{}, errors.New("exact enrolled HTTPS or loopback origin required")
		}
		id, err = a.resolveIdentity(ctx, actual, origin)
		if err != nil {
			return Result{}, err
		}
		if err = ctx.Err(); err != nil {
			return Result{}, err
		}
	}
	for key, destination := range map[string]*string{"profileChannel": &id.ProfileChannel, "browserInstance": &id.BrowserInstance, "origin": &id.Origin, "documentId": &id.DocumentID, "extensionOrigin": &id.ExtensionOrigin, "brokerEpoch": &id.BrokerEpoch, "channelEpoch": &id.ChannelEpoch, "scopeHash": &id.ScopeHash} {
		limit := 256
		if key == "origin" {
			limit = 2048
		}
		if a.resolveIdentity == nil {
			value, err := text(key, limit)
			if err != nil {
				return Result{}, err
			}
			*destination = value
		} else {
			if _, err := webBounded(model.Value{Kind: model.StringValue, String: *destination}, limit, false); err != nil {
				return Result{}, err
			}
			if hint, supplied := inputs[key]; supplied {
				value, err := webBounded(hint, limit, false)
				if err != nil || value != *destination {
					return Result{}, errors.New("web identity hint differs from original admitted binding")
				}
			}
		}
	}
	if !webChannelIdentifier.MatchString(id.ProfileChannel) || !webChannelIdentifier.MatchString(id.BrowserInstance) {
		return Result{}, errors.New("bounded enrolled web channel identifiers required")
	}
	parsed, err := url.Parse(id.Origin)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Scheme+"://"+parsed.Host != id.Origin || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && (parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "localhost"))) {
		return Result{}, errors.New("exact enrolled HTTPS or loopback origin required")
	}
	extension := strings.TrimSuffix(strings.TrimPrefix(id.ExtensionOrigin, "chrome-extension://"), "/")
	if len(extension) != 32 || id.ExtensionOrigin != "chrome-extension://"+extension+"/" {
		return Result{}, errors.New("exact enrolled extension origin required")
	}
	for _, r := range extension {
		if r < 'a' || r > 'p' {
			return Result{}, errors.New("invalid extension identity")
		}
	}
	identityNumber := func(key string, pinned, min, max int64) (int64, error) {
		if a.resolveIdentity == nil {
			return webNumber(inputs[key], min, max)
		}
		if _, err := webNumber(model.Value{Kind: model.NumberValue, Number: pinned}, min, max); err != nil {
			return 0, err
		}
		if hint, supplied := inputs[key]; supplied {
			value, err := webNumber(hint, min, max)
			if err != nil || value != pinned {
				return 0, errors.New("web identity hint differs from original admitted binding")
			}
		}
		return pinned, nil
	}
	tab, err := identityNumber("tabId", int64(id.TabID), 1, 2147483647)
	if err != nil {
		return Result{}, err
	}
	id.TabID = int(tab)
	frame, err := identityNumber("frameId", int64(id.FrameID), 0, 0)
	if err != nil {
		return Result{}, err
	}
	id.FrameID = int(frame)
	generation, err := identityNumber("documentGeneration", int64(id.Generation), 1, 9007199254740991)
	if err != nil {
		return Result{}, err
	}
	id.Generation = uint64(generation)
	strategy, err := text("strategy", 16)
	if err != nil {
		return Result{}, err
	}
	if strategy != "id" && strategy != "testId" && strategy != "role" && strategy != "label" {
		return Result{}, errors.New("qualified exact web locator required")
	}
	selector, err := text("selector", 1024)
	if err != nil {
		return Result{}, err
	}
	attribute, err := text("attribute", 16)
	if err != nil {
		return Result{}, err
	}
	if attribute != "value" && attribute != "text" && attribute != "name" {
		return Result{}, errors.New("protected web attribute required")
	}
	expected, err := webBounded(inputs["expected"], 4096, true)
	if err != nil || len(utf16.Encode([]rune(expected))) >= 256 {
		return Result{}, errors.New("web expected value exceeds the qualified nontruncated read bound")
	}
	target := model.Selector{Surface: model.Surface{Kind: "web", Origin: id.Origin, TabID: id.ProfileChannel + "/" + id.BrowserInstance + "/" + strconv.Itoa(id.TabID)}, Cardinality: "one", Locator: &model.Locator{Strategy: strategy, Value: model.Value{Kind: model.StringValue, String: selector}, Exact: true}}
	if raw, exists := inputs["name"]; exists {
		roleName, err := webBounded(raw, 1024, false)
		if err != nil || strategy != "role" {
			return Result{}, errors.New("web role name requires a role selector")
		}
		target.Locator.Name = &model.Value{Kind: model.StringValue, String: roleName}
	}
	if err := target.Validate(); err != nil {
		return Result{}, err
	}
	value, evidence, err := a.read(ctx, p, target, attribute, id)
	if err != nil {
		return Result{}, err
	}
	if err = ctx.Err(); err != nil {
		return Result{}, err
	}
	observed, err := webBounded(value, 4096, true)
	if err != nil || observed == "[redacted]" || len(utf16.Encode([]rune(observed))) >= 256 || evidence.Owner != p.Namespace || evidence.ClientID != p.ClientID || !webSameIdentity(evidence.Identity, id) || evidence.Identity.Generation < id.Generation || evidence.Identity.Generation > 9007199254740991 || !nativeEvidenceID(evidence.RequestID) || evidence.ObservedAt.IsZero() {
		return Result{Truth: Unknown, Authority: Observational, Reason: "protected web read identity, coverage or evidence is incomplete"}, nil
	}
	reference, _ := json.Marshal(struct {
		Identity  WebIdentity `json:"identity"`
		RequestID string      `json:"requestId"`
	}{evidence.Identity, evidence.RequestID})
	truth := False
	if observed == expected {
		truth = True
	}
	return Result{Truth: truth, Authority: Observational, ObservedAt: evidence.ObservedAt, Evidence: []Evidence{{Kind: "webDOMRead", Reference: string(reference)}}}, nil
}

var webChannelIdentifier = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

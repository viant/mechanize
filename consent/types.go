// Package consent is the authenticated local broker's operation-consent boundary.
// Its persistence operations are private generated Datly use-case components.
package consent

import (
	"context"
	"fmt"
	"github.com/viant/datly/exec"
	"net/url"
	"strings"
	"time"
)

type Mode string

const (
	Observe Mode = "observe"
	Control Mode = "control"
	Record  Mode = "record"
)

type Decision string

const (
	AllowOnce         Decision = "allow_once"
	AllowSession      Decision = "allow_session"
	AllowUntilRevoked Decision = "allow_until_revoked"
	Deny              Decision = "deny"
)

type RevocationState string

const (
	Requested      RevocationState = "requested"
	Stopping       RevocationState = "stopping"
	Revoked        RevocationState = "revoked"
	CleanupUnknown RevocationState = "cleanupUnknown"
)

type Scope struct {
	Kind        string `json:"kind"`
	BundleID    string `json:"bundleID,omitempty"`
	WindowID    string `json:"windowID,omitempty"`
	Origin      string `json:"origin,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

func (s Scope) Validate() error {
	if len(s.DisplayName) > 512 || len(s.BundleID) > 256 || len(s.WindowID) > 256 || len(s.Origin) > 2048 {
		return fmt.Errorf("consent scope exceeds bounds")
	}
	if strings.ContainsAny(s.BundleID, "*?") || strings.ContainsAny(s.WindowID, "*?") || strings.Contains(s.Origin, "*") {
		return fmt.Errorf("wildcard consent targets are unsupported")
	}
	switch s.Kind {
	case "desktop":
		if s.BundleID != "" || s.WindowID != "" || s.Origin != "" {
			return fmt.Errorf("desktop scope cannot carry application, window, or origin selectors")
		}
	case "application":
		if s.BundleID == "" || s.WindowID != "" || s.Origin != "" {
			return fmt.Errorf("exact application bundle required")
		}
	case "window":
		if s.BundleID == "" || s.WindowID == "" || s.Origin != "" {
			return fmt.Errorf("exact window and bundle required")
		}
	case "origin":
		u, err := url.Parse(s.Origin)
		if err != nil || u == nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.ForceQuery || s.BundleID != "" || s.WindowID != "" || s.Origin != u.Scheme+"://"+u.Host {
			return fmt.Errorf("exact HTTP(S) origin required")
		}
	default:
		return fmt.Errorf("unsupported consent scope")
	}
	return nil
}

// Covers compares validated target selectors. DisplayName is presentation only;
// broker-resolved identifiers determine authority. Desktop is an explicit scope
// over the current logged-in desktop and its connected browser targets, never a
// wildcard application/origin identifier. Narrow grants stay exact.
func (s Scope) Covers(operation Scope) bool {
	if s.Validate() != nil || operation.Validate() != nil {
		return false
	}
	if s.Kind == "desktop" {
		return true
	}
	return s.Kind == operation.Kind && s.BundleID == operation.BundleID && s.WindowID == operation.WindowID && s.Origin == operation.Origin
}

type Client struct {
	ID           string `json:"id"`
	DisplayName  string `json:"displayName"`
	Verification string `json:"verification"`
	SessionID    string `json:"-"`
}
type Actor struct {
	ID    string
	Human bool
	Admin bool
}
type RequestInput struct {
	Scope           Scope  `json:"scope"`
	Modes           []Mode `json:"modes"`
	Purpose         string `json:"purpose"`
	DurationSeconds int    `json:"durationSeconds"`
}
type Request struct {
	ID              string    `json:"id"`
	VerifiedClient  Client    `json:"verifiedClient"`
	Scope           Scope     `json:"scope"`
	Modes           []Mode    `json:"modes"`
	Purpose         string    `json:"purpose"`
	DurationSeconds int       `json:"durationSeconds"`
	CreatedAt       time.Time `json:"createdAt"`
	ExpiresAt       time.Time `json:"expiresAt"`
}
type Grant struct {
	ID              string          `json:"id"`
	RequestID       string          `json:"requestID"`
	ClientID        string          `json:"clientID"`
	Scope           Scope           `json:"scope"`
	Modes           []Mode          `json:"modes"`
	Purpose         string          `json:"purpose"`
	DurationSeconds int             `json:"durationSeconds"`
	Decision        Decision        `json:"decision"`
	CreatedAt       time.Time       `json:"createdAt"`
	ExpiresAt       time.Time       `json:"expiresAt"`
	Permanent       bool            `json:"permanent,omitempty"`
	State           string          `json:"state"`
	RevocationState RevocationState `json:"revocationState,omitempty"`
}
type Snapshot struct {
	Requests []Request `json:"requests"`
	Grants   []Grant   `json:"grants"`
}

// Operation facts are broker-resolved target facts, never unverified LLM aliases.
type Operation struct {
	GrantID   string
	SessionID string
	Scope     Scope
	Mode      Mode
	Purpose   string
}

// Lease binds a single dispatch to a cancellation context. Release must be called
// only after helper/Endly dispatch has stopped and cleanup is confirmed.
type Lease struct {
	Context context.Context
	Release func()
}

// Options callbacks must come from trusted transport/host authentication. Policy
// checks principal + operator ceilings and current helper/TCC capability each time.
// Missing callbacks fail closed; no default identity, admin or permission exists.
type Options struct {
	Namespace     string
	Invoke        func(context.Context, exec.ComponentRequest) (any, error)
	VerifyClient  func(context.Context) (Client, error)
	VerifyActor   func(context.Context) (Actor, error)
	ResolveClient func(context.Context, string, string) (Client, error)
	Policy        func(context.Context, Client, Scope, []Mode, int) error
	Now           func() time.Time
	RequestTTL    time.Duration
	MaxDuration   time.Duration
}

func validateInput(in RequestInput, max time.Duration) error {
	if err := in.Scope.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(in.Purpose) == "" || len(in.Purpose) > 2048 {
		return fmt.Errorf("bounded explicit purpose required")
	}
	if in.DurationSeconds < 1 || in.DurationSeconds > int(max/time.Second) {
		return fmt.Errorf("bounded consent duration required")
	}
	if len(in.Modes) < 1 || len(in.Modes) > 3 {
		return fmt.Errorf("consent modes required")
	}
	seen := map[Mode]bool{}
	for _, mode := range in.Modes {
		if seen[mode] {
			return fmt.Errorf("duplicate consent mode")
		}
		seen[mode] = true
		switch mode {
		case Observe, Control, Record:
		default:
			return fmt.Errorf("unsupported consent mode")
		}
	}
	return nil
}

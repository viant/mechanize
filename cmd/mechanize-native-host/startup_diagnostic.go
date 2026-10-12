package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/viant/mechanize/auth/nativepeer"
)

// startupFailure is private stage provenance, never an arbitrary error string.
// Unwrap supports internal errors.Is; all public formatting is fixed metadata.
type startupFailure struct {
	code  string
	cause error
}

func (e *startupFailure) Error() string              { return "native host startup: " + e.code }
func (e *startupFailure) Unwrap() error              { return e.cause }
func (e *startupFailure) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, e.Error()) }
func (e *startupFailure) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Code string `json:"code"`
	}{e.code})
}
func startupCodeAllowed(code string) bool {
	switch code {
	case "chromeImagePathMismatch", "runningImageMismatch", "nativeHostSignatureUnavailable", "chromeSignatureUnavailable", "nativeHostProcessUnavailable", "nativeHostUIDUnavailable", "nativeHostDynamicSignatureUnavailable", "chromeAncestryUnavailable", "chromeParentUnavailable", "ancestryChanged", "configUnavailable", "processTrustUnavailable", "launchScopeUnavailable", "socketUnavailable", "brokerUnavailable", "brokerTrustUnavailable", "enrollmentCredentialUnavailable", "helloIdentityMismatch":
		return true
	}
	return false
}
func atStartup(code string, err error) error {
	if err == nil {
		return nil
	}
	if previous, ok := err.(*startupFailure); ok && startupCodeAllowed(previous.code) {
		return previous
	}
	if !startupCodeAllowed(code) {
		return errors.New("native host startup unavailable")
	}
	return &startupFailure{code: code, cause: err}
}

// nativeForwardingFailure cannot be mistaken for a startup-only frame even when
// a runtime reader returns a nested startupFailure. Its cause remains internal.
type nativeForwardingFailure struct{ cause error }

func (e *nativeForwardingFailure) Error() string              { return "native transport unavailable" }
func (e *nativeForwardingFailure) Unwrap() error              { return e.cause }
func (e *nativeForwardingFailure) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, e.Error()) }

// reportNativeFailure runs only after run returns. A startupFailure can originate
// only before Bridge starts forwarding. Runtime failures NEVER write stdout:
// the forwarding goroutine may still own that stream during teardown.
func reportNativeFailure(err error, stdout, stderr io.Writer) bool {
	if err == nil {
		return false
	}
	code := "transportUnavailable"
	if failure, ok := err.(*startupFailure); ok && startupCodeAllowed(failure.code) {
		code = failure.code
		frame, _ := json.Marshal(struct {
			Type string `json:"type"`
			Code string `json:"code"`
		}{"nativeHostError", code})
		_ = WriteFrame(stdout, frame)
	} else if forwarding, ok := err.(*nativeForwardingFailure); ok {
		var rejection *brokerStartupFailure
		if errors.As(forwarding.cause, &rejection) && (brokerStartupCodeAllowed(rejection.code) || rejection.code == "brokerHandshakeUnavailable") {
			code = rejection.code // stdout was already written by the sole broker reader.
		} else if errors.Is(err, io.EOF) {
			return false
		}
	} else if errors.Is(err, io.EOF) {
		return false
	}
	_, _ = fmt.Fprintln(stderr, "Mechanize native transport:", code)
	return true
}
func startupAuthenticatedCredential(ctx context.Context, config *Config, broker net.Conn, process func(context.Context, *Config) (nativepeer.ChromeProcessEvidence, error), peer func(*Config, net.Conn) error, load func() (string, error)) (string, error) {
	credential, err := authenticatedCredential(ctx, config, broker,
		func(ctx context.Context, c *Config) (nativepeer.ChromeProcessEvidence, error) {
			e, err := process(ctx, c)
			return e, atStartup(processStartupCode(err), err)
		},
		func(c *Config, conn net.Conn) error { return atStartup("brokerTrustUnavailable", peer(c, conn)) },
		func() (string, error) {
			value, err := load()
			return value, atStartup("enrollmentCredentialUnavailable", err)
		})
	if processStartupCode(err) != "processTrustUnavailable" {
		return credential, atStartup(processStartupCode(err), err)
	}
	return credential, atStartup("enrollmentCredentialUnavailable", err)
}

func processStartupCode(err error) string {
	for _, entry := range []struct {
		cause error
		code  string
	}{
		{nativepeer.ErrRunningImageMismatch, "runningImageMismatch"}, {nativepeer.ErrNativeHostSignatureUnavailable, "nativeHostSignatureUnavailable"}, {nativepeer.ErrChromeSignatureUnavailable, "chromeSignatureUnavailable"}, {nativepeer.ErrNativeHostProcessUnavailable, "nativeHostProcessUnavailable"}, {nativepeer.ErrNativeHostUIDUnavailable, "nativeHostUIDUnavailable"}, {nativepeer.ErrNativeHostDynamicSignatureUnavailable, "nativeHostDynamicSignatureUnavailable"}, {nativepeer.ErrChromeAncestryUnavailable, "chromeAncestryUnavailable"}, {nativepeer.ErrChromeParentUnavailable, "chromeParentUnavailable"}, {nativepeer.ErrAncestryChanged, "ancestryChanged"}} {
		if errors.Is(err, entry.cause) {
			return entry.code
		}
	}
	return "processTrustUnavailable"
}

// Diagnostic classification only: a signed alternative image still fails the
// original exact-path verifier. Metadata never admits a process or loads a secret.
func diagnoseChromePathFailure(err error, d nativepeer.ChromeLaunchDiagnostic) error {
	if errors.Is(err, nativepeer.ErrChromeAncestryUnavailable) &&
		d.HostPIDMatches && d.HostStartMatches && d.HostUIDMatches &&
		d.ParentPIDMatches && d.ParentStartMatches && d.ParentUIDMatches &&
		d.DynamicParentPinMatches && !d.ParentPathMatchesPolicy {
		return atStartup("chromeImagePathMismatch", err)
	}
	return err
}

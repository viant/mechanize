package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth/nativepeer"
)

func TestStartupDiagnosticClosedCodesAndNoPrivateCause(t *testing.T) {
	private := errors.New("private-token-canary /private/path-canary")
	for _, code := range []string{"configUnavailable", "processTrustUnavailable", "launchScopeUnavailable", "socketUnavailable", "brokerUnavailable", "brokerTrustUnavailable", "enrollmentCredentialUnavailable", "helloIdentityMismatch"} {
		t.Run(code, func(t *testing.T) {
			err := atStartup(code, private)
			if !errors.Is(err, private) {
				t.Fatal("internal error identity lost")
			}
			for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
				if strings.Contains(fmt.Sprintf(format, err), "canary") {
					t.Fatal("private cause formatted")
				}
			}
			var stdout, stderr bytes.Buffer
			if !reportNativeFailure(err, &stdout, &stderr) {
				t.Fatal("failure disappeared")
			}
			raw, e := ReadFrame(&stdout)
			if e != nil {
				t.Fatal(e)
			}
			var frame map[string]string
			if json.Unmarshal(raw, &frame) != nil || len(frame) != 2 || frame["type"] != "nativeHostError" || frame["code"] != code || stdout.Len() != 0 {
				t.Fatal("startup frame contract changed")
			}
			if strings.Contains(string(raw)+stderr.String(), "canary") || stderr.String() != "Mechanize native transport: "+code+"\n" {
				t.Fatal("private diagnostic escaped")
			}
		})
	}
	for _, err := range []error{private, atStartup("private-code-canary", private), &nativeForwardingFailure{cause: atStartup("brokerUnavailable", private)}} {
		var stdout, stderr bytes.Buffer
		reportNativeFailure(err, &stdout, &stderr)
		if stdout.Len() != 0 || strings.Contains(stderr.String(), "canary") {
			t.Fatal("untyped or runtime failure emitted a startup frame")
		}
	}
}
func TestStartupAuthenticationClassifiesStagesBeforeCredentialAccess(t *testing.T) {
	cause := errors.New("credential-private-canary")
	for _, stage := range []string{"process", "peer", "load", "peerAfter", "processAfter"} {
		t.Run(stage, func(t *testing.T) {
			processCalls, peerCalls, loads := 0, 0, 0
			config := &Config{FixtureEnrollment: true}
			_, err := startupAuthenticatedCredential(context.Background(), config, nil,
				func(context.Context, *Config) (nativepeer.ChromeProcessEvidence, error) {
					processCalls++
					if stage == "process" || stage == "processAfter" && processCalls == 2 {
						return nativepeer.ChromeProcessEvidence{}, cause
					}
					return nativepeer.ChromeProcessEvidence{}, nil
				},
				func(*Config, net.Conn) error {
					peerCalls++
					if stage == "peer" || stage == "peerAfter" && peerCalls == 2 {
						return cause
					}
					return nil
				},
				func() (string, error) {
					loads++
					if stage == "load" {
						return "", cause
					}
					return "private-enrollment-canary", nil
				})
			expected := "enrollmentCredentialUnavailable"
			if strings.HasPrefix(stage, "process") {
				expected = "processTrustUnavailable"
			}
			if strings.HasPrefix(stage, "peer") {
				expected = "brokerTrustUnavailable"
			}
			actual, ok := err.(*startupFailure)
			if !ok || actual.code != expected || !errors.Is(err, cause) || strings.Contains(err.Error(), "canary") {
				t.Fatal("incorrect safe startup stage")
			}
			if (stage == "process" || stage == "peer") && loads != 0 {
				t.Fatal("credential loaded before peer qualification")
			}
		})
	}
}
func TestBridgeHelloFailureEmitsOnlyStartupDiagnostic(t *testing.T) {
	var input, output, stderr bytes.Buffer
	WriteFrame(&input, json.RawMessage(`{"type":"hello","protocolVersion":1,"profileChannel":"private-canary","browserInstance":"wrong"}`))
	host, peer := net.Pipe()
	defer host.Close()
	defer peer.Close()
	err := Bridge(&input, &output, host, &Config{FixtureEnrollment: true, ProfileChannel: "expected", BrowserInstance: "expected"}, "credential-canary")
	if !reportNativeFailure(err, &output, &stderr) {
		t.Fatal("hello mismatch disappeared")
	}
	raw, e := ReadFrame(&output)
	if e != nil || !bytes.Contains(raw, []byte(`"helloIdentityMismatch"`)) || bytes.Contains(raw, []byte("canary")) {
		t.Fatal("hello diagnostic leaked or missing")
	}
}

// A runtime reader can return any error, even one wrapping a startup error.
// Forwarding ownership must remain explicit rather than inferred by errors.As.
type diagnosticRuntimeReader struct {
	prefix *bytes.Reader
	cause  error
}

func (r *diagnosticRuntimeReader) Read(p []byte) (int, error) {
	if r.prefix.Len() != 0 {
		return r.prefix.Read(p)
	}
	return 0, r.cause
}
func TestBridgeRuntimeFailureNeverEmitsStartupFrame(t *testing.T) {
	var hello, output, stderr bytes.Buffer
	WriteFrame(&hello, json.RawMessage(`{"type":"hello","protocolVersion":1,"profileChannel":"profile","browserInstance":"browser"}`))
	cause := atStartup("brokerUnavailable", errors.New("private-runtime-canary"))
	input := &diagnosticRuntimeReader{prefix: bytes.NewReader(hello.Bytes()), cause: cause}
	host, peer := net.Pipe()
	defer host.Close()
	defer peer.Close()
	readHello := make(chan struct{})
	go func() { ReadFrame(peer); close(readHello) }()
	err := Bridge(input, &output, host, &Config{FixtureEnrollment: true, ProfileChannel: "profile", BrowserInstance: "browser"}, "credential-canary")
	<-readHello
	if !errors.Is(err, cause) {
		t.Fatal("runtime cause lost internally")
	}
	reportNativeFailure(err, &output, &stderr)
	if output.Len() != 0 || stderr.String() != "Mechanize native transport: transportUnavailable\n" {
		t.Fatal("runtime failure interleaved startup output")
	}
	var eofOut, eofErr bytes.Buffer
	if reportNativeFailure(&nativeForwardingFailure{cause: io.EOF}, &eofOut, &eofErr) || eofOut.Len() != 0 || eofErr.Len() != 0 {
		t.Fatal("normal closure produced diagnostic")
	}
}

func TestProcessDiagnosticSubcodesRemainClosedBeforeCredentials(t *testing.T) {
	for _, tc := range []struct {
		stage error
		code  string
	}{
		{nativepeer.ErrRunningImageMismatch, "runningImageMismatch"}, {nativepeer.ErrNativeHostSignatureUnavailable, "nativeHostSignatureUnavailable"}, {nativepeer.ErrChromeSignatureUnavailable, "chromeSignatureUnavailable"}, {nativepeer.ErrNativeHostProcessUnavailable, "nativeHostProcessUnavailable"}, {nativepeer.ErrNativeHostUIDUnavailable, "nativeHostUIDUnavailable"}, {nativepeer.ErrNativeHostDynamicSignatureUnavailable, "nativeHostDynamicSignatureUnavailable"}, {nativepeer.ErrChromeAncestryUnavailable, "chromeAncestryUnavailable"}, {nativepeer.ErrChromeParentUnavailable, "chromeParentUnavailable"}, {nativepeer.ErrAncestryChanged, "ancestryChanged"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			cause := nativepeer.ProcessFailure(tc.stage, errors.New("private-process-canary"))
			_, err := startupAuthenticatedCredential(context.Background(), &Config{FixtureEnrollment: true}, nil, func(context.Context, *Config) (nativepeer.ChromeProcessEvidence, error) {
				return nativepeer.ChromeProcessEvidence{}, cause
			}, func(*Config, net.Conn) error { t.Fatal("peer checked after process refusal"); return nil }, func() (string, error) { t.Fatal("credential read after process refusal"); return "", nil })
			var stdout, stderr bytes.Buffer
			reportNativeFailure(err, &stdout, &stderr)
			raw, e := ReadFrame(&stdout)
			if e != nil {
				t.Fatal(e)
			}
			var frame map[string]string
			json.Unmarshal(raw, &frame)
			if len(frame) != 2 || frame["type"] != "nativeHostError" || frame["code"] != tc.code || strings.Contains(string(raw)+stderr.String(), "canary") || !errors.Is(err, tc.stage) {
				t.Fatal("unsafe or imprecise process diagnostic")
			}
		})
	}
}

func TestChromePathDiagnosisNeverChangesAdmission(t *testing.T) {
	denied := nativepeer.ProcessFailure(nativepeer.ErrChromeAncestryUnavailable, errors.New("private path canary"))
	d := nativepeer.ChromeLaunchDiagnostic{HostPIDMatches: true, HostStartMatches: true, HostUIDMatches: true, ParentPIDMatches: true, ParentStartMatches: true, ParentUIDMatches: true, DynamicParentPinMatches: true}
	classified := diagnoseChromePathFailure(denied, d)
	failure, ok := classified.(*startupFailure)
	if !ok || failure.code != "chromeImagePathMismatch" || !errors.Is(classified, nativepeer.ErrChromeAncestryUnavailable) || strings.Contains(fmt.Sprint(classified), "canary") {
		t.Fatal("failed to preserve denial privately")
	}
	d.DynamicParentPinMatches = false
	if diagnoseChromePathFailure(denied, d) != denied {
		t.Fatal("unverified parent misclassified")
	}
	if diagnoseChromePathFailure(nil, d) != nil {
		t.Fatal("diagnostic created admission failure")
	}
}

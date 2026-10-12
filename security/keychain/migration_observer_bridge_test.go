//go:build darwin || linux

package keychain

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func observerResponseFixture(r migrationObserverRequest, payload []byte) migrationObserverResponse {
	return migrationObserverResponse{Version: 1, Nonce: r.Nonce, Session: r.Session, ManifestSHA256: r.ManifestSHA256, RequestSHA256: migrationDigest(payload), ObservedAtUnixMilliseconds: time.Now().Add(-time.Second).UnixMilli(), SourceReceiptSHA256: strings.Repeat("a", 64), LoadedExtensionPath: "/private/fixture/extension", ExtensionID: strings.Repeat("a", 32), StorageSHA256: strings.Repeat("b", 64), StoppedExecutables: []string{"/private/fixture/broker"}, OldConsoleRequirement: runtimeFixtureRequirement("consent", "c"), OldConsoleBirth: "123:1"}
}
func TestMigrationObserverClosedTranscriptRejectsSubstitutionAndStaleEvidence(t *testing.T) {
	request := migrationObserverRequest{Version: 1, Nonce: strings.Repeat("1", 64), Session: strings.Repeat("2", 64), ManifestSHA256: strings.Repeat("3", 64), DeadlineUnixMilliseconds: time.Now().Add(time.Second).UnixMilli()}
	payload, _ := json.Marshal(request)
	for _, mode := range []string{"valid", "nonce", "session", "manifest", "transcript", "stale", "future", "path", "duplicate path", "unknown bool"} {
		t.Run(mode, func(t *testing.T) {
			response := observerResponseFixture(request, payload)
			switch mode {
			case "nonce":
				response.Nonce = strings.Repeat("4", 64)
			case "session":
				response.Session = strings.Repeat("4", 64)
			case "manifest":
				response.ManifestSHA256 = strings.Repeat("4", 64)
			case "transcript":
				response.RequestSHA256 = strings.Repeat("4", 64)
			case "stale":
				response.ObservedAtUnixMilliseconds = time.Now().Add(-time.Minute).UnixMilli()
			case "future":
				response.ObservedAtUnixMilliseconds = time.Now().Add(time.Minute).UnixMilli()
			case "path":
				response.LoadedExtensionPath = "/private/fixture/../wrong"
			case "duplicate path":
				response.StoppedExecutables = append(response.StoppedExecutables, response.StoppedExecutables[0])
			}
			raw, _ := json.Marshal(response)
			if mode == "unknown bool" {
				raw = append(raw[:len(raw)-1], []byte(`,"quiescent":true}`)...)
			}
			got, err := decodeMigrationObserverResponse(raw, request, payload)
			if mode == "valid" {
				if err != nil || got.at.UnixMilli() != response.ObservedAtUnixMilliseconds {
					t.Fatalf("valid proof rejected: %v", err)
				}
			} else if err == nil {
				t.Fatal("substituted observer proof accepted")
			}
		})
	}
}
func TestMigrationObserverUsesAuthenticatedAuthorityAndRechecksPeer(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "verified", true: "changed peer"}[changed], func(t *testing.T) {
			a, _, console, ctx := migrationAuthorityFixture(t)
			sendMigrationCredential(t, console)
			human, err := a.workerAuthority(ctx)
			if err != nil {
				t.Fatal(err)
			}
			observer, err := newMigrationAuthenticatedObserver(a, strings.Repeat("1", 64), strings.Repeat("2", 64))
			if err != nil {
				t.Fatal(err)
			}
			peerChanges := make(chan struct{})
			a.peer = func(*net.UnixConn) error {
				select {
				case <-peerChanges:
					return errors.New("changed")
				default:
					return nil
				}
			}
			done := make(chan error, 1)
			go func() {
				raw, err := observerReadFrame(console, "MMOBSQ\x00\x01")
				if err != nil {
					done <- err
					return
				}
				var request migrationObserverRequest
				if json.Unmarshal(raw, &request) != nil {
					done <- errMigrationUnavailable
					return
				}
				response := observerResponseFixture(request, raw)
				reply, _ := json.Marshal(response)
				if changed {
					close(peerChanges)
				}
				done <- observerWriteFrame(console, "MMOBSR\x00\x01", reply)
			}()
			got, err := observer.observe(human)
			if !changed && (err != nil || got.loadedExtensionPath != "/private/fixture/extension") {
				t.Fatalf("bridge failed: %v", err)
			}
			if changed && err == nil {
				t.Fatal("changed peer accepted")
			}
			<-done
			if _, err := observer.terminal(context.Background()); err == nil {
				t.Fatal("console channel manufactured credential readiness")
			}
		})
	}
}

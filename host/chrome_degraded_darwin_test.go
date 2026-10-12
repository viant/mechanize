//go:build darwin && cgo

package host

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
	"github.com/viant/scy"
	"github.com/viant/scy/auth/jwt/verifier"
)

func TestChromeVerificationFailureKeepsNativeAdministrationAndNeverLoadsEnrollment(t *testing.T) {
	dir, e := os.MkdirTemp("/private/tmp", "mechanize-degraded-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	consoleDir := filepath.Join(dir, "console")
	if e = os.Mkdir(consoleDir, 0700); e != nil {
		t.Fatal(e)
	}
	key := filepath.Join(dir, "fixture-hmac")
	if e = os.WriteFile(key, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{39}, 32))), 0600); e != nil {
		t.Fatal(e)
	}
	_, file, _, _ := runtime.Caller(0)
	p, _ := auth.NewPrincipal("fixture", "", "operator", []string{"desktop:control", "desktop:observe", "consent:admin"})
	p.ClientID = "fixture-agent"
	p.ClientName = "Fixture"
	ctx := auth.WithPrincipal(context.Background(), p)
	// Synthetic missing/unsigned image stands for failed exact process enrollment.
	// Poisoned resource fields would fail a later loader; process rejection must
	// occur before any enrollment-resource validation, read, decryption or socket.
	cc := &chrome.Config{SocketPath: filepath.Join(dir, "chrome.sock"), ProcessTrust: &nativepeer.ChromeProcessPolicy{ExpectedUID: uint32(os.Getuid()), NativeHostExecutable: filepath.Join(dir, "missing-native-host"), ChromeExecutable: filepath.Join(dir, "updated-chrome"), NativeHostRequirement: `identifier "fixture.native"`, ChromeRequirement: `identifier "com.google.Chrome" and cdhash H"0000000000000000000000000000000000000000"`}, Grants: []chrome.Enrollment{{Principal: p, TrustScope: chrome.TrustScopeDesktop, AllWebsites: true, CredentialResource: scy.Resource{URL: "credential-resource-canary", Key: "credential-key-canary"}}}}
	if broker, e := chrome.NewBroker(ctx, *cc); broker != nil || !errors.Is(e, chrome.ErrProcessQualification) || strings.Contains(e.Error(), "canary") {
		t.Fatal("verifier did not fail before resource loader", e)
	}
	cfg := Config{SourceRoot: filepath.Dir(filepath.Dir(file)), StorageRoot: filepath.Join(dir, "storage"), Keys: verifier.Config{HMAC: &scy.Resource{URL: key}}, IdentityPolicy: auth.Policy{Issuer: "fixture", Audience: "mechanize", Algorithms: []string{"HS256"}, Clients: map[string]string{p.ClientID: p.ClientName}}, Users: []User{{Subject: p.Subject, DesktopAccess: true}}, NativeConsole: &NativeConsoleConfig{SocketPath: filepath.Join(consoleDir, "console.sock"), ExpectedUID: uint32(os.Getuid()), DesignatedRequirement: `identifier "fixture.console"`}, Chrome: cc, ChromeRetirement: &ChromeRetirementConfig{BrokerRequirement: `identifier "fixture.broker"`}}
	// Construct real native Vault services on empty disposable roots. No key is
	// generated/resolved and no installed Vault/configuration is read.
	vaultConfig := nativeVaultConfigFixture(t)
	vaultConfig.NativeVault.Root = filepath.Join(dir, "vault")
	vaultConfig.NativeVault.RecordRoot = filepath.Join(dir, "records")
	vaultRuntime, e := configuredNativeVault(vaultConfig)
	if e != nil {
		t.Fatal(e)
	}
	defer vaultRuntime.store.Close()
	defer vaultRuntime.recordStore.Close()
	h, e := NewWithOptions(context.Background(), cfg, HostOptions{NativeVaultInput: vaultRuntime.input, NativeVaultEntry: vaultRuntime.entry, NativeVaultKeySetup: vaultRuntime.setup, NativeVaultRecords: vaultRuntime.records})
	if e != nil {
		t.Fatal("Chrome rejection killed native host", e)
	}
	defer h.Close(context.Background())
	if !h.chromeStartupUnqualified || h.chrome != nil || h.webControl != nil || h.chromeRetirementEvidence != nil || h.consent == nil || h.consentListener == nil || h.Server == nil || h.vaultExposure != vaultRuntime.input.ExposureGate() {
		t.Fatal("degraded host lost native/admin services or retained Chrome dispatch")
	}
	if _, e = os.Lstat(cc.SocketPath); !os.IsNotExist(e) {
		t.Fatal("unqualified Chrome endpoint created")
	}
	if info, e := os.Lstat(cfg.NativeConsole.SocketPath); e != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
		t.Fatal("native admin listener absent/unsafe", e)
	}
	connection, e := net.Dial("unix", cfg.NativeConsole.SocketPath)
	if e != nil {
		t.Fatal(e)
	}
	connection.Close() // No credentials; actual peer verifier still applies.
	session, e := h.Runtime.Open(ctx, "degraded native fixture")
	if e != nil {
		t.Fatal(e)
	}
	human, _ := auth.WithNativeHuman(ctx)
	if _, e = h.NativeInformation(human, "browserStatus", nil); e != nil {
		t.Fatal("native administration unavailable", e)
	}
	request, e := h.consent.Request(ctx, p, session.SessionID, consent.RequestInput{Scope: consent.Scope{Kind: "desktop"}, Modes: []consent.Mode{consent.Observe, consent.Control}, Purpose: "native repair", DurationSeconds: 60})
	if e != nil {
		t.Fatal(e)
	}
	decision, _ := json.Marshal(map[string]any{"requestID": request.ID, "decision": consent.AllowSession})
	value, e := h.consent.NativeRPC(human, "decide", decision)
	if e != nil {
		t.Fatal(e)
	}
	bound := auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: session.SessionID, GrantID: value.(*consent.Grant).ID, Purpose: "native repair"})
	// Inert exposure check for permission-policy assertions: never inspect UI.
	h.vaultExposure, _ = vault.NewGuardedExposureGate(func(context.Context) error { return nil })
	lease, e := h.AuthorizeOperation(bound, p, model.Surface{Kind: "native", BundleID: "com.google.Chrome"}, true, consent.Control)
	if e != nil {
		t.Fatal("independent native repair permission blocked", e)
	}
	lease.Release()
	protected, e := h.vaultExposure.BeginDelivery(bound, vault.Binding{SessionID: session.SessionID, DocumentID: "fixture-document", NavigationID: strings.Repeat("a", 64), Target: vault.Target{Origin: "https://fixture.invalid", Account: "opaque"}}, func(c context.Context) error { return c.Err() }, func(context.Context) error { return vault.ErrEntryCleanup })
	if e != nil {
		t.Fatal(e)
	}
	defer protected.Retire()
	lease, e = h.AuthorizeOperation(bound, p, model.Surface{Kind: "native", BundleID: "com.google.Chrome"}, false, consent.Observe)
	if e != nil {
		t.Fatal("browser DOM protection blocked independent native observation", e)
	}
	lease.Release()
	if _, e = h.vaultExposure.AcquireExposureContext(bound); !errors.Is(e, vault.ErrDeliveryProtected) {
		t.Fatal("native observation cleared browser protection")
	}

	if _, e = h.AuthorizeOperation(bound, p, model.Surface{Kind: "web", Origin: "https://fixture.invalid"}, true, consent.Control); !errors.Is(e, chrome.ErrProcessQualification) {
		t.Fatal("web automation admitted", e)
	}
	for i := 0; i < 3; i++ {
		status, e := h.BrowserStatus(ctx, p)
		if e != nil || status.Available || status.AttentionCode != "chromeProcessUnqualified" || len(status.Channels) != 0 || status.Setup.State != "qualificationRequired" {
			t.Fatal("degraded status not bounded", status, e)
		}
		raw, _ := json.Marshal(status)
		if strings.Contains(string(raw), "canary") || strings.Contains(string(raw), dir) {
			t.Fatal("private enrollment diagnostics escaped")
		}
	}
	if _, e = os.Lstat(cc.SocketPath); !os.IsNotExist(e) || h.chrome != nil {
		t.Fatal("status retried or trusted failed enrollment")
	}
}

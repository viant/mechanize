package host

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/model"
	"github.com/viant/scy"
	"github.com/viant/scy/auth/jwt/verifier"
)

func TestConfiguredHostArtifactDatlyPublication(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(root, "fixture-artifact-key.json")
	keyJSON, _ := json.Marshal(map[string][]byte{"key": bytes.Repeat([]byte{7}, 32)})
	if err = os.WriteFile(keyPath, keyJSON, 0600); err != nil {
		t.Fatal(err)
	}
	hmacPath := filepath.Join(root, "fixture-hmac")
	if err = os.WriteFile(hmacPath, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))), 0600); err != nil {
		t.Fatal(err)
	}
	_, file, _, _ := runtime.Caller(0)
	c := Config{SourceRoot: filepath.Dir(filepath.Dir(file)), StorageRoot: root,
		Keys:           verifier.Config{HMAC: &scy.Resource{URL: hmacPath}},
		IdentityPolicy: auth.Policy{Issuer: "fixture:issuer", Audience: "mechanize", Algorithms: []string{"HS256"}, Clients: map[string]string{"fixture-agent": "Fixture Agent"}},
		Users:          []User{{Subject: "alice", NativeBundles: []string{"fixture.app"}}},
		Artifacts:      &ArtifactConfig{SourceKeyReference: "v1", KeyResources: map[string]scy.Resource{"v1": {URL: keyPath}}, MaxBytes: 1024, NamespaceQuotaBytes: 8192},
	}
	h, err := New(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close(context.Background())
	p, _ := auth.NewPrincipal("fixture:issuer", "", "alice", []string{"desktop:observe", "consent:admin"})
	p.ClientID, p.ClientName = "fixture-agent", "Fixture Agent"
	ctx := auth.WithPrincipal(context.Background(), p)
	session, err := h.Runtime.Open(ctx, "fixture artifacts")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Runtime.Close(ctx, session.SessionID)
	surface := model.Surface{Kind: "native", BundleID: "fixture.app"}
	if _, err = h.artifacts.Publish(ctx, p, surface, "text/plain", strings.NewReader("fixture evidence")); err == nil {
		t.Fatal("artifact published without human grant")
	}
	r, err := h.consent.Request(ctx, p, session.SessionID, consent.RequestInput{Scope: consent.Scope{Kind: "application", BundleID: "fixture.app"}, Modes: []consent.Mode{consent.Observe}, Purpose: "Retain fixture evidence", DurationSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	human, err := auth.WithNativeHuman(ctx) // Disposable fixture replaces verified native transport.
	if err != nil {
		t.Fatal(err)
	}
	decision, _ := json.Marshal(map[string]any{"requestID": r.ID, "decision": consent.AllowOnce})
	approved, err := h.consent.NativeRPC(human, "decide", decision)
	if err != nil {
		t.Fatal(err)
	}
	grant := approved.(*consent.Grant)
	bound := auth.WithConsentBinding(ctx, auth.ConsentBinding{GrantID: grant.ID, SessionID: session.SessionID, Purpose: "Retain fixture evidence"})
	ref, err := h.artifacts.Publish(bound, p, surface, "text/plain", strings.NewReader("fixture evidence"))
	if err != nil {
		t.Fatal(err)
	}
	if err = h.artifacts.VerifyArtifact(ctx, p, ref); err != nil {
		t.Fatalf("immutable publication verification: %v", err)
	}
	got, err := h.artifacts.Read(ctx, p, ref)
	if err != nil || string(got) != "fixture evidence" {
		t.Fatalf("read: %s %v", got, err)
	}
	if _, err = h.artifacts.Publish(bound, p, surface, "text/plain", strings.NewReader("second evidence")); err == nil {
		t.Fatal("once grant reused")
	}
	raw, err := os.ReadFile(filepath.Join(root, "artifacts", p.Namespace, ref.ID))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("fixture evidence")) || bytes.Contains(raw, []byte("text/plain")) {
		t.Fatal("plaintext artifact persisted")
	}
}

func TestArtifactConfigurationRejectsUntrustedKeyForms(t *testing.T) {
	valid := Config{SourceRoot: "/fixture/source", StorageRoot: "/fixture/storage", IdentityPolicy: auth.Policy{Issuer: "fixture", Audience: "fixture", Algorithms: []string{"HS256"}}, Users: []User{{Subject: "alice"}}}
	for _, config := range []*ArtifactConfig{
		{SourceKeyReference: "missing", KeyResources: map[string]scy.Resource{"v1": {URL: "fixture:key"}}, MaxBytes: 1, NamespaceQuotaBytes: 1},
		{SourceKeyReference: "v1", KeyResources: map[string]scy.Resource{"v1": {URL: "fixture:key", Data: []byte("inline key")}}, MaxBytes: 1, NamespaceQuotaBytes: 1},
		{SourceKeyReference: "v1", KeyResources: map[string]scy.Resource{"v1": {URL: "fixture:key"}}, MaxBytes: 2, NamespaceQuotaBytes: 1},
	} {
		valid.Artifacts = config
		if err := valid.Validate(); err == nil {
			t.Fatal("invalid artifact key/limit configuration accepted")
		}
	}
}

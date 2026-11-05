package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/session"
)

type launchReadinessFixture struct {
	identity session.ProcessIdentity
	trusted  bool
	doctor   map[string]any
}

func (f *launchReadinessFixture) TrustedIdentity() (session.ProcessIdentity, bool) {
	return f.identity, f.trusted
}
func (f *launchReadinessFixture) Identity() (session.ProcessIdentity, error) { return f.identity, nil }
func (f *launchReadinessFixture) Close() error                               { return nil }
func (f *launchReadinessFixture) Stop(context.Context) (session.CleanupReport, error) {
	return session.CleanupReport{}, nil
}
func (f *launchReadinessFixture) Call(context.Context, native.Request) (native.Reply, error) {
	raw, _ := json.Marshal(f.doctor)
	return native.Reply{Result: raw}, nil
}

func TestConfiguredLaunchRequiresSignedLaunchOnlyGraphicalEvidence(t *testing.T) {
	uid := uint32(os.Getuid())
	options, err := launchHostOptions(Config{NativeHelper: "/fixture/helper", NativeLaunch: &NativeLaunchConfig{LockPath: "/fixture/desktop.lock", HelperRequirement: `identifier "fixture"`, ExpectedUID: &uid}})
	if err != nil {
		t.Fatal(err)
	}
	identity := session.ProcessIdentity{PID: 123, UID: uid, Executable: "/fixture/helper", StartToken: "fixture"}
	fixture := func() *launchReadinessFixture {
		return &launchReadinessFixture{identity: identity, trusted: true, doctor: map[string]any{"brokerIdentityAuthenticated": true, "launchEnabled": true, "mutationEnabled": false, "physicalFenceEnrolled": true, "watchdogLive": true, "windowSession": map[string]any{"available": true, "onConsole": true, "loginDone": true, "uid": uid}}}
	}
	p, _ := auth.NewPrincipal("fixture", "", "user", []string{"desktop:control"})
	ctx := auth.WithPrincipal(context.Background(), p)
	valid, err := options.NativeControl.QualifyHelper(ctx, p, identity, []string{"com.apple.mail"}, fixture())
	if err != nil || !valid.LaunchQualified || valid.Unlocked || valid.MutationQualified || valid.Accessibility || valid.EventPost {
		t.Fatalf("launch-only evidence broadened input authority: %+v %v", valid, err)
	}
	for _, field := range []string{"brokerIdentityAuthenticated", "launchEnabled", "physicalFenceEnrolled", "watchdogLive"} {
		t.Run(field, func(t *testing.T) {
			f := fixture()
			f.doctor[field] = false
			if _, err := options.NativeControl.QualifyHelper(ctx, p, identity, []string{"com.apple.mail"}, f); err == nil {
				t.Fatal("missing evidence admitted")
			}
		})
	}
	t.Run("input-enabled", func(t *testing.T) {
		f := fixture()
		f.doctor["mutationEnabled"] = true
		if _, err := options.NativeControl.QualifyHelper(ctx, p, identity, []string{"com.apple.mail"}, f); err == nil {
			t.Fatal("input authority admitted")
		}
	})
	t.Run("untrusted-peer", func(t *testing.T) {
		f := fixture()
		f.trusted = false
		if _, err := options.NativeControl.QualifyHelper(ctx, p, identity, []string{"com.apple.mail"}, f); err == nil {
			t.Fatal("unsigned peer admitted")
		}
	})
	for _, field := range []string{"available", "onConsole", "loginDone", "uid"} {
		t.Run("session-"+field, func(t *testing.T) {
			f := fixture()
			delete(f.doctor["windowSession"].(map[string]any), field)
			if _, err := options.NativeControl.QualifyHelper(ctx, p, identity, []string{"com.apple.mail"}, f); err == nil {
				t.Fatal("unknown graphical session admitted")
			}
		})
	}
}

func TestNativeLaunchEnrollmentDefaultsAndUID(t *testing.T) {
	options, err := launchHostOptions(Config{})
	if err != nil || options.NativeControl != nil {
		t.Fatal("default enabled launch")
	}
	wrong := uint32(os.Getuid() + 1)
	if _, err = launchHostOptions(Config{NativeLaunch: &NativeLaunchConfig{ExpectedUID: &wrong}}); err == nil {
		t.Fatal("foreign login UID enrolled")
	}
	if (Config{NativeLaunch: &NativeLaunchConfig{}}).Validate() == nil {
		t.Fatal("incomplete launch enrollment accepted")
	}
}

func TestSemanticReadinessDistinguishesSecureInputWithoutGrantingControl(t *testing.T) {
	uid := uint32(os.Getuid())
	options, err := launchHostOptions(Config{NativeHelper: "/fixture/helper", NativeLaunch: &NativeLaunchConfig{Mode: "semantic", LockPath: "/fixture/desktop.lock", HelperRequirement: `identifier "fixture"`, ExpectedUID: &uid}})
	if err != nil {
		t.Fatal(err)
	}
	identity := session.ProcessIdentity{PID: 123, UID: uid, Executable: "/fixture/helper", StartToken: "fixture"}
	p, _ := auth.NewPrincipal("fixture", "", "user", []string{"desktop:control"})
	ctx := auth.WithPrincipal(context.Background(), p)
	for _, state := range []string{"active", "inactive", "missing", "malformed", "untrusted"} {
		t.Run(state, func(t *testing.T) {
			f := &launchReadinessFixture{identity: identity, trusted: true, doctor: map[string]any{"brokerIdentityAuthenticated": true, "mutationEnabled": false, "physicalFenceEnrolled": true, "watchdogLive": true, "semanticEnabled": true, "axTrusted": true, "windowSession": map[string]any{"available": true, "onConsole": true, "loginDone": true, "uid": uid}}}
			switch state {
			case "active", "untrusted":
				f.doctor["secureInputEnabled"] = true
			case "inactive":
				f.doctor["secureInputEnabled"] = false
			case "malformed":
				f.doctor["secureInputEnabled"] = "false"
			}
			if state == "untrusted" {
				f.trusted = false
			}
			ready, err := options.NativeControl.QualifyHelper(ctx, p, identity, []string{"com.example.Editor"}, f)
			if state == "inactive" {
				if err != nil || !ready.SemanticQualified {
					t.Fatalf("known inactive input rejected: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrNativeControlUnqualified) || ready.SemanticQualified {
				t.Fatalf("unqualified control accepted: %+v %v", ready, err)
			}
			want := "nativeControlUnqualified"
			if state == "active" {
				want = "nativeSecureInputActive"
			}
			if got := nativeControlAdmissionReason(err); got != want {
				t.Fatalf("reason %q, want %q", got, want)
			}
		})
	}
	// The helper disables keyboard routes during Secure Input. That derived
	// failure must not hide the actual cause, and must never admit dispatch.
	options, err = launchHostOptions(Config{NativeHelper: "/fixture/helper", NativeLaunch: &NativeLaunchConfig{Mode: "semantic", LockPath: "/fixture/desktop.lock", HelperRequirement: `identifier "fixture"`, ExpectedUID: &uid, TargetedKeyboard: true, WindowFrameClick: true}})
	if err != nil {
		t.Fatal(err)
	}
	f := &launchReadinessFixture{identity: identity, trusted: true, doctor: map[string]any{"brokerIdentityAuthenticated": true, "mutationEnabled": false, "physicalFenceEnrolled": true, "watchdogLive": true, "secureInputEnabled": true, "targetedKeyboardEnabled": false, "windowFrameClickEnabled": false, "windowSession": map[string]any{"available": true, "onConsole": true, "loginDone": true, "uid": uid}}}
	ready, err := options.NativeControl.QualifyHelper(ctx, p, identity, []string{"com.example.Editor"}, f)
	if !errors.Is(err, ErrNativeSecureInputActive) || ready.SemanticQualified || ready.WindowFrameClickQualified || ready.TargetedKeyboardQualified {
		t.Fatalf("derived readiness hid secure input or allowed control: %+v %v", ready, err)
	}
}

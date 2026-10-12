//go:build darwin || linux

package keychain

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/viant/mechanize/session"
	"os"
	"strings"
	"testing"
	"time"
)

func installerServerEvidence(f *compositionFixture) (migrationPreparationPlan, migrationPreparationEvidence, []byte) {
	plan := migrationPreparationPlan{MutationExecutable: "/fixture/private/worker", MutationRequirement: f.enrollment.worker.executorRequirement, MutationSHA256: strings.Repeat("9", 64), RuntimeManifestSHA256: strings.Repeat("8", 64)}
	identity := []byte("synthetic-persistent-item")
	c := migrationCoordinator{options: f.enrollment.worker.options, record: &migrationJournalRecord{transitionID: strings.Repeat("7", 64), identity: identity}}
	evidence := migrationPreparationEvidence{IntentSHA256: migrationPreparationIntent(f.enrollment.worker, f.enrollment.template.oldConfigSHA256, plan), ConfigSHA256: f.enrollment.template.oldConfigSHA256, OptionsSHA256: migrationOptionsDigest(f.enrollment.worker.options), RuntimeManifestSHA256: plan.RuntimeManifestSHA256, MutationRequirement: plan.MutationRequirement, Transition: c.transition()}
	return plan, evidence, identity
}
func installerServerChannel(t *testing.T, requests ...migrationInstallerRequest) *migrationWorkerChannelFixture {
	t.Helper()
	var wire bytes.Buffer
	for _, r := range requests {
		if err := writeMigrationWorkerFrame(&wire, r); err != nil {
			t.Fatal(err)
		}
	}
	return migrationWorkerChannel(wire.Bytes())
}
func TestInstallerServerExecutesAdoptedTransitionAndRejectsRawWorkerMode(t *testing.T) {
	f := newCompositionFixture(t)
	plan, evidence, identity := installerServerEvidence(f)
	deadline, _ := f.ctx.Deadline()
	execute := migrationInstallerRequest{Version: 1, ID: strings.Repeat("1", 64), Session: f.enrollment.worker.session, Operation: "execute", Preparation: &evidence, Identity: identity, DeadlineUnixMilliseconds: deadline.UnixMilli()}
	finalize := migrationInstallerRequest{Version: 1, ID: strings.Repeat("2", 64), Session: execute.Session, Operation: "finalize"}
	close := migrationInstallerRequest{Version: 1, ID: strings.Repeat("3", 64), Session: execute.Session, Operation: "close"}
	channel := installerServerChannel(t, execute, finalize, close)
	finalizations := 0
	frozenChecks := 0
	factory := func(context.Context) (*migrationInstallerSession, error) {
		return &migrationInstallerSession{composition: f.composition, expectedPreparation: plan, frozen: func(context.Context) error { frozenChecks++; return nil }, finalize: func(ctx context.Context, r migrationCompositionReceipt) (session.ProcessIdentity, error) {
			finalizations++
			if r.TransitionID != evidence.Transition.ID {
				return session.ProcessIdentity{}, errMigrationUnavailable
			}
			return session.ProcessIdentity{PID: 123, StartToken: "100:200", UID: uint32(os.Getuid()), Executable: f.enrollment.worker.options.canonicalExecutable}, nil
		}}, nil
	}
	done := fixtureCompositionAttest(f, migrationApprovalAttested)
	if err := serveMigrationInstaller(f.ctx, channel, f.enrollment.worker, f.authority.workerAuthority, factory); err != nil {
		t.Fatal(err)
	}
	<-done
	if f.executor.commits != 1 || f.executor.prepares != 1 || finalizations != 1 || frozenChecks == 0 {
		t.Fatal("server did not own single installation sequence")
	}
	reader := bytes.NewReader(channel.outputBytes())
	for n, want := range []string{"verified", "verified", "closed"} {
		var reply migrationInstallerResponse
		if readMigrationWorkerFrame(reader, &reply) != nil || reply.Status != want {
			t.Fatal("bad closed installer reply", n, reply.Status)
		}
		if n < 2 && reply.TransitionID != evidence.Transition.ID {
			t.Fatal("server regenerated trusted transition")
		}
	}
}
func TestInstallerServerRejectsManualVerbsAndReceiptClaimsBeforeFactory(t *testing.T) {
	for _, op := range []string{"prepare", "verify", "commit", "inspect", "finalize"} {
		t.Run(op, func(t *testing.T) {
			f := newCompositionFixture(t)
			calls := 0
			request := migrationInstallerRequest{Version: 1, ID: strings.Repeat("1", 64), Session: f.enrollment.worker.session, Operation: op}
			factory := func(context.Context) (*migrationInstallerSession, error) {
				calls++
				return nil, errMigrationUnavailable
			}
			if serveMigrationInstaller(f.ctx, installerServerChannel(t, request), f.enrollment.worker, f.authority.workerAuthority, factory) == nil || calls != 0 || f.executor.prepares != 0 {
				t.Fatal("manual worker verb reached composition")
			}
		})
	}
	f := newCompositionFixture(t)
	var raw bytes.Buffer
	request := map[string]any{"version": 1, "id": strings.Repeat("1", 64), "session": f.enrollment.worker.session, "op": "execute", "approved": true, "receipts": []string{"caller"}}
	if writeMigrationWorkerFrame(&raw, request) != nil {
		t.Fatal("fixture encoding")
	}
	if serveMigrationInstaller(f.ctx, migrationWorkerChannel(raw.Bytes()), f.enrollment.worker, f.authority.workerAuthority, func(context.Context) (*migrationInstallerSession, error) {
		t.Fatal("caller receipt reached factory")
		return nil, nil
	}) == nil {
		t.Fatal("caller claims admitted")
	}
}
func TestInstallerServerRejectsStaleOrMixedPreparationBeforeMutation(t *testing.T) {
	for _, mode := range []string{"deadline", "identity", "manifest", "frozen"} {
		t.Run(mode, func(t *testing.T) {
			f := newCompositionFixture(t)
			plan, evidence, identity := installerServerEvidence(f)
			deadline, _ := f.ctx.Deadline()
			if mode == "deadline" {
				deadline = time.Now().Add(-time.Second)
			}
			if mode == "identity" {
				identity = []byte("foreign-item")
			}
			if mode == "manifest" {
				evidence.RuntimeManifestSHA256 = strings.Repeat("f", 64)
			}
			request := migrationInstallerRequest{Version: 1, ID: strings.Repeat("1", 64), Session: f.enrollment.worker.session, Operation: "execute", Preparation: &evidence, Identity: identity, DeadlineUnixMilliseconds: deadline.UnixMilli()}
			factory := func(context.Context) (*migrationInstallerSession, error) {
				return &migrationInstallerSession{composition: f.composition, expectedPreparation: plan, frozen: func(context.Context) error {
					if mode == "frozen" {
						return errMigrationUnavailable
					}
					return nil
				}, finalize: func(context.Context, migrationCompositionReceipt) (session.ProcessIdentity, error) {
					return session.ProcessIdentity{}, errMigrationUnavailable
				}}, nil
			}
			_ = serveMigrationInstaller(f.ctx, installerServerChannel(t, request), f.enrollment.worker, f.authority.workerAuthority, factory)
			if f.executor.commits != 0 {
				t.Fatal("stale/mixed preparation committed")
			}
		})
	}
}
func TestInstallCandidateConfigurationPreservesCredentialsAndScope(t *testing.T) {
	uid := uint32(501)
	enrolled := migrationPackagedEnrollment{ExpectedUID: &uid, ConsoleRequirement: "old-console", OldRequirement: "old-broker", NewRequirement: "new-broker", Alias: "master", Service: "com.viant.mechanize.vault", Account: "fixture"}
	old := map[string]any{"sourceRoot": "/old/source", "nativeHelper": "/private/helper-preflight/native", "nativeLaunch": map[string]any{"helperRequirement": "active-helper", "windowFrameClick": true}, "nativeConsole": map[string]any{"designatedRequirement": "old-console", "expectedUID": 501}, "nativeVault": map[string]any{"keyAlias": "master", "brokerRequirement": "old-broker", "root": "/private/vault"}, "keychain": map[string]any{"Items": map[string]any{"master": map[string]any{"Service": "com.viant.mechanize.vault", "Account": "fixture"}}}, "credentialReference": "unchanged-fixture-reference", "users": []any{map[string]any{"desktopAccess": false}}, "chrome": map[string]any{"processTrust": map[string]any{"nativeHostRequirement": "old-host"}, "grants": []string{"unchanged-grant"}}}
	raw, _ := json.Marshal(old)
	p := migrationPackagedInstallPlan{NewSourceRoot: "/new/source", Runtime: migrationRuntimeArtifactPlan{ActiveHelperPath: "/private/helper-preflight/native", ActiveHelperRequirement: "active-helper", Artifacts: []migrationRuntimeArtifact{{Role: "helper", Target: "/runtime/mechanize-native", NewRequirement: "new-helper"}, {Role: "console", NewRequirement: "new-console"}, {Role: "native-host", NewRequirement: "new-host"}}}}
	var next map[string]any
	json.Unmarshal(raw, &next)
	next["sourceRoot"] = "/new/source"
	next["nativeHelper"] = "/runtime/mechanize-native"
	next["nativeLaunch"].(map[string]any)["helperRequirement"] = "new-helper"
	next["nativeConsole"].(map[string]any)["designatedRequirement"] = "new-console"
	next["nativeVault"].(map[string]any)["brokerRequirement"] = "new-broker"
	next["chrome"].(map[string]any)["processTrust"].(map[string]any)["nativeHostRequirement"] = "new-host"
	updated, _ := json.Marshal(next)
	if !migrationInstallConfigPreserved(raw, updated, p, enrolled) {
		t.Fatal("exact runtime-reference update refused")
	}
	for _, field := range []string{"credentialReference", "users", "keychain"} {
		t.Run(field, func(t *testing.T) {
			var changed map[string]any
			json.Unmarshal(updated, &changed)
			changed[field] = fmt.Sprintf("changed-%s", field)
			data, _ := json.Marshal(changed)
			if migrationInstallConfigPreserved(raw, data, p, enrolled) {
				t.Fatal("unrelated setting changed")
			}
		})
	}
}

//go:build darwin || linux

package keychain

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/session"
)

type readinessSystemFixture struct {
	running                                   bool
	starts, stops, diagnostics, verifications int
	changed                                   bool
	jobError                                  bool
	afterDiagnostic                           func()
	broker                                    string
	output                                    []byte
}

func (s *readinessSystemFixture) job(context.Context, string, migrationLaunchdJob, string) (int, error) {
	if s.jobError {
		return 0, errMigrationUnavailable
	}
	if s.running {
		return 123, nil
	}
	return 0, nil
}
func (s *readinessSystemFixture) kickstart(context.Context, string) error {
	s.starts++
	s.running = true
	return nil
}
func (s *readinessSystemFixture) inspect(context.Context, int, string) (session.ProcessIdentity, error) {
	return session.ProcessIdentity{PID: 123, UID: uint32(os.Getuid()), Executable: s.broker, StartToken: "owned-generation"}, nil
}
func (s *readinessSystemFixture) verifyProcess(context.Context, session.ProcessIdentity, string) error {
	s.verifications++
	if s.changed {
		return errMigrationUnavailable
	}
	return nil
}
func (s *readinessSystemFixture) terminate(context.Context, string, session.ProcessIdentity, string) error {
	if s.changed {
		return errMigrationUnavailable
	}
	s.stops++
	s.running = false
	return nil
}
func (s *readinessSystemFixture) gone(context.Context, session.ProcessIdentity) error {
	if s.running {
		return errMigrationUnavailable
	}
	return nil
}
func (s *readinessSystemFixture) diagnostic(context.Context, string, string, session.ProcessIdentity) ([]byte, error) {
	s.diagnostics++
	if s.afterDiagnostic != nil {
		s.afterDiagnostic()
	}
	return append([]byte(nil), s.output...), nil
}
func readinessJobBytes(broker, config string) []byte {
	return []byte(`<plist><dict><key>Label</key><string>com.viant.mechanize.fixture</string><key>ProgramArguments</key><array><string>` + broker + `</string><string>serve</string><string>-config</string><string>` + config + `</string><string>-listen</string><string>127.0.0.1:4987</string></array><key>KeepAlive</key><false/></dict></plist>`)
}
func readinessFixture(t *testing.T) (*migrationKeyReadiness, *readinessSystemFixture, *migrationWorkerExecutorFixture, migrationStagePlan, context.Context) {
	t.Helper()
	f := newRuntimePlacementFixture(t)
	p := f.p
	runtimeWrite(t, p.options.canonicalExecutable, []byte("new-broker"), 0700)
	p.newBinarySHA256 = migrationDigest([]byte("new-broker"))
	config := filepath.Join(filepath.Dir(p.options.canonicalExecutable), "config.json")
	runtimeWrite(t, config, []byte("new-config"), 0600)
	p.newConfigSHA256 = migrationDigest([]byte("new-config"))
	acl, _ := fileMigrationFixture(t)
	record := migrationJournalRecord{state: migrationUnknown, transitionID: p.transitionID, optionsSHA256: migrationOptionsDigest(p.options), identity: p.itemIdentity}
	if err := acl.markUnknown(f.ctx, record); err != nil {
		t.Fatal(err)
	}
	if err := acl.markVerified(f.ctx, record); err != nil {
		t.Fatal(err)
	}
	jobPath := filepath.Join(filepath.Dir(p.options.canonicalExecutable), "broker.plist")
	job := readinessJobBytes(p.options.canonicalExecutable, config)
	runtimeWrite(t, jobPath, job, 0600)
	manifestPath := filepath.Join(filepath.Dir(p.options.canonicalExecutable), "frozen-manifest.json")
	runtimeWrite(t, manifestPath, []byte("frozen-runtime-manifest"), 0600)
	console := f.r.artifact("console")
	plan := migrationKeyReadinessPlan{Launchd: migrationPackagedResource{Path: jobPath, SHA256: migrationDigest(job)}, Listen: "127.0.0.1:4987", ConsoleCandidate: console.Candidate, ConsoleRequirement: console.NewRequirement, ConsoleInventory: console.New}
	system := &readinessSystemFixture{broker: p.options.canonicalExecutable, output: []byte(`{"authenticated":true,"inventoryReadable":true,"keyReady":true,"stage":"complete"}`)}
	metadata := &migrationWorkerExecutorFixture{migrationBackendFixture: &migrationBackendFixture{events: &[]string{}, newPolicy: true}}
	read := func(ref migrationPackagedResource) ([]byte, error) {
		data, err := os.ReadFile(ref.Path)
		if err != nil || migrationDigest(data) != ref.SHA256 {
			return nil, errMigrationUnavailable
		}
		return data, nil
	}
	adapter := &migrationKeyReadiness{plan: plan, manifest: migrationPackagedResource{Path: manifestPath, SHA256: migrationDigest([]byte("frozen-runtime-manifest"))}, acl: acl, metadata: metadata, code: f.signatures, system: system, readResource: read}
	return adapter, system, metadata, p, f.ctx
}
func TestKeyReadinessUsesFreshNewBrokerAndStopsOwnedProbe(t *testing.T) {
	adapter, system, metadata, p, ctx := readinessFixture(t)
	if err := adapter.check(ctx, p); err != nil {
		t.Fatal(err)
	}
	if system.starts != 1 || system.stops != 1 || system.diagnostics != 1 || system.running || metadata.inspections < 3 {
		t.Fatal("readiness did not verify fresh owned process and custody around probe")
	}
}
func TestKeyReadinessRejectsUnsafeAdmissionWithoutStart(t *testing.T) {
	for _, mode := range []string{"already-running", "loaded-job", "definition", "config", "manifest", "policy"} {
		t.Run(mode, func(t *testing.T) {
			r, s, m, p, ctx := readinessFixture(t)
			switch mode {
			case "already-running":
				s.running = true
			case "loaded-job":
				s.jobError = true
			case "definition":
				runtimeWrite(t, r.plan.Launchd.Path, []byte("changed-job"), 0600)
			case "config":
				runtimeWrite(t, filepath.Join(filepath.Dir(p.options.canonicalExecutable), "config.json"), []byte("changed-config"), 0600)
			case "manifest":
				runtimeWrite(t, r.manifest.Path, []byte("changed-manifest"), 0600)
			case "policy":
				m.newPolicy = false
			}
			if r.check(ctx, p) == nil || s.starts != 0 || s.diagnostics != 0 {
				t.Fatal("unsafe readiness admission launched a process")
			}
		})
	}
}
func TestKeyReadinessKeepsFailureUnknownAndNeverStopsUnownedProcess(t *testing.T) {
	for _, mode := range []string{"report", "identity", "policy"} {
		t.Run(mode, func(t *testing.T) {
			r, s, m, p, ctx := readinessFixture(t)
			switch mode {
			case "report":
				s.output = []byte(`{"authenticated":true,"inventoryReadable":true,"keyReady":true,"stage":"complete","secret":"private-canary"}`)
			case "identity":
				s.afterDiagnostic = func() { s.changed = true }
			case "policy":
				s.afterDiagnostic = func() { m.newPolicy = false }
			}
			if err := r.check(ctx, p); err != errMigrationUnknown {
				t.Fatal("probe failure lost unknown classification", err)
			}
			if mode == "identity" {
				if s.stops != 0 {
					t.Fatal("unowned replacement stopped")
				}
			} else if s.stops != 1 {
				t.Fatal("owned failed probe left running")
			}
		})
	}
}
func TestKeyReadinessLaunchdAndReportDecodersAreClosed(t *testing.T) {
	broker := "/private/runtime/mechanize"
	config := "/private/runtime/config.json"
	job, err := decodeMigrationLaunchdJob(readinessJobBytes(broker, config), broker, config, "127.0.0.1:4987")
	if err != nil {
		t.Fatal(err)
	}
	service := migrationReadinessService(job.label)
	definition := "/private/runtime/broker.plist"
	status := service + " = {\n path = " + definition + "\n program = " + broker + "\n arguments = {\n" + strings.Join(job.arguments, "\n") + "\n}\npid = 123\n}\n"
	if pid, err := decodeMigrationLaunchdStatus([]byte(status), service, job, definition); err != nil || pid != 123 {
		t.Fatal("exact loaded job refused")
	}
	for _, bad := range []string{strings.Replace(status, broker, "/wrong/broker", 1), status + "pid = 456\n", strings.Replace(status, definition, "/wrong/definition", 1)} {
		if _, err := decodeMigrationLaunchdStatus([]byte(bad), service, job, definition); err == nil {
			t.Fatal("changed loaded job accepted")
		}
	}
	for _, bad := range []string{`{"authenticated":true,"inventoryReadable":true,"keyReady":true,"keyReady":false,"stage":"complete"}`, `{"authenticated":true,"inventoryReadable":true,"keyReady":false,"stage":"complete"}`, `{"authenticated":true,"inventoryReadable":true,"keyReady":true,"stage":"complete","token":"private"}`} {
		if validMigrationVaultDiagnostic([]byte(bad)) {
			t.Fatal("untrusted diagnostic accepted")
		}
	}
}

func TestTerminalCredentialEvidenceRequiresFreshSuccessfulLocalProbe(t *testing.T) {
	r, system, _, plan, ctx := readinessFixture(t)
	if _, err := r.terminalCredentialEvidence(ctx); err == nil {
		t.Fatal("missing signed probe accepted")
	}
	if err := r.check(ctx, plan); err != nil {
		t.Fatal(err)
	}
	if r.credentialProof == nil || system.diagnostics != 1 || system.running {
		t.Fatal("successful probe not retained after verified stop")
	}
	proof, err := r.terminalCredentialEvidence(ctx)
	if err != nil || proof.newConsoleAccount != "new-account" || !validMigrationID(proof.newConsoleCredentialReceiptSHA256) {
		t.Fatalf("verified candidate/account proof unavailable: %+v %v", proof, err)
	}
	originalPath := r.plan.ConsoleCandidate
	r.plan.ConsoleCandidate += "-substituted"
	if _, err := r.terminalCredentialEvidence(ctx); err == nil {
		t.Fatal("substituted candidate accepted")
	}
	r.plan.ConsoleCandidate = originalPath
	old := r.credentialProof.at
	r.credentialProof.at = old.Add(-time.Minute)
	if _, err := r.terminalCredentialEvidence(ctx); err == nil {
		t.Fatal("stale probe accepted")
	}
	r.credentialProof.at = old
	system.output = []byte(`{"authenticated":false}`)
	if err := r.check(ctx, plan); err == nil {
		t.Fatal("failed probe accepted")
	}
	if r.credentialProof != nil {
		t.Fatal("old readiness survived a failed new probe")
	}
}

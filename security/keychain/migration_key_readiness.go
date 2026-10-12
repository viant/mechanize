//go:build darwin || linux

package keychain

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/viant/mechanize/session"
)

// Frozen launchd definition is preserved, never rewritten or replaced by a
// direct child broker. Only the new signed console's fixed diagnostic is run.
type migrationKeyReadinessPlan struct {
	Launchd            migrationPackagedResource `json:"launchd"`
	Listen             string                    `json:"listen"`
	ConsoleCandidate   string                    `json:"consoleCandidate"`
	ConsoleRequirement string                    `json:"consoleRequirement"`
	ConsoleInventory   migrationRuntimeInventory `json:"consoleInventory"`
}
type migrationLaunchdJob struct {
	label     string
	arguments []string
}
type migrationReadinessSystem interface {
	job(context.Context, string, migrationLaunchdJob, string) (int, error)
	kickstart(context.Context, string) error
	inspect(context.Context, int, string) (session.ProcessIdentity, error)
	verifyProcess(context.Context, session.ProcessIdentity, string) error
	terminate(context.Context, string, session.ProcessIdentity, string) error
	gone(context.Context, session.ProcessIdentity) error
	diagnostic(context.Context, string, string, session.ProcessIdentity) ([]byte, error)
}
type migrationCredentialReadinessProof struct {
	at               time.Time
	stage            migrationStagePlan
	diagnosticSHA256 string
	broker           session.ProcessIdentity
}
type migrationKeyReadiness struct {
	credentialProof *migrationCredentialReadinessProof
	plan            migrationKeyReadinessPlan
	manifest        migrationPackagedResource
	acl             migrationJournal
	metadata        migrationWorkerExecutor
	code            migrationRuntimeSignatureVerifier
	system          migrationReadinessSystem
	readResource    func(migrationPackagedResource) ([]byte, error)
}

func (*migrationKeyReadiness) String() string   { return "Checked native key readiness" }
func (*migrationKeyReadiness) GoString() string { return "Checked native key readiness" }
func (*migrationKeyReadiness) MarshalJSON() ([]byte, error) {
	return []byte(`{"state":"private"}`), nil
}

func decodeMigrationLaunchdJob(raw []byte, broker, config, listen string) (migrationLaunchdJob, error) {
	var result migrationLaunchdJob
	if len(raw) == 0 || len(raw) > 1<<20 {
		return result, errMigrationUnavailable
	}
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	depth := 0
	key := ""
	seen := map[string]bool{}
	rootSeen := false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return migrationLaunchdJob{}, errMigrationUnavailable
		}
		switch t := token.(type) {
		case xml.StartElement:
			depth++
			if depth > 24 {
				return migrationLaunchdJob{}, errMigrationUnavailable
			}
			if depth == 1 {
				if rootSeen || t.Name.Local != "plist" {
					return migrationLaunchdJob{}, errMigrationUnavailable
				}
				rootSeen = true
			}
			if depth == 2 && t.Name.Local != "dict" {
				return migrationLaunchdJob{}, errMigrationUnavailable
			}
			if depth != 3 {
				continue
			}
			if t.Name.Local == "key" {
				if decoder.DecodeElement(&key, &t) != nil || seen[key] {
					return migrationLaunchdJob{}, errMigrationUnavailable
				}
				seen[key] = true
				depth--
				continue
			}
			switch key {
			case "Label":
				if t.Name.Local != "string" || decoder.DecodeElement(&result.label, &t) != nil {
					return migrationLaunchdJob{}, errMigrationUnavailable
				}
			case "ProgramArguments":
				if t.Name.Local != "array" {
					return migrationLaunchdJob{}, errMigrationUnavailable
				}
				var a struct {
					Strings []string `xml:"string"`
				}
				if decoder.DecodeElement(&a, &t) != nil {
					return migrationLaunchdJob{}, errMigrationUnavailable
				}
				result.arguments = a.Strings
			case "KeepAlive":
				if t.Name.Local != "false" || decoder.Skip() != nil {
					return migrationLaunchdJob{}, errMigrationUnavailable
				}
			case "Program":
				return migrationLaunchdJob{}, errMigrationUnavailable // no alternate executable source
			default:
				if decoder.Skip() != nil {
					return migrationLaunchdJob{}, errMigrationUnavailable
				}
			}
			key = ""
			depth--
		case xml.EndElement:
			depth--
		}
	}
	expected := []string{broker, "serve", "-config", config, "-listen", listen}
	if depth != 0 || !regexp.MustCompile(`^com\.viant\.mechanize\.[a-z0-9.-]+$`).MatchString(result.label) || len(result.arguments) != len(expected) {
		return migrationLaunchdJob{}, errMigrationUnavailable
	}
	for i, value := range expected {
		if result.arguments[i] != value {
			return migrationLaunchdJob{}, errMigrationUnavailable
		}
	}
	return result, nil
}

// launchctl output is internal metadata only; nothing is forwarded to callers.
// Verify the loaded job actually points at the frozen plist/program/arguments.
func decodeMigrationLaunchdStatus(raw []byte, service string, job migrationLaunchdJob, definition string) (int, error) {
	if len(raw) == 0 || len(raw) > 65536 {
		return 0, errMigrationUnavailable
	}
	lines := strings.Split(string(raw), "\n")
	if strings.TrimSpace(lines[0]) != service+" = {" {
		return 0, errMigrationUnavailable
	}
	path, program := "", ""
	pid := 0
	arguments := []string{}
	inArguments := false
	argumentBlocks := 0
	paths, programs, pids := 0, 0, 0
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if inArguments {
			if line == "}" {
				inArguments = false
				continue
			}
			arguments = append(arguments, line)
			continue
		}
		if line == "arguments = {" {
			argumentBlocks++
			inArguments = true
			continue
		}
		if strings.HasPrefix(line, "path = ") {
			paths++
			path = strings.TrimPrefix(line, "path = ")
		}
		if strings.HasPrefix(line, "program = ") {
			programs++
			program = strings.TrimPrefix(line, "program = ")
		}
		if strings.HasPrefix(line, "pid = ") {
			pids++
			value, err := strconv.Atoi(strings.TrimPrefix(line, "pid = "))
			if err != nil || value <= 0 {
				return 0, errMigrationUnavailable
			}
			pid = value
		}
	}
	if paths != 1 || programs != 1 || pids > 1 || argumentBlocks != 1 || inArguments || path != definition || program != job.arguments[0] || len(arguments) != len(job.arguments) {
		return 0, errMigrationUnavailable
	}
	for i, value := range arguments {
		if value != job.arguments[i] {
			return 0, errMigrationUnavailable
		}
	}
	return pid, nil
}
func validMigrationVaultDiagnostic(raw []byte) bool {
	if len(raw) == 0 || len(raw) > 4096 {
		return false
	}
	// Field order matches Swift JSONEncoder.sortedKeys. Canonical comparison also
	// rejects duplicate/extra fields without surfacing their possibly private data.
	var report struct {
		Authenticated     bool    `json:"authenticated"`
		ErrorCode         *string `json:"errorCode,omitempty"`
		InventoryReadable bool    `json:"inventoryReadable"`
		KeyReady          *bool   `json:"keyReady,omitempty"`
		Stage             string  `json:"stage"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&report) != nil || decoder.Decode(new(any)) != io.EOF {
		return false
	}
	canonical, _ := json.Marshal(report)
	return bytes.Equal(bytes.TrimSpace(raw), canonical) && report.Authenticated && report.ErrorCode == nil && report.InventoryReadable && report.KeyReady != nil && *report.KeyReady && report.Stage == "complete"
}
func (r *migrationKeyReadiness) verifyCustody(ctx context.Context, p migrationStagePlan) error {
	record, err := r.acl.load(ctx)
	if err != nil || record == nil || record.state != migrationVerified || record.transitionID != p.transitionID || record.optionsSHA256 != migrationOptionsDigest(p.options) || !bytes.Equal(record.identity, p.itemIdentity) {
		return errMigrationUnavailable
	}
	actual, err := r.metadata.inspect(ctx, p.options, bytes.Clone(p.itemIdentity))
	if err != nil || !actual.exactNewPolicy || !bytes.Equal(actual.identity, p.itemIdentity) || migrationContext(ctx) != nil {
		return errMigrationUnavailable
	}
	return nil
}
func (r *migrationKeyReadiness) verifyFiles(ctx context.Context, p migrationStagePlan) error {
	if migrationContext(ctx) != nil || !validMigrationStagePlan(p) || r.verifyCustody(ctx, p) != nil {
		return errMigrationUnavailable
	}
	if digest, err := migrationFileDigest(p.options.destinationExecutable(), true); err != nil || digest != p.newBinarySHA256 {
		return errMigrationUnavailable
	}
	if digest, err := migrationFileDigest(p.configPath(), false); err != nil || digest != p.newConfigSHA256 {
		return errMigrationUnavailable
	}
	if runtimeVerifyInventory(r.plan.ConsoleCandidate, r.plan.ConsoleInventory) != nil || r.code.verify(ctx, "console", r.plan.ConsoleCandidate, r.plan.ConsoleRequirement) != nil {
		return errMigrationUnavailable
	}
	data, err := runtimeReadFile(filepath.Join(r.plan.ConsoleCandidate, "Contents/Info.plist"), r.plan.ConsoleInventory["Contents/Info.plist"])
	if err != nil {
		return errMigrationUnavailable
	}
	values, err := runtimePlistStrings(data)
	if err != nil || values["MechanizeBrokerRequirement"] != p.options.newRequirement {
		return errMigrationUnavailable
	}
	return nil
}
func (r *migrationKeyReadiness) check(ctx context.Context, p migrationStagePlan) error {
	r.credentialProof = nil
	_, err := r.run(ctx, p, false)
	return err
}
func (r *migrationKeyReadiness) startAndVerify(ctx context.Context, p migrationStagePlan) (session.ProcessIdentity, error) {
	return r.run(ctx, p, true)
}
func (r *migrationKeyReadiness) run(ctx context.Context, p migrationStagePlan, leaveRunning bool) (session.ProcessIdentity, error) {
	if r == nil || !migrationPackagedPath(r.manifest.Path) || !validMigrationID(r.manifest.SHA256) || r.acl == nil || r.metadata == nil || r.code == nil || r.system == nil || r.readResource == nil || !migrationPackagedPath(r.plan.Launchd.Path) || !validMigrationID(r.plan.Launchd.SHA256) || !runtimeRoleRequirement("console", r.plan.ConsoleRequirement) || !runtimeValidInventory(r.plan.ConsoleInventory) || r.verifyFiles(ctx, p) != nil {
		return session.ProcessIdentity{}, errMigrationUnavailable
	}
	manifest, manifestErr := r.readResource(r.manifest)
	for i := range manifest {
		manifest[i] = 0
	}
	if manifestErr != nil {
		return session.ProcessIdentity{}, errMigrationUnavailable
	}
	raw, err := r.readResource(r.plan.Launchd)
	if err != nil {
		return session.ProcessIdentity{}, errMigrationUnavailable
	}
	job, err := decodeMigrationLaunchdJob(raw, p.options.destinationExecutable(), p.configPath(), r.plan.Listen)
	for i := range raw {
		raw[i] = 0
	}
	if err != nil {
		return session.ProcessIdentity{}, errMigrationUnavailable
	}
	service := migrationReadinessService(job.label)
	pid, err := r.system.job(ctx, service, job, r.plan.Launchd.Path)
	if err != nil || pid != 0 {
		return session.ProcessIdentity{}, errMigrationUnavailable
	}
	if r.system.kickstart(ctx, service) != nil {
		return session.ProcessIdentity{}, errMigrationUnknown
	}
	// Once kickstart dispatches, any failure is unknown. Never start a fallback
	// broker or kill a process that cannot be tied to this launchd job and birth.
	var owned session.ProcessIdentity
	wait, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for wait.Err() == nil {
		pid, err = r.system.job(wait, service, job, r.plan.Launchd.Path)
		if err != nil {
			return session.ProcessIdentity{}, errMigrationUnknown
		}
		if pid > 0 {
			owned, err = r.system.inspect(wait, pid, p.options.destinationExecutable())
			if err == nil {
				break
			}
		}
		select {
		case <-wait.Done():
		case <-time.After(50 * time.Millisecond):
		}
	}
	if owned.PID <= 0 || err != nil || r.system.verifyProcess(ctx, owned, p.options.newRequirement) != nil {
		return session.ProcessIdentity{}, errMigrationUnknown
	}
	// A probe broker is gracefully stopped even if its diagnostic fails. This
	// preserves quiescence through deferred console placement; terminal orchestration
	// later starts the complete new installation via the same unchanged launchd job.
	success := false

	output, diagnosticErr := r.system.diagnostic(ctx, r.plan.ConsoleCandidate, r.plan.ConsoleRequirement, owned)
	diagnosticOK := diagnosticErr == nil && validMigrationVaultDiagnostic(output)
	diagnosticAt := time.Now()
	diagnosticSHA256 := migrationDigest(output)
	for i := range output {
		output[i] = 0
	}
	ownedBeforeStop := r.system.verifyProcess(ctx, owned, p.options.newRequirement) == nil
	filesBeforeStop := r.verifyFiles(ctx, p) == nil
	raw, err = r.readResource(r.plan.Launchd)
	for i := range raw {
		raw[i] = 0
	}
	definitionOK := err == nil
	manifest, manifestErr = r.readResource(r.manifest)
	for i := range manifest {
		manifest[i] = 0
	}
	definitionOK = definitionOK && manifestErr == nil
	if !ownedBeforeStop || !definitionOK {
		return session.ProcessIdentity{}, errMigrationUnknown
	}
	jobPID, jobErr := r.system.job(ctx, service, job, r.plan.Launchd.Path)
	if jobErr != nil || jobPID != owned.PID {
		return session.ProcessIdentity{}, errMigrationUnknown
	}
	if leaveRunning && diagnosticOK && filesBeforeStop && r.verifyFiles(ctx, p) == nil {
		if r.system.verifyProcess(ctx, owned, p.options.newRequirement) != nil {
			return session.ProcessIdentity{}, errMigrationUnknown
		}
		return owned, nil
	}
	if r.system.terminate(ctx, service, owned, p.options.newRequirement) != nil {
		return session.ProcessIdentity{}, errMigrationUnknown
	}
	stopped, cancelStop := context.WithTimeout(ctx, 5*time.Second)
	defer cancelStop()
	for stopped.Err() == nil {
		pid, err = r.system.job(stopped, service, job, r.plan.Launchd.Path)
		if err != nil {
			return session.ProcessIdentity{}, errMigrationUnknown
		}
		if pid == 0 {
			if r.system.gone(stopped, owned) != nil {
				return session.ProcessIdentity{}, errMigrationUnknown
			}
			success = true
			break
		}
		if pid != owned.PID {
			return session.ProcessIdentity{}, errMigrationUnknown
		}
		select {
		case <-stopped.Done():
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !success || !diagnosticOK || !filesBeforeStop || r.verifyFiles(ctx, p) != nil {
		return session.ProcessIdentity{}, errMigrationUnknown
	}
	r.credentialProof = &migrationCredentialReadinessProof{at: diagnosticAt, stage: p, diagnosticSHA256: diagnosticSHA256, broker: owned}
	return session.ProcessIdentity{}, nil
}

func (r *migrationKeyReadiness) terminalCredentialEvidence(ctx context.Context) (migrationRuntimeTerminalEvidence, error) {
	proof := r.credentialProof
	if proof == nil || proof.at.After(time.Now()) || time.Since(proof.at) > 30*time.Second || r.verifyFiles(ctx, proof.stage) != nil || r.system.gone(ctx, proof.broker) != nil {
		return migrationRuntimeTerminalEvidence{}, errMigrationUnavailable
	}
	raw, err := runtimeReadFile(filepath.Join(r.plan.ConsoleCandidate, "Contents/Info.plist"), r.plan.ConsoleInventory["Contents/Info.plist"])
	values, decodeErr := runtimePlistStrings(raw)
	account := values["MechanizeEnrollmentAccount"]
	if err != nil || decodeErr != nil || account == "" {
		return migrationRuntimeTerminalEvidence{}, errMigrationUnavailable
	}
	binding, _ := json.Marshal([]any{"mechanize-console-credential-readiness-v1", proof.at.UnixMilli(), proof.stage.transitionID, r.plan.ConsoleCandidate, r.plan.ConsoleRequirement, runtimeInventoryDigest(r.plan.ConsoleInventory), account, proof.broker, proof.stage.options.newRequirement, proof.diagnosticSHA256})
	return migrationRuntimeTerminalEvidence{receiptSHA256: migrationDigest(binding), newConsoleCredentialReceiptSHA256: migrationDigest(binding), newConsoleAccount: account}, nil
}

func migrationReadinessService(label string) string {
	return "gui/" + strconv.Itoa(os.Getuid()) + "/" + label
}

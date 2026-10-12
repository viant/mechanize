//go:build darwin && cgo

package keychain

import (
	"context"
	"io"
	"net"
	"os"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/session"
)

// The signed native-console bridge is the only production observer. No CLI,
// environment or RPC setter can replace its peer/authority/manifest binding.
func packagedInstallerObserverFactory(ctx context.Context, authority *migrationNativeAuthority, session, manifest, mode string) (*migrationAuthenticatedObserver, error) {
	if migrationContext(ctx) != nil {
		return nil, errMigrationUnavailable
	}
	return newMigrationAuthenticatedObserver(authority, session, manifest, mode)
}

func servePackagedInstallerEntry(ctx context.Context, channel io.ReadWriteCloser, console *net.UnixConn, entry migrationEntryEnrollment, enrolled migrationPackagedEnrollment, verifier *auth.Verifier) error {
	if enrolled.InstallPlan == nil || enrolled.Preparation != nil || entry.worker.expectedIdentity != nil || !nativeMigrationExecutorMatches(entry.worker.executorRequirement) {
		return errMigrationUnavailable
	}
	authority, err := newMigrationNativeAuthority(console, entry.parent, verifier)
	if err != nil {
		return errMigrationUnavailable
	}
	defer authority.close()
	loader, err := newMigrationBootstrapLoader(entry.worker, entry.configDigest, entry.parent.parentRequirement, authority.authenticate)
	if err != nil {
		return errMigrationUnavailable
	}
	config, err := loader.load(ctx, channel)
	if err != nil {
		return err
	}
	raw, err := readMigrationPackagedResource(*enrolled.InstallPlan)
	if err != nil {
		return errMigrationUnavailable
	}
	plan, err := decodeMigrationInstallPlan(raw, enrolled)
	for i := range raw {
		raw[i] = 0
	}
	if err != nil {
		return errMigrationUnavailable
	}
	oldConfig, err := readMigrationPackagedResource(enrolled.Config)
	if err != nil {
		return errMigrationUnavailable
	}
	defer func() {
		for i := range oldConfig {
			oldConfig[i] = 0
		}
	}()
	nextConfig, err := readMigrationPackagedResource(plan.ConfigCandidate)
	if err != nil {
		return errMigrationUnavailable
	}
	defer func() {
		for i := range nextConfig {
			nextConfig[i] = 0
		}
	}()
	var recovery [][]byte
	if plan.Runtime.ChromeRecovery != nil {
		original, e := readMigrationPackagedResource(plan.Runtime.ChromeRecovery.OriginalConfig)
		if e != nil {
			return errMigrationUnavailable
		}
		defer clear(original)
		recovery = append(recovery, original)
	}
	if !migrationInstallConfigPreserved(oldConfig, nextConfig, plan, enrolled, recovery...) {
		return errMigrationUnavailable
	}
	workerPath, err := os.Executable()
	if err != nil || !migrationPackagedPath(workerPath) {
		return errMigrationUnavailable
	}
	workerSHA, err := migrationFileDigest(workerPath, true)
	if err != nil {
		return errMigrationUnavailable
	}
	preparation := migrationPreparationPlan{MutationExecutable: workerPath, MutationRequirement: config.executorRequirement, MutationSHA256: workerSHA, RuntimeManifestSHA256: enrolled.InstallPlan.SHA256}
	if !preparation.valid() {
		return errMigrationUnavailable
	}
	factory := func(authorized context.Context) (*migrationInstallerSession, error) {
		observer, e := packagedInstallerObserverFactory(authorized, authority, config.session, enrolled.InstallPlan.SHA256, plan.Runtime.Mode)
		if e != nil || observer == nil {
			return nil, errMigrationUnavailable
		}
		artifacts, e := newSignedRuntimeArtifacts(plan.Runtime, plan.ArtifactJournalRoot, observer)
		if e != nil {
			return nil, e
		}
		acl, e := newFileMigrationJournal(enrolled.JournalRoot)
		if e != nil {
			return nil, e
		}
		consoleArtifact := artifacts.artifact("console")
		if plan.Readiness.ConsoleCandidate != consoleArtifact.Candidate || plan.Readiness.ConsoleRequirement != consoleArtifact.NewRequirement || runtimeInventoryDigest(plan.Readiness.ConsoleInventory) != consoleArtifact.NewDigest {
			return nil, errMigrationUnavailable
		}
		readinessPlan := plan.Readiness
		if plan.Runtime.Mode == unifiedUpdateMode {
			// Create-only enrollment belongs to the final installed image/path;
			// the staged candidate must never stand in for that credential reader.
			readinessPlan.ConsoleCandidate = consoleArtifact.Target
		}
		readiness, e := newNativeMigrationKeyReadiness(readinessPlan, acl, *enrolled.InstallPlan)
		if e != nil {
			return nil, e
		}
		observer.readiness = readiness.terminalCredentialEvidence
		template := migrationStagePlan{options: config.options, oldBinarySHA256: plan.OldBrokerSHA256, newBinarySHA256: plan.BrokerCandidate.SHA256, oldConfigSHA256: enrolled.Config.SHA256, newConfigSHA256: plan.ConfigCandidate.SHA256}
		if unifiedRuntimeMode(plan.Runtime.Mode) {
			template.unifiedInventorySHA256 = plan.Runtime.Artifacts[0].NewDigest
			template.preinstalledUnifiedApp = plan.Runtime.PreinstalledUnifiedApp
			if plan.Runtime.Mode == unifiedUpdateMode {
				template.updateConfig = enrolled.Config.Path
				template.updateOldInventorySHA256 = plan.Runtime.Artifacts[0].OldDigest
			}
		}
		compositionEnrollment := migrationCompositionEnrollment{worker: config, template: template, candidateBinary: plan.BrokerCandidate.Path, candidateConfig: plan.ConfigCandidate.Path, canonicalConfig: enrolled.Config.Path, backup: plan.Backup, aclJournalRoot: enrolled.JournalRoot, stageJournalRoot: plan.StageJournalRoot}
		if unifiedRuntimeMode(plan.Runtime.Mode) {
			app := plan.Runtime.Artifacts[0]
			compositionEnrollment.unified = &app
		}
		runtimeReady := artifacts.verifyNonConsoleReady
		if unifiedRuntimeMode(plan.Runtime.Mode) {
			runtimeReady = func(ctx context.Context, p migrationStagePlan) error {
				app := plan.Runtime.Artifacts[0]
				if artifacts.verifyOriginalConsole(ctx) != nil || !artifacts.binding(p) || runtimeVerifyInventory(app.Target, app.New) != nil || artifacts.signatures.verify(ctx, "console", app.Target, app.NewRequirement) != nil {
					return errMigrationUnavailable
				}
				if artifacts.verifyOriginalConsole(ctx) != nil {
					return errMigrationUnavailable
				}
				return artifacts.verifyPreservedExtension()
			}
		}
		var composition *migrationComposition
		enrollment := &migrationConsoleEnrollment{}
		keyReady := func(ctx context.Context, p migrationStagePlan) error {
			if plan.Runtime.Mode == unifiedUpdateMode {
				if composition == nil || composition.installer.stage == nil {
					return errMigrationUnavailable
				}
				backend := composition.installer.stage.backend
				if guarded, ok := backend.(*migrationInstallStageBackend); ok {
					backend = guarded.backend
				}
				stage, ok := backend.(*migrationUnifiedStage)
				if !ok {
					return errMigrationUnavailable
				}
				verify := func(ctx context.Context) error {
					if readiness.verifyCustody(ctx, p) != nil || runtimeReady(ctx, p) != nil {
						return errMigrationUnavailable
					}
					return nil
				}
				if enrollment.ensure(ctx, stage.attempted, verify, func(ctx context.Context) error {
					return enrollUpdatedNativeConsole(ctx, authority, plan.Runtime.Artifacts[0], verify)
				}) != nil {
					return errMigrationUnknown
				}
			}
			return readiness.check(ctx, p)
		}
		composition, e = newSignedMigrationComposition(authorized, authority, compositionEnrollment, artifacts.observe, artifacts.prepared, runtimeReady, keyReady)
		if e != nil {
			return nil, e
		}
		if !unifiedRuntimeMode(plan.Runtime.Mode) {
			composition.installer.stageFactory = artifacts.stageFactory(composition.installer.stageFactory)
		}
		frozen := func(ctx context.Context) error {
			if migrationContext(ctx) != nil || verifyMigrationExecutable(ctx, workerPath, config.executorRequirement) != nil {
				return errMigrationUnavailable
			}
			if digest, e := migrationFileDigest(workerPath, true); e != nil || digest != workerSHA {
				return errMigrationUnavailable
			}
			for _, ref := range []migrationPackagedResource{*enrolled.InstallPlan, enrolled.Config, plan.ConfigCandidate} {
				data, e := readMigrationPackagedResource(ref)
				for i := range data {
					data[i] = 0
				}
				if e != nil {
					return errMigrationUnavailable
				}
			}
			if digest, e := migrationFileDigest(plan.BrokerCandidate.Path, true); e != nil || digest != plan.BrokerCandidate.SHA256 {
				return errMigrationUnavailable
			}
			return nil
		}
		finalize := func(ctx context.Context, receipt migrationCompositionReceipt) (session.ProcessIdentity, error) {
			if receipt.State != migrationVerified || receipt.Scope != "custody-broker-config" || composition.installer.stage == nil {
				return session.ProcessIdentity{}, errMigrationUnavailable
			}
			check, release, e := migrationPlacementLock(composition.enrollment.template.configPath())
			if e != nil {
				return session.ProcessIdentity{}, errMigrationUnavailable
			}
			defer release()
			stagePlan := composition.installer.stage.planCopy()
			if receipt.TransitionID != stagePlan.transitionID || check() != nil {
				return session.ProcessIdentity{}, errMigrationUnavailable
			}
			if !unifiedRuntimeMode(plan.Runtime.Mode) && artifacts.placeConsoleTerminal(ctx, stagePlan, receipt, check) != nil {
				return session.ProcessIdentity{}, errMigrationUnknown
			}
			finalReadiness := *readiness
			finalReadiness.plan = readiness.plan
			finalReadiness.plan.ConsoleCandidate = consoleArtifact.Target
			if unifiedRuntimeMode(plan.Runtime.Mode) {
				finalReadiness.plan.ConsoleCandidate = plan.Runtime.Artifacts[0].Target
			}
			identity, err := finalReadiness.startAndVerify(ctx, stagePlan)
			if err != nil || check() != nil || artifacts.verifyOriginalConsole(ctx) != nil {
				return session.ProcessIdentity{}, errMigrationUnknown
			}
			return identity, nil
		}
		return &migrationInstallerSession{composition: composition, expectedPreparation: preparation, frozen: frozen, finalize: finalize}, nil
	}
	return serveMigrationInstaller(ctx, channel, config, authority.workerAuthority, factory)
}

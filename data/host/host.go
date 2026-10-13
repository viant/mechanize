// Package host links selected private Datly components and owns one immutable
// per-user connector lifetime. Callers invoke the generated typed contracts directly.
package host

import (
	"context"
	"github.com/viant/datly/bootstrap/connector"
	"github.com/viant/datly/standalone"
	"github.com/viant/datly/standalone/config"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/credentialprotectionscopeget"
	"github.com/viant/mechanize/data/credentialprotectionscopelegacy"
	"github.com/viant/mechanize/data/credentialprotectionscopelist"
	"github.com/viant/mechanize/data/credentialprotectionscopereserve"

	"github.com/viant/mechanize/data/applicationpolicyread"
	"github.com/viant/mechanize/data/applicationpolicywrite"
	"github.com/viant/mechanize/data/attachoperation"
	"github.com/viant/mechanize/data/beginattempt"
	"github.com/viant/mechanize/data/checkpoint"
	"github.com/viant/mechanize/data/chromeattemptbindingcreate"
	"github.com/viant/mechanize/data/chromeattemptbindingget"
	"github.com/viant/mechanize/data/chromeattemptbindinglist"
	"github.com/viant/mechanize/data/chromeattemptbindingpage"
	"github.com/viant/mechanize/data/chromeattemptbindingsnapshot"
	"github.com/viant/mechanize/data/chromeretirementget"
	"github.com/viant/mechanize/data/chromeretirementwrite"
	"github.com/viant/mechanize/data/commitoutcome"
	"github.com/viant/mechanize/data/consentconsume"
	"github.com/viant/mechanize/data/consentcreate"
	"github.com/viant/mechanize/data/consentdecide"
	"github.com/viant/mechanize/data/consentgrants"
	"github.com/viant/mechanize/data/consentrequests"
	"github.com/viant/mechanize/data/consentrevoke"
	"github.com/viant/mechanize/data/consenttrusted"
	"github.com/viant/mechanize/data/createrun"
	"github.com/viant/mechanize/data/credentialdeliveryblocked"
	"github.com/viant/mechanize/data/credentialdeliveryfinish"
	"github.com/viant/mechanize/data/credentialdeliveryget"
	"github.com/viant/mechanize/data/credentialdeliveryreserve"
	"github.com/viant/mechanize/data/credentialpreparationfinish"
	"github.com/viant/mechanize/data/credentialpreparationget"
	"github.com/viant/mechanize/data/credentialpreparationreserve"
	"github.com/viant/mechanize/data/credentialrecoveryload"
	"github.com/viant/mechanize/data/getartifact"
	"github.com/viant/mechanize/data/listcheckpoints"
	"github.com/viant/mechanize/data/listevents"
	"github.com/viant/mechanize/data/listrecordingevents"
	"github.com/viant/mechanize/data/listruns"
	"github.com/viant/mechanize/data/loadplan"
	"github.com/viant/mechanize/data/loadrun"
	"github.com/viant/mechanize/data/publishartifact"
	"github.com/viant/mechanize/data/publishplan"
	"github.com/viant/mechanize/data/reconcileeffect"
	"github.com/viant/mechanize/data/recordevents"
	"github.com/viant/mechanize/data/recoveryload"
	"github.com/viant/mechanize/data/repairadmit"
	"github.com/viant/mechanize/data/scenariolist"
	"github.com/viant/mechanize/data/scenariopublish"
	"github.com/viant/mechanize/data/stateget"
	"github.com/viant/mechanize/data/statepatch"
	"github.com/viant/mechanize/data/stopboundary"
	"github.com/viant/mechanize/data/transitionrun"
)

// Open starts no listener. Compiled contracts and embedded resources own runtime
// discovery; sourceRoot is retained for API compatibility, not source authority.
// The caller bounds user pool admission/eviction.
func Open(ctx context.Context, sourceRoot, storageRoot string, scope data.Scope) (*standalone.Server, error) {
	cfg, err := data.Provision(ctx, storageRoot, scope)
	if err != nil {
		return nil, err
	}
	const prefix = "github.com/viant/mechanize/data/"
	packages := []string{prefix + "credentialprotectionscopelegacy", prefix + "credentialprotectionscopereserve", prefix + "credentialprotectionscopeget", prefix + "credentialprotectionscopelist", prefix + "credentialpreparationfinish", prefix + "credentialrecoveryload", prefix + "credentialpreparationreserve", prefix + "credentialpreparationget", prefix + "credentialdeliveryblocked", prefix + "credentialdeliveryreserve", prefix + "credentialdeliveryget", prefix + "credentialdeliveryfinish", prefix + "consentcreate", prefix + "consentrequests", prefix + "consentdecide", prefix + "consentgrants", prefix + "consentconsume", prefix + "consentrevoke", prefix + "consenttrusted", prefix + "applicationpolicyread", prefix + "applicationpolicywrite", prefix + "chromeattemptbindingcreate", prefix + "chromeattemptbindingget", prefix + "chromeattemptbindinglist", prefix + "chromeattemptbindingpage", prefix + "chromeattemptbindingsnapshot", prefix + "chromeretirementget", prefix + "chromeretirementwrite", prefix + "publishplan", prefix + "createrun", prefix + "loadrun", prefix + "beginattempt", prefix + "commitoutcome", prefix + "reconcileeffect", prefix + "stopboundary", prefix + "checkpoint", prefix + "recordevents", prefix + "stateget", prefix + "statepatch", prefix + "transitionrun", prefix + "attachoperation", prefix + "publishartifact", prefix + "getartifact", prefix + "scenariopublish", prefix + "scenariolist", prefix + "recoveryload", prefix + "repairadmit", prefix + "listruns", prefix + "loadplan", prefix + "listevents", prefix + "listcheckpoints", prefix + "listrecordingevents"}
	server, err := standalone.New(ctx, standalone.Options{Config: &config.Config{BaseDir: sourceRoot, Connector: "user", Connectors: []connector.Config{cfg}, GoBootstrap: &config.Packages{Packages: packages, LinkedOnly: true}}, Holders: []any{credentialprotectionscopelegacy.CredentialProtectionScopeLegacyComponent{}, credentialprotectionscopereserve.CredentialProtectionScopeReserveComponent{}, credentialprotectionscopeget.CredentialProtectionScopeGetComponent{}, credentialprotectionscopelist.CredentialProtectionScopeListComponent{}, credentialpreparationfinish.CredentialPreparationFinishComponent{}, credentialrecoveryload.CredentialRecoveryLoadComponent{}, credentialpreparationreserve.CredentialPreparationReserveComponent{}, credentialpreparationget.CredentialPreparationGetComponent{}, credentialdeliveryblocked.CredentialDeliveryBlockedComponent{}, credentialdeliveryreserve.CredentialDeliveryReserveComponent{}, credentialdeliveryget.CredentialDeliveryGetComponent{}, credentialdeliveryfinish.CredentialDeliveryFinishComponent{}, consentcreate.ConsentcreateComponent{}, consentrequests.ConsentrequestsComponent{}, consentdecide.ConsentdecideComponent{}, consentgrants.ConsentgrantsComponent{}, consentconsume.ConsentconsumeComponent{}, consentrevoke.ConsentrevokeComponent{}, consenttrusted.ConsenttrustedComponent{}, applicationpolicyread.ApplicationpolicyreadComponent{}, applicationpolicywrite.ApplicationpolicywriteComponent{}, chromeattemptbindingcreate.CreateChromeAttemptBindingComponent{}, chromeattemptbindingget.LoadChromeAttemptBindingComponent{}, chromeattemptbindinglist.ListChromeAttemptBindingsComponent{}, chromeattemptbindingpage.PageChromeAttemptBindingsComponent{}, chromeattemptbindingsnapshot.Component{}, chromeretirementget.LoadChromeRetirementComponent{}, chromeretirementwrite.WriteChromeRetirementComponent{}, publishplan.PublishPlanRevisionComponent{}, createrun.CreateRunComponent{}, loadrun.LoadRunComponent{}, beginattempt.BeginAttemptComponent{}, commitoutcome.CommitOutcomeComponent{}, reconcileeffect.ReconcileEffectComponent{}, stopboundary.StopBoundaryComponent{}, checkpoint.PublishCheckpointComponent{}, recordevents.AppendRecordingEventsComponent{}, stateget.StateGetComponent{}, statepatch.StatePatchComponent{}, transitionrun.TransitionRunComponent{}, attachoperation.AttachOperationComponent{}, publishartifact.PublishArtifactComponent{}, getartifact.GetArtifactComponent{}, scenariopublish.PublishScenarioDraftComponent{}, scenariolist.ListScenariosComponent{}, recoveryload.LoadRecoveryComponent{}, repairadmit.AdmitRepairComponent{}, listruns.ListRunsComponent{}, loadplan.LoadPlanComponent{}, listevents.ListEventsComponent{}, listcheckpoints.ListCheckpointsComponent{}, listrecordingevents.ListRecordingEventsComponent{}}})
	if err != nil {
		return nil, err
	}
	if err = server.Reload(ctx, 1); err != nil {
		_ = server.Shutdown(context.Background())
		return nil, err
	}
	return server, nil
}

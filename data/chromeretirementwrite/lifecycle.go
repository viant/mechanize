package chromeretirementwrite

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/data"
	xhandler "github.com/viant/xdatly/handler"
	"reflect"
)

type RetirementLifecycle struct{}

func RetirementLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*RetirementLifecycle)(nil)).Elem()
}

var RetirementLifecycleHooks = new(RetirementLifecycle)
var RetirementLifecycleDatly = RetirementLifecycleDatlyType()

type ManifestLifecycle struct{}

func ManifestLifecycleDatlyType() reflect.Type {
	return reflect.TypeOf((*ManifestLifecycle)(nil)).Elem()
}

var ManifestLifecycleHooks = new(ManifestLifecycle)
var ManifestLifecycleDatly = ManifestLifecycleDatlyType()

type AuditLifecycle struct{}

func AuditLifecycleDatlyType() reflect.Type { return reflect.TypeOf((*AuditLifecycle)(nil)).Elem() }

var AuditLifecycleHooks = new(AuditLifecycle)
var AuditLifecycleDatly = AuditLifecycleDatlyType()

func object(v any) map[string]json.RawMessage {
	raw, _ := json.Marshal(v)
	var m map[string]json.RawMessage
	_ = json.Unmarshal(raw, &m)
	return m
}
func matches(got map[string]json.RawMessage, key string, want any) bool {
	raw, _ := json.Marshal(want)
	return string(got[key]) == string(raw)
}
func fields(a data.ChromeRetirementAuthority) map[string]any {
	return map[string]any{"namespace": a.Namespace, "id": a.TransitionID, "clientId": a.ClientID, "requestId": a.RequestID, "profileChannel": a.ProfileChannel, "browserInstance": a.BrowserInstance, "trustScope": a.TrustScope, "oldBrokerEpoch": a.OldBrokerEpoch, "oldChannelEpoch": a.OldChannelEpoch, "oldScopeHash": a.OldScopeHash, "processEvidenceJson": a.ProcessJSON, "policyEvidenceJson": a.PolicyJSON, "evidenceDigest": a.EvidenceDigest, "createdAt": a.CreatedAt}
}
func checkImmutable(v any, a data.ChromeRetirementAuthority) error {
	m := object(v)
	for k, w := range fields(a) {
		if !matches(m, k, w) {
			return errors.New("owned immutable retirement correlation or evidence changed")
		}
	}
	return nil
}

func (h *RetirementLifecycle) Init(ctx context.Context, r *Retirement, s xhandler.LifecycleContext[Retirement, xhandler.NoParent, WriteChromeRetirementOutput]) error {
	if s.Previous != nil && s.Previous.Revision != nil {
		n := *s.Previous.Revision + 1
		r.SetRevision(&n)
	}
	return nil
}
func (h *RetirementLifecycle) Validate(ctx context.Context, r *Retirement, s xhandler.LifecycleContext[Retirement, xhandler.NoParent, WriteChromeRetirementOutput]) error {
	a, err := data.RequireChromeRetirementAuthority(ctx)
	if err != nil {
		return err
	}
	if r == nil {
		return errors.New("exact retirement required")
	}
	if err := checkImmutable(r, a); err != nil {
		return err
	}
	m := object(r)
	if !matches(m, "revision", a.PriorRevision+1) || !matches(m, "phase", a.Phase) || !matches(m, "updatedAt", a.Now) || len(r.Audit) != 1 {
		return errors.New("exact retirement phase CAS and new audit required")
	}
	if s.Previous == nil {
		if a.Phase != "intended" || a.PriorRevision != 0 || len(r.Manifests) != 0 {
			return errors.New("retirement must begin at intended revision one")
		}
	} else {
		if err := checkImmutable(s.Previous, a); err != nil {
			return err
		}
		prior := object(s.Previous)
		if !matches(prior, "revision", a.PriorRevision) || !matches(prior, "phase", data.ChromeRetirementPreviousPhase(a.Phase)) {
			return errors.New("retirement phase skips and stale revisions forbidden")
		}
		if len(s.Previous.Audit) != a.PriorRevision {
			return errors.New("complete original retirement phase audit required")
		}
		for _, old := range s.Previous.Audit {
			if old == nil || old.Id == nil || *old.Id == a.AuditID {
				return errors.New("retirement audit already exists; adopt exact generated readback")
			}
		}
		if a.Phase != "prepared" {
			resolutionMatched := false
			for _, old := range s.Previous.Audit {
				if old != nil && old.Phase != nil && *old.Phase == "prepared" && old.PayloadJson != nil {
					var payload struct {
						Proof data.ChromeRetirementPhaseProof `json:"proof"`
					}
					if json.Unmarshal([]byte(*old.PayloadJson), &payload) != nil || payload.Proof.HostResolutionDigest != a.Proof.HostResolutionDigest {
						return errors.New("immutable prepared host resolution proof changed")
					}
					resolutionMatched = true
				}
			}
			if !resolutionMatched {
				return errors.New("prepared host resolution audit required")
			}
			if len(r.Manifests) != 0 || len(s.Previous.Manifests) != a.ManifestCount || !matches(prior, "manifestDigest", a.ManifestDigest) || !matches(prior, "manifestCount", a.ManifestCount) || !matches(prior, "receiptCount", a.ReceiptCount) {
				return errors.New("immutable original receipt manifest must be retained")
			}
			for _, old := range s.Previous.Manifests {
				if err := validateManifest(old, a); err != nil {
					return err
				}
			}
		} else if len(s.Previous.Manifests) != 0 {
			return errors.New("receipt manifest can be attached only once")
		}
	}
	if a.Phase == "intended" {
		for _, k := range []string{"manifestDigest", "manifestCount", "receiptCount", "adoptionEvidenceJson", "adoptionDigest"} {
			if !matches(m, k, nil) {
				return errors.New("intended phase cannot manufacture later evidence")
			}
		}
	} else {
		if !matches(m, "manifestDigest", a.ManifestDigest) || !matches(m, "manifestCount", a.ManifestCount) || !matches(m, "receiptCount", a.ReceiptCount) {
			return errors.New("canonical aggregate manifest differs")
		}
		if a.Phase == "prepared" {
			if len(r.Manifests) != a.ManifestCount {
				return errors.New("complete manifest attachment required")
			}
			seen := map[string]bool{}
			for _, child := range r.Manifests {
				if err := validateManifest(child, a); err != nil {
					return err
				}
				if seen[*child.Id] {
					return errors.New("duplicate manifest attachment")
				}
				seen[*child.Id] = true
			}
		}
		if a.Phase == "adopted" {
			if !matches(m, "adoptionEvidenceJson", a.AdoptionJSON) || !matches(m, "adoptionDigest", a.AdoptionDigest) {
				return errors.New("exact independent adoption evidence required")
			}
		} else if !matches(m, "adoptionEvidenceJson", nil) || !matches(m, "adoptionDigest", nil) {
			return errors.New("early adoption evidence forbidden")
		}
	}
	return validateAudit(r.Audit[0], a)
}

func validateManifest(m *Manifest, a data.ChromeRetirementAuthority) error {
	if m == nil || m.Id == nil || m.CanonicalManifestJson == nil {
		return errors.New("exact immutable manifest required")
	}
	for _, expected := range a.Manifests {
		if *m.Id != data.ChromeRetirementManifestID(expected.Identity) {
			continue
		}
		raw, digest, err := data.ChromeRetirementManifestJSON(expected)
		if err != nil {
			return err
		}
		identity, _ := json.Marshal(expected.Identity)
		v := object(m)
		for key, want := range map[string]any{"namespace": a.Namespace, "transitionId": a.TransitionID, "id": *m.Id, "documentIdentityJson": string(identity), "receiptRevision": expected.ReceiptRevision, "receiptCount": len(expected.Receipts), "canonicalManifestJson": raw, "manifestDigest": digest} {
			if !matches(v, key, want) {
				return errors.New("manifest differs from complete sanitized exported history")
			}
		}
		if _, err := data.DecodeChromeRetirementManifest(*m.CanonicalManifestJson); err != nil {
			return err
		}
		return nil
	}
	return errors.New("unattested retirement manifest")
}
func (h *ManifestLifecycle) Init(context.Context, *Manifest, xhandler.LifecycleContext[Manifest, Retirement, WriteChromeRetirementOutput]) error {
	return nil
}
func (h *ManifestLifecycle) Validate(ctx context.Context, m *Manifest, s xhandler.LifecycleContext[Manifest, Retirement, WriteChromeRetirementOutput]) error {
	a, err := data.RequireChromeRetirementAuthority(ctx)
	if err != nil {
		return err
	}
	if a.Phase != "prepared" || s.Previous != nil || s.Parent == nil || s.Parent.Id == nil || *s.Parent.Id != a.TransitionID || m.CreatedAt == nil || *m.CreatedAt != a.Now {
		return errors.New("manifest is append-only at prepared phase")
	}
	return validateManifest(m, a)
}
func validateAudit(e *Audit, a data.ChromeRetirementAuthority) error {
	if e == nil {
		return errors.New("phase audit required")
	}
	m := object(e)
	for key, want := range map[string]any{"namespace": a.Namespace, "id": a.AuditID, "transitionId": a.TransitionID, "phase": a.Phase, "priorRevision": a.PriorRevision, "sequence": a.PriorRevision + 1, "requestId": a.RequestID, "payloadJson": a.AuditPayloadJSON, "createdAt": a.Now} {
		if !matches(m, key, want) {
			return errors.New("exact immutable retirement phase audit required")
		}
	}
	return nil
}
func (h *AuditLifecycle) Init(context.Context, *Audit, xhandler.LifecycleContext[Audit, Retirement, WriteChromeRetirementOutput]) error {
	return nil
}
func (h *AuditLifecycle) Validate(ctx context.Context, e *Audit, s xhandler.LifecycleContext[Audit, Retirement, WriteChromeRetirementOutput]) error {
	a, err := data.RequireChromeRetirementAuthority(ctx)
	if err != nil {
		return err
	}
	if s.Previous != nil || s.Parent == nil || s.Parent.Id == nil || *s.Parent.Id != a.TransitionID {
		return errors.New("phase audit is newly appended to exact retirement")
	}
	return validateAudit(e, a)
}

func (h *RetirementLifecycle) AfterSequence(context.Context, *Retirement, xhandler.LifecycleContext[Retirement, xhandler.NoParent, WriteChromeRetirementOutput]) error {
	return nil
}
func (h *RetirementLifecycle) AfterQueue(context.Context, *Retirement, xhandler.LifecycleContext[Retirement, xhandler.NoParent, WriteChromeRetirementOutput]) error {
	return nil
}
func (h *RetirementLifecycle) Finalize(context.Context, *WriteChromeRetirementInput, *WriteChromeRetirementOutput, xhandler.Outcome) error {
	return nil
}
func (h *ManifestLifecycle) AfterSequence(context.Context, *Manifest, xhandler.LifecycleContext[Manifest, Retirement, WriteChromeRetirementOutput]) error {
	return nil
}
func (h *ManifestLifecycle) AfterQueue(context.Context, *Manifest, xhandler.LifecycleContext[Manifest, Retirement, WriteChromeRetirementOutput]) error {
	return nil
}
func (h *AuditLifecycle) AfterSequence(context.Context, *Audit, xhandler.LifecycleContext[Audit, Retirement, WriteChromeRetirementOutput]) error {
	return nil
}
func (h *AuditLifecycle) AfterQueue(context.Context, *Audit, xhandler.LifecycleContext[Audit, Retirement, WriteChromeRetirementOutput]) error {
	return nil
}

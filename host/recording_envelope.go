package host

import (
	"errors"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/record"
)

// nativeRecordingEnvelope projects the verified typed transport without a
// JSON round trip that could erase native identity or discard unknown fields.
// Owner is checked before persistence in the authenticated namespace.
func nativeRecordingEnvelope(batch native.RecordBatch, p auth.Principal, sessionID string, uid uint32) (record.RecordBatch, error) {
	if p.Validate() != nil || batch.Owner.Validate() != nil || batch.Owner.Namespace != p.Namespace || batch.Owner.ClientID != p.ClientID || batch.Owner.SessionID != sessionID || sessionID == "" {
		return record.RecordBatch{}, auth.ErrUnauthorized
	}
	result := record.RecordBatch{RecordingID: batch.RecordingID, State: batch.State, LeaseExpiresUnixMS: batch.LeaseExpiresUnixMS, LastSequence: batch.LastSequence, Truncated: batch.Truncated}
	for _, gap := range batch.Gaps {
		result.Gaps = append(result.Gaps, record.RecordGap{Kind: gap.Kind, Reason: gap.Reason, FromSequence: gap.FromSequence, ToSequence: gap.ToSequence, Lost: gap.Lost, UnknownExtent: gap.UnknownExtent})
	}
	for _, source := range batch.Events {
		if source.RecordingID != batch.RecordingID || source.Trusted {
			return record.RecordBatch{}, errors.New("native recording provenance mismatch")
		}
		event := record.RecordEvent{EventSurface: "native", RecordingID: source.RecordingID, Sequence: source.Sequence, TimestampUnixMS: source.TimestampUnixMS, Kind: source.Kind, Redacted: source.Redacted, ParameterRequired: source.ParameterRequired, SelectorConfidence: source.SelectorConfidence, Lineage: source.Lineage, Source: source.Source, Reason: source.Reason}
		if source.NativeIdentity != nil {
			identity := source.NativeIdentity
			if identity.UID != uid {
				return record.RecordBatch{}, auth.ErrUnauthorized
			}
			event.NativeIdentity = &record.NativeIdentity{UID: identity.UID, BundleID: identity.BundleID, PID: identity.PID, StartToken: identity.StartToken}
			if identity.WindowID != nil {
				event.NativeIdentity.WindowID = *identity.WindowID
			}
		}
		if source.Target != nil {
			target := source.Target
			event.NativeTarget = &record.NativeTarget{Role: target.Role, IdentifierQualified: target.IdentifierQualified, NameWithheld: target.NameWithheld}
			if target.Identifier != nil {
				event.NativeTarget.Identifier = *target.Identifier
			}
			if target.IdentifierDigest != nil {
				event.NativeTarget.IdentifierDigest = *target.IdentifierDigest
			}
		}
		if source.Locator != nil {
			locator := source.Locator
			event.Locator = &chrome.Locator{Strategy: locator.Strategy, Value: locator.Value, Exact: locator.Exact}
		}
		if err := event.Validate(); err != nil {
			return record.RecordBatch{}, err
		}
		result.Events = append(result.Events, event)
	}
	return result, nil
}

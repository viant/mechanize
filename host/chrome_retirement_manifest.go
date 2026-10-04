package host

import (
	"errors"
	"sort"

	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/data"
)

// retirementManifest converts an already completely collected export to the
// storage contract. It grants no authority: the lifecycle owner must separately
// verify the pinned channel, complete executor inventory and durable effects.
func retirementManifest(export chrome.ReceiptExportManifest) (data.ChromeRetirementManifest, error) {
	const safeInteger = uint64(1<<53 - 1)
	fail := func() (data.ChromeRetirementManifest, error) {
		return data.ChromeRetirementManifest{}, errors.New("complete quiescent Chrome receipt manifest required")
	}
	if (export.Version != 1 && export.Version != 2) || len(export.Receipts) > 512 || export.Identity.Generation == 0 || export.Identity.Generation > safeInteger || export.Revision > safeInteger || export.Readiness.ControlLeaseHeld || export.Readiness.ControlLease != nil || export.Readiness.RecordingLastSequence > safeInteger || export.Readiness.RecordingDroppedThrough > safeInteger {
		return fail()
	}
	m := data.ChromeRetirementManifest{
		Version: export.Version,
		Identity: data.ChromeRetirementDocumentIdentity{
			ProfileChannel: export.Identity.ProfileChannel, BrowserInstance: export.Identity.BrowserInstance,
			TabID: export.Identity.TabID, FrameID: export.Identity.FrameID, DocumentID: export.Identity.DocumentID,
		},
		ReceiptRevision: int64(export.Revision),
		Receipts:        make([]data.ChromeRetirementReceipt, len(export.Receipts)),
		Readiness: data.ChromeRetirementReadiness{
			Quiesced: export.Readiness.Quiesced, ControlLeaseHeld: export.Readiness.ControlLeaseHeld,
			RecordingState: export.Readiness.RecordingState, RecordingLastSequence: int64(export.Readiness.RecordingLastSequence),
			RecordingDroppedThrough: int64(export.Readiness.RecordingDroppedThrough), RecordingLeaseExpiresUnixMs: export.Readiness.RecordingLeaseExpiresUnixMS,
		},
	}
	for i, row := range export.Receipts {
		m.Receipts[i] = data.ChromeRetirementReceipt{
			FingerprintVersion: row.FingerprintVersion, AttemptID: row.AttemptID, FingerprintSHA256: row.FingerprintSHA256,
			DispatchState: row.DispatchState, EffectState: row.EffectState,
			ErrorCode: row.ErrorCode, ErrorDispatchState: row.ErrorDispatchState,
		}
	}
	sort.Slice(m.Receipts, func(i, j int) bool { return m.Receipts[i].AttemptID < m.Receipts[j].AttemptID })
	if _, _, err := data.ChromeRetirementManifestJSON(m); err != nil {
		return fail()
	}
	return m, nil
}

package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
)

const maxReceiptExportRows = 512
const maxReceiptExportPage = 64
const maxReceiptExportInteger = uint64(1<<53 - 1)

var receiptOpaqueID = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var receiptSHA256 = regexp.MustCompile(`^[a-f0-9]{64}$`)

// ReceiptExportRow preserves renderer dispatch/error facts. An effectState of
// verified is a renderer fact, never an authoritative business-success proof.
type ReceiptExportRow struct {
	FingerprintVersion int    `json:"fingerprintVersion,omitempty"`
	AttemptID          string `json:"attemptId"`
	FingerprintSHA256  string `json:"fingerprintSHA256"`
	DispatchState      string `json:"dispatchState"`
	EffectState        string `json:"effectState"`
	ErrorCode          string `json:"errorCode,omitempty"`
	ErrorDispatchState string `json:"errorDispatchState,omitempty"`
}

type ReceiptExportReadiness struct {
	Quiesced                    bool   `json:"quiesced"`
	ControlLeaseHeld            bool   `json:"controlLeaseHeld"`
	ControlLease                *Lease `json:"controlLease,omitempty"`
	RecordingState              string `json:"recordingState"`
	RecordingLastSequence       uint64 `json:"recordingLastSequence"`
	RecordingDroppedThrough     uint64 `json:"recordingDroppedThrough"`
	RecordingLeaseExpiresUnixMS int64  `json:"recordingLeaseExpiresUnixMs"`
}

type ReceiptExportPage struct {
	Version    int                    `json:"version"`
	RequestID  string                 `json:"requestId"`
	Identity   Identity               `json:"identity"`
	Total      int                    `json:"total"`
	Revision   uint64                 `json:"revision"`
	Offset     int                    `json:"offset"`
	NextOffset int                    `json:"nextOffset"`
	Truncated  bool                   `json:"truncated"`
	Receipts   []ReceiptExportRow     `json:"receipts"`
	Readiness  ReceiptExportReadiness `json:"readiness"`
}

type ReceiptExportManifest struct {
	Version   int                    `json:"version"`
	Identity  Identity               `json:"identity"`
	Revision  uint64                 `json:"revision"`
	Receipts  []ReceiptExportRow     `json:"receipts"`
	Readiness ReceiptExportReadiness `json:"readiness"`
}

type ReceiptExportRequest struct {
	RequestID        string  `json:"requestId"`
	Offset           int     `json:"offset"`
	Limit            int     `json:"limit"`
	ExpectedRevision *uint64 `json:"expectedRevision,omitempty"`
}

// ReceiptPageFetcher must be supplied by the authenticated lifecycle owner and
// remain pinned to the same document and broker/channel/scope fence for every
// call. This package neither constructs that authority nor dispatches input.
type ReceiptPageFetcher func(context.Context, Identity, ReceiptExportRequest) (json.RawMessage, error)

func invalidReceiptExport() error {
	return errors.New("closed bounded renderer receipt export required")
}

type receiptIdentityWire struct {
	ProfileChannel  *string `json:"profileChannel"`
	BrowserInstance *string `json:"browserInstance"`
	TabID           *int    `json:"tabId"`
	FrameID         *int    `json:"frameId"`
	DocumentID      *string `json:"documentId"`
	Generation      *uint64 `json:"documentGeneration"`
}
type receiptLeaseWire struct {
	ID         *string `json:"id"`
	Generation *uint64 `json:"generation"`
}
type receiptReadinessWire struct {
	Quiesced                    *bool           `json:"quiesced"`
	ControlLeaseHeld            *bool           `json:"controlLeaseHeld"`
	ControlLease                json.RawMessage `json:"controlLease"`
	RecordingState              *string         `json:"recordingState"`
	RecordingLastSequence       *uint64         `json:"recordingLastSequence"`
	RecordingDroppedThrough     *uint64         `json:"recordingDroppedThrough"`
	RecordingLeaseExpiresUnixMS *int64          `json:"recordingLeaseExpiresUnixMs"`
}
type receiptRowWire struct {
	FingerprintVersion *int            `json:"fingerprintVersion"`
	AttemptID          *string         `json:"attemptId"`
	FingerprintSHA256  *string         `json:"fingerprintSHA256"`
	DispatchState      *string         `json:"dispatchState"`
	EffectState        *string         `json:"effectState"`
	ErrorCode          json.RawMessage `json:"errorCode"`
	ErrorDispatchState json.RawMessage `json:"errorDispatchState"`
}
type receiptPageWire struct {
	Version    *int                  `json:"version"`
	RequestID  *string               `json:"requestId"`
	Identity   *receiptIdentityWire  `json:"identity"`
	Total      *int                  `json:"total"`
	Revision   *uint64               `json:"revision"`
	Offset     *int                  `json:"offset"`
	NextOffset *int                  `json:"nextOffset"`
	Truncated  *bool                 `json:"truncated"`
	Receipts   *[]receiptRowWire     `json:"receipts"`
	Readiness  *receiptReadinessWire `json:"readiness"`
}

func receiptClosedDecode(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
		return invalidReceiptExport()
	}
	return nil
}

func receiptExactKeys(raw []byte, required []string, optional ...string) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return false
	}
	allowed := make(map[string]bool, len(required)+len(optional))
	for _, key := range required {
		if _, ok := object[key]; !ok {
			return false
		}
		allowed[key] = true
	}
	for _, key := range optional {
		allowed[key] = true
	}
	for key := range object {
		if !allowed[key] {
			return false
		}
	}
	return true
}

func receiptExactShape(raw []byte) bool {
	if !receiptExactKeys(raw, []string{"version", "requestId", "identity", "total", "revision", "offset", "nextOffset", "truncated", "receipts", "readiness"}) {
		return false
	}
	var root map[string]json.RawMessage
	_ = json.Unmarshal(raw, &root)
	if !receiptExactKeys(root["identity"], []string{"profileChannel", "browserInstance", "tabId", "frameId", "documentId", "documentGeneration"}) || !receiptExactKeys(root["readiness"], []string{"quiesced", "controlLeaseHeld", "recordingState", "recordingLastSequence", "recordingDroppedThrough", "recordingLeaseExpiresUnixMs"}, "controlLease") {
		return false
	}
	var readiness map[string]json.RawMessage
	_ = json.Unmarshal(root["readiness"], &readiness)
	if lease, exists := readiness["controlLease"]; exists && !receiptExactKeys(lease, []string{"id", "generation"}) {
		return false
	}
	var version int
	if json.Unmarshal(root["version"], &version) != nil || (version != 1 && version != 2) {
		return false
	}
	var rows []json.RawMessage
	if json.Unmarshal(root["receipts"], &rows) != nil {
		return false
	}
	for _, row := range rows {
		var fields map[string]json.RawMessage
		if json.Unmarshal(row, &fields) != nil {
			return false
		}
		fv, present := fields["fingerprintVersion"]
		if version == 1 && present || version == 2 && (!present || string(fv) != "2") {
			return false
		}
		if !receiptExactKeys(row, []string{"attemptId", "fingerprintSHA256", "dispatchState", "effectState"}, "errorCode", "errorDispatchState", "fingerprintVersion") {
			return false
		}
	}
	return true
}

// Duplicate keys cannot be normalized away before required-field/schema checks.
func receiptJSONShape(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	tokens := 0
	var scan func(int) bool
	scan = func(depth int) bool {
		tokens++
		if depth > 8 || tokens > 4096 {
			return false
		}
		token, err := d.Token()
		if err != nil {
			return false
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return true
		}
		switch delimiter {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				token, err := d.Token()
				key, ok := token.(string)
				if err != nil || !ok || keys[key] {
					return false
				}
				keys[key] = true
				if !scan(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim('}')
		case '[':
			for d.More() {
				if !scan(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim(']')
		default:
			return false
		}
	}
	if !scan(0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}
func receiptDispatch(value string) bool {
	return value == "dispatched" || value == "notDispatched" || value == "unknown"
}
func receiptEffect(value string) bool {
	return value == "none" || value == "unverified" || value == "unknown" || value == "verified"
}
func receiptErrorCode(value string) bool {
	switch value {
	case "ambiguousTarget", "coverageIncomplete", "invalidLocator", "invalidRequest", "targetNotActionable", "targetNotFound", "unsupportedAction", "unsupportedAttribute", "unsupportedControl", "unsupportedSelector", "userActivationRequired", "dispatchFailure", "unclassified":
		return true
	}
	return false
}
func receiptIdentityValid(i Identity) bool {
	return receiptOpaqueID.MatchString(i.ProfileChannel) && receiptOpaqueID.MatchString(i.BrowserInstance) && receiptOpaqueID.MatchString(i.DocumentID) && i.TabID >= 0 && uint64(i.TabID) <= maxReceiptExportInteger && i.FrameID >= 0 && uint64(i.FrameID) <= maxReceiptExportInteger && i.Generation >= 1 && i.Generation <= maxReceiptExportInteger
}

// DecodeReceiptExportPage accepts closed homogeneous version-1 or version-2 exports.
// Error responses and unknown/raw fields fail with a static payload-free error.
func DecodeReceiptExportPage(raw []byte) (ReceiptExportPage, error) {
	fail := func() (ReceiptExportPage, error) { return ReceiptExportPage{}, invalidReceiptExport() }
	if len(raw) == 0 || len(raw) > MaxFrameBytes || !receiptJSONShape(raw) || !receiptExactShape(raw) {
		return fail()
	}
	var in *receiptPageWire
	if receiptClosedDecode(raw, &in) != nil || in == nil || in.Version == nil || (*in.Version != 1 && *in.Version != 2) || in.RequestID == nil || !receiptOpaqueID.MatchString(*in.RequestID) || in.Identity == nil || in.Total == nil || in.Revision == nil || in.Offset == nil || in.NextOffset == nil || in.Truncated == nil || in.Receipts == nil || in.Readiness == nil {
		return fail()
	}
	i := in.Identity
	if i.ProfileChannel == nil || i.BrowserInstance == nil || i.TabID == nil || i.FrameID == nil || i.DocumentID == nil || i.Generation == nil {
		return fail()
	}
	identity := Identity{ProfileChannel: *i.ProfileChannel, BrowserInstance: *i.BrowserInstance, TabID: *i.TabID, FrameID: *i.FrameID, DocumentID: *i.DocumentID, Generation: *i.Generation}
	if !receiptIdentityValid(identity) || *in.Total < 0 || *in.Total > maxReceiptExportRows || *in.Revision > maxReceiptExportInteger || *in.Revision < uint64(*in.Total) || *in.Offset < 0 || *in.Offset > *in.Total || len(*in.Receipts) > maxReceiptExportPage || *in.NextOffset != *in.Offset+len(*in.Receipts) || *in.NextOffset > *in.Total || *in.Truncated != (*in.NextOffset < *in.Total) || *in.Total == 0 && *in.Revision != 0 {
		return fail()
	}
	r := in.Readiness
	if r.Quiesced == nil || r.ControlLeaseHeld == nil || r.RecordingState == nil || r.RecordingLastSequence == nil || r.RecordingDroppedThrough == nil || r.RecordingLeaseExpiresUnixMS == nil || *r.RecordingLastSequence > maxReceiptExportInteger || *r.RecordingDroppedThrough > *r.RecordingLastSequence || *r.RecordingLeaseExpiresUnixMS < 0 || uint64(*r.RecordingLeaseExpiresUnixMS) > maxReceiptExportInteger {
		return fail()
	}
	ready := ReceiptExportReadiness{Quiesced: *r.Quiesced, ControlLeaseHeld: *r.ControlLeaseHeld, RecordingState: *r.RecordingState, RecordingLastSequence: *r.RecordingLastSequence, RecordingDroppedThrough: *r.RecordingDroppedThrough, RecordingLeaseExpiresUnixMS: *r.RecordingLeaseExpiresUnixMS}
	if ready.ControlLeaseHeld {
		var lease *receiptLeaseWire
		if len(r.ControlLease) == 0 || receiptClosedDecode(r.ControlLease, &lease) != nil || lease == nil || lease.ID == nil || !receiptOpaqueID.MatchString(*lease.ID) || lease.Generation == nil || *lease.Generation < 1 || *lease.Generation > maxReceiptExportInteger {
			return fail()
		}
		ready.ControlLease = &Lease{ID: *lease.ID, Generation: *lease.Generation}
	} else if len(r.ControlLease) != 0 {
		return fail()
	}
	switch ready.RecordingState {
	case "none":
		if ready.RecordingLastSequence != 0 || ready.RecordingDroppedThrough != 0 || ready.RecordingLeaseExpiresUnixMS != 0 {
			return fail()
		}
	case "paused", "stopped":
		if ready.RecordingLastSequence == 0 || ready.RecordingLeaseExpiresUnixMS != 0 {
			return fail()
		}
	case "recording":
		if ready.Quiesced || ready.RecordingLastSequence == 0 || ready.RecordingLeaseExpiresUnixMS <= 0 {
			return fail()
		}
	default:
		return fail()
	}
	result := ReceiptExportPage{Version: *in.Version, RequestID: *in.RequestID, Identity: identity, Total: *in.Total, Revision: *in.Revision, Offset: *in.Offset, NextOffset: *in.NextOffset, Truncated: *in.Truncated, Receipts: make([]ReceiptExportRow, 0, len(*in.Receipts)), Readiness: ready}
	seen := map[string]bool{}
	for _, row := range *in.Receipts {
		if row.AttemptID == nil || !receiptOpaqueID.MatchString(*row.AttemptID) || seen[*row.AttemptID] || row.FingerprintSHA256 == nil || !receiptSHA256.MatchString(*row.FingerprintSHA256) || row.DispatchState == nil || !receiptDispatch(*row.DispatchState) || row.EffectState == nil || !receiptEffect(*row.EffectState) {
			return fail()
		}
		if *in.Version == 1 && row.FingerprintVersion != nil || *in.Version == 2 && (row.FingerprintVersion == nil || *row.FingerprintVersion != 2) {
			return fail()
		}
		seen[*row.AttemptID] = true
		exported := ReceiptExportRow{AttemptID: *row.AttemptID, FingerprintSHA256: *row.FingerprintSHA256, DispatchState: *row.DispatchState, EffectState: *row.EffectState}
		if row.FingerprintVersion != nil {
			exported.FingerprintVersion = *row.FingerprintVersion
		}
		if len(row.ErrorCode) != 0 || len(row.ErrorDispatchState) != 0 {
			var code, state *string
			if len(row.ErrorCode) == 0 || len(row.ErrorDispatchState) == 0 || receiptClosedDecode(row.ErrorCode, &code) != nil || receiptClosedDecode(row.ErrorDispatchState, &state) != nil || code == nil || state == nil || !receiptErrorCode(*code) || !receiptDispatch(*state) {
				return fail()
			}
			exported.ErrorCode, exported.ErrorDispatchState = *code, *state
		}
		result.Receipts = append(result.Receipts, exported)
	}
	return result, nil
}

func sameReceiptDocument(a, b Identity) bool { a.Generation, b.Generation = 0, 0; return a == b }

// CollectReceiptExport performs bounded read-only paging with no retries. A
// complete manifest is returned only after every exact page has been validated;
// failure/cancellation never publishes a partial trusted result or releases any
// document/fence authority owned by the injected caller.
func CollectReceiptExport(ctx context.Context, pinned Identity, fetch ReceiptPageFetcher) (ReceiptExportManifest, error) {
	fail := func(err error) (ReceiptExportManifest, error) { return ReceiptExportManifest{}, err }
	if ctx == nil || !receiptIdentityValid(pinned) || fetch == nil {
		return fail(invalidReceiptExport())
	}
	result := ReceiptExportManifest{Version: 1, Identity: pinned, Receipts: []ReceiptExportRow{}}
	offset, total := 0, -1
	seen := map[string]bool{}
	for calls := 0; calls < 8; calls++ {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		request := ReceiptExportRequest{RequestID: newID(), Offset: offset, Limit: maxReceiptExportPage}
		if total >= 0 {
			revision := result.Revision
			request.ExpectedRevision = &revision
		}
		raw, err := fetch(ctx, pinned, request)
		if ctx.Err() != nil {
			return fail(ctx.Err())
		}
		if err != nil {
			return fail(errors.New("pinned renderer receipt page unavailable"))
		}
		page, err := DecodeReceiptExportPage(raw)
		if err != nil {
			return fail(err)
		}
		if page.RequestID != request.RequestID || !sameReceiptDocument(page.Identity, pinned) || page.Identity.Generation < result.Identity.Generation || page.Offset != offset {
			return fail(invalidReceiptExport())
		}
		if total < 0 {
			total = page.Total
			result.Version = page.Version
			result.Revision = page.Revision
			result.Readiness = page.Readiness
		} else if page.Version != result.Version || page.Total != total || page.Revision != result.Revision || !reflect.DeepEqual(page.Readiness, result.Readiness) {
			return fail(errors.New("renderer receipt snapshot changed during collection"))
		}
		expected := min(request.Limit, total-offset)
		if len(page.Receipts) != expected {
			return fail(invalidReceiptExport())
		}
		for _, row := range page.Receipts {
			if seen[row.AttemptID] {
				return fail(invalidReceiptExport())
			}
			seen[row.AttemptID] = true
			result.Receipts = append(result.Receipts, row)
		}
		result.Identity = page.Identity
		offset = page.NextOffset
		if offset == total {
			if page.Truncated || len(result.Receipts) != total {
				return fail(invalidReceiptExport())
			}
			if result.Readiness.ControlLease != nil {
				lease := *result.Readiness.ControlLease
				result.Readiness.ControlLease = &lease
			}
			return result, nil
		}
		if !page.Truncated {
			return fail(invalidReceiptExport())
		}
	}
	return fail(invalidReceiptExport())
}

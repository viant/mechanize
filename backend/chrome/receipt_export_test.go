package chrome

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const serializedReceiptExport = `{"version":1,"requestId":"request1","identity":{"profileChannel":"profile1","browserInstance":"browser1","tabId":7,"frameId":0,"documentId":"doc1","documentGeneration":2},"total":2,"revision":2,"offset":0,"nextOffset":2,"truncated":false,"receipts":[{"attemptId":"filled","fingerprintSHA256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","dispatchState":"dispatched","effectState":"unverified"},{"attemptId":"unknown","fingerprintSHA256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","dispatchState":"unknown","effectState":"unknown","errorCode":"unclassified","errorDispatchState":"unknown"}],"readiness":{"quiesced":false,"controlLeaseHeld":false,"recordingState":"none","recordingLastSequence":0,"recordingDroppedThrough":0,"recordingLeaseExpiresUnixMs":0}}`

func receiptPageObject(t *testing.T) map[string]any {
	t.Helper()
	var page map[string]any
	if err := json.Unmarshal([]byte(serializedReceiptExport), &page); err != nil {
		t.Fatal(err)
	}
	return page
}
func receiptEncode(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func assertReceiptRejected(t *testing.T, raw []byte) {
	t.Helper()
	page, err := DecodeReceiptExportPage(raw)
	if err == nil || !reflect.DeepEqual(page, ReceiptExportPage{}) {
		t.Fatalf("invalid export accepted: %+v %v", page, err)
	}
	if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "private.example") {
		t.Fatal("receipt error echoed private payload")
	}
}

func TestDecodeReceiptExportExactSerializedRendererFacts(t *testing.T) {
	page, err := DecodeReceiptExportPage([]byte(serializedReceiptExport))
	if err != nil {
		t.Fatal(err)
	}
	if page.Version != 1 || page.Total != 2 || page.Revision != 2 || page.Truncated || page.Readiness.ControlLease != nil || page.Readiness.Quiesced || page.Receipts[1].DispatchState != "unknown" || page.Receipts[1].EffectState != "unknown" || page.Receipts[1].ErrorCode != "unclassified" {
		t.Fatalf("renderer facts changed: %+v", page)
	}
	raw := []byte(serializedReceiptExport)
	detached, err := DecodeReceiptExportPage(raw)
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] = 'x'
	}
	if detached.Receipts[0].AttemptID != "filled" || detached.Identity.DocumentID != "doc1" {
		t.Fatal("decoded export aliases caller bytes")
	}
}

func TestDecodeReceiptExportRequiresEveryFieldAndRejectsSecrets(t *testing.T) {
	for _, field := range []string{"version", "requestId", "identity", "total", "revision", "offset", "nextOffset", "truncated", "receipts", "readiness"} {
		t.Run("root_"+field, func(t *testing.T) {
			page := receiptPageObject(t)
			delete(page, field)
			assertReceiptRejected(t, receiptEncode(t, page))
		})
	}
	for _, object := range []string{"identity", "readiness"} {
		base := receiptPageObject(t)
		for field := range base[object].(map[string]any) {
			t.Run(object+"_"+field, func(t *testing.T) {
				page := receiptPageObject(t)
				delete(page[object].(map[string]any), field)
				assertReceiptRejected(t, receiptEncode(t, page))
			})
		}
	}
	for _, field := range []string{"attemptId", "fingerprintSHA256", "dispatchState", "effectState"} {
		t.Run("row_"+field, func(t *testing.T) {
			page := receiptPageObject(t)
			delete(page["receipts"].([]any)[0].(map[string]any), field)
			assertReceiptRejected(t, receiptEncode(t, page))
		})
	}
	for _, where := range []string{"root", "identity", "readiness", "row"} {
		t.Run("secret_"+where, func(t *testing.T) {
			page := receiptPageObject(t)
			target := page
			switch where {
			case "identity", "readiness":
				target = page[where].(map[string]any)
			case "row":
				target = page["receipts"].([]any)[0].(map[string]any)
			}
			target["rawFingerprint"] = "SECRET https://private.example?credential=SECRET"
			assertReceiptRejected(t, receiptEncode(t, page))
		})
	}
	for _, raw := range []string{"null", serializedReceiptExport + " {}", strings.Replace(serializedReceiptExport, `"version":1`, `"version":1,"version":1`, 1), strings.Replace(serializedReceiptExport, `"version":1`, `"Version":1`, 1)} {
		assertReceiptRejected(t, []byte(raw))
	}
	assertReceiptRejected(t, []byte(strings.Repeat(" ", MaxFrameBytes+1)))
}

func TestDecodeReceiptExportBoundsEnumsReadinessAndEmptyPages(t *testing.T) {
	mutations := map[string]func(map[string]any){
		"version": func(p map[string]any) { p["version"] = 2 }, "opaque": func(p map[string]any) { p["requestId"] = "SECRET https://private.example" }, "total": func(p map[string]any) { p["total"] = 513 }, "revision": func(p map[string]any) { p["revision"] = uint64(1 << 53) }, "revision_too_small": func(p map[string]any) { p["revision"] = 0 }, "offset": func(p map[string]any) { p["offset"] = -1 }, "next": func(p map[string]any) { p["nextOffset"] = 1 }, "truncated": func(p map[string]any) { p["truncated"] = true },
		"identity_null": func(p map[string]any) { p["identity"] = nil }, "generation": func(p map[string]any) { p["identity"].(map[string]any)["documentGeneration"] = 0 }, "fractional_tab": func(p map[string]any) { p["identity"].(map[string]any)["tabId"] = 1.5 }, "nil_receipts": func(p map[string]any) { p["receipts"] = nil },
		"digest": func(p map[string]any) {
			p["receipts"].([]any)[0].(map[string]any)["fingerprintSHA256"] = strings.Repeat("A", 64)
		}, "dispatch": func(p map[string]any) {
			p["receipts"].([]any)[0].(map[string]any)["dispatchState"] = "businessSucceeded"
		}, "effect": func(p map[string]any) { p["receipts"].([]any)[0].(map[string]any)["effectState"] = "confirmed" }, "duplicate_attempt": func(p map[string]any) { p["receipts"].([]any)[1].(map[string]any)["attemptId"] = "filled" }, "error_missing_state": func(p map[string]any) { delete(p["receipts"].([]any)[1].(map[string]any), "errorDispatchState") }, "error_null": func(p map[string]any) { p["receipts"].([]any)[1].(map[string]any)["errorCode"] = nil }, "error_private": func(p map[string]any) { p["receipts"].([]any)[1].(map[string]any)["errorCode"] = "SECRET" },
		"held_missing_lease": func(p map[string]any) { p["readiness"].(map[string]any)["controlLeaseHeld"] = true }, "unheld_lease": func(p map[string]any) {
			p["readiness"].(map[string]any)["controlLease"] = map[string]any{"id": "lease1", "generation": 1}
		}, "null_lease": func(p map[string]any) { p["readiness"].(map[string]any)["controlLease"] = nil }, "recording_state": func(p map[string]any) { p["readiness"].(map[string]any)["recordingState"] = "SECRET" }, "none_sequence": func(p map[string]any) { p["readiness"].(map[string]any)["recordingLastSequence"] = 1 }, "dropped": func(p map[string]any) { p["readiness"].(map[string]any)["recordingDroppedThrough"] = 1 }, "paused_expiry": func(p map[string]any) {
			r := p["readiness"].(map[string]any)
			r["recordingState"] = "paused"
			r["recordingLastSequence"] = 1
			r["recordingLeaseExpiresUnixMs"] = 1
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			page := receiptPageObject(t)
			mutate(page)
			assertReceiptRejected(t, receiptEncode(t, page))
		})
	}
	page := receiptPageObject(t)
	page["total"], page["revision"], page["offset"], page["nextOffset"], page["truncated"], page["receipts"] = 0, 0, 0, 0, false, []any{}
	if result, err := DecodeReceiptExportPage(receiptEncode(t, page)); err != nil || result.Receipts == nil || len(result.Receipts) != 0 {
		t.Fatalf("empty renderer export rejected: %+v %v", result, err)
	}
	page["total"], page["revision"], page["offset"], page["nextOffset"] = 2, 2, 2, 2
	if _, err := DecodeReceiptExportPage(receiptEncode(t, page)); err != nil {
		t.Fatal("valid final empty cursor rejected", err)
	}
	page["truncated"] = true
	assertReceiptRejected(t, receiptEncode(t, page))
	for _, state := range []string{"paused", "stopped", "recording"} {
		p := receiptPageObject(t)
		r := p["readiness"].(map[string]any)
		r["recordingState"], r["recordingLastSequence"], r["recordingDroppedThrough"] = state, 2, 1
		r["controlLeaseHeld"], r["controlLease"] = true, map[string]any{"id": "lease1", "generation": 1}
		if state == "recording" {
			r["recordingLeaseExpiresUnixMs"] = 1000
		}
		if _, err := DecodeReceiptExportPage(receiptEncode(t, p)); err != nil {
			t.Fatal("valid readiness rejected", state, err)
		}
		if state == "recording" {
			r["quiesced"] = true
			assertReceiptRejected(t, receiptEncode(t, p))
		}
	}
}

func receiptCollectorFixture(t *testing.T, total int) (Identity, ReceiptPageFetcher, *int) {
	t.Helper()
	identity := Identity{ProfileChannel: "profile1", BrowserInstance: "browser1", TabID: 7, FrameID: 0, DocumentID: "doc1", Generation: 4}
	calls := 0
	fetch := func(ctx context.Context, pinned Identity, request ReceiptExportRequest) (json.RawMessage, error) {
		calls++
		if pinned != identity || request.Limit != 64 || !receiptOpaqueID.MatchString(request.RequestID) || request.Offset != (calls-1)*64 {
			t.Fatal("collector request changed its pinned target/cursor/bounds")
		}
		if calls == 1 && request.ExpectedRevision != nil || calls > 1 && (request.ExpectedRevision == nil || *request.ExpectedRevision != uint64(total)) {
			t.Fatal("collector did not pin later revision")
		}
		page := receiptPageObject(t)
		page["requestId"] = request.RequestID
		page["total"], page["revision"], page["offset"] = total, total, request.Offset
		end := min(total, request.Offset+request.Limit)
		page["nextOffset"], page["truncated"] = end, end < total
		page["identity"].(map[string]any)["documentGeneration"] = identity.Generation + uint64(calls)
		rows := []any{}
		for i := request.Offset; i < end; i++ {
			row := map[string]any{"attemptId": fmt.Sprintf("attempt-%d", i), "fingerprintSHA256": strings.Repeat("a", 64), "dispatchState": "dispatched", "effectState": "unverified"}
			if i == total-1 {
				row["dispatchState"], row["effectState"], row["errorCode"], row["errorDispatchState"] = "unknown", "unknown", "unclassified", "unknown"
			}
			rows = append(rows, row)
		}
		page["receipts"] = rows
		return receiptEncode(t, page), nil
	}
	return identity, fetch, &calls
}

func TestCollectReceiptExportEmptyPaginationMaximumAndUnknownFacts(t *testing.T) {
	for _, total := range []int{0, 1, 64, 65, 130, 512} {
		t.Run(fmt.Sprint(total), func(t *testing.T) {
			identity, fetch, calls := receiptCollectorFixture(t, total)
			manifest, err := CollectReceiptExport(context.Background(), identity, fetch)
			if err != nil || manifest.Version != 1 || len(manifest.Receipts) != total || manifest.Receipts == nil || *calls != max(1, (total+63)/64) || manifest.Identity.Generation != identity.Generation+uint64(*calls) {
				t.Fatalf("complete manifest: %+v calls=%d %v", manifest, *calls, err)
			}
			if total > 0 && manifest.Receipts[total-1].DispatchState != "unknown" {
				t.Fatal("unknown receipt was promoted or discarded")
			}
		})
	}
}

func TestCollectReceiptExportRejectsChangedOrIncompleteSnapshots(t *testing.T) {
	for _, change := range []string{"request", "document", "profile", "generation", "offset", "total", "revision", "readiness", "duplicate", "short_page", "too_many"} {
		t.Run(change, func(t *testing.T) {
			identity, base, calls := receiptCollectorFixture(t, 65)
			fetch := func(c context.Context, i Identity, r ReceiptExportRequest) (json.RawMessage, error) {
				raw, err := base(c, i, r)
				if err != nil {
					return nil, err
				}
				var page map[string]any
				json.Unmarshal(raw, &page)
				if *calls == 2 || change == "too_many" {
					switch change {
					case "request":
						page["requestId"] = "other-request"
					case "document":
						page["identity"].(map[string]any)["documentId"] = "other-doc"
					case "profile":
						page["identity"].(map[string]any)["profileChannel"] = "other-profile"
					case "generation":
						page["identity"].(map[string]any)["documentGeneration"] = identity.Generation
					case "offset":
						page["offset"] = 63
					case "total":
						page["total"] = 66
						page["truncated"] = true
					case "revision":
						page["revision"] = 66
					case "readiness":
						page["readiness"].(map[string]any)["quiesced"] = true
					case "duplicate":
						page["receipts"].([]any)[0].(map[string]any)["attemptId"] = "attempt-0"
					case "short_page":
						page["receipts"] = []any{}
						page["nextOffset"], page["truncated"] = 64, true
					case "too_many":
						page["total"], page["revision"] = 513, 513
					}
				}
				return receiptEncode(t, page), nil
			}
			manifest, err := CollectReceiptExport(context.Background(), identity, fetch)
			if err == nil || !reflect.DeepEqual(manifest, ReceiptExportManifest{}) || *calls > 2 {
				t.Fatalf("partial/changed snapshot admitted: %+v %v calls=%d", manifest, err, *calls)
			}
		})
	}
}

func TestCollectReceiptExportCancellationAndFetcherFailureHaveNoPartialResult(t *testing.T) {
	identity, base, calls := receiptCollectorFixture(t, 65)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	manifest, err := CollectReceiptExport(ctx, identity, base)
	if !errors.Is(err, context.Canceled) || *calls != 0 || !reflect.DeepEqual(manifest, ReceiptExportManifest{}) {
		t.Fatal("cancelled collector fetched or published")
	}
	ctx, cancel = context.WithCancel(context.Background())
	fetch := func(c context.Context, i Identity, r ReceiptExportRequest) (json.RawMessage, error) {
		raw, err := base(c, i, r)
		cancel()
		return raw, err
	}
	manifest, err = CollectReceiptExport(ctx, identity, fetch)
	if !errors.Is(err, context.Canceled) || *calls != 1 || !reflect.DeepEqual(manifest, ReceiptExportManifest{}) {
		t.Fatal("collector published after cancellation")
	}
	_, base, calls = receiptCollectorFixture(t, 65)
	fetch = func(c context.Context, i Identity, r ReceiptExportRequest) (json.RawMessage, error) {
		if *calls == 1 {
			return nil, errors.New("SECRET private credential payload")
		}
		return base(c, i, r)
	}
	manifest, err = CollectReceiptExport(context.Background(), identity, fetch)
	if err == nil || strings.Contains(err.Error(), "SECRET") || !reflect.DeepEqual(manifest, ReceiptExportManifest{}) || *calls != 1 {
		t.Fatal("fetcher failure leaked/retried/published partial data")
	}
}

func TestReceiptExportVersion2PreservesFingerprintsAndRejectsMixedRows(t *testing.T) {
	newPage := func() map[string]any {
		p := receiptPageObject(t)
		p["version"] = 2
		for _, r := range p["receipts"].([]any) {
			r.(map[string]any)["fingerprintVersion"] = 2
		}
		return p
	}
	page, err := DecodeReceiptExportPage(receiptEncode(t, newPage()))
	if err != nil || page.Version != 2 || page.Receipts[0].FingerprintVersion != 2 || page.Receipts[0].FingerprintSHA256 != strings.Repeat("a", 64) {
		t.Fatalf("v2 lost receipt identity: %+v %v", page, err)
	}
	for _, bad := range []any{nil, 0, 1, 3, "2"} {
		p := newPage()
		p["receipts"].([]any)[0].(map[string]any)["fingerprintVersion"] = bad
		assertReceiptRejected(t, receiptEncode(t, p))
	}
	p := newPage()
	delete(p["receipts"].([]any)[0].(map[string]any), "fingerprintVersion")
	assertReceiptRejected(t, receiptEncode(t, p))
	p = newPage()
	p["version"] = 1
	assertReceiptRejected(t, receiptEncode(t, p))
}

func TestCollectReceiptExportPinsVersionAcrossPages(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		identity, fetch, calls := receiptCollectorFixture(t, 65)
		wrapped := func(ctx context.Context, pin Identity, req ReceiptExportRequest) (json.RawMessage, error) {
			raw, err := fetch(ctx, pin, req)
			if err != nil {
				return nil, err
			}
			var p map[string]any
			if err = json.Unmarshal(raw, &p); err != nil {
				return nil, err
			}
			if !mixed || req.Offset == 0 {
				p["version"] = 2
				for _, r := range p["receipts"].([]any) {
					r.(map[string]any)["fingerprintVersion"] = 2
				}
			}
			return receiptEncode(t, p), nil
		}
		m, err := CollectReceiptExport(context.Background(), identity, wrapped)
		if mixed {
			if err == nil || m.Version != 0 {
				t.Fatal("mixed page versions accepted")
			}
		} else if err != nil || m.Version != 2 || len(m.Receipts) != 65 || m.Receipts[64].FingerprintVersion != 2 {
			t.Fatalf("v2 collection lost facts: %+v %v", m, err)
		}
		if *calls != 2 {
			t.Fatal("unexpected paging")
		}
	}
}

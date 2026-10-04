package host

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/data"
)

func TestRetirementManifestUsesSharedCanonicalContract(t *testing.T) {
	for _, path := range []string{"../testdata/chrome-retirement-canonical-v1.json", "../testdata/chrome-retirement-canonical-v2.json"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var fixture struct {
			Cases []struct {
				Name              string
				Manifest          data.ChromeRetirementManifest
				Canonical, SHA256 string
			}
		}
		if err = json.Unmarshal(raw, &fixture); err != nil {
			t.Fatal(err)
		}
		for _, c := range fixture.Cases {
			t.Run(c.Name, func(t *testing.T) {
				b, _ := json.Marshal(c.Manifest)
				var export chrome.ReceiptExportManifest
				if err := json.Unmarshal(b, &export); err != nil {
					t.Fatal(err)
				}
				export.Revision = uint64(c.Manifest.ReceiptRevision)
				export.Identity.Generation = 42
				m, err := retirementManifest(export)
				if err != nil {
					t.Fatal(err)
				}
				canonical, digest, err := data.ChromeRetirementManifestJSON(m)
				if err != nil || canonical != c.Canonical || digest != c.SHA256 {
					t.Fatalf("canonical mismatch: %v", err)
				}
				// Receipt arrays are detached; caller mutations cannot rewrite the copy.
				if len(export.Receipts) > 0 {
					export.Receipts[0].AttemptID = "changed"
					if m.Receipts[0].AttemptID == "changed" {
						t.Fatal("shared receipt slice")
					}
				}
			})
		}
	}
}

func TestRetirementManifestRejectsUnreadyOrIncompleteHistory(t *testing.T) {
	base := chrome.ReceiptExportManifest{Version: 1, Identity: chrome.Identity{ProfileChannel: "channel", BrowserInstance: "browser", TabID: 7, DocumentID: "document", Generation: 1}, Readiness: chrome.ReceiptExportReadiness{Quiesced: true, RecordingState: "none"}}
	for name, change := range map[string]func(*chrome.ReceiptExportManifest){
		"excess receipts": func(m *chrome.ReceiptExportManifest) { m.Receipts = make([]chrome.ReceiptExportRow, 513) },
		"live executor":   func(m *chrome.ReceiptExportManifest) { m.Readiness.Quiesced = false },
		"hidden lease": func(m *chrome.ReceiptExportManifest) {
			m.Readiness.ControlLease = &chrome.Lease{ID: "lease", Generation: 1}
		},
		"missing receipts":   func(m *chrome.ReceiptExportManifest) { m.Revision = 1 },
		"recording":          func(m *chrome.ReceiptExportManifest) { m.Readiness.RecordingState = "recording" },
		"unsafe sequence":    func(m *chrome.ReceiptExportManifest) { m.Readiness.RecordingLastSequence = ^uint64(0) },
		"missing generation": func(m *chrome.ReceiptExportManifest) { m.Identity.Generation = 0 },
		"unknown receipt": func(m *chrome.ReceiptExportManifest) {
			m.Revision = 1
			m.Receipts = []chrome.ReceiptExportRow{{AttemptID: "attempt", FingerprintSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", DispatchState: "unknown", EffectState: "unknown"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := base
			change(&m)
			out, err := retirementManifest(m)
			if err == nil || out.Version != 0 || out.Receipts != nil {
				t.Fatal("unready or partial result accepted")
			}
		})
	}
}

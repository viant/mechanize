package chrome

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/model"
	"sync/atomic"
	"testing"
	"time"
)

func TestPrivateAcquisitionRefusalIsExactClosedMetadata(t *testing.T) {
	id := credentialTestPending().identity
	lease := Lease{ID: "held", Generation: 2}
	p := &credentialAdmissionPending{requestID: "request", identity: id, lease: &lease}
	for _, mode := range []string{"staleGeneration", "acquisitionRejected", "privateError", "changedIdentity", "changedLease", "trueValidated", "extra", "null"} {
		frame := map[string]any{"requestId": "request", "identity": id, "controlLease": lease, "validated": false, "errorCode": "staleGeneration"}
		switch mode {
		case "acquisitionRejected":
			frame["errorCode"] = mode
		case "privateError":
			frame["errorCode"] = "PRIVATE_CANARY"
		case "changedIdentity":
			next := id
			next.Generation++
			frame["identity"] = next
		case "changedLease":
			frame["controlLease"] = Lease{ID: "foreign", Generation: 2}
		case "trueValidated":
			frame["validated"] = true
		case "extra":
			frame["privateValue"] = "PRIVATE_CANARY"
		case "null":
			frame["validated"] = nil
		}
		raw, _ := json.Marshal(frame)
		reply := decodeCredentialAdmission(raw, p)
		valid := mode == "staleGeneration" || mode == "acquisitionRejected"
		if (reply.identity.DocumentID != "") != valid || reply.ready {
			t.Fatal("invalid private refusal admitted", mode)
		}
		if valid && reply.acquisitionFailure != mode {
			t.Fatal("closed refusal reason unavailable")
		}
	}
}

func TestPrivatePinnedAcquisitionRetryIsBoundedAndRetainsOriginalAuthority(t *testing.T) {
	for _, mode := range []string{"once", "always", "rejected", "replacement", "expired", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			g, p, ctx, conn, c, doc := credentialAdmissionFixture(t)
			g.broker.mu.Lock()
			if mode != "legacy" {
				c.workerBuild = 29
			}
			g.broker.mu.Unlock()
			var acquires, inspections atomic.Int32
			done := make(chan struct{})
			defer close(done)
			go func() {
				var pin string
				var heldLease Lease
				var deadline int64
				for {
					raw, e := ReadFrame(conn)
					if e != nil {
						return
					}
					var m struct {
						Type        string   `json:"type"`
						Action      string   `json:"action"`
						RequestID   string   `json:"requestId"`
						Identity    Identity `json:"identity"`
						RecipientID string   `json:"recipientId"`
						Lease       *Lease   `json:"controlLease"`
						Deadline    int64    `json:"deadlineUnixMs"`
					}
					json.Unmarshal(raw, &m)
					if deadline == 0 {
						deadline = m.Deadline
					}
					if m.Deadline != deadline {
						t.Error("retry renewed deadline")
					}
					if m.Type == "credentialInspect" {
						n := inspections.Add(1)
						if n == 1 {
							pin = m.RecipientID
						} else if pin == "" || m.RecipientID != pin {
							t.Error("retry repinned private recipient")
						}
						identity := m.Identity
						if n > 1 {
							identity.Generation++
						}
						ready := mode != "replacement" || n == 1
						frame := map[string]any{"type": "credentialInspectResult", "requestId": m.RequestID, "identity": identity, "ready": ready, "stage": "pair", "privateCredentialProtocolVersion": 2}
						if pin != "" {
							frame["recipientId"] = pin
							frame["privateCredentialProtocolVersion"] = 3
						}
						WriteFrame(conn, frame)
					} else if m.Action == "executor.acquire" {
						n := acquires.Add(1)
						if n == 1 {
							heldLease = *m.Lease
						} else if heldLease != *m.Lease {
							t.Error("retry replaced lease")
						}
						if mode == "once" && n == 2 {
							WriteFrame(conn, map[string]any{"requestId": m.RequestID, "identity": m.Identity, "validated": true, "controlLease": m.Lease})
							continue
						}
						code := "staleGeneration"
						if mode == "rejected" {
							code = "acquisitionRejected"
						}
						WriteFrame(conn, map[string]any{"requestId": m.RequestID, "identity": m.Identity, "validated": false, "controlLease": m.Lease, "errorCode": code})
					} else {
						t.Error("private retry sent input/public command")
						return
					}
				}
			}()
			admit := func(context.Context) error {
				if mode == "expired" && acquires.Load() > 0 {
					return context.DeadlineExceeded
				}
				return nil
			}
			started := time.Now()
			result, e := g.AdmitCredentialControl(ctx, p, model.Surface{Kind: "web", Origin: doc.Origin}, admit)
			if (e == nil) != (mode == "once") {
				t.Fatal("incorrect retry result", mode, e)
			}
			if acquires.Load() > 3 || inspections.Load() > 3 || time.Since(started) > time.Second {
				t.Fatal("retry exceeded attempts/original budget")
			}
			if mode == "once" {
				if !result.Confirmed || acquires.Load() != 2 || inspections.Load() != 2 || result.Authority.Document.Generation != doc.Generation+1 || result.Authority.PrivateRecipientID == "" {
					t.Fatal("same pin acquisition not freshly confirmed")
				}
			}
			if (mode == "rejected" || mode == "legacy" || mode == "expired") && inspections.Load() != 1 {
				t.Fatal("unretryable refusal reinspected")
			}
			if mode == "always" && acquires.Load() != 3 {
				t.Fatal("retry attempt bound changed")
			}
		})
	}
}

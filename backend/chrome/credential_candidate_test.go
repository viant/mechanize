package chrome

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/viant/mechanize/model"
)

func TestCredentialCandidateClosedAdmissionReasons(t *testing.T) {
	for _, mode := range []string{"missing", "ambiguous", "busy"} {
		t.Run(mode, func(t *testing.T) {
			g, p, ctx, _, c, doc := credentialAdmissionFixture(t)
			g.broker.mu.Lock()
			want := ErrCredentialCandidateUnavailable
			switch mode {
			case "missing":
				c.documents = nil
			case "ambiguous":
				other := doc
				other.TabID++
				c.documents = append(c.documents, other)
				want = ErrCredentialCandidateAmbiguous
			case "busy":
				c.unknown["held-attempt"] = true
				want = ErrCredentialChannelBusy
			}
			g.broker.mu.Unlock()
			if err := g.CredentialCandidateAvailable(ctx, p, model.Surface{Kind: "web", Origin: doc.Origin}); !errors.Is(err, want) {
				t.Fatalf("closed admission reason: %v; want %v", err, want)
			}
		})
	}
}

func TestPrivateCredentialCandidateWireRejectsContentAndForeignScope(t *testing.T) {
	e := Enrollment{ProfileChannel: "profile", BrowserInstance: "browser", Origins: []string{"https://fixture.invalid"}}
	original := credentialCandidate{Identity: Identity{ProfileChannel: "profile", BrowserInstance: "browser", TabID: 7, FrameID: 0, DocumentID: "document", Generation: 1}, Origin: "https://fixture.invalid"}
	raw, _ := json.Marshal(original)
	var decoded credentialCandidate
	if json.Unmarshal(raw, &decoded) != nil || decoded != original || !decoded.valid(e) {
		t.Fatal("closed routing metadata rejected")
	}
	for _, key := range []string{"title", "value", "username", "password", "url", "text"} {
		var value map[string]any
		json.Unmarshal(raw, &value)
		value[key] = "PRIVATE-CANARY"
		wire, _ := json.Marshal(value)
		if json.Unmarshal(wire, &decoded) == nil {
			t.Fatal("content field accepted", key)
		}
	}
	for _, mode := range []string{"other profile", "other browser", "child frame", "foreign origin", "userinfo", "invalid identity", "zero generation"} {
		v := original
		switch mode {
		case "other profile":
			v.ProfileChannel = "foreign"
		case "other browser":
			v.BrowserInstance = "foreign"
		case "child frame":
			v.FrameID = 1
		case "foreign origin":
			v.Origin = "https://foreign.invalid"
		case "userinfo":
			v.Origin = "https://user:password@fixture.invalid"
		case "invalid identity":
			v.DocumentID = "bad\nidentity"
		case "zero generation":
			v.Generation = 0
		}
		if v.valid(e) {
			t.Fatal("unsafe candidate accepted", mode)
		}
	}
}

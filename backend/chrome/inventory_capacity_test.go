package chrome

import (
	"encoding/json"
	"testing"
)

func TestCompleteInventoryDocumentBoundIsConsistentWithPrivateProjection(t *testing.T) {
	g, _, _, c, peer := setupFixture(t)
	defer g.Close()
	g.broker.mu.Lock()
	c.executorQualified = true
	g.broker.mu.Unlock()
	docs := make([]Document, 211)
	for i := range docs {
		docs[i] = Document{Identity: Identity{ProfileChannel: c.grant.ProfileChannel, BrowserInstance: c.grant.BrowserInstance, TabID: 7 + i%4, FrameID: i, DocumentID: newID(), Generation: 1}, Origin: c.grant.Origins[0]}
	}
	if err := WriteFrame(peer, map[string]any{"type": "documents", "documents": docs}); err != nil {
		t.Fatal(err)
	}
	waitControl(t, func() bool {
		g.broker.mu.Lock()
		defer g.broker.mu.Unlock()
		return len(c.documents) == len(docs) && c.inventoryComplete
	})
	raw, _ := json.Marshal(map[string]any{"type": "documents", "documents": docs})
	g.broker.mu.Lock()
	c.privacy = &credentialPrivacyState{active: false}
	accepted := inactivePrivacyControlPlaneFrameLocked(c, raw)
	g.broker.mu.Unlock()
	if !accepted {
		t.Fatal("private metadata projection retained old document capacity")
	}
	tooMany := make([]Document, MaxInventoryDocuments+1)
	for i := range tooMany {
		tooMany[i] = docs[i%len(docs)]
	}
	raw, _ = json.Marshal(map[string]any{"type": "documents", "documents": tooMany})
	g.broker.mu.Lock()
	accepted = inactivePrivacyControlPlaneFrameLocked(c, raw)
	g.broker.mu.Unlock()
	if accepted {
		t.Fatal("document overflow bypassed complete inventory projection")
	}
}

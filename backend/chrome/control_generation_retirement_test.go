package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func packagedFillRetirementReply(command Command) (Reply, error) {
	_, file, _, _ := runtime.Caller(0)
	source := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	input, _ := json.Marshal(command)
	child := exec.CommandContext(ctx, "node", filepath.Join(source, "backend/chrome/testdata/fill_retirement_content.cjs"), source)
	child.Stdin = bytes.NewReader(input)
	output, err := child.Output()
	if err != nil {
		return Reply{}, err
	}
	var reply Reply
	err = json.Unmarshal(output, &reply)
	return reply, err
}

// The shipped content executor performs a fill whose input handler changes the
// same document, then retires its original lease. Go consumes that real ACK over
// the existing Broker socket; signed peers and the app DOM are inert fixtures.
func TestRendererFillRetirementAcceptsMonotonicSameDocumentGeneration(t *testing.T) {
	g, p, ctx, _ := controlFixtureVersion(t, 2, func() string { return "fillRetirementContent" })
	a, err := g.AdmitControl(ctx, p, modelSurfaceFixture())
	if err != nil {
		t.Fatal(err)
	}
	retired, err := g.RetireControl(ctx, p, a)
	if err != nil || !retired {
		t.Fatal("same-document fill retirement rejected", err)
	}
	c := g.controlChannel(a)
	g.broker.mu.Lock()
	generation := c.documents[0].Generation
	g.broker.mu.Unlock()
	if generation <= a.Document.Generation {
		t.Fatal("real renderer did not advance document revision")
	}
	if g.VerifyControl(ctx, p, a) == nil {
		t.Fatal("retired fill lease remained usable")
	}
}

func TestRendererFillRetirementStillRejectsChangedSourceOrLease(t *testing.T) {
	for _, mode := range []string{"fillRetirementContentWrongDocument", "fillRetirementContentOldGeneration", "fillRetirementContentWrongLease"} {
		t.Run(mode, func(t *testing.T) {
			g, p, ctx, _ := controlFixtureVersion(t, 2, func() string { return mode })
			a, err := g.AdmitControl(ctx, p, modelSurfaceFixture())
			if err != nil {
				t.Fatal(err)
			}
			retired, err := g.RetireControl(ctx, p, a)
			if err == nil || retired {
				t.Fatal("mismatched renderer ACK retired original authority")
			}
			if g.VerifyControl(ctx, p, a) == nil {
				t.Fatal("uncertain retirement permitted more input")
			}
		})
	}
}

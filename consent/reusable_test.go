package consent_test

import (
	"github.com/viant/mechanize/consent"
	"testing"
)

func TestPrivatePreparationRejectsOnceWithoutConsumingIt(t *testing.T) {
	f := newFixture(t)
	g := grant(t, f, consent.AllowOnce)
	if lease, e := f.service.Authorize(consent.RequireReusableGrant(f.client), operation(g)); e == nil {
		lease.Release()
		t.Fatal("one-shot grant admitted a multi-operation preparation")
	}
	lease, e := f.service.Authorize(f.client, operation(g))
	if e != nil {
		t.Fatal("private preparation consumed the one-shot grant", e)
	}
	lease.Release()
	if lease, e = f.service.Authorize(f.client, operation(g)); e == nil {
		lease.Release()
		t.Fatal("one-shot semantics weakened")
	}
}
func TestPrivatePreparationRetainsActualReusableGrantSemantics(t *testing.T) {
	for _, decision := range []consent.Decision{consent.AllowSession, consent.AllowUntilRevoked} {
		t.Run(string(decision), func(t *testing.T) {
			f := newFixture(t)
			g := grant(t, f, decision)
			for i := 0; i < 2; i++ {
				lease, e := f.service.Authorize(consent.RequireReusableGrant(f.client), operation(g))
				if e != nil {
					t.Fatal(e)
				}
				lease.Release()
			}
		})
	}
}

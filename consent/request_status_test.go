package consent_test

import (
	"github.com/viant/mechanize/consent"
	"testing"
	"time"
)

func TestOwnedRequestExpiryHasNoInventedGrant(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	f.options.Now = func() time.Time { return now }
	service, err := consent.New(f.options)
	if err != nil {
		t.Fatal(err)
	}
	request, err := service.CreateRequest(f.client, "fixture-session", input())
	if err != nil {
		t.Fatal(err)
	}
	status, err := service.RequestStatus(f.client, request.ID)
	if err != nil || status.Status != "pending" || status.Grant != nil {
		t.Fatalf("pending: %+v %v", status, err)
	}
	now = now.Add(3 * time.Minute)
	status, err = service.RequestStatus(f.client, request.ID)
	if err != nil || status.Status != "expired" || status.Grant != nil {
		t.Fatalf("expired: %+v %v", status, err)
	}
	if _, err = service.Decide(f.admin, request.ID, consent.AllowSession); err == nil {
		t.Fatal("expired request approved")
	}
}

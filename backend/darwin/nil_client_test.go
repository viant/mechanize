package darwin

import (
	"context"
	"errors"
	"testing"
)

func TestGatewayRejectsTypedNilNativeClient(t *testing.T) {
	var client *Client
	if gateway, err := NewGateway(client, GatewayOptions{AllApplications: true}); err == nil || gateway != nil {
		t.Fatal("typed nil client admitted")
	}
}

func TestNilNativeClientCannotDispatchOrConfirmCleanup(t *testing.T) {
	var client *Client
	_, err := client.Call(context.Background(), Request{Method: "doctor"})
	var transport *TransportError
	if !errors.As(err, &transport) || transport.DispatchState != "notDispatched" {
		t.Fatalf("nil client must return a predispatch failure: %v", err)
	}
	if client.Close() == nil {
		t.Fatal("nil client cannot establish cleanup")
	}
}

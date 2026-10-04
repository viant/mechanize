package darwin

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

func TestIdentityNonceFrames(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name   string
		length uint32
		body   string
		valid  bool
	}{
		{"valid", 64, nonce, true}, {"wrong nonce", 64, strings.Repeat("b", 64), false},
		{"truncated", 64, nonce[:63], false}, {"oversize", MaximumFrameBytes, nonce, false}, {"empty", 0, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var data bytes.Buffer
			_ = binary.Write(&data, binary.BigEndian, tc.length)
			data.WriteString(tc.body)
			err := readIdentityNonce(&data, nonce)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
			if err != nil && strings.Contains(err.Error(), nonce) {
				t.Fatal("nonce leaked in error")
			}
		})
	}
}
func TestMutationLaunchRequiresEnrollment(t *testing.T) {
	fence, err := os.CreateTemp(t.TempDir(), "fence")
	if err != nil {
		t.Fatal(err)
	}
	defer fence.Close()
	client, err := NewClient(context.Background(), Options{HelperPath: "/must-not-launch", AllowMutations: true, Fence: fence})
	if err == nil || client != nil || !strings.Contains(err.Error(), "enrolled") {
		t.Fatalf("client=%v error=%v", client, err)
	}
}
func TestIdentityEnvironmentDoesNotInheritRendezvous(t *testing.T) {
	t.Setenv(identitySocketEnv, "untrusted-socket")
	t.Setenv(identityNonceEnv, "untrusted-nonce")
	var handshake *identityHandshake
	for _, entry := range handshake.environment() {
		if strings.HasPrefix(entry, identitySocketEnv+"=") || strings.HasPrefix(entry, identityNonceEnv+"=") {
			t.Fatal("inherited rendezvous configuration")
		}
	}
}
func TestPartialHelperEnrollmentRejected(t *testing.T) {
	uid := uint32(os.Getuid())
	for _, options := range []Options{{HelperPath: "/must-not-launch", ExpectedUID: &uid}, {HelperPath: "/must-not-launch", Requirement: "identifier fixture"}} {
		client, err := NewClient(context.Background(), options)
		if client != nil || err == nil {
			t.Fatalf("client=%v error=%v", client, err)
		}
	}
}

func TestUnverifiedCleanupClientCannotDispatch(t *testing.T) {
	// A failed launch with uncertain reaping may return a client for supervisor
	// cleanup. It must never become a usable protocol transport.
	client := &Client{trustRequired: true}
	_, err := client.Call(context.Background(), Request{RequestID: "blocked", Method: "doctor", DeadlineRemainingMS: 100})
	if err == nil {
		t.Fatal("unauthenticated client dispatched")
	}
	transport, ok := err.(*TransportError)
	if !ok || transport.DispatchState != "notDispatched" {
		t.Fatalf("error=%v", err)
	}
	if _, trusted := client.TrustedIdentity(); trusted {
		t.Fatal("failed handshake marked trusted")
	}
}

func TestLaunchOnlyRequiresEnrollmentAndFence(t *testing.T) {
	client, err := NewClient(context.Background(), Options{HelperPath: "/must-not-launch", AllowLaunch: true})
	if client != nil || err == nil || !strings.Contains(err.Error(), "fence") {
		t.Fatalf("client=%v error=%v", client, err)
	}
	fence, err := os.CreateTemp(t.TempDir(), "fence")
	if err != nil {
		t.Fatal(err)
	}
	defer fence.Close()
	client, err = NewClient(context.Background(), Options{HelperPath: "/must-not-launch", AllowLaunch: true, Fence: fence})
	if client != nil || err == nil || !strings.Contains(err.Error(), "enrolled") {
		t.Fatalf("client=%v error=%v", client, err)
	}
}
func TestNativeAuthorityProfilesAreExclusive(t *testing.T) {
	client, err := NewClient(context.Background(), Options{HelperPath: "/must-not-launch", AllowLaunch: true, AllowMutations: true})
	if client != nil || err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("client=%v error=%v", client, err)
	}
}

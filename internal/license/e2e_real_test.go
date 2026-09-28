package license

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"testing"
	"time"
)

// TestRealServerEndToEnd exercises the frozen activation contract against a
// real magicvpn-license-server instance: signed denial for a mistyped key
// must not clobber the trial, a real key activates and survives restart,
// forced revalidation keeps the session, and a second installation hits
// activation_limit while keeping its own trial.
//
// It skips unless the harness exports MAGICVPN_LIC_E2E_URL,
// MAGICVPN_LIC_E2E_KEY and MAGICVPN_LIC_E2E_PUBKEY (base64url raw Ed25519
// public key, matching the server's -print-pubkey output).
func TestRealServerEndToEnd(t *testing.T) {
	serverURL := os.Getenv("MAGICVPN_LIC_E2E_URL")
	key := os.Getenv("MAGICVPN_LIC_E2E_KEY")
	pubkeyRaw := os.Getenv("MAGICVPN_LIC_E2E_PUBKEY")
	if serverURL == "" || key == "" || pubkeyRaw == "" {
		t.Skip("set MAGICVPN_LIC_E2E_URL/KEY/PUBKEY to run the real-server e2e")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(pubkeyRaw)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		t.Fatalf("bad MAGICVPN_LIC_E2E_PUBKEY: %v", err)
	}
	publicKey := ed25519.PublicKey(decoded)
	ctx := context.Background()

	newManager := func(t *testing.T) *Manager {
		t.Helper()
		manager, err := New(Config{
			Dir: t.TempDir(), ServerURL: serverURL,
			Keys:      map[string]ed25519.PublicKey{"mk-1": publicKey},
			Policy:    Policy{Enabled: true, TrialDays: 7, Message: "license required", Contact: "support"},
			ClientVer: func() string { return "e2e" },
			Now:       time.Now,
		})
		if err != nil {
			t.Fatal(err)
		}
		return manager
	}

	// A mistyped key surfaces a signed denial without killing the trial.
	manager := newManager(t)
	snapshot, err := manager.Activate(ctx, "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE")
	var gate *GateError
	if !errors.As(err, &gate) || gate.Code != "invalid_key" {
		t.Fatalf("typo Activate() = %#v, %v", snapshot, err)
	}
	if snapshot.State != StateTrial || !snapshot.CanConnect {
		t.Fatalf("typo clobbered trial: %#v", snapshot)
	}
	restarted, err := New(manager.cfg)
	if err != nil || restarted.Snapshot().State != StateTrial {
		t.Fatalf("typo restart = %#v, %v", restarted.Snapshot(), err)
	}

	// The real key activates and survives a restart.
	snapshot, err = restarted.Activate(ctx, key)
	if err != nil || snapshot.State != StateActivated || !snapshot.CanConnect || !snapshot.Activated {
		t.Fatalf("Activate() = %#v, %v", snapshot, err)
	}
	activated, err := New(manager.cfg)
	if err != nil || activated.Snapshot().State != StateActivated {
		t.Fatalf("activated restart = %#v, %v", activated.Snapshot(), err)
	}

	// Forced revalidation keeps the session active.
	snapshot, err = activated.Revalidate(ctx, true)
	if err != nil || snapshot.State != StateActivated || !snapshot.CanConnect {
		t.Fatalf("Revalidate() = %#v, %v", snapshot, err)
	}

	// A second installation hits activation_limit without losing its trial.
	second := newManager(t)
	snapshot, err = second.Activate(ctx, key)
	if !errors.As(err, &gate) || gate.Code != "activation_limit" {
		t.Fatalf("second device Activate() = %#v, %v", snapshot, err)
	}
	if snapshot.State != StateTrial || !snapshot.CanConnect {
		t.Fatalf("second device lost trial: %#v", snapshot)
	}
}

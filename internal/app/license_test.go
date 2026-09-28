package app

import (
	"errors"
	"strings"
	"testing"

	"github.com/aethergui/aethergui/internal/license"
)

type deniedLicenseGate struct{}

func (deniedLicenseGate) AllowConnect() error {
	return errors.New("connection denied")
}

func (deniedLicenseGate) Snapshot() license.Snapshot {
	return license.Snapshot{State: license.StateDenied}
}

func TestConnectChecksLicenseBeforeSubsystems(t *testing.T) {
	application := &App{License: deniedLicenseGate{}}

	err := application.Connect()
	if err == nil {
		t.Fatal("Connect() error = nil, want license denial")
	}
	if !strings.Contains(err.Error(), "license: connection denied") {
		t.Fatalf("Connect() error = %q, want wrapped license denial", err)
	}
}

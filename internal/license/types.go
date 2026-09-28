// Package license implements the standalone paid-license domain.
package license

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// State is the effective local license state.
type State string

const (
	StateTrial     State = "trial"
	StateActivated State = "activated"
	StateGrace     State = "grace"
	StateExpired   State = "expired"
	StateDenied    State = "denied"
)

// Snapshot is the immutable, caller-facing view of the current license state.
type Snapshot struct {
	State           State      `json:"state"`
	CanConnect      bool       `json:"can_connect"`
	Activated       bool       `json:"activated"`
	Offline         bool       `json:"offline"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	RevalidateAfter *time.Time `json:"revalidate_after,omitempty"`
	GraceExpiresAt  *time.Time `json:"grace_expires_at,omitempty"`
	TrialExpiresAt  *time.Time `json:"trial_expires_at,omitempty"`
	DaysLeft        int        `json:"days_left"`
	Code            string     `json:"code,omitempty"`
	Message         string     `json:"message,omitempty"`
	Contact         string     `json:"contact,omitempty"`
	KeyHint         string     `json:"key_hint,omitempty"`
	LastValidatedAt *time.Time `json:"last_validated_at,omitempty"`
}

// Policy is supplied by the version manifest owner. This package never reads
// the manifest directly.
type Policy struct {
	Enabled   bool
	TrialDays int
	Message   string
	Contact   string
}

// Config contains all dependencies and policy needed by Manager.
type Config struct {
	Dir       string
	ServerURL string
	Keys      map[string]ed25519.PublicKey
	HTTP      *http.Client
	Policy    Policy
	Grace     time.Duration
	Product   string
	ClientVer func() string
	Now       func() time.Time
}

// GateError reports an authoritative business decision that prevents a VPN
// connection. Callers can inspect State and Code without parsing Error().
type GateError struct {
	State   State
	Code    string
	Message string
}

func (e *GateError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return e.Message
	}
	if e.Code != "" {
		return fmt.Sprintf("license %s: %s", e.State, e.Code)
	}
	return "license " + string(e.State)
}

// ErrUnreachable identifies transport, HTTP, malformed-response, and
// untrusted-response failures. It is never an authoritative denial.
var ErrUnreachable = errors.New("license server unreachable")

const (
	stateVersion       = 1
	defaultTrialDays   = 7
	defaultGrace       = 72 * time.Hour
	defaultHTTPTimeout = 10 * time.Second
	defaultProduct     = "magicvpn"
	licenseFileName    = "license.json"
	legacyFirstRunName = "firstrun"
)

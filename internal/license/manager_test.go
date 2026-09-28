package license

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type testSigner struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func newTestSigner(t *testing.T) testSigner {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testSigner{public: public, private: private}
}

func (signer testSigner) token(t *testing.T, installationID string, issuedAt, expiresAt, revalidateAfter time.Time, licenseID string) string {
	t.Helper()
	payload := tokenPayload{
		Version: 1, KID: "mk-1", LicenseID: licenseID,
		InstallationID: installationID, Product: defaultProduct,
		IssuedAt:        issuedAt.UTC().Format(time.RFC3339),
		ExpiresAt:       expiresAt.UTC().Format(time.RFC3339),
		RevalidateAfter: revalidateAfter.UTC().Format(time.RFC3339),
	}
	contents, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(signer.private, contents)
	return base64.RawURLEncoding.EncodeToString(contents) + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (signer testSigner) denial(code, licenseID string, serverTime time.Time) serverResponse {
	stamp := serverTime.UTC().Format(time.RFC3339)
	message := []byte("v1|denied|" + code + "|" + licenseID + "|" + stamp)
	return serverResponse{
		Status: "denied", Code: code, LicenseID: licenseID, ServerTime: stamp,
		Message:   "denied " + code,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer.private, message)),
	}
}

func activeResponseFor(t *testing.T, signer testSigner, installationID string, now time.Time, licenseID string) serverResponse {
	t.Helper()
	expires := now.Add(30 * 24 * time.Hour)
	revalidate := now.Add(24 * time.Hour)
	return serverResponse{
		Status: "active", LicenseID: licenseID,
		Token:           signer.token(t, installationID, now, expires, revalidate, licenseID),
		ServerTime:      now.UTC().Format(time.RFC3339),
		ExpiresAt:       expires.UTC().Format(time.RFC3339),
		RevalidateAfter: revalidate.UTC().Format(time.RFC3339),
		Message:         "active",
	}
}

func newTestManager(t *testing.T, signer testSigner, now *time.Time, serverURL string) *Manager {
	t.Helper()
	manager, err := New(Config{
		Dir: t.TempDir(), ServerURL: serverURL,
		Keys:      map[string]ed25519.PublicKey{"mk-1": signer.public},
		Policy:    Policy{Enabled: true, TrialDays: 7, Message: "license required", Contact: "support"},
		ClientVer: func() string { return "1.2.3" }, Now: func() time.Time { return *now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func TestActivationHappyPathPersistsWithoutPlaintextKey(t *testing.T) {
	signer := newTestSigner(t)
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	var installationID string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var input struct {
			Key            string `json:"key"`
			InstallationID string `json:"installation_id"`
			Product        string `json:"product"`
			ClientVersion  string `json:"client_version"`
			Platform       string `json:"platform"`
		}
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			t.Error(err)
		}
		installationID = input.InstallationID
		_ = json.NewEncoder(writer).Encode(activeResponseFor(t, signer, input.InstallationID, now, "lic_1"))
	}))
	defer server.Close()
	manager := newTestManager(t, signer, &now, server.URL)
	key := "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE"
	snapshot, err := manager.Activate(context.Background(), key)
	if err != nil || snapshot.State != StateActivated || !snapshot.CanConnect || !snapshot.Activated {
		t.Fatalf("Activate() = %#v, %v", snapshot, err)
	}
	if !validInstallationID(installationID) || snapshot.KeyHint != "EEEEE" {
		t.Fatalf("installation/key hint = %q/%q", installationID, snapshot.KeyHint)
	}
	contents, err := os.ReadFile(filepath.Join(manager.cfg.Dir, licenseFileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), key) || !strings.Contains(string(contents), `"token"`) {
		t.Fatalf("unsafe or incomplete persisted state: %s", contents)
	}
}

func TestSignedActivationDenialsDoNotClobberTrial(t *testing.T) {
	for _, code := range []string{"invalid_key", "revoked", "expired", "activation_limit", "product_mismatch"} {
		t.Run(code, func(t *testing.T) {
			signer := newTestSigner(t)
			now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(writer).Encode(signer.denial(code, "lic_1", now))
			}))
			defer server.Close()
			manager := newTestManager(t, signer, &now, server.URL)
			snapshot, err := manager.Activate(context.Background(), "AAAAA-BBBBB")
			var gate *GateError
			if !errors.As(err, &gate) || gate.Code != code {
				t.Fatalf("Activate() error = %v", err)
			}
			if snapshot.State != StateTrial || !snapshot.CanConnect {
				t.Fatalf("denial about a key never held clobbered trial: %#v", snapshot)
			}
			restarted, err := New(manager.cfg)
			if err != nil || restarted.Snapshot().State != StateTrial {
				t.Fatalf("restart = %#v, %v", restarted.Snapshot(), err)
			}
		})
	}
}

func TestDenialAboutOwnLicensePersistsAcrossRestart(t *testing.T) {
	signer := newTestSigner(t)
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	revoked := false
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var input map[string]string
		_ = json.NewDecoder(request.Body).Decode(&input)
		if strings.HasSuffix(request.URL.Path, "/activate") {
			_ = json.NewEncoder(writer).Encode(activeResponseFor(t, signer, input["installation_id"], now, "lic_1"))
			return
		}
		if revoked {
			_ = json.NewEncoder(writer).Encode(signer.denial("revoked", "lic_1", now))
			return
		}
		_ = json.NewEncoder(writer).Encode(activeResponseFor(t, signer, input["installation_id"], now, "lic_1"))
	}))
	defer server.Close()
	manager := newTestManager(t, signer, &now, server.URL)
	if _, err := manager.Activate(context.Background(), "AAAAA-BBBBB"); err != nil {
		t.Fatal(err)
	}
	revoked = true
	snapshot, err := manager.Revalidate(context.Background(), true)
	var gate *GateError
	if !errors.As(err, &gate) || gate.Code != "revoked" || snapshot.State != StateDenied {
		t.Fatalf("Revalidate() = %#v, %v", snapshot, err)
	}
	restarted, err := New(manager.cfg)
	if err != nil || restarted.Snapshot().State != StateDenied || restarted.Snapshot().Code != "revoked" {
		t.Fatalf("restart = %#v, %v", restarted.Snapshot(), err)
	}
	if err := restarted.AllowConnect(); err == nil {
		t.Fatal("AllowConnect() = nil after persisted revocation")
	}
}

func TestForgedDenialIsUnreachable(t *testing.T) {
	signer := newTestSigner(t)
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		response := signer.denial("revoked", "lic_1", now)
		response.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		_ = json.NewEncoder(writer).Encode(response)
	}))
	defer server.Close()
	manager := newTestManager(t, signer, &now, server.URL)
	snapshot, err := manager.Activate(context.Background(), "AAAAA-BBBBB")
	if !errors.Is(err, ErrUnreachable) || snapshot.State != StateTrial {
		t.Fatalf("Activate() = %#v, %v", snapshot, err)
	}
}

func TestFirstRunMigrationAndTrialBoundary(t *testing.T) {
	signer := newTestSigner(t)
	dir := t.TempDir()
	firstRun := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	if err := os.WriteFile(filepath.Join(dir, legacyFirstRunName), []byte("1788220800"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := firstRun.Add(7*24*time.Hour - time.Nanosecond)
	cfg := Config{Dir: dir, Keys: map[string]ed25519.PublicKey{"mk-1": signer.public}, Policy: Policy{Enabled: true, TrialDays: 7}, Now: func() time.Time { return now }}
	manager, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if manager.Snapshot().State != StateTrial {
		t.Fatalf("before boundary = %s", manager.Snapshot().State)
	}
	now = firstRun.Add(7 * 24 * time.Hour)
	manager.evaluateAndNotify()
	if manager.Snapshot().State != StateExpired {
		t.Fatalf("at boundary = %s", manager.Snapshot().State)
	}
	if err := os.WriteFile(filepath.Join(dir, legacyFirstRunName), []byte("1893456000"), 0o600); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(cfg)
	if err != nil || restarted.Snapshot().State != StateExpired {
		t.Fatalf("legacy reread refreshed trial: %#v, %v", restarted.Snapshot(), err)
	}
}

func TestGraceBoundariesAndExpiry(t *testing.T) {
	tests := []struct {
		name    string
		expires time.Duration
		advance time.Duration
		want    State
	}{
		{"before grace end", 30 * 24 * time.Hour, 72*time.Hour - time.Nanosecond, StateGrace},
		{"at grace end", 30 * 24 * time.Hour, 72 * time.Hour, StateExpired},
		{"token expires first", 48 * time.Hour, 48 * time.Hour, StateExpired},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signer := newTestSigner(t)
			origin := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
			now := origin
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if strings.HasSuffix(request.URL.Path, "/activate") {
					var input map[string]string
					_ = json.NewDecoder(request.Body).Decode(&input)
					expires := origin.Add(test.expires)
					response := serverResponse{Status: "active", LicenseID: "lic_1", ServerTime: origin.Format(time.RFC3339), ExpiresAt: expires.Format(time.RFC3339), RevalidateAfter: origin.Add(time.Hour).Format(time.RFC3339)}
					response.Token = signer.token(t, input["installation_id"], origin, expires, origin.Add(time.Hour), "lic_1")
					_ = json.NewEncoder(writer).Encode(response)
					return
				}
				http.Error(writer, "offline", http.StatusInternalServerError)
			}))
			defer server.Close()
			manager := newTestManager(t, signer, &now, server.URL)
			if _, err := manager.Activate(context.Background(), "AAAAA-BBBBB"); err != nil {
				t.Fatal(err)
			}
			now = origin.Add(test.advance)
			snapshot, err := manager.Revalidate(context.Background(), true)
			if !errors.Is(err, ErrUnreachable) || snapshot.State != test.want {
				t.Fatalf("Revalidate() = %#v, %v", snapshot, err)
			}
		})
	}
}

func TestUnreachableResponsesNeverDeny(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
	}{{"429", 429, `{}`}, {"500", 500, `{}`}, {"bad json", 200, `{`}} {
		t.Run(test.name, func(t *testing.T) {
			signer := newTestSigner(t)
			now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()
			manager := newTestManager(t, signer, &now, server.URL)
			snapshot, err := manager.Activate(context.Background(), "AAAAA-BBBBB")
			if !errors.Is(err, ErrUnreachable) || snapshot.State == StateDenied {
				t.Fatalf("Activate() = %#v, %v", snapshot, err)
			}
		})
	}
}

func TestRevalidateRotatesToken(t *testing.T) {
	signer := newTestSigner(t)
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestCount++
		var input map[string]string
		_ = json.NewDecoder(request.Body).Decode(&input)
		if requestCount == 2 {
			now = now.Add(time.Hour)
		}
		_ = json.NewEncoder(writer).Encode(activeResponseFor(t, signer, input["installation_id"], now, "lic_1"))
	}))
	defer server.Close()
	manager := newTestManager(t, signer, &now, server.URL)
	if _, err := manager.Activate(context.Background(), "AAAAA-BBBBB"); err != nil {
		t.Fatal(err)
	}
	oldToken := manager.state.Token
	if _, err := manager.Revalidate(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if manager.state.Token == oldToken {
		t.Fatal("revalidation did not rotate token")
	}
}

func TestClockRollbackAndForwardJump(t *testing.T) {
	signer := newTestSigner(t)
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	manager := newTestManager(t, signer, &now, "http://127.0.0.1:1")
	trialEnd := *manager.Snapshot().TrialExpiresAt
	now = now.Add(-24 * time.Hour)
	manager.evaluateAndNotify()
	if manager.Snapshot().TrialExpiresAt == nil || !manager.Snapshot().TrialExpiresAt.Equal(trialEnd) {
		t.Fatal("rollback extended trial")
	}
	now = trialEnd.Add(time.Second)
	manager.evaluateAndNotify()
	if manager.Snapshot().State != StateExpired {
		t.Fatalf("forward jump state = %s", manager.Snapshot().State)
	}
}

func TestCorruptActivatedStateFailsClosed(t *testing.T) {
	signer := newTestSigner(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, licenseFileName), []byte(`{"version":1,"token":"truncated`), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	manager, err := New(Config{Dir: dir, Keys: map[string]ed25519.PublicKey{"mk-1": signer.public}, Policy: Policy{Enabled: true, TrialDays: 7}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if manager.Snapshot().State != StateDenied || manager.Snapshot().Code != "invalid_token" {
		t.Fatalf("corrupt activated state = %#v", manager.Snapshot())
	}
}

func TestConcurrentOperations(t *testing.T) {
	signer := newTestSigner(t)
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var input map[string]string
		_ = json.NewDecoder(request.Body).Decode(&input)
		_ = json.NewEncoder(writer).Encode(activeResponseFor(t, signer, input["installation_id"], now, "lic_1"))
	}))
	defer server.Close()
	manager := newTestManager(t, signer, &now, server.URL)
	if _, err := manager.Activate(context.Background(), "AAAAA-BBBBB"); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for index := 0; index < 30; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			switch index % 4 {
			case 0:
				_ = manager.Snapshot()
			case 1:
				_, _ = manager.Activate(context.Background(), "AAAAA-BBBBB")
			case 2:
				_, _ = manager.Revalidate(context.Background(), true)
			case 3:
				manager.evaluateAndNotify()
			}
		}(index)
	}
	wait.Wait()
}

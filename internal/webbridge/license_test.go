//go:build windows

package webbridge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aethergui/aethergui/internal/app"
	"github.com/aethergui/aethergui/internal/coremgr"
	"github.com/aethergui/aethergui/internal/license"
)

type fakeLicenseService struct {
	snapshot      license.Snapshot
	activateError error
	revalidateErr error
	activateCalls int
	policy        license.Policy
}

func (service *fakeLicenseService) AllowConnect() error { return nil }
func (service *fakeLicenseService) Snapshot() license.Snapshot {
	return service.snapshot
}
func (service *fakeLicenseService) Activate(context.Context, string) (license.Snapshot, error) {
	service.activateCalls++
	return service.snapshot, service.activateError
}
func (service *fakeLicenseService) Revalidate(context.Context, bool) (license.Snapshot, error) {
	return service.snapshot, service.revalidateErr
}
func (service *fakeLicenseService) SetPolicy(policy license.Policy) { service.policy = policy }
func (service *fakeLicenseService) OnChange(func(license.Snapshot)) {}

type deniedWebLicenseService struct{ fakeLicenseService }

func (service *deniedWebLicenseService) AllowConnect() error {
	return &license.GateError{State: license.StateExpired, Code: "expired", Message: "授权已过期"}
}

func requestLicense(t *testing.T, bridge *Bridge, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path+"?t="+bridge.token, strings.NewReader(body))
	response := httptest.NewRecorder()
	bridge.Handler().ServeHTTP(response, request)
	return response
}

func decodeResponse(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return result
}

func TestGetLicenseReturnsSnapshot(t *testing.T) {
	service := &fakeLicenseService{snapshot: license.Snapshot{State: license.StateActivated, CanConnect: true, Activated: true, DaysLeft: 12}}
	bridge := &Bridge{app: &app.App{License: service}, token: "test-token"}

	response := requestLicense(t, bridge, http.MethodGet, "/api/license", "")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	result := decodeResponse(t, response)
	if result["state"] != string(license.StateActivated) || result["can_connect"] != true {
		t.Fatalf("response = %#v, want activated snapshot", result)
	}
}

func TestActivateLicenseRejectsEmptyKey(t *testing.T) {
	service := &fakeLicenseService{snapshot: license.Snapshot{State: license.StateTrial, CanConnect: true}}
	bridge := &Bridge{app: &app.App{License: service}, token: "test-token"}

	response := requestLicense(t, bridge, http.MethodPost, "/api/license/activate", `{"key":"   "}`)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
	if service.activateCalls != 0 {
		t.Fatalf("Activate calls = %d, want 0", service.activateCalls)
	}
	result := decodeResponse(t, response)
	errorValue := result["error"].(map[string]any)
	if errorValue["code"] != "bad_input" {
		t.Fatalf("error code = %v, want bad_input", errorValue["code"])
	}
}

func TestActivateLicenseMapsGateError(t *testing.T) {
	service := &fakeLicenseService{
		snapshot:      license.Snapshot{State: license.StateDenied, Code: "revoked"},
		activateError: &license.GateError{State: license.StateDenied, Code: "revoked"},
	}
	bridge := &Bridge{app: &app.App{License: service}, token: "test-token"}

	response := requestLicense(t, bridge, http.MethodPost, "/api/license/activate", `{"key":"valid-key"}`)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", response.Code)
	}
	result := decodeResponse(t, response)
	errorValue := result["error"].(map[string]any)
	if errorValue["code"] != "revoked" || errorValue["message"] != "授权已被撤销" {
		t.Fatalf("error = %#v, want revoked default message", errorValue)
	}
}

func TestActivateLicenseMapsUnreachable(t *testing.T) {
	service := &fakeLicenseService{
		snapshot:      license.Snapshot{State: license.StateTrial, CanConnect: true},
		activateError: errors.Join(license.ErrUnreachable, errors.New("network failure")),
	}
	bridge := &Bridge{app: &app.App{License: service}, token: "test-token"}

	response := requestLicense(t, bridge, http.MethodPost, "/api/license/activate", `{"key":"valid-key"}`)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", response.Code)
	}
	result := decodeResponse(t, response)
	errorValue := result["error"].(map[string]any)
	if errorValue["code"] != "unreachable" {
		t.Fatalf("error code = %v, want unreachable", errorValue["code"])
	}
}

func TestActivateLicenseSuccessShape(t *testing.T) {
	service := &fakeLicenseService{snapshot: license.Snapshot{State: license.StateActivated, CanConnect: true, Activated: true}}
	bridge := &Bridge{app: &app.App{License: service}, token: "test-token"}

	response := requestLicense(t, bridge, http.MethodPost, "/api/license/activate", `{"key":"valid-key"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	result := decodeResponse(t, response)
	if result["ok"] != true || result["license"] == nil {
		t.Fatalf("response = %#v, want ok and license", result)
	}
}

func TestConnectReturnsLicenseDenied(t *testing.T) {
	service := &deniedWebLicenseService{fakeLicenseService: fakeLicenseService{snapshot: license.Snapshot{State: license.StateExpired}}}
	bridge := &Bridge{app: &app.App{License: service}, token: "test-token"}

	response := requestLicense(t, bridge, http.MethodPost, "/api/connect", `{}`)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
	result := decodeResponse(t, response)
	if result["error"] != "license_denied" || result["message"] != "授权已过期" {
		t.Fatalf("response = %#v, want license_denied", result)
	}
}

func TestUpdateCheckResponseHasNoLicense(t *testing.T) {
	bridge := &Bridge{
		app:   &app.App{Core: coremgr.NewManager(nil)},
		token: "test-token",
	}
	response := httptest.NewRecorder()
	bridge.updateCheck(response, httptest.NewRequest(http.MethodPost, "/api/update/check", nil))

	result := decodeResponse(t, response)
	if _, exists := result["license"]; exists {
		t.Fatalf("response contains obsolete license key: %#v", result)
	}
	if _, exists := result["update"]; !exists {
		t.Fatalf("response = %#v, want update key", result)
	}
}

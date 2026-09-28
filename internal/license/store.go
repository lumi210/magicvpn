package license

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type persistedState struct {
	Version         int             `json:"version"`
	InstallationID  string          `json:"installation_id"`
	KeyHint         string          `json:"key_hint,omitempty"`
	Token           string          `json:"token,omitempty"`
	FirstRunAt      string          `json:"first_run_at"`
	LastServerTime  string          `json:"last_server_time,omitempty"`
	LastWallTime    string          `json:"last_wall_time,omitempty"`
	LastValidatedAt string          `json:"last_validated_at,omitempty"`
	LastResult      persistedResult `json:"last_result,omitempty"`
}

type persistedResult struct {
	Status     string `json:"status,omitempty"`
	Code       string `json:"code,omitempty"`
	LicenseID  string `json:"license_id,omitempty"`
	ServerTime string `json:"server_time,omitempty"`
	Signature  string `json:"sig,omitempty"`
}

func loadState(dir string, now time.Time) (persistedState, bool, error) {
	path := filepath.Join(dir, licenseFileName)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		state, createErr := newState(dir, now)
		return state, true, createErr
	}
	if err != nil {
		return persistedState{}, false, fmt.Errorf("read license state: %w", err)
	}
	var state persistedState
	if err := json.Unmarshal(raw, &state); err == nil && state.Version == stateVersion && validInstallationID(state.InstallationID) {
		if _, parseErr := parseWireTime(state.FirstRunAt); parseErr == nil {
			return state, false, nil
		}
	}

	// A malformed file is rebuilt conservatively. If it contains evidence of
	// prior activation, preserve that fact as invalid_token rather than granting
	// a fresh trial. Truly empty or unrelated damage may restart trial once,
	// anchored at the damaged file's modification time when available.
	activatedEvidence := strings.Contains(string(raw), `"token"`) ||
		strings.Contains(string(raw), `"status":"active"`) ||
		strings.Contains(string(raw), `"status": "active"`)
	rebuilt, createErr := newState(dir, now)
	if createErr != nil {
		return persistedState{}, false, createErr
	}
	if info, statErr := os.Stat(path); statErr == nil && info.ModTime().Before(now) {
		rebuilt.FirstRunAt = info.ModTime().UTC().Format(time.RFC3339)
	}
	if activatedEvidence {
		rebuilt.LastResult = persistedResult{Status: "denied", Code: "invalid_token"}
	}
	return rebuilt, true, nil
}

func newState(dir string, now time.Time) (persistedState, error) {
	installationID, err := generateInstallationID()
	if err != nil {
		return persistedState{}, err
	}
	firstRun := now.UTC()
	legacyPath := filepath.Join(dir, legacyFirstRunName)
	if raw, readErr := os.ReadFile(legacyPath); readErr == nil {
		if unixSeconds, parseErr := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64); parseErr == nil && unixSeconds > 0 {
			candidate := time.Unix(unixSeconds, 0).UTC()
			if !candidate.After(now.Add(clockRollbackTolerance)) {
				firstRun = candidate
			}
		}
	}
	return persistedState{
		Version: stateVersion, InstallationID: installationID,
		FirstRunAt: firstRun.Format(time.RFC3339), LastWallTime: now.UTC().Format(time.RFC3339),
	}, nil
}

func generateInstallationID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate installation id: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func validInstallationID(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16
}

func saveState(dir string, state persistedState) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create license directory: %w", err)
	}
	contents, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal license state: %w", err)
	}
	path := filepath.Join(dir, licenseFileName)
	temporary, err := os.CreateTemp(dir, ".license-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary license state: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("protect temporary license state: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary license state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary license state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary license state: %w", err)
	}
	if err := replaceFile(temporaryPath, path); err != nil {
		return fmt.Errorf("install license state: %w", err)
	}
	return nil
}

func keyHint(key string) string {
	compact := strings.ReplaceAll(strings.TrimSpace(key), "-", "")
	if len(compact) <= 5 {
		return compact
	}
	return compact[len(compact)-5:]
}

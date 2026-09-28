// Package updater handles GUI/core update checks and the remote license
// policy published in the release repository.
//
// Two independent feeds are consulted:
//
//   - the GUI comes from the publishing repo (version.json at its root), which
//     also carries the license parameters so they can be tuned remotely;
//   - the Aether core comes from the official upstream releases.
package updater

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/aethergui/aethergui/internal/license"
	"golang.org/x/sys/windows/registry"
)

const (
	// ManifestURL is version.json at the root of the publishing repo.
	ManifestURL = "https://raw.githubusercontent.com/lumi210/magicvpn/main/version.json"
	// CoreReleaseAPI is the official Aether core release feed; the pinned tag
	// is appended when resolving which core to install.
	CoreReleaseAPI = "https://api.github.com/repos/CluvexStudio/Aether/releases"
)

// LicensePolicy is the license policy carried by version.json.
type LicensePolicy struct {
	Enabled bool `json:"enabled"`
	// Expiry is deprecated: retained for wire compatibility; no longer enforced.
	Expiry    string `json:"expiry"`
	TrialDays int    `json:"trial_days"`
	Message   string `json:"message"`
	Contact   string `json:"contact"`
}

// Manifest mirrors version.json in the publishing repository.
type Manifest struct {
	GUI struct {
		Version string `json:"version"`
		URL     string `json:"url"`
		Notes   string `json:"notes"`
	} `json:"gui"`
	// Core pins the core release this GUI build is validated against. The
	// core is offered only from here and never straight from upstream, so a
	// newer upstream core can never land before a GUI that supports it.
	Core struct {
		Version string `json:"version"`
		Notes   string `json:"notes"`
	} `json:"core"`
	License LicensePolicy `json:"license"`
}

// Policy converts the manifest's wire representation into the license
// manager's runtime policy. The deprecated fixed expiry is intentionally
// ignored; expiry decisions belong to the license manager.
func (m *Manifest) Policy() license.Policy {
	if m == nil {
		return license.Policy{}
	}
	return license.Policy{
		Enabled:   m.License.Enabled,
		TrialDays: m.License.TrialDays,
		Message:   m.License.Message,
		Contact:   m.License.Contact,
	}
}

// UpdateInfo is the result of one check, sent to the UI.
//
// There is deliberately no "core update available" flag: the core ships
// inside the GUI bundle and is only ever swapped together with it, so it can
// never run ahead of the UI that drives it.
type UpdateInfo struct {
	GUIHas    bool   `json:"gui_has"`
	GUIVer    string `json:"gui_version"`
	GUIURL    string `json:"gui_url"`
	GUINotes  string `json:"gui_notes"`
	CoreVer   string `json:"core_version"`
	CoreNotes string `json:"core_notes"`
	CheckedAt string `json:"checked_at"`
	Error     string `json:"error,omitempty"`
}

// systemProxy returns the proxy configured in Internet Settings, if enabled.
// GitHub is not reachable directly on some networks, so update checks must
// honour it.
func systemProxy() *url.URL {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()

	en, _, err := k.GetIntegerValue("ProxyEnable")
	if err != nil || en != 1 {
		return nil
	}
	s, _, err := k.GetStringValue("ProxyServer")
	if err != nil {
		return nil
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil
	}
	return u
}

func client(timeout time.Duration) *http.Client {
	tr := &http.Transport{}
	if p := systemProxy(); p != nil {
		tr.Proxy = http.ProxyURL(p)
	} else {
		// The Internet Settings switch is often off even when a local proxy
		// client is running, so fall back to HTTPS_PROXY/HTTP_PROXY.
		tr.Proxy = http.ProxyFromEnvironment
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

// FetchManifest reads version.json from the publishing repo.
func FetchManifest() (*Manifest, error) {
	resp, err := client(20 * time.Second).Get(ManifestURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest http %d", resp.StatusCode)
	}
	var m Manifest
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

// parseVer extracts "2.0.0" out of strings like "v2.0.0" or "aether 2.0.0".
func parseVer(s string) [3]int {
	var v [3]int
	start := -1
	for i, r := range s {
		if r >= '0' && r <= '9' {
			start = i
			break
		}
	}
	if start < 0 {
		return v
	}
	parts := strings.Split(s[start:], ".")
	for i := 0; i < 3 && i < len(parts); i++ {
		n := 0
		for _, r := range parts[i] {
			if r >= '0' && r <= '9' {
				n = n*10 + int(r-'0')
			} else {
				break
			}
		}
		v[i] = n
	}
	return v
}

// newer reports whether a is strictly greater than b.
func newer(a, b string) bool {
	if strings.TrimSpace(a) == "" || strings.TrimSpace(b) == "" {
		return false
	}
	va, vb := parseVer(a), parseVer(b)
	for i := 0; i < 3; i++ {
		if va[i] != vb[i] {
			return va[i] > vb[i]
		}
	}
	return false
}

// CheckFromManifest compares the running GUI/core against an already-fetched
// manifest without performing any network access.
func CheckFromManifest(m *Manifest, guiVer, coreVer string) *UpdateInfo {
	info := &UpdateInfo{CheckedAt: time.Now().Format(time.RFC3339)}
	if m == nil {
		return info
	}
	if m.GUI.Version != "" && newer(m.GUI.Version, guiVer) {
		info.GUIHas = true
		info.GUIVer = m.GUI.Version
		info.GUIURL = m.GUI.URL
		info.GUINotes = m.GUI.Notes
	}

	// The core is never updated on its own: it ships inside the same bundle
	// as the GUI, so a core can never run ahead of the UI that drives it.
	// These two fields are informational — they describe what comes inside.
	info.CoreVer = m.Core.Version
	info.CoreNotes = m.Core.Notes
	return info
}

// Check fetches the manifest and compares the running GUI/core against it.
func Check(guiVer, coreVer string) (*UpdateInfo, error) {
	m, err := FetchManifest()
	if err != nil {
		return nil, err
	}
	return CheckFromManifest(m, guiVer, coreVer), nil
}

// download fetches url into dest, writing through a .part file first.
func download(rawURL, dest string) error {
	resp, err := client(0).Get(rawURL) // no total timeout: binaries can be large
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	tmp := dest + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dest)
}

// ApplyGUI downloads the new GUI binary next to the running one and hands the
// swap to a batch script: a running exe cannot overwrite itself.
// ApplyBundle installs one release bundle.
//
// A bundle is a zip holding the GUI exe plus its matching core under
// core-bin/. Both are staged and swapped together by a batch script once
// this process exits: shipping them as one unit is what keeps a newer core
// from ever landing under an older UI.
func ApplyBundle(dlURL, exePath, corePath string) error {
	if dlURL == "" {
		return fmt.Errorf("no download url in the manifest")
	}
	dir := filepath.Dir(exePath)
	zipPath := filepath.Join(dir, "aether-update.zip")
	if err := download(dlURL, zipPath); err != nil {
		return err
	}
	defer os.Remove(zipPath)

	guiTmp, coreTmp, err := stageBundle(zipPath, dir)
	if err != nil {
		return err
	}

	var b strings.Builder
	b.WriteString("@echo off\r\n")
	b.WriteString("ping -n 3 127.0.0.1 >nul\r\n")
	b.WriteString("move /Y \"" + guiTmp + "\" \"" + exePath + "\"\r\n")
	if coreTmp != "" && corePath != "" {
		b.WriteString("move /Y \"" + coreTmp + "\" \"" + corePath + "\"\r\n")
	}
	b.WriteString("start \"\" \"" + exePath + "\"\r\n")
	b.WriteString("del \"%~f0\"\r\n")

	bat := filepath.Join(dir, "aether-update.bat")
	if err := os.WriteFile(bat, []byte(b.String()), 0o644); err != nil {
		return err
	}
	return exec.Command("cmd", "/c", "start", "", "/min", bat).Start()
}

// stageBundle unpacks the GUI and the bundled core out of a release bundle.
// Either may be missing from the archive; the GUI never may.
func stageBundle(zipPath, dir string) (guiTmp, coreTmp string, err error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", "", err
	}
	defer r.Close()

	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := strings.ToLower(filepath.ToSlash(f.Name))
		if !strings.HasSuffix(name, ".exe") {
			continue
		}
		dst := filepath.Join(dir, "aether-gui.new")
		if strings.Contains(name, "core-bin/") {
			dst = filepath.Join(dir, "aether-core.new")
			coreTmp = dst
		} else {
			guiTmp = dst
		}
		if err := extractZipFile(f, dst); err != nil {
			return "", "", err
		}
	}
	if guiTmp == "" {
		return "", "", fmt.Errorf("bundle contains no GUI executable")
	}
	return guiTmp, coreTmp, nil
}

func extractZipFile(f *zip.File, dst string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, rc); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

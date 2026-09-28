package updater

import (
	"testing"

	"github.com/aethergui/aethergui/internal/license"
)

func TestCheckFromManifest(t *testing.T) {
	tests := []struct {
		name       string
		remote     string
		local      string
		wantGUIHas bool
	}{
		{name: "newer", remote: "v2.1.0", local: "2.0.0", wantGUIHas: true},
		{name: "older", remote: "1.9.0", local: "2.0.0", wantGUIHas: false},
		{name: "same", remote: "2.0.0", local: "v2.0.0", wantGUIHas: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := &Manifest{}
			manifest.GUI.Version = test.remote
			manifest.GUI.URL = "https://example.test/update.zip"
			manifest.GUI.Notes = "GUI notes"
			manifest.Core.Version = "3.4.5"
			manifest.Core.Notes = "Core notes"

			info := CheckFromManifest(manifest, test.local, "3.0.0")
			if info.GUIHas != test.wantGUIHas {
				t.Fatalf("GUIHas = %v, want %v", info.GUIHas, test.wantGUIHas)
			}
			if info.CoreVer != "3.4.5" || info.CoreNotes != "Core notes" {
				t.Fatalf("core info = %q, %q", info.CoreVer, info.CoreNotes)
			}
			if info.CheckedAt == "" {
				t.Fatal("CheckedAt is empty")
			}
			if test.wantGUIHas {
				if info.GUIVer != test.remote || info.GUIURL != "https://example.test/update.zip" || info.GUINotes != "GUI notes" {
					t.Fatalf("GUI info = %#v", info)
				}
			}
		})
	}
}

func TestManifestPolicy(t *testing.T) {
	manifest := &Manifest{}
	manifest.License = LicensePolicy{
		Enabled:   true,
		Expiry:    "2000-01-01",
		TrialDays: 14,
		Message:   "renew",
		Contact:   "support@example.test",
	}

	want := license.Policy{
		Enabled:   true,
		TrialDays: 14,
		Message:   "renew",
		Contact:   "support@example.test",
	}
	if got := manifest.Policy(); got != want {
		t.Fatalf("Policy() = %#v, want %#v", got, want)
	}
}

package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var errInvalidToken = errors.New("invalid license token")

// tokenPayload follows the server's canonical field order. Signatures are
// checked against the original payload bytes before these claims are trusted.
type tokenPayload struct {
	Version         int    `json:"ver"`
	KID             string `json:"kid"`
	LicenseID       string `json:"license_id"`
	InstallationID  string `json:"installation_id"`
	Product         string `json:"product"`
	IssuedAt        string `json:"issued_at"`
	ExpiresAt       string `json:"expires_at"`
	RevalidateAfter string `json:"revalidate_after"`
}

type verifiedToken struct {
	Raw             string
	KID             string
	LicenseID       string
	InstallationID  string
	Product         string
	IssuedAt        time.Time
	ExpiresAt       time.Time
	RevalidateAfter time.Time
}

func verifyToken(raw, installationID, product string, keys map[string]ed25519.PublicKey) (verifiedToken, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return verifiedToken{}, errInvalidToken
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return verifiedToken{}, errInvalidToken
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return verifiedToken{}, errInvalidToken
	}

	// Decode only enough to select a key. No claim is consumed until the exact
	// payload bytes have passed signature verification.
	var selector struct {
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(payloadBytes, &selector); err != nil || selector.KID == "" {
		return verifiedToken{}, errInvalidToken
	}
	publicKey, ok := keys[selector.KID]
	if !ok || len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(publicKey, payloadBytes, signature) {
		return verifiedToken{}, errInvalidToken
	}

	var payload tokenPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return verifiedToken{}, errInvalidToken
	}
	if payload.Version != 1 || payload.KID != selector.KID || payload.LicenseID == "" ||
		payload.InstallationID != installationID || payload.Product != product {
		return verifiedToken{}, errInvalidToken
	}
	issuedAt, err := parseWireTime(payload.IssuedAt)
	if err != nil {
		return verifiedToken{}, errInvalidToken
	}
	expiresAt, err := parseWireTime(payload.ExpiresAt)
	if err != nil {
		return verifiedToken{}, errInvalidToken
	}
	revalidateAfter, err := parseWireTime(payload.RevalidateAfter)
	if err != nil || !expiresAt.After(issuedAt) || revalidateAfter.Before(issuedAt) || revalidateAfter.After(expiresAt) {
		return verifiedToken{}, errInvalidToken
	}
	return verifiedToken{
		Raw: raw, KID: payload.KID, LicenseID: payload.LicenseID,
		InstallationID: payload.InstallationID, Product: payload.Product,
		IssuedAt: issuedAt, ExpiresAt: expiresAt, RevalidateAfter: revalidateAfter,
	}, nil
}

func verifyDenied(result persistedResult, keys map[string]ed25519.PublicKey, allowed map[string]bool) error {
	if result.Status != "denied" || !allowed[result.Code] || result.ServerTime == "" || result.Signature == "" {
		return errors.New("invalid denial")
	}
	if _, err := parseWireTime(result.ServerTime); err != nil {
		return errors.New("invalid denial time")
	}
	signature, err := base64.RawURLEncoding.DecodeString(result.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid denial signature")
	}
	message := []byte("v1|denied|" + result.Code + "|" + result.LicenseID + "|" + result.ServerTime)
	for _, publicKey := range keys {
		if len(publicKey) == ed25519.PublicKeySize && ed25519.Verify(publicKey, message, signature) {
			return nil
		}
	}
	return errors.New("invalid denial signature")
}

func parseWireTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse RFC3339 time: %w", err)
	}
	return parsed.UTC(), nil
}

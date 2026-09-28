package license

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

var activationDenialCodes = map[string]bool{
	"invalid_key": true, "revoked": true, "expired": true,
	"activation_limit": true, "product_mismatch": true,
}

var revalidationDenialCodes = map[string]bool{
	"invalid_token": true, "revoked": true, "expired": true, "product_mismatch": true,
}

type Manager struct {
	mu           sync.RWMutex
	remoteMu     sync.Mutex
	startMu      sync.Mutex
	started      bool
	revalidating bool
	cfg          Config
	client       apiClient
	state        persistedState
	snapshot     Snapshot
	callbacks    []func(Snapshot)
	offline      bool
	rollback     bool
}

func New(cfg Config) (*Manager, error) {
	if strings.TrimSpace(cfg.Dir) == "" {
		return nil, errors.New("license state directory is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: defaultHTTPTimeout}
	}
	if cfg.Product == "" {
		cfg.Product = defaultProduct
	}
	if cfg.ClientVer == nil {
		cfg.ClientVer = func() string { return "unknown" }
	}
	if cfg.Grace <= 0 {
		cfg.Grace = defaultGrace
	}
	if cfg.Policy == (Policy{}) {
		cfg.Policy = Policy{Enabled: true, TrialDays: defaultTrialDays}
	} else if cfg.Policy.Enabled && cfg.Policy.TrialDays <= 0 {
		cfg.Policy.TrialDays = defaultTrialDays
	}
	now := cfg.Now().UTC()
	state, mustSave, err := loadState(cfg.Dir, now)
	if err != nil {
		return nil, err
	}
	manager := &Manager{
		cfg:    cfg,
		client: apiClient{baseURL: cfg.ServerURL, product: cfg.Product, http: cfg.HTTP, version: cfg.ClientVer, platform: defaultPlatform()},
		state:  state,
	}
	manager.evaluateLocked(now)
	if shouldPersistWall(now, parseOptionalTime(state.LastWallTime)) {
		manager.state.LastWallTime = now.Format(time.RFC3339)
		mustSave = true
	}
	if mustSave {
		if err := saveState(cfg.Dir, manager.state); err != nil {
			return nil, err
		}
	}
	return manager, nil
}

func (manager *Manager) Start(ctx context.Context) {
	manager.startMu.Lock()
	if manager.started {
		manager.startMu.Unlock()
		<-ctx.Done()
		return
	}
	manager.started = true
	manager.startMu.Unlock()
	defer func() {
		manager.startMu.Lock()
		manager.started = false
		manager.startMu.Unlock()
	}()
	manager.startRevalidationIfDue(ctx)
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			manager.evaluateAndNotify()
			manager.startRevalidationIfDue(ctx)
		}
	}
}

func (manager *Manager) startRevalidationIfDue(ctx context.Context) {
	manager.mu.RLock()
	due := manager.revalidationDueLocked(manager.cfg.Now().UTC())
	manager.mu.RUnlock()
	if !due {
		return
	}
	manager.startMu.Lock()
	if manager.revalidating {
		manager.startMu.Unlock()
		return
	}
	manager.revalidating = true
	manager.startMu.Unlock()
	go func() {
		defer func() {
			manager.startMu.Lock()
			manager.revalidating = false
			manager.startMu.Unlock()
		}()
		manager.revalidationLoop(ctx)
	}()
}

func (manager *Manager) revalidationLoop(ctx context.Context) {
	backoffs := []time.Duration{15 * time.Minute, 30 * time.Minute, time.Hour, 6 * time.Hour}
	for attempt := 0; ; attempt++ {
		_, err := manager.Revalidate(ctx, true)
		if err == nil || !errors.Is(err, ErrUnreachable) {
			return
		}
		delay := backoffs[minInt(attempt, len(backoffs)-1)]
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (manager *Manager) Snapshot() Snapshot {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	return copySnapshot(manager.snapshot)
}

func (manager *Manager) AllowConnect() error {
	snapshot := manager.Snapshot()
	if snapshot.CanConnect {
		return nil
	}
	return &GateError{State: snapshot.State, Code: snapshot.Code, Message: snapshot.Message}
}

func (manager *Manager) Activate(ctx context.Context, key string) (Snapshot, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return manager.Snapshot(), errors.New("activation key is required")
	}
	if len(key) < 5 || strings.ContainsAny(key, "\r\n\t") {
		return manager.Snapshot(), errors.New("activation key is malformed")
	}
	manager.remoteMu.Lock()
	defer manager.remoteMu.Unlock()
	manager.mu.RLock()
	installationID := manager.state.InstallationID
	manager.mu.RUnlock()
	response, err := manager.client.activate(ctx, key, installationID)
	if err != nil {
		return manager.Snapshot(), err
	}
	return manager.applyResponse(response, keyHint(key), activationDenialCodes)
}

func (manager *Manager) Revalidate(ctx context.Context, force bool) (Snapshot, error) {
	manager.remoteMu.Lock()
	defer manager.remoteMu.Unlock()
	manager.mu.RLock()
	token := manager.state.Token
	installationID := manager.state.InstallationID
	due := manager.revalidationDueLocked(manager.cfg.Now().UTC())
	manager.mu.RUnlock()
	if token == "" {
		snapshot := manager.Snapshot()
		return snapshot, &GateError{State: snapshot.State, Code: snapshot.Code, Message: snapshot.Message}
	}
	if !force && !due {
		return manager.Snapshot(), nil
	}
	response, err := manager.client.revalidate(ctx, token, installationID)
	if err != nil {
		manager.mu.Lock()
		before := manager.snapshot
		manager.offline = true
		manager.evaluateLocked(manager.cfg.Now().UTC())
		after := manager.snapshot
		callbacks := manager.callbacksIfChangedLocked(before, after)
		manager.mu.Unlock()
		invokeCallbacks(callbacks, after)
		return after, err
	}
	return manager.applyResponse(response, "", revalidationDenialCodes)
}

func (manager *Manager) applyResponse(response serverResponse, hint string, allowed map[string]bool) (Snapshot, error) {
	manager.mu.Lock()
	before := manager.snapshot
	previousState := manager.state
	previousOffline := manager.offline
	previousRollback := manager.rollback
	now := manager.cfg.Now().UTC()
	switch response.Status {
	case "active":
		verified, err := verifyToken(response.Token, manager.state.InstallationID, manager.cfg.Product, manager.cfg.Keys)
		if err != nil {
			manager.mu.Unlock()
			return before, fmt.Errorf("%w: invalid active token", ErrUnreachable)
		}
		serverTime, err := parseWireTime(response.ServerTime)
		if err != nil || response.LicenseID != verified.LicenseID || response.ExpiresAt != verified.ExpiresAt.Format(time.RFC3339) || response.RevalidateAfter != verified.RevalidateAfter.Format(time.RFC3339) {
			manager.mu.Unlock()
			return before, fmt.Errorf("%w: inconsistent active response", ErrUnreachable)
		}
		manager.state.Token = response.Token
		if hint != "" {
			manager.state.KeyHint = hint
		}
		manager.state.LastServerTime = serverTime.Format(time.RFC3339)
		manager.state.LastValidatedAt = now.Format(time.RFC3339)
		manager.state.LastResult = persistedResult{Status: "active", LicenseID: response.LicenseID, ServerTime: response.ServerTime}
		manager.offline = false
	case "denied":
		result := persistedResult{Status: "denied", Code: response.Code, LicenseID: response.LicenseID, ServerTime: response.ServerTime, Signature: response.Signature}
		if err := verifyDenied(result, manager.cfg.Keys, allowed); err != nil {
			manager.mu.Unlock()
			return before, fmt.Errorf("%w: untrusted denial", ErrUnreachable)
		}
		// Persist only verdicts about a license this installation previously
		// activated; a mistyped key must not revoke a valid trial/entitlement.
		if denialAppliesToInstallation(result, previousState, manager.cfg) {
			manager.state.LastResult = result
		}
		manager.state.LastServerTime = response.ServerTime
		manager.state.LastValidatedAt = now.Format(time.RFC3339)
		manager.offline = false
	default:
		manager.mu.Unlock()
		return before, fmt.Errorf("%w: unknown response status", ErrUnreachable)
	}
	manager.state.LastWallTime = maxTime(now, parseOptionalTime(manager.state.LastWallTime)).Format(time.RFC3339)
	manager.evaluateLocked(now)
	if response.Message != "" {
		manager.snapshot.Message = response.Message
	}
	if err := saveState(manager.cfg.Dir, manager.state); err != nil {
		manager.state = previousState
		manager.offline = previousOffline
		manager.rollback = previousRollback
		manager.snapshot = before
		manager.mu.Unlock()
		return before, err
	}
	after := manager.snapshot
	callbacks := manager.callbacksIfChangedLocked(before, after)
	manager.mu.Unlock()
	invokeCallbacks(callbacks, after)
	if response.Status == "denied" {
		message := response.Message
		if message == "" {
			message = after.Message
		}
		return after, &GateError{State: after.State, Code: response.Code, Message: message}
	}
	return after, nil
}

func (manager *Manager) SetPolicy(policy Policy) {
	if policy.Enabled && policy.TrialDays <= 0 {
		policy.TrialDays = defaultTrialDays
	}
	manager.mu.Lock()
	before := manager.snapshot
	manager.cfg.Policy = policy
	manager.evaluateLocked(manager.cfg.Now().UTC())
	after := manager.snapshot
	callbacks := manager.callbacksIfChangedLocked(before, after)
	manager.mu.Unlock()
	invokeCallbacks(callbacks, after)
}

// OnChange adds a listener to the package's callback list. As with the rest of
// the repository's listener style, callbacks remain registered for Manager's
// lifetime and there is intentionally no unsubscribe handle.
func (manager *Manager) OnChange(callback func(Snapshot)) {
	if callback == nil {
		return
	}
	manager.mu.Lock()
	manager.callbacks = append(manager.callbacks, callback)
	manager.mu.Unlock()
}

func (manager *Manager) evaluateAndNotify() {
	manager.mu.Lock()
	before := manager.snapshot
	now := manager.cfg.Now().UTC()
	manager.evaluateLocked(now)
	if shouldPersistWall(now, parseOptionalTime(manager.state.LastWallTime)) {
		manager.state.LastWallTime = now.Format(time.RFC3339)
		_ = saveState(manager.cfg.Dir, manager.state)
	}
	after := manager.snapshot
	callbacks := manager.callbacksIfChangedLocked(before, after)
	manager.mu.Unlock()
	invokeCallbacks(callbacks, after)
}

func (manager *Manager) evaluateLocked(localNow time.Time) {
	lastServer := parseOptionalTime(manager.state.LastServerTime)
	lastWall := parseOptionalTime(manager.state.LastWallTime)
	now, rollback := estimatedNow(localNow, lastServer, lastWall)
	manager.rollback = rollback
	snapshot := Snapshot{Contact: manager.cfg.Policy.Contact, KeyHint: manager.state.KeyHint}
	if manager.state.LastValidatedAt != "" {
		value := parseOptionalTime(manager.state.LastValidatedAt)
		if !value.IsZero() {
			snapshot.LastValidatedAt = timePointer(value)
		}
	}
	if manager.state.LastResult.Status == "denied" {
		if manager.state.LastResult.Signature == "" && manager.state.LastResult.Code == "invalid_token" {
			snapshot.State, snapshot.Code = StateDenied, "invalid_token"
			snapshot.Message = manager.cfg.Policy.Message
			manager.snapshot = snapshot
			return
		}
		if verifyDenied(manager.state.LastResult, manager.cfg.Keys, unionDenialCodes()) == nil {
			snapshot.State, snapshot.Code = StateDenied, manager.state.LastResult.Code
			snapshot.Message = manager.cfg.Policy.Message
			manager.snapshot = snapshot
			return
		}
	}
	if manager.state.Token != "" {
		token, err := verifyToken(manager.state.Token, manager.state.InstallationID, manager.cfg.Product, manager.cfg.Keys)
		if err != nil {
			snapshot.State, snapshot.Code = StateDenied, "invalid_token"
			snapshot.Message = manager.cfg.Policy.Message
			manager.snapshot = snapshot
			return
		}
		snapshot.Activated = true
		snapshot.ExpiresAt = timePointer(token.ExpiresAt)
		snapshot.RevalidateAfter = timePointer(token.RevalidateAfter)
		graceEnd := minTime(token.ExpiresAt, lastServer.Add(manager.cfg.Grace))
		snapshot.GraceExpiresAt = timePointer(graceEnd)
		snapshot.DaysLeft = daysRemaining(now, token.ExpiresAt)
		if !now.Before(token.ExpiresAt) || (manager.offline && !now.Before(graceEnd)) {
			snapshot.State, snapshot.Code, snapshot.Message = StateExpired, "expired", manager.cfg.Policy.Message
			manager.snapshot = snapshot
			return
		}
		if now.Before(token.RevalidateAfter) && !rollback {
			snapshot.State, snapshot.CanConnect = StateActivated, true
			manager.snapshot = snapshot
			return
		}
		if manager.offline && now.Before(graceEnd) {
			snapshot.State, snapshot.CanConnect, snapshot.Offline = StateGrace, true, true
			manager.snapshot = snapshot
			return
		}
		if now.Before(token.ExpiresAt) {
			snapshot.State, snapshot.CanConnect = StateActivated, true
			manager.snapshot = snapshot
			return
		}
	}
	firstRun := parseOptionalTime(manager.state.FirstRunAt)
	trialEnd := firstRun.Add(time.Duration(manager.cfg.Policy.TrialDays) * 24 * time.Hour)
	snapshot.TrialExpiresAt = timePointer(trialEnd)
	snapshot.DaysLeft = daysRemaining(now, trialEnd)
	if !manager.cfg.Policy.Enabled || now.Before(trialEnd) {
		snapshot.State, snapshot.CanConnect = StateTrial, true
	} else {
		snapshot.State, snapshot.Code, snapshot.Message = StateExpired, "trial_expired", manager.cfg.Policy.Message
	}
	manager.snapshot = snapshot
}

func (manager *Manager) revalidationDueLocked(now time.Time) bool {
	if manager.state.Token == "" || manager.rollback {
		return manager.rollback && manager.state.Token != ""
	}
	token, err := verifyToken(manager.state.Token, manager.state.InstallationID, manager.cfg.Product, manager.cfg.Keys)
	if err != nil {
		return false
	}
	delay := token.RevalidateAfter.Sub(token.IssuedAt)
	if delay < time.Hour {
		delay = time.Hour
	}
	if delay > 7*24*time.Hour {
		delay = 7 * 24 * time.Hour
	}
	dueAt := token.IssuedAt.Add(delay)
	return !now.Before(dueAt)
}

func (manager *Manager) callbacksIfChangedLocked(before, after Snapshot) []func(Snapshot) {
	if snapshotsEqual(before, after) {
		return nil
	}
	return append([]func(Snapshot){}, manager.callbacks...)
}

func snapshotsEqual(left, right Snapshot) bool {
	return left.State == right.State && left.CanConnect == right.CanConnect && left.Activated == right.Activated &&
		left.Offline == right.Offline && timesEqual(left.ExpiresAt, right.ExpiresAt) &&
		timesEqual(left.RevalidateAfter, right.RevalidateAfter) && timesEqual(left.GraceExpiresAt, right.GraceExpiresAt) &&
		timesEqual(left.TrialExpiresAt, right.TrialExpiresAt) && left.DaysLeft == right.DaysLeft &&
		left.Code == right.Code && left.Message == right.Message && left.Contact == right.Contact &&
		left.KeyHint == right.KeyHint && timesEqual(left.LastValidatedAt, right.LastValidatedAt)
}

func copySnapshot(snapshot Snapshot) Snapshot {
	snapshot.ExpiresAt = copyTimePointer(snapshot.ExpiresAt)
	snapshot.RevalidateAfter = copyTimePointer(snapshot.RevalidateAfter)
	snapshot.GraceExpiresAt = copyTimePointer(snapshot.GraceExpiresAt)
	snapshot.TrialExpiresAt = copyTimePointer(snapshot.TrialExpiresAt)
	snapshot.LastValidatedAt = copyTimePointer(snapshot.LastValidatedAt)
	return snapshot
}

func invokeCallbacks(callbacks []func(Snapshot), snapshot Snapshot) {
	for _, callback := range callbacks {
		callback(copySnapshot(snapshot))
	}
}

func parseOptionalTime(value string) time.Time {
	parsed, _ := parseWireTime(value)
	return parsed
}

func timePointer(value time.Time) *time.Time { value = value.UTC(); return &value }
func copyTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	return timePointer(*value)
}
func timesEqual(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}
func maxTime(left, right time.Time) time.Time {
	if right.After(left) {
		return right
	}
	return left
}
func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

// denialAppliesToInstallation reports whether a verified denial is an
// authoritative verdict about a license this installation previously
// activated. Typos (invalid_key) and verdicts about keys this install never
// held must not clobber local entitlement state: a single mistyped key would
// otherwise disconnect an otherwise valid session until reactivation.
func denialAppliesToInstallation(result persistedResult, previous persistedState, cfg Config) bool {
	if result.Code == "invalid_key" || result.LicenseID == "" {
		return false
	}
	if previous.LastResult.Status == "active" && previous.LastResult.LicenseID == result.LicenseID {
		return true
	}
	if previous.Token == "" {
		return false
	}
	verified, err := verifyToken(previous.Token, previous.InstallationID, cfg.Product, cfg.Keys)
	return err == nil && verified.LicenseID == result.LicenseID
}

func unionDenialCodes() map[string]bool {
	result := make(map[string]bool, len(activationDenialCodes)+len(revalidationDenialCodes))
	for code := range activationDenialCodes {
		result[code] = true
	}
	for code := range revalidationDenialCodes {
		result[code] = true
	}
	return result
}

package license

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
)

type serverResponse struct {
	Status          string `json:"status"`
	Code            string `json:"code"`
	LicenseID       string `json:"license_id"`
	Token           string `json:"token"`
	ServerTime      string `json:"server_time"`
	ExpiresAt       string `json:"expires_at"`
	RevalidateAfter string `json:"revalidate_after"`
	Message         string `json:"message"`
	Signature       string `json:"sig"`
}

type apiClient struct {
	baseURL  string
	product  string
	http     *http.Client
	version  func() string
	platform string
}

func (client *apiClient) activate(ctx context.Context, key, installationID string) (serverResponse, error) {
	body := struct {
		Key            string `json:"key"`
		InstallationID string `json:"installation_id"`
		Product        string `json:"product"`
		ClientVersion  string `json:"client_version"`
		Platform       string `json:"platform"`
	}{key, installationID, client.product, client.version(), client.platform}
	return client.post(ctx, "/v1/licenses/activate", body)
}

func (client *apiClient) revalidate(ctx context.Context, token, installationID string) (serverResponse, error) {
	body := struct {
		Token          string `json:"token"`
		InstallationID string `json:"installation_id"`
		Product        string `json:"product"`
		ClientVersion  string `json:"client_version"`
	}{token, installationID, client.product, client.version()}
	return client.post(ctx, "/v1/licenses/revalidate", body)
}

func (client *apiClient) post(ctx context.Context, path string, body any) (serverResponse, error) {
	contents, err := json.Marshal(body)
	if err != nil {
		return serverResponse{}, fmt.Errorf("%w: encode request: %v", ErrUnreachable, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(client.baseURL, "/")+path, bytes.NewReader(contents))
	if err != nil {
		return serverResponse{}, fmt.Errorf("%w: create request: %v", ErrUnreachable, err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.http.Do(request)
	if err != nil {
		return serverResponse{}, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		return serverResponse{}, fmt.Errorf("%w: HTTP status %d", ErrUnreachable, response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	decoder.DisallowUnknownFields()
	var result serverResponse
	if err := decoder.Decode(&result); err != nil {
		return serverResponse{}, fmt.Errorf("%w: decode response: %v", ErrUnreachable, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return serverResponse{}, fmt.Errorf("%w: response contains trailing data", ErrUnreachable)
	}
	return result, nil
}

func defaultPlatform() string { return runtime.GOOS + "-" + runtime.GOARCH }

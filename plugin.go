package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	sdk "github.com/getcreddy/creddy-plugin-sdk"
)

const (
	PluginName       = "dockerhub"
	PluginVersion    = "0.1.0"
	DockerHubAPIBase = "https://hub.docker.com/v2"
)

// DockerHubPlugin implements the Creddy Plugin interface for Docker Hub
type DockerHubPlugin struct {
	config *DockerHubConfig
	token  string // JWT token for API calls
}

// DockerHubConfig contains the plugin configuration
type DockerHubConfig struct {
	// Username is the Docker Hub username
	Username string `json:"username"`
	// Password is the Docker Hub password or personal access token with admin scope
	Password string `json:"password"`
}

func (p *DockerHubPlugin) Info(ctx context.Context) (*sdk.PluginInfo, error) {
	return &sdk.PluginInfo{
		Name:             PluginName,
		Version:          PluginVersion,
		Description:      "Docker Hub access tokens with repository scoping",
		MinCreddyVersion: "0.4.0",
	}, nil
}

func (p *DockerHubPlugin) Scopes(ctx context.Context) ([]sdk.ScopeSpec, error) {
	return []sdk.ScopeSpec{
		{
			Pattern:     "dockerhub:*",
			Description: "Full Docker Hub access",
			Examples:    []string{"dockerhub:*"},
		},
		{
			Pattern:     "dockerhub:<namespace>/*",
			Description: "Access to all repositories in a namespace",
			Examples:    []string{"dockerhub:myorg/*"},
		},
		{
			Pattern:     "dockerhub:<namespace>/<repo>",
			Description: "Access to a specific repository",
			Examples:    []string{"dockerhub:myorg/myimage", "dockerhub:myorg/myimage:read"},
		},
	}, nil
}

func (p *DockerHubPlugin) Configure(ctx context.Context, configJSON string) error {
	var config DockerHubConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return fmt.Errorf("invalid config JSON: %w", err)
	}

	if config.Username == "" {
		return fmt.Errorf("username is required")
	}
	if config.Password == "" {
		return fmt.Errorf("password is required")
	}

	p.config = &config
	return nil
}

func (p *DockerHubPlugin) Validate(ctx context.Context) error {
	if p.config == nil {
		return fmt.Errorf("plugin not configured")
	}

	// Authenticate to get a JWT token
	token, err := p.authenticate(ctx)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	p.token = token

	return nil
}

func (p *DockerHubPlugin) GetCredential(ctx context.Context, req *sdk.CredentialRequest) (*sdk.Credential, error) {
	if p.config == nil {
		return nil, fmt.Errorf("plugin not configured")
	}

	// Ensure we have a valid token
	if p.token == "" {
		token, err := p.authenticate(ctx)
		if err != nil {
			return nil, fmt.Errorf("authentication failed: %w", err)
		}
		p.token = token
	}

	// Parse scope for repository access
	scopes := p.parseScopeToDockerScopes(req.Scope)

	// Create a personal access token
	tokenName := fmt.Sprintf("creddy-%s-%d", req.Agent.Name, time.Now().Unix())
	
	accessToken, tokenUUID, err := p.createAccessToken(ctx, tokenName, scopes)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(req.TTL)

	return &sdk.Credential{
		Value:      accessToken,
		ExpiresAt:  expiresAt,
		ExternalID: tokenUUID,
		Metadata: map[string]string{
			"token_name": tokenName,
			"username":   p.config.Username,
		},
	}, nil
}

func (p *DockerHubPlugin) RevokeCredential(ctx context.Context, externalID string) error {
	if p.config == nil {
		return fmt.Errorf("plugin not configured")
	}

	// Ensure we have a valid token
	if p.token == "" {
		token, err := p.authenticate(context.Background())
		if err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
		p.token = token
	}

	return p.deleteAccessToken(ctx, externalID)
}

func (p *DockerHubPlugin) MatchScope(ctx context.Context, scope string) (bool, error) {
	return strings.HasPrefix(scope, "dockerhub:"), nil
}

// authenticate logs in and returns a JWT token
func (p *DockerHubPlugin) authenticate(ctx context.Context) (string, error) {
	reqBody := map[string]string{
		"username": p.config.Username,
		"password": p.config.Password,
	}
	bodyJSON, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, "POST", DockerHubAPIBase+"/users/login", bytes.NewReader(bodyJSON))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("login failed (%d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}

	return result.Token, nil
}

// createAccessToken creates a new personal access token
func (p *DockerHubPlugin) createAccessToken(ctx context.Context, name string, scopes []dockerScope) (string, string, error) {
	url := fmt.Sprintf("%s/access-tokens", DockerHubAPIBase)

	reqBody := map[string]interface{}{
		"token_label": name,
		"scopes":      scopes,
	}
	bodyJSON, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyJSON))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", "", fmt.Errorf("failed to create token (%d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		UUID  string `json:"uuid"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", "", err
	}

	return result.Token, result.UUID, nil
}

// deleteAccessToken deletes an access token by UUID
func (p *DockerHubPlugin) deleteAccessToken(ctx context.Context, uuid string) error {
	url := fmt.Sprintf("%s/access-tokens/%s", DockerHubAPIBase, uuid)

	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete token (%d): %s", resp.StatusCode, string(body))
	}

	return nil
}

type dockerScope struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

// parseScopeToDockerScopes converts a creddy scope to Docker Hub token scopes
func (p *DockerHubPlugin) parseScopeToDockerScopes(scope string) []dockerScope {
	if !strings.HasPrefix(scope, "dockerhub:") {
		return nil
	}

	rest := strings.TrimPrefix(scope, "dockerhub:")
	
	// Default to read-write
	actions := []string{"pull", "push"}
	
	// Check for :read suffix
	if strings.HasSuffix(rest, ":read") {
		rest = strings.TrimSuffix(rest, ":read")
		actions = []string{"pull"}
	} else if strings.HasSuffix(rest, ":write") {
		rest = strings.TrimSuffix(rest, ":write")
	}

	// Wildcard = all access
	if rest == "*" {
		return []dockerScope{
			{Type: "repository", Name: "*", Actions: actions},
		}
	}

	// Namespace wildcard
	if strings.HasSuffix(rest, "/*") {
		namespace := strings.TrimSuffix(rest, "/*")
		return []dockerScope{
			{Type: "repository", Name: namespace + "/*", Actions: actions},
		}
	}

	// Specific repository
	return []dockerScope{
		{Type: "repository", Name: rest, Actions: actions},
	}
}

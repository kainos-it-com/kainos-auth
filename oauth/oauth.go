package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kainos.it.com/kainos-auth/core"
	"github.com/kainos.it.com/kainos-auth/store"
)

// Provider represents an OAuth provider configuration
type Provider struct {
	ID           string
	Name         string
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	Scopes       []string
	RedirectURL  string
	MapProfile   func(map[string]interface{}) *core.OAuthProfile
}

// TokenResponse represents the OAuth token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token"`
}

// Manager handles OAuth operations
type Manager struct {
	providers map[string]*Provider
	store     store.Store
}

// New creates a new OAuth manager
func New(s store.Store) *Manager {
	return &Manager{
		providers: make(map[string]*Provider),
		store:     s,
	}
}

// RegisterProvider registers an OAuth provider
func (m *Manager) RegisterProvider(provider *Provider) {
	m.providers[provider.ID] = provider
}

// GetProvider returns a provider by ID
func (m *Manager) GetProvider(id string) (*Provider, error) {
	p, ok := m.providers[id]
	if !ok {
		return nil, core.ErrProviderNotFound
	}
	return p, nil
}

// GetAuthURL generates the OAuth authorization URL
func (m *Manager) GetAuthURL(providerID string) (string, string, error) {
	provider, err := m.GetProvider(providerID)
	if err != nil {
		return "", "", err
	}

	state, err := generateState()
	if err != nil {
		return "", "", err
	}

	params := url.Values{}
	params.Set("client_id", provider.ClientID)
	params.Set("redirect_uri", provider.RedirectURL)
	params.Set("response_type", "code")
	params.Set("scope", strings.Join(provider.Scopes, " "))
	params.Set("state", state)

	authURL := provider.AuthURL + "?" + params.Encode()
	return authURL, state, nil
}

// ExchangeCode exchanges an authorization code for tokens
func (m *Manager) ExchangeCode(ctx context.Context, providerID, code string) (*TokenResponse, error) {
	provider, err := m.GetProvider(providerID)
	if err != nil {
		return nil, err
	}

	data := url.Values{}
	data.Set("client_id", provider.ClientID)
	data.Set("client_secret", provider.ClientSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", provider.RedirectURL)

	req, err := http.NewRequestWithContext(ctx, "POST", provider.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// GetUserInfo fetches user profile from the OAuth provider
func (m *Manager) GetUserInfo(ctx context.Context, providerID, accessToken string) (*core.OAuthProfile, error) {
	provider, err := m.GetProvider(providerID)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", provider.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	if provider.MapProfile != nil {
		return provider.MapProfile(raw), nil
	}

	return defaultMapProfile(raw), nil
}

func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func defaultMapProfile(raw map[string]interface{}) *core.OAuthProfile {
	profile := &core.OAuthProfile{Raw: raw}

	if id, ok := raw["id"].(string); ok {
		profile.ID = id
	} else if id, ok := raw["sub"].(string); ok {
		profile.ID = id
	}

	if email, ok := raw["email"].(string); ok {
		profile.Email = email
	}

	if name, ok := raw["name"].(string); ok {
		profile.Name = name
	}

	if picture, ok := raw["picture"].(string); ok {
		profile.Image = &picture
	} else if avatar, ok := raw["avatar_url"].(string); ok {
		profile.Image = &avatar
	}

	if verified, ok := raw["email_verified"].(bool); ok {
		profile.EmailVerified = verified
	}

	return profile
}

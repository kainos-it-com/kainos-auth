package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/kainos.it.com/kainos-auth/core"
)

// Manager handles token operations
type Manager struct {
	secret []byte
}

// New creates a new token manager
func New(secret string) *Manager {
	return &Manager{
		secret: []byte(secret),
	}
}

// Claims represents token claims
type Claims struct {
	UserID    string    `json:"sub"`
	SessionID string    `json:"sid"`
	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`
	Type      string    `json:"type"`
}

// Pair represents an access/refresh token pair
type Pair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// CreateAccessToken creates a signed access token
func (m *Manager) CreateAccessToken(userID, sessionID string, duration time.Duration) (string, error) {
	claims := Claims{
		UserID:    userID,
		SessionID: sessionID,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(duration),
		Type:      "access",
	}
	return m.sign(claims)
}

// CreateRefreshToken creates a signed refresh token
func (m *Manager) CreateRefreshToken(userID, sessionID string, duration time.Duration) (string, error) {
	claims := Claims{
		UserID:    userID,
		SessionID: sessionID,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(duration),
		Type:      "refresh",
	}
	return m.sign(claims)
}

// Validate validates and parses a token
func (m *Manager) Validate(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, core.ErrInvalidToken
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, core.ErrInvalidToken
	}

	signature, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, core.ErrInvalidToken
	}

	expectedSig := m.computeSignature(payload)
	if !hmac.Equal(signature, expectedSig) {
		return nil, core.ErrInvalidToken
	}

	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, core.ErrInvalidToken
	}

	if time.Now().After(claims.ExpiresAt) {
		return nil, core.ErrTokenExpired
	}

	return &claims, nil
}

func (m *Manager) sign(claims Claims) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	signature := m.computeSignature(payload)

	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	encodedSignature := hex.EncodeToString(signature)

	return encodedPayload + "." + encodedSignature, nil
}

func (m *Manager) computeSignature(payload []byte) []byte {
	h := hmac.New(sha256.New, m.secret)
	h.Write(payload)
	return h.Sum(nil)
}

// GenerateRandom generates a cryptographically secure random token
func GenerateRandom(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GenerateOpaque generates a hex-encoded random token
func GenerateOpaque(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// CreatePair creates both access and refresh tokens
func (m *Manager) CreatePair(userID, sessionID string, accessDuration, refreshDuration time.Duration) (*Pair, error) {
	accessToken, err := m.CreateAccessToken(userID, sessionID, accessDuration)
	if err != nil {
		return nil, err
	}

	refreshToken, err := m.CreateRefreshToken(userID, sessionID, refreshDuration)
	if err != nil {
		return nil, err
	}

	return &Pair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(accessDuration.Seconds()),
		ExpiresAt:    time.Now().Add(accessDuration),
	}, nil
}

// RefreshPair validates a refresh token and creates a new token pair
func (m *Manager) RefreshPair(refreshToken string, accessDuration, refreshDuration time.Duration) (*Pair, error) {
	claims, err := m.Validate(refreshToken)
	if err != nil {
		return nil, err
	}

	if claims.Type != "refresh" {
		return nil, errors.New("invalid token type")
	}

	return m.CreatePair(claims.UserID, claims.SessionID, accessDuration, refreshDuration)
}

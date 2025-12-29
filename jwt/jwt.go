package jwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/kainos.it.com/kainos-auth/core"
)

// Manager handles JWT operations
type Manager struct {
	secretKey     []byte
	issuer        string
	accessExpiry  time.Duration
	refreshExpiry time.Duration
}

// Config holds JWT configuration
type Config struct {
	SecretKey     string
	Issuer        string
	AccessExpiry  time.Duration
	RefreshExpiry time.Duration
}

// DefaultConfig returns sensible JWT defaults
func DefaultConfig(secret string) *Config {
	return &Config{
		SecretKey:     secret,
		Issuer:        "kainos-auth",
		AccessExpiry:  15 * time.Minute,
		RefreshExpiry: 7 * 24 * time.Hour,
	}
}

// New creates a new JWT manager
func New(cfg *Config) *Manager {
	return &Manager{
		secretKey:     []byte(cfg.SecretKey),
		issuer:        cfg.Issuer,
		accessExpiry:  cfg.AccessExpiry,
		refreshExpiry: cfg.RefreshExpiry,
	}
}

// Claims represents JWT claims
type Claims struct {
	UserID    string `json:"uid"`
	SessionID string `json:"sid"`
	Email     string `json:"email,omitempty"`
	Name      string `json:"name,omitempty"`
	TokenType string `json:"type"`
	jwt.RegisteredClaims
}

// TokenPair represents an access/refresh token pair
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	ExpiresAt    int64  `json:"expires_at"`
}

// CreateAccessToken creates a signed JWT access token
func (m *Manager) CreateAccessToken(userID, sessionID, email, name string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID:    userID,
		SessionID: sessionID,
		Email:     email,
		Name:      name,
		TokenType: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.accessExpiry)),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secretKey)
}

// CreateRefreshToken creates a signed JWT refresh token
func (m *Manager) CreateRefreshToken(userID, sessionID string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID:    userID,
		SessionID: sessionID,
		TokenType: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.refreshExpiry)),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secretKey)
}

// CreateTokenPair creates both access and refresh JWT tokens
func (m *Manager) CreateTokenPair(userID, sessionID, email, name string) (*TokenPair, error) {
	accessToken, err := m.CreateAccessToken(userID, sessionID, email, name)
	if err != nil {
		return nil, err
	}

	refreshToken, err := m.CreateRefreshToken(userID, sessionID)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(m.accessExpiry)

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(m.accessExpiry.Seconds()),
		ExpiresAt:    expiresAt.Unix(),
	}, nil
}

// ValidateToken validates a JWT token and returns the claims
func (m *Manager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return m.secretKey, nil
	})

	if err != nil {
		return nil, core.ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, core.ErrInvalidToken
	}

	return claims, nil
}

// ValidateAccessToken validates an access token
func (m *Manager) ValidateAccessToken(tokenString string) (*Claims, error) {
	claims, err := m.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != "access" {
		return nil, errors.New("invalid token type: expected access token")
	}

	return claims, nil
}

// ValidateRefreshToken validates a refresh token
func (m *Manager) ValidateRefreshToken(tokenString string) (*Claims, error) {
	claims, err := m.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != "refresh" {
		return nil, errors.New("invalid token type: expected refresh token")
	}

	return claims, nil
}

// RefreshTokenPair validates a refresh token and creates a new token pair
func (m *Manager) RefreshTokenPair(refreshToken, email, name string) (*TokenPair, error) {
	claims, err := m.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	return m.CreateTokenPair(claims.UserID, claims.SessionID, email, name)
}

// GetExpiryTime returns the expiry time from a token without full validation
func (m *Manager) GetExpiryTime(tokenString string) (*time.Time, error) {
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, &Claims{})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, errors.New("invalid claims")
	}

	if claims.ExpiresAt == nil {
		return nil, errors.New("no expiry time")
	}

	t := claims.ExpiresAt.Time
	return &t, nil
}

// IsExpired checks if a token is expired without full validation
func (m *Manager) IsExpired(tokenString string) bool {
	expiry, err := m.GetExpiryTime(tokenString)
	if err != nil {
		return true
	}
	return time.Now().After(*expiry)
}

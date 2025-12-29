package kainos_auth_lib

import (
	"github.com/kainos-it-com/kainos-auth/admin"
	"github.com/kainos-it-com/kainos-auth/core"
	"github.com/kainos-it-com/kainos-auth/db/sqlc"
	"github.com/kainos-it-com/kainos-auth/jwt"
	"github.com/kainos-it-com/kainos-auth/magiclink"
	"github.com/kainos-it-com/kainos-auth/oauth"
	"github.com/kainos-it-com/kainos-auth/organization"
	"github.com/kainos-it-com/kainos-auth/passkey"
	"github.com/kainos-it-com/kainos-auth/ratelimit"
	"github.com/kainos-it-com/kainos-auth/store"
	"github.com/kainos-it-com/kainos-auth/token"
	"github.com/kainos-it-com/kainos-auth/twofa"
)

// Re-export types for convenience
type (
	// Config Core types
	Config         = core.Config
	SessionConfig  = core.SessionConfig
	PasswordConfig = core.PasswordConfig

	// SignUpInput Input types
	SignUpInput         = core.SignUpInput
	SignInInput         = core.SignInInput
	AuthResponse        = core.AuthResponse
	OAuthCallbackInput  = core.OAuthCallbackInput
	OAuthProfile        = core.OAuthProfile
	ChangePasswordInput = core.ChangePasswordInput
	ResetPasswordInput  = core.ResetPasswordInput
	ChangeEmailInput    = core.ChangeEmailInput
	UpdateUserInput     = core.UpdateUserInput
	DeleteUserInput     = core.DeleteUserInput

	// Store types
	CreateUserInput  = store.CreateUserInput
	UserWithAccounts = store.UserWithAccounts
	UserWithSessions = store.UserWithSessions
	PaginatedUsers   = store.PaginatedUsers
	UserStats        = store.UserStats

	// OAuthProvider OAuth types
	OAuthProvider      = oauth.Provider
	OAuthTokenResponse = oauth.TokenResponse

	// JWTConfig JWT types
	JWTConfig    = jwt.Config
	JWTClaims    = jwt.Claims
	JWTTokenPair = jwt.TokenPair

	// TokenClaims Token types
	TokenClaims = token.Claims
	TokenPair   = token.Pair

	// TwoFactor types
	TwoFactorConfig = twofa.Config

	// MagicLink types
	MagicLinkConfig = magiclink.Config

	// Admin types
	AdminConfig = admin.Config

	// Organization types
	OrganizationConfig = organization.Config
	Organization       = organization.Organization
	OrgMember          = organization.Member
	OrgInvitation      = organization.Invitation
	OrgTeam            = organization.Team

	// RateLimit types
	RateLimitConfig = ratelimit.Config
	RateLimitResult = ratelimit.Result

	// Passkey types
	PasskeyConfig = passkey.Config
	Passkey       = passkey.Passkey
)

// AuthResponseWithTokens extends AuthResponse with JWT tokens
type AuthResponseWithTokens struct {
	User         *sqlc.User    `json:"user"`
	Session      *sqlc.Session `json:"session"`
	AccessToken  string        `json:"accessToken"`
	RefreshToken string        `json:"refreshToken"`
	TokenType    string        `json:"tokenType"`
	ExpiresIn    int64         `json:"expiresIn"`
}

// RefreshTokenInput contains the refresh token
type RefreshTokenInput struct {
	RefreshToken string `json:"refreshToken"`
}

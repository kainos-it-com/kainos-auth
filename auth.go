// Package kainos_auth_lib provides a modular authentication library for Go.
// It follows a plugin-like architecture similar to Better Auth.
//
// Usage:
//
//	auth := kainos_auth_lib.New(myStore,
//		kainos_auth_lib.WithSecret("your-secret"),
//		kainos_auth_lib.WithEmailVerification(true),
//	)
//
//	// Use individual modules
//	auth.Session.Create(ctx, userID, nil, nil)
//	auth.Password.Change(ctx, input)
//	auth.Email.RequestVerification(ctx, email)
//	auth.OAuth.GetAuthURL("google")
//
//	// Enable plugins
//	auth.WithTwoFactor(twofa.DefaultConfig("MyApp"))
//	auth.WithMagicLink(magiclink.DefaultConfig())
//	auth.WithAdmin(admin.DefaultConfig())
//	auth.WithOrganization(organization.DefaultConfig())
//	auth.WithRateLimiter(ratelimit.DefaultConfig())
//	auth.WithPasskey(passkey.DefaultConfig("example.com", "My App", "https://example.com"))
package kainos_auth_lib

import (
	"context"

	"github.com/kainos-it-com/kainos-auth/admin"
	"github.com/kainos-it-com/kainos-auth/core"
	"github.com/kainos-it-com/kainos-auth/email"
	"github.com/kainos-it-com/kainos-auth/jwt"
	"github.com/kainos-it-com/kainos-auth/magiclink"
	"github.com/kainos-it-com/kainos-auth/oauth"
	"github.com/kainos-it-com/kainos-auth/organization"
	"github.com/kainos-it-com/kainos-auth/passkey"
	"github.com/kainos-it-com/kainos-auth/password"
	"github.com/kainos-it-com/kainos-auth/ratelimit"
	"github.com/kainos-it-com/kainos-auth/session"
	"github.com/kainos-it-com/kainos-auth/store"
	"github.com/kainos-it-com/kainos-auth/token"
	"github.com/kainos-it-com/kainos-auth/twofa"
	"github.com/kainos-it-com/kainos-auth/user"
)

// Auth is the main authentication instance with modular components
type Auth struct {
	// Core configuration
	Config *core.Config

	// Core Modules
	Session  *session.Manager
	Password *password.Manager
	Email    *email.Manager
	User     *user.Manager
	OAuth    *oauth.Manager
	JWT      *jwt.Manager
	Token    *token.Manager

	// Plugin Modules (optional, enable with With* methods)
	TwoFactor    *twofa.Manager
	MagicLink    *magiclink.Manager
	Admin        *admin.Manager
	Organization *organization.Manager
	RateLimiter  *ratelimit.Limiter
	Passkey      *passkey.Manager

	// Internal store reference
	Store store.Store
}

// Option is a functional option for configuring Auth
type Option = core.Option

// Re-export option functions for convenience
var (
	WithSessionExpiry     = core.WithSessionExpiry
	WithEmailVerification = core.WithEmailVerification
	WithSecret            = core.WithSecret
	WithPasswordPolicy    = core.WithPasswordPolicy
)

// New creates a new Auth instance with the given store and options
func New(s store.Store, opts ...Option) *Auth {
	cfg := core.DefaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	auth := &Auth{
		Config: cfg,
		Store:  s,
	}

	// Initialize modules
	auth.Session = session.New(s, &cfg.Session)
	auth.Password = password.New(s, &cfg.Password)
	auth.Email = email.New(s)
	auth.User = user.New(s)
	auth.OAuth = oauth.New(s)

	// Initialize token managers if secret is set
	if cfg.Secret != "" {
		auth.JWT = jwt.New(jwt.DefaultConfig(cfg.Secret))
		auth.Token = token.New(cfg.Secret)
	}

	return auth
}

// WithJWT configures a custom JWT manager
func (a *Auth) WithJWT(cfg *jwt.Config) *Auth {
	a.JWT = jwt.New(cfg)
	return a
}

// WithOAuthProvider registers an OAuth provider
func (a *Auth) WithOAuthProvider(provider *oauth.Provider) *Auth {
	a.OAuth.RegisterProvider(provider)
	return a
}

// WithTwoFactor enables two-factor authentication
func (a *Auth) WithTwoFactor(cfg *twofa.Config) *Auth {
	a.TwoFactor = twofa.New(a.Store, cfg)
	return a
}

// WithMagicLink enables magic link authentication
func (a *Auth) WithMagicLink(cfg *magiclink.Config) *Auth {
	a.MagicLink = magiclink.New(a.Store, cfg)
	return a
}

// WithAdmin enables admin functionality
func (a *Auth) WithAdmin(cfg *admin.Config) *Auth {
	a.Admin = admin.New(a.Store, cfg)
	return a
}

// WithOrganization enables organization/multi-tenancy
func (a *Auth) WithOrganization(cfg *organization.Config) *Auth {
	a.Organization = organization.New(a.Store, cfg)
	return a
}

// WithRateLimiter enables rate limiting
func (a *Auth) WithRateLimiter(cfg *ratelimit.Config) *Auth {
	a.RateLimiter = ratelimit.New(cfg)
	return a
}

// WithPasskey enables passkey/WebAuthn authentication
func (a *Auth) WithPasskey(cfg *passkey.Config) *Auth {
	a.Passkey = passkey.New(a.Store, cfg)
	return a
}

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
	CreateUserInput   = store.CreateUserInput
	UserWithAccounts  = store.UserWithAccounts
	UserWithSessions  = store.UserWithSessions
	PaginatedUsers    = store.PaginatedUsers
	UserStats         = store.UserStats

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

// Re-export errors for convenience
var (
	ErrInvalidCredentials      = core.ErrInvalidCredentials
	ErrEmailAlreadyExists      = core.ErrEmailAlreadyExists
	ErrUserNotFound            = core.ErrUserNotFound
	ErrSessionExpired          = core.ErrSessionExpired
	ErrSessionNotFound         = core.ErrSessionNotFound
	ErrInvalidToken            = core.ErrInvalidToken
	ErrTokenExpired            = core.ErrTokenExpired
	ErrPasswordTooShort        = core.ErrPasswordTooShort
	ErrPasswordNoUpper         = core.ErrPasswordNoUpper
	ErrPasswordNoLower         = core.ErrPasswordNoLower
	ErrPasswordNoNumber        = core.ErrPasswordNoNumber
	ErrPasswordNoSpecial       = core.ErrPasswordNoSpecial
	ErrPasswordMismatch        = core.ErrPasswordMismatch
	ErrPasswordNotSet          = core.ErrPasswordNotSet
	ErrOAuthStateMismatch      = core.ErrOAuthStateMismatch
	ErrOAuthCodeInvalid        = core.ErrOAuthCodeInvalid
	ErrProviderNotFound        = core.ErrProviderNotFound
	ErrAccountNotFound         = core.ErrAccountNotFound
	ErrCannotUnlinkLastAccount = core.ErrCannotUnlinkLastAccount
	ErrAccountAlreadyLinked    = core.ErrAccountAlreadyLinked
	ErrVerificationNotFound    = core.ErrVerificationNotFound
	ErrVerificationExpired     = core.ErrVerificationExpired
	ErrEmailNotVerified        = core.ErrEmailNotVerified
	ErrSessionNotFresh         = core.ErrSessionNotFresh
)

// Re-export OAuth provider constructors
var (
	GoogleProvider    = oauth.Google
	GitHubProvider    = oauth.GitHub
	DiscordProvider   = oauth.Discord
	MicrosoftProvider = oauth.Microsoft
	AppleProvider     = oauth.Apple
)

// Re-export utility functions
var (
	HashPassword        = password.Hash
	CheckPassword       = password.Check
	GenerateRandomToken = token.GenerateRandom
	GenerateOpaqueToken = token.GenerateOpaque
)

// SignUp creates a new user with email and password
func (a *Auth) SignUp(ctx context.Context, input SignUpInput) (*AuthResponse, error) {
	// Validate password
	if err := a.Password.Validate(input.Password); err != nil {
		return nil, err
	}

	// Hash password
	hashedPassword, err := HashPassword(input.Password)
	if err != nil {
		return nil, err
	}

	// Create user with credential
	userWithAccounts, err := a.Store.CreateUserWithCredential(ctx, store.CreateUserInput{
		Name:  input.Name,
		Email: input.Email,
		Image: input.Image,
	}, hashedPassword)
	if err != nil {
		return nil, err
	}

	// Create session
	session, err := a.Session.Create(ctx, userWithAccounts.User.ID, input.IPAddress, input.UserAgent)
	if err != nil {
		return nil, err
	}

	return &AuthResponse{
		User:    &userWithAccounts.User,
		Session: session,
	}, nil
}

// SignIn authenticates a user with email and password
func (a *Auth) SignIn(ctx context.Context, input SignInInput) (*AuthResponse, error) {
	// Get user by email
	user, err := a.User.GetByEmail(ctx, input.Email)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// Get credential account
	account, err := a.Store.GetCredentialAccount(ctx, user.ID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// Check if password is set
	if account.Password == nil {
		return nil, ErrPasswordNotSet
	}

	// Verify password
	if !CheckPassword(input.Password, *account.Password) {
		return nil, ErrInvalidCredentials
	}

	// Create session
	session, err := a.Session.Create(ctx, user.ID, input.IPAddress, input.UserAgent)
	if err != nil {
		return nil, err
	}

	return &AuthResponse{
		User:    user,
		Session: session,
	}, nil
}

// CreateUser creates a new user with email and password (without session)
func (a *Auth) CreateUser(ctx context.Context, input SignUpInput) (*store.UserWithAccounts, error) {
	// Validate password
	if err := a.Password.Validate(input.Password); err != nil {
		return nil, err
	}

	// Hash password
	hashedPassword, err := HashPassword(input.Password)
	if err != nil {
		return nil, err
	}

	// Create user with credential
	return a.Store.CreateUserWithCredential(ctx, store.CreateUserInput{
		Name:  input.Name,
		Email: input.Email,
		Image: input.Image,
	}, hashedPassword)
}

// Re-export plugin default configs
var (
	DefaultTwoFactorConfig    = twofa.DefaultConfig
	DefaultMagicLinkConfig    = magiclink.DefaultConfig
	DefaultAdminConfig        = admin.DefaultConfig
	DefaultOrganizationConfig = organization.DefaultConfig
	DefaultRateLimitConfig    = ratelimit.DefaultConfig
	DefaultPasskeyConfig      = passkey.DefaultConfig
)

// Re-export plugin errors
var (
	// TwoFactor errors
	ErrTwoFactorNotEnabled = twofa.ErrTwoFactorNotEnabled
	ErrTwoFactorRequired   = twofa.ErrTwoFactorRequired
	ErrInvalidTOTPCode     = twofa.ErrInvalidTOTPCode
	ErrInvalidBackupCode   = twofa.ErrInvalidBackupCode

	// MagicLink errors
	ErrMagicLinkInvalid  = magiclink.ErrInvalidToken
	ErrMagicLinkExpired  = magiclink.ErrTokenExpired
	ErrSignUpDisabled    = magiclink.ErrSignUpDisabled

	// Admin errors
	ErrAdminNotAuthorized      = admin.ErrNotAuthorized
	ErrCannotImpersonateAdmin  = admin.ErrCannotImpersonateAdmin

	// Organization errors
	ErrOrgCreationDisabled = organization.ErrOrgCreationDisabled
	ErrOrgLimitReached     = organization.ErrOrgLimitReached
	ErrSlugTaken           = organization.ErrSlugTaken
	ErrOwnerCannotLeave    = organization.ErrOwnerCannotLeave

	// RateLimit errors
	ErrRateLimitExceeded = ratelimit.ErrRateLimitExceeded

	// Passkey errors
	ErrInvalidChallenge = passkey.ErrInvalidChallenge
	ErrPasskeyNotFound  = passkey.ErrPasskeyNotFound
)

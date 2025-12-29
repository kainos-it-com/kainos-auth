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
	"github.com/kainos-it-com/kainos-auth/db/sqlc"
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

// SignUp creates a new user with email and password
func (a *Auth) SignUp(ctx context.Context, input SignUpInput) (*AuthResponseWithTokens, error) {
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

	// Generate JWT tokens if JWT manager is configured
	if a.JWT != nil {
		tokenPair, err := a.JWT.CreateTokenPair(
			userWithAccounts.User.ID,
			session.ID,
			userWithAccounts.User.Email,
			userWithAccounts.User.Name,
		)
		if err != nil {
			return nil, err
		}

		return &AuthResponseWithTokens{
			User:         &userWithAccounts.User,
			Session:      session,
			AccessToken:  tokenPair.AccessToken,
			RefreshToken: tokenPair.RefreshToken,
			TokenType:    tokenPair.TokenType,
			ExpiresIn:    tokenPair.ExpiresIn,
		}, nil
	}

	// Return without tokens if JWT is not configured
	return &AuthResponseWithTokens{
		User:    &userWithAccounts.User,
		Session: session,
	}, nil
}

// SignIn authenticates a user with email and password
func (a *Auth) SignIn(ctx context.Context, input SignInInput) (*AuthResponseWithTokens, error) {
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

	// Generate JWT tokens if JWT manager is configured
	if a.JWT != nil {
		tokenPair, err := a.JWT.CreateTokenPair(
			user.ID,
			session.ID,
			user.Email,
			user.Name,
		)
		if err != nil {
			return nil, err
		}

		return &AuthResponseWithTokens{
			User:         user,
			Session:      session,
			AccessToken:  tokenPair.AccessToken,
			RefreshToken: tokenPair.RefreshToken,
			TokenType:    tokenPair.TokenType,
			ExpiresIn:    tokenPair.ExpiresIn,
		}, nil
	}

	// Return without tokens if JWT is not configured
	return &AuthResponseWithTokens{
		User:    user,
		Session: session,
	}, nil
}

// RefreshToken generates new access and refresh tokens using a valid refresh token
func (a *Auth) RefreshToken(ctx context.Context, input RefreshTokenInput) (*AuthResponseWithTokens, error) {
	// Check if JWT manager is configured
	if a.JWT == nil {
		return nil, ErrJWTNotConfigured
	}

	// Verify and extract claims from refresh token
	claims, err := a.JWT.ValidateRefreshToken(input.RefreshToken)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Get user
	user, err := a.User.Get(ctx, claims.UserID)
	if err != nil {
		return nil, ErrUserNotFound
	}

	// Get active sessions for the user to verify session still exists
	sessions, err := a.Session.List(ctx, claims.UserID)
	if err != nil {
		return nil, err
	}

	// Find the session
	var session *sqlc.Session
	for _, s := range sessions {
		if s.ID == claims.SessionID {
			session = &s
			break
		}
	}

	if session == nil {
		return nil, ErrSessionNotFound
	}

	// Generate new token pair using RefreshTokenPair
	tokenPair, err := a.JWT.RefreshTokenPair(input.RefreshToken, user.Email, user.Name)
	if err != nil {
		return nil, err
	}

	return &AuthResponseWithTokens{
		User:         user,
		Session:      session,
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		TokenType:    tokenPair.TokenType,
		ExpiresIn:    tokenPair.ExpiresIn,
	}, nil
}

// Logout invalidates a user's session
func (a *Auth) Logout(ctx context.Context, sessionID string) error {
	// Revoke the session by ID
	return a.Session.RevokeByID(ctx, sessionID)
}

// LogoutAll invalidates all sessions for a user
func (a *Auth) LogoutAll(ctx context.Context, userID string) error {
	// Revoke all sessions for the user
	return a.Session.RevokeAll(ctx, userID)
}

// LogoutByToken invalidates a session by its token
func (a *Auth) LogoutByToken(ctx context.Context, token string) error {
	// Revoke the session by token
	return a.Session.Revoke(ctx, token)
}

// VerifyAccessToken validates an access token and returns the claims
func (a *Auth) VerifyAccessToken(ctx context.Context, accessToken string) (*jwt.Claims, error) {
	// Check if JWT manager is configured
	if a.JWT == nil {
		return nil, ErrJWTNotConfigured
	}

	// Verify the access token
	claims, err := a.JWT.ValidateAccessToken(accessToken)
	if err != nil {
		return nil, err
	}

	// Optionally verify the session is still valid
	sessions, err := a.Session.List(ctx, claims.UserID)
	if err != nil {
		return nil, err
	}

	// Find the session
	sessionExists := false
	for _, s := range sessions {
		if s.ID == claims.SessionID {
			sessionExists = true
			break
		}
	}

	if !sessionExists {
		return nil, ErrSessionNotFound
	}

	return claims, nil
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

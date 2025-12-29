package kainos_auth_lib

import (
	"errors"

	"github.com/kainos-it-com/kainos-auth/admin"
	"github.com/kainos-it-com/kainos-auth/core"
	"github.com/kainos-it-com/kainos-auth/magiclink"
	"github.com/kainos-it-com/kainos-auth/oauth"
	"github.com/kainos-it-com/kainos-auth/organization"
	"github.com/kainos-it-com/kainos-auth/passkey"
	"github.com/kainos-it-com/kainos-auth/password"
	"github.com/kainos-it-com/kainos-auth/ratelimit"
	"github.com/kainos-it-com/kainos-auth/token"
	"github.com/kainos-it-com/kainos-auth/twofa"
)

// Re-export option functions for convenience
var (
	WithSessionExpiry     = core.WithSessionExpiry
	WithEmailVerification = core.WithEmailVerification
	WithSecret            = core.WithSecret
	WithPasswordPolicy    = core.WithPasswordPolicy
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

// ErrJWTNotConfigured Additional errors
var (
	ErrJWTNotConfigured = errors.New("JWT manager not configured, please set secret in config")
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
	ErrMagicLinkInvalid = magiclink.ErrInvalidToken
	ErrMagicLinkExpired = magiclink.ErrTokenExpired
	ErrSignUpDisabled   = magiclink.ErrSignUpDisabled

	// Admin errors
	ErrAdminNotAuthorized     = admin.ErrNotAuthorized
	ErrCannotImpersonateAdmin = admin.ErrCannotImpersonateAdmin

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

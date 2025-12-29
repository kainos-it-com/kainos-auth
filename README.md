# Kainos Auth Library

A comprehensive, modular authentication library for Go, inspired by [Better Auth](https://better-auth.com). Provides a plugin-like architecture with all the features you need for modern authentication.

## Features

### Core Features (Built-in)
- ✅ Email/Password Authentication
- ✅ Session Management (create, validate, refresh, revoke)
- ✅ OAuth Providers (Google, GitHub, Discord, Microsoft, Apple)
- ✅ Email Verification
- ✅ Password Reset
- ✅ JWT Tokens
- ✅ Session Freshness
- ✅ Multi-Session Support
- ✅ Account Linking/Unlinking

### Plugin Features (Optional)
- ✅ Two-Factor Authentication (TOTP, OTP, Backup Codes)
- ✅ Magic Link (Passwordless Email Login)
- ✅ Admin (User Management, Ban/Unban, Impersonation)
- ✅ Organization (Multi-Tenancy, Teams, RBAC)
- ✅ Rate Limiting
- ✅ Passkeys/WebAuthn

## Installation

```bash
go get kainos.it.com/kainos-auth/lib
```

## Quick Start

```go
package main

import (
    "context"
    "log"
    
    auth "kainos.it.com/kainos-auth/lib"
    "kainos.it.com/kainos-auth/lib/store"
)

func main() {
    ctx := context.Background()
    
    // Initialize store
    s, err := store.NewStore(ctx, "postgres://user:pass@localhost/db")
    if err != nil {
        log.Fatal(err)
    }
    defer s.Close()
    
    // Create auth instance with options
    a := auth.New(s,
        auth.WithSecret("your-secret-key"),
        auth.WithEmailVerification(true),
        auth.WithSessionExpiry(7 * 24 * time.Hour),
    )
    
    // Register OAuth providers
    a.WithOAuthProvider(auth.GoogleProvider(
        "client-id",
        "client-secret", 
        "https://yourapp.com/auth/google/callback",
    ))
}
```

## Core Usage

### User Registration

```go
// Create user with password
result, err := a.store.CreateUserWithCredential(ctx, store.CreateUserInput{
    Name:  "John Doe",
    Email: "john@example.com",
}, hashedPassword)

// Request email verification
verification, err := a.Email.RequestVerification(ctx, "john@example.com")
// Send verification.Token to user's email

// Verify email
err = a.Email.Verify(ctx, "john@example.com", token)
```

### Authentication

```go
// Validate password and create session
user, err := a.store.GetUserByEmail(ctx, email)
if !auth.CheckPassword(password, user.PasswordHash) {
    return errors.New("invalid credentials")
}

session, err := a.Session.Create(ctx, user.ID, &ipAddress, &userAgent)
```

### Session Management

```go
// Validate session
response, err := a.Session.Validate(ctx, sessionToken)
// response.User, response.Session

// Refresh session
response, err := a.Session.Refresh(ctx, sessionToken)

// Check if session is fresh (for sensitive operations)
fresh, err := a.Session.IsFresh(ctx, sessionToken)

// List all user sessions
sessions, err := a.Session.List(ctx, userID)

// Revoke specific session
err = a.Session.Revoke(ctx, sessionToken)

// Revoke all other sessions
err = a.Session.RevokeOthers(ctx, userID, currentSessionID)
```

### Password Management

```go
// Change password
err := a.Password.Change(ctx, auth.ChangePasswordInput{
    UserID:              userID,
    CurrentPassword:     "old-password",
    NewPassword:         "new-password",
    RevokeOtherSessions: true,
    CurrentSessionID:    sessionID,
})

// Request password reset
request, err := a.Password.RequestReset(ctx, "john@example.com")
// Send request.Token to user's email

// Reset password with token
err = a.Password.Reset(ctx, auth.ResetPasswordInput{
    Email:       "john@example.com",
    Token:       token,
    NewPassword: "new-password",
})
```

### OAuth

```go
// Get authorization URL
url, state, err := a.OAuth.GetAuthURL("google")
// Redirect user to url, store state in session

// Handle callback
tokens, err := a.OAuth.ExchangeCode(ctx, "google", code)
profile, err := a.OAuth.GetUserInfo(ctx, "google", tokens.AccessToken)

// Link/unlink accounts
err = a.store.LinkOAuthAccount(ctx, store.LinkAccountInput{
    UserID:     userID,
    ProviderID: "google",
    AccountID:  profile.ID,
    // ... tokens
})
```

### JWT Tokens

```go
// Create token pair
pair, err := a.JWT.CreateTokenPair(userID, sessionID, email, name)
// pair.AccessToken, pair.RefreshToken

// Validate access token
claims, err := a.JWT.ValidateAccessToken(accessToken)

// Refresh tokens
newPair, err := a.JWT.RefreshTokenPair(refreshToken, email, name)
```

## Plugin Usage

### Two-Factor Authentication

```go
// Enable 2FA plugin
a.WithTwoFactor(auth.DefaultTwoFactorConfig("MyApp"))

// Generate TOTP secret for user
secret, err := a.TwoFactor.GenerateSecret()
uri := a.TwoFactor.GenerateTOTPURI(secret, user.Email)
// Display QR code from uri

// Validate TOTP code
valid := a.TwoFactor.ValidateTOTP(secret, userCode)

// Generate backup codes
codes, err := a.TwoFactor.GenerateBackupCodes()

// Generate OTP for email/SMS
otp, err := a.TwoFactor.GenerateOTP()
// Send otp.Code to user
```

### Magic Link

```go
// Enable magic link plugin
a.WithMagicLink(&auth.MagicLinkConfig{
    ExpiresIn:   5 * time.Minute,
    CallbackURL: "https://yourapp.com/auth/magic-link",
})

// Send magic link
result, err := a.MagicLink.Send(ctx, magiclink.SendInput{
    Email:       "john@example.com",
    CallbackURL: "https://yourapp.com/verify",
})
// Send result.URL to user's email

// Verify magic link
response, err := a.MagicLink.Verify(ctx, magiclink.VerifyInput{
    Token: token,
    Email: email,
})
// response.User, response.Session
```

### Admin

```go
// Enable admin plugin
a.WithAdmin(&auth.AdminConfig{
    AdminUserIDs: []string{"admin-user-id"},
    AdminRoles:   []string{"admin", "superadmin"},
})

// Create user as admin
user, err := a.Admin.CreateUser(ctx, adminID, admin.CreateUserInput{
    Email:    "new@example.com",
    Password: "password",
    Name:     "New User",
    Role:     "user",
})

// List users with pagination
users, err := a.Admin.ListUsers(ctx, adminID, admin.ListUsersInput{
    Limit:  100,
    Offset: 0,
})

// Ban user
err = a.Admin.BanUser(ctx, adminID, admin.BanUserInput{
    UserID:    targetUserID,
    BanReason: "Violation of terms",
})

// Impersonate user
response, err := a.Admin.ImpersonateUser(ctx, adminID, targetUserID, nil, nil)
```

### Organization (Multi-Tenancy)

```go
// Enable organization plugin
a.WithOrganization(&auth.OrganizationConfig{
    AllowUserToCreateOrg: true,
    MembershipLimit:      100,
    TeamsEnabled:         true,
})

// Create organization
result, err := a.Organization.Create(ctx, organization.CreateInput{
    Name:   "Acme Inc",
    Slug:   "acme",
    UserID: userID,
})

// Invite member
invitation, err := a.Organization.Invite(ctx, organization.InviteInput{
    Email:          "member@example.com",
    OrganizationID: orgID,
    InviterID:      userID,
    Role:           "member",
})

// Accept invitation
member, err := a.Organization.AcceptInvitation(ctx, userID, invitationID)

// Check permissions
hasPermission := a.Organization.HasPermission(ctx, userID, orgID, "member", "create")

// Create team (if enabled)
team, err := a.Organization.CreateTeam(ctx, userID, orgID, "Engineering")
```

### Rate Limiting

```go
// Enable rate limiting
a.WithRateLimiter(&auth.RateLimitConfig{
    DefaultLimit:  100,
    DefaultWindow: time.Minute,
    EndpointLimits: map[string]*ratelimit.EndpointLimit{
        "sign-in": {Limit: 5, Window: time.Minute},
        "sign-up": {Limit: 3, Window: time.Minute},
    },
})

// Check rate limit
result, err := a.RateLimiter.Check(ctx, ipAddress, "sign-in")
if !result.Allowed {
    return errors.New("rate limit exceeded")
}
// result.Remaining, result.ResetAt
```

### Passkeys (WebAuthn)

```go
// Enable passkey plugin
a.WithPasskey(auth.DefaultPasskeyConfig(
    "example.com",           // RP ID
    "My App",                // RP Name
    "https://example.com",   // Origin
))

// Begin registration
options, err := a.Passkey.BeginRegistration(ctx, userID, "platform")
// Send options to client for WebAuthn API

// Finish registration (after client response)
passkey, err := a.Passkey.FinishRegistration(ctx, passkey.FinishRegistrationInput{
    UserID:       userID,
    Name:         "My MacBook",
    CredentialID: credentialID,
    PublicKey:    publicKey,
    // ...
})

// Begin authentication
options, err := a.Passkey.BeginAuthentication(ctx, "")
// Send options to client

// List user's passkeys
passkeys, err := a.Passkey.ListUserPasskeys(ctx, userID)
```

## Database Schema

Run the schema files to set up your database:

```bash
psql -d yourdb -f db/schema/schema.sql
psql -d yourdb -f db/schema/plugins.sql  # For plugin features
```

## Configuration Options

### Core Options

```go
auth.WithSecret("your-secret-key")           // Required for JWT/tokens
auth.WithSessionExpiry(7 * 24 * time.Hour)   // Session duration
auth.WithEmailVerification(true)              // Require email verification
auth.WithPasswordPolicy(8, true, true, true, true) // Min length, upper, lower, number, special
```

## Comparison with Better Auth

| Feature | Better Auth | Kainos Auth |
|---------|-------------|-------------|
| Email/Password | ✅ | ✅ |
| Session Management | ✅ | ✅ |
| OAuth Providers | ✅ | ✅ |
| Email Verification | ✅ | ✅ |
| Password Reset | ✅ | ✅ |
| JWT Tokens | ✅ | ✅ |
| Two-Factor Auth | ✅ | ✅ |
| Magic Link | ✅ | ✅ |
| Passkeys/WebAuthn | ✅ | ✅ |
| Admin Plugin | ✅ | ✅ |
| Organization | ✅ | ✅ |
| Rate Limiting | ✅ | ✅ |
| Cookie Cache | ✅ | 🔜 |
| API Keys | ✅ | 🔜 |
| Anonymous Users | ✅ | 🔜 |

## License

MIT

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2024-12-29

### Added
- **Built-in Authentication Methods**: New high-level authentication methods for easier integration
  - `SignUp(ctx, SignUpInput)` - Automatic password validation, hashing, and session creation
  - `SignIn(ctx, SignInInput)` - Automatic password verification and session creation  
  - `CreateUser(ctx, SignUpInput)` - User creation without session for advanced use cases
- **Enhanced Type Exports**: Added store types (`CreateUserInput`, `UserWithAccounts`, etc.) to package level
- **Example Usage**: Added comprehensive `example_usage.go` demonstrating all authentication patterns
- **Contributing Guide**: Added detailed `CONTRIBUTING.md` with development guidelines

### Changed
- **Exported Store Field**: Changed `Auth.store` to `Auth.Store` for direct database access
- **Updated Documentation**: Enhanced README with new authentication methods and corrected import paths
- **Import Paths**: All examples now use correct `github.com/kainos-it-com/kainos-auth` import path

### Technical Details
- Added `context` import to main auth package
- Maintained full backward compatibility - all existing functionality preserved
- Direct store access still available for advanced use cases

### Migration Guide
- **No breaking changes** - existing code continues to work
- **New recommended approach**: Use `SignUp()` and `SignIn()` for simpler authentication flows
- **Direct store access**: Still available via `auth.Store.CreateUserWithCredential()` etc.

## [1.0.0] - 2024-12-29

### Added
- Initial release of Kainos Auth library
- **Core Authentication Features**:
  - Email/Password authentication with bcrypt hashing
  - Session management (create, validate, refresh, revoke)
  - OAuth providers (Google, GitHub, Discord, Microsoft, Apple)
  - Email verification and password reset
  - JWT token management
  - Multi-session support with session freshness
  - Account linking/unlinking

- **Plugin Architecture**:
  - Two-Factor Authentication (TOTP, OTP, backup codes)
  - Magic Link authentication (passwordless email login)
  - Admin functionality (user management, ban/unban, impersonation)
  - Organization support (multi-tenancy, teams, RBAC)
  - Rate limiting
  - Passkeys/WebAuthn support

- **Database Integration**:
  - PostgreSQL support with connection pooling
  - SQLC-generated type-safe queries
  - Database schema and migrations
  - Transaction support

- **Developer Experience**:
  - Modular plugin-like architecture
  - Comprehensive error handling
  - Type-safe APIs
  - Extensive configuration options
  - Re-exported utility functions

### Technical Implementation
- **Module Structure**: Clean separation of concerns with individual packages
- **Store Pattern**: Database abstraction layer with interface-based design
- **Configuration**: Functional options pattern for flexible setup
- **Security**: bcrypt password hashing, secure session tokens, CSRF protection
- **Performance**: Connection pooling, efficient queries, minimal allocations

### Documentation
- Comprehensive README with usage examples
- Code examples for all major features
- Plugin configuration guides
- Database schema documentation
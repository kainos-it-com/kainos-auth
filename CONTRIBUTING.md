# Contributing to Kainos Auth

Thank you for your interest in contributing to Kainos Auth! This guide will help you get started with contributing to our modular authentication library for Go.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Contributing Guidelines](#contributing-guidelines)
- [Code Standards](#code-standards)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Release Process](#release-process)

## Getting Started

Kainos Auth is a modular authentication library inspired by Better Auth, designed with a plugin-like architecture. Before contributing, please:

1. Read the [README.md](README.md) to understand the project
2. Check existing [issues](https://github.com/kainos-it-com/kainos-auth/issues) and [pull requests](https://github.com/kainos-it-com/kainos-auth/pulls)
3. Join our discussions to understand current priorities

## Development Setup

### Prerequisites

- Go 1.21 or later
- PostgreSQL (for database operations)
- Git

### Local Setup

1. **Fork and clone the repository**
   ```bash
   git clone https://github.com/your-username/kainos-auth.git
   cd kainos-auth
   ```

2. **Install dependencies**
   ```bash
   go mod download
   ```

3. **Set up database (optional for core development)**
   ```bash
   # Create a test database
   createdb kainos_auth_test
   
   # Run migrations (if available)
   # migrate -path db/migrations -database "postgresql://localhost/kainos_auth_test?sslmode=disable" up
   ```

4. **Verify setup**
   ```bash
   go build ./...
   ```

## Project Structure

```
kainos-auth/
├── admin/          # Admin functionality (user management, impersonation)
├── core/           # Core types, errors, and configurations
├── db/             # Database schema, queries, and generated code
├── email/          # Email verification and change functionality
├── jwt/            # JWT token management
├── magiclink/      # Magic link authentication
├── oauth/          # OAuth provider integrations
├── organization/   # Multi-tenancy and organization management
├── passkey/        # WebAuthn/Passkey authentication
├── password/       # Password hashing, validation, and management
├── ratelimit/      # Rate limiting functionality
├── session/        # Session management
├── store/          # Database abstraction layer
├── token/          # Token generation and validation
├── twofa/          # Two-factor authentication
├── user/           # User management operations
├── auth.go         # Main Auth struct and public API
└── example_usage.go # Usage examples
```

### Module Architecture

Each module follows a consistent pattern:

- **Manager struct**: Main interface for the module
- **Config struct**: Configuration options
- **Types**: Module-specific types and inputs
- **Errors**: Module-specific error definitions
- **Default configs**: Sensible defaults for easy setup

## Contributing Guidelines

### Types of Contributions

1. **Bug Fixes**: Fix existing functionality
2. **New Features**: Add new authentication methods or modules
3. **Documentation**: Improve docs, examples, or comments
4. **Performance**: Optimize existing code
5. **Security**: Address security vulnerabilities

### Before You Start

1. **Check existing issues**: Look for related issues or discussions
2. **Create an issue**: For new features, create an issue to discuss the approach
3. **Small PRs**: Keep pull requests focused and manageable
4. **Backward compatibility**: Ensure changes don't break existing APIs

### Development Workflow

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Follow the existing code patterns
   - Add tests for new functionality
   - Update documentation as needed

3. **Test your changes**
   ```bash
   go test ./...
   go build ./...
   ```

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: add new authentication method"
   ```

## Code Standards

### Go Style Guide

- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Use `gofmt` for formatting
- Use meaningful variable and function names
- Add comments for exported functions and types

### Naming Conventions

- **Packages**: lowercase, single word when possible
- **Types**: PascalCase for exported, camelCase for internal
- **Functions**: PascalCase for exported, camelCase for internal
- **Constants**: PascalCase or UPPER_CASE for package-level

### Error Handling

- Use custom error types defined in `core/errors.go`
- Return meaningful error messages
- Don't expose internal implementation details in errors

### Example Code Style

```go
// Manager handles user authentication operations
type Manager struct {
    store  store.Store
    config *Config
}

// New creates a new authentication manager with the given configuration
func New(s store.Store, cfg *Config) *Manager {
    return &Manager{
        store:  s,
        config: cfg,
    }
}

// Authenticate verifies user credentials and returns an auth response
func (m *Manager) Authenticate(ctx context.Context, input AuthInput) (*AuthResponse, error) {
    if err := m.validateInput(input); err != nil {
        return nil, err
    }
    
    // Implementation...
    
    return &AuthResponse{
        User:    user,
        Session: session,
    }, nil
}
```

## Testing

### Test Structure

- Unit tests for individual functions
- Integration tests for module interactions
- Example tests for documentation

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test ./password/

# Run with verbose output
go test -v ./...
```

### Writing Tests

```go
func TestManager_Authenticate(t *testing.T) {
    // Setup
    store := &mockStore{}
    manager := New(store, DefaultConfig())
    
    // Test cases
    tests := []struct {
        name    string
        input   AuthInput
        want    *AuthResponse
        wantErr bool
    }{
        {
            name: "valid credentials",
            input: AuthInput{
                Email:    "test@example.com",
                Password: "password123",
            },
            want: &AuthResponse{
                User: &User{Email: "test@example.com"},
            },
            wantErr: false,
        },
        // More test cases...
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := manager.Authenticate(context.Background(), tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("Authenticate() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            // Assert results...
        })
    }
}
```

## Submitting Changes

### Pull Request Process

1. **Update documentation**: Ensure README and docs reflect your changes
2. **Add tests**: Include tests for new functionality
3. **Update examples**: Add usage examples if applicable
4. **Check compatibility**: Ensure backward compatibility
5. **Create PR**: Submit with a clear description

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Security fix

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No breaking changes (or clearly documented)
```

### Commit Message Format

Use conventional commits:

```
type(scope): description

feat(auth): add built-in SignUp method
fix(session): resolve token expiration issue
docs(readme): update installation instructions
test(password): add validation test cases
```

## Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

1. Update version in relevant files
2. Update CHANGELOG.md
3. Create release notes
4. Tag the release
5. Push to GitHub
6. Create GitHub release

## Getting Help

- **Issues**: Create an issue for bugs or feature requests
- **Discussions**: Use GitHub Discussions for questions
- **Security**: Email security issues privately

## Code of Conduct

Please be respectful and professional in all interactions. We're building this together!

## Recognition

Contributors will be recognized in:
- README.md contributors section
- Release notes
- GitHub contributors page

Thank you for contributing to Kainos Auth! 🚀
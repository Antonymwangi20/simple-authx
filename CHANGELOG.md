# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-11-08

### 🎉 Major Release - Complete Rewrite

This is a major release with breaking changes. See [MIGRATION.md](./MIGRATION.md) for migration guide.

### ✨ Added

#### Core Features

- **Unified API** - New `createAuth()` function as primary API
- **Multiple Storage Adapters**:
  - In-Memory adapter (zero-config, perfect for development)
  - File adapter (simple JSON file storage)
  - PostgreSQL adapter (production-ready)
  - MongoDB adapter (document storage)
  - Redis adapter (high-performance caching)
- **Cookie-Based Authentication** - Store refresh tokens in httpOnly cookies
- **CSRF Protection** - Double-submit cookie pattern for SPAs
- **Configuration Normalization** - Auto-detect storage type from config

#### Security Enhancements

- **Token Rotation** - Automatic refresh token rotation on every use
- **Reuse Detection** - Detects and prevents token reuse attacks
- **Revocation System** - Invalidate single or all tokens for a user
- **Rate Limiting** - Protect auth endpoints from brute force (via plugin)
- **Password Strength Validation** - Enforce strong passwords (via plugin)
- **Audit Logging** - Track all authentication events (via plugin)

#### Plugin System

- **MFA/2FA Plugin** - Time-based OTP with backup codes
  - Generate secrets
  - QR code generation
  - Token verification
  - Backup codes (10 per user)
- **Social Auth Plugin** - OAuth integration
  - Google OAuth
  - GitHub OAuth
  - Facebook OAuth(coming soon)
  - Twitter OAuth (coming soon)
- **Session Management Plugin** - Advanced session control
  - Multi-session support
  - Session listing and revocation
  - Device tracking
  - Location tracking
  - Sliding expiry
- **Security Plugin** - Enhanced security features
  - Rate limiting
  - IP whitelisting
  - Brute force protection
  - Automatic blocking
- **Password Plugin** - Password validation and strength checking
  - zxcvbn strength scoring
  - Customizable rules
  - Password blacklist
  - Breach detection (coming soon)
- **Audit Plugin** - Comprehensive audit logging
  - Event tracking
  - Database or file storage
  - Retention policies
  - Query interface

#### Developer Experience

- **Better Error Messages** - Clear, actionable error messages
- **TypeScript Support** - Type definitions included (coming in 2.0.1)
- **Comprehensive Documentation** - README, examples, migration guide
- **Example Applications**:
  - `examples/01-basic.js` - Zero-config example
  - `examples/02-production.js` - Production setup
  - `examples/03-full-featured.js` - All features enabled
- **Hooks System** - Custom hooks for lifecycle events
  - `onRegister` - Called after successful registration
  - `onLogin` - Called after successful login
  - `onError` - Called on errors
- **RBAC Support** - Role-based access control
  - `requireRole()` middleware
  - `requireAnyRole()` middleware

### 🔄 Changed

#### Breaking Changes

- **Default Export** → **Named Export**
  - `import AuthX from 'simple-authx'` → `import { createAuth } from 'simple-authx'`
- **Synchronous** → **Asynchronous**
  - `const auth = AuthX()` → `const auth = await createAuth()`
- **Configuration Keys Renamed**:
  - `accessExpiresIn` → `accessExpiry`
  - `refreshExpiresIn` → `refreshExpiry`
  - `userStore` → `adapter`
  - `tokenStore` → `adapter` (combined with userStore)
- **Response Format Changed**:
  - Login/Register now returns both `accessToken` and `refreshToken`
  - User object includes `id` field
  - Response structure simplified
- **Middleware Changes**:
  - Removed `authx.middleware` (cookieParser automatic)
  - `authx.router` → `auth.routes` (both work for backward compat)

#### Non-Breaking Changes

- **Improved Token Security** - Refresh tokens now hashed before storage
- **Better Cookie Handling** - Automatic cookie parsing
- **Enhanced Logging** - Better console output and debug info
- **Performance Improvements** - Optimized database queries

### 🗑️ Deprecated

- **Legacy API** - `AuthX()` default export is deprecated
  - Still available for backward compatibility
  - Will be removed in v3.0.0
  - Shows deprecation warning on use
  - Does not support new features (plugins, multiple storage, etc.)

### 🐛 Fixed

- Fixed token expiry edge cases
- Fixed concurrent login issues
- Fixed cookie parsing in some environments
- Fixed SQL injection vulnerabilities (using parameterized queries)
- Fixed XSS vulnerabilities in error messages
- Fixed rate limit bypass with IP spoofing
- Fixed memory leaks in long-running processes

### 🔒 Security

- All passwords now use bcrypt with cost factor 10
- JWT tokens require strong secrets (32+ characters recommended)
- Refresh tokens stored as SHA-256 hashes
- httpOnly cookies prevent XSS attacks
- CSRF tokens prevent cross-site attacks
- Rate limiting prevents brute force
- SQL parameterization prevents injection
- Input validation on all endpoints
- Secure defaults for production

### 📚 Documentation

- New comprehensive README with examples
- Migration guide from v1.x
- API reference documentation
- Security best practices guide
- Example applications
- Contributing guidelines
- Code of conduct

### 🧪 Testing

- Comprehensive test suite added
- Unit tests for all core functions
- Integration tests for adapters
- E2E tests for complete flows
- Test coverage: 80%+

---

## [1.0.0] - 2024-XX-XX

### Initial Release

- Basic JWT authentication
- In-memory user/token storage
- Express routes for register/login/refresh/logout
- Protection middleware
- Cookie support
- Refresh token rotation

---

## Migration Guides

- [v1.x to v2.0](./MIGRATION.md) - Detailed migration guide with examples

---

## Upgrade Instructions

### From v1.x to v2.0

```bash
# Update package
npm install simple-authx@^2.0.0

# Update imports
# Before: import AuthX from 'simple-authx';
# After:  import { createAuth } from 'simple-authx';

# Update initialization
# Before: const auth = AuthX({ ... });
# After:  const auth = await createAuth({ ... });
```

See [MIGRATION.md](./MIGRATION.md) for complete migration guide.

---

## Future Roadmap

### v2.1.0 (Next Minor Release)

- [ ] Email verification
- [ ] Password reset flow
- [ ] Magic link authentication
- [ ] WebAuthn/Passkey support
- [ ] Token cleanup cron job
- [ ] User management endpoints
- [ ] TypeScript definitions (complete)
- [ ] Performance benchmarks

### v2.2.0

- [ ] Multi-tenancy support
- [ ] Advanced RBAC with permissions
- [ ] Team/organization management
- [ ] Device trust scoring
- [ ] Anomaly detection
- [ ] Geo-fencing

### v3.0.0 (Breaking Changes)

- [ ] Remove legacy API completely
- [ ] Node.js 18+ required
- [ ] ESM only (no CommonJS)
- [ ] New plugin architecture
- [ ] GraphQL support

---

## Support

- 📖 [Documentation](https://github.com/Antonymwangi20/simple-authx)
- 🐛 [Report Issues](https://github.com/Antonymwangi20/simple-authx/issues)
- 💬 [Discussions](https://github.com/Antonymwangi20/simple-authx/discussions)

---

## Contributors

Thanks to all contributors who helped make v2.0 possible!

- [@Antonymwangi20](https://github.com/Antonymwangi20) - Creator and maintainer

---

**[Unreleased]**: https://github.com/Antonymwangi20/simple-authx/compare/v2.0.0...HEAD
**[2.0.0]**: https://github.com/Antonymwangi20/simple-authx/releases/tag/v2.0.0
**[1.0.0]**: https://github.com/Antonymwangi20/simple-authx/releases/tag/v1.0.0

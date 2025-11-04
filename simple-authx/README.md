# 🔐 simple-authx v2.0

**The simplest, most powerful authentication library for Node.js**

Zero config to production-ready in seconds. One function. All the features.

[![npm version](https://img.shields.io/npm/v/simple-authx.svg)](https://www.npmjs.com/package/simple-authx)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)]()

---

## 🚀 Quick Start

```bash
npm install simple-authx
```

### Zero Config (Perfect for Development)

```javascript
import express from 'express';
import { createAuth } from 'simple-authx';

const app = express();
app.use(express.json());

// That's it! In-memory auth ready to go
const auth = await createAuth();

app.use('/auth', auth.routes);
app.get('/protected', auth.protect, (req, res) => {
  res.json({ user: req.user });
});

app.listen(3000);
```

**Try it now:**
```bash
# Register
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"secret123"}'

# Login
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"secret123"}'

# Access protected route
curl http://localhost:3000/protected \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

---

## ✨ Features

### 🎯 **One Function, Everything Included**
- 🔑 JWT-based authentication (access + refresh tokens)
- 🔄 Automatic token rotation & reuse detection
- 🍪 Cookie-based auth with CSRF protection
- 📦 Multiple storage options (Memory, File, Postgres, MongoDB, Redis)
- 🛡️ MFA/2FA support (TOTP, backup codes)
- 🌐 Social login (Google, GitHub, Facebook, Twitter)
- 👥 Session management
- 🔒 Password strength validation
- 📊 Audit logging
- 🚦 Rate limiting & security
- 🔐 Role-based access control (RBAC)

### 🚄 **From Zero to Production**
```javascript
// Development (in-memory)
const auth = await createAuth();

// Production (Postgres + all features)
const auth = await createAuth({
  storage: 'postgres',
  postgres: { connectionString: process.env.DATABASE_URL },
  cookies: { refresh: true, secure: true },
  csrf: { enabled: true },
  plugins: {
    mfa: { issuer: 'MyApp' },
    social: {
      google: {
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET
      }
    },
    sessions: { redis: process.env.REDIS_URL },
    security: { rateLimit: true, maxAttempts: 5 }
  }
});
```

---

## 📚 Storage Options

### 1. **In-Memory** (Development/Testing)
```javascript
const auth = await createAuth();
```

### 2. **File Storage** (Simple Persistence)
```javascript
const auth = await createAuth('./data/auth.json');
// or
const auth = await createAuth({
  storage: 'file',
  file: './data/auth.json'
});
```

### 3. **PostgreSQL** (Production Ready)
```javascript
const auth = await createAuth({
  storage: 'postgres',
  postgres: {
    connectionString: 'postgresql://user:pass@localhost:5432/mydb'
  }
});
```

### 4. **MongoDB** (Document Store)
```javascript
const auth = await createAuth({
  storage: 'mongodb',
  mongodb: 'mongodb://localhost:27017/myapp'
});
```

### 5. **Redis** (High Performance)
```javascript
const auth = await createAuth({
  storage: 'redis',
  redis: {
    host: 'localhost',
    port: 6379
  }
});
```

---

## 🍪 Cookie-Based Auth (SPA/Web Apps)

Perfect for single-page applications with same-domain backend:

```javascript
const auth = await createAuth({
  cookies: {
    refresh: true,      // Store refresh token in httpOnly cookie
    secure: true,       // HTTPS only (production)
    sameSite: 'strict', // CSRF protection
    domain: '.myapp.com' // Share across subdomains
  },
  csrf: {
    enabled: true,      // Double-submit cookie pattern
    cookieName: 'csrfToken',
    headerName: 'x-csrf-token'
  }
});

app.use('/auth', auth.routes);

// Frontend receives refresh token in cookie automatically
// Only access token returned in response body
```

**Frontend Usage:**
```javascript
// Login
const response = await fetch('/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username, password }),
  credentials: 'include' // Important for cookies
});

const { accessToken } = await response.json();

// Refresh (automatic cookie handling)
const refreshResponse = await fetch('/auth/refresh', {
  method: 'POST',
  credentials: 'include',
  headers: {
    'x-csrf-token': getCsrfToken() // From cookie
  }
});
```

---

## 🔌 Plugins

### MFA/2FA
```javascript
const auth = await createAuth({
  plugins: {
    mfa: {
      issuer: 'MyApp',
      algorithm: 'sha256'
    }
  }
});

// Generate secret for user
const secret = auth.mfa.generateSecret();
const qrCode = await auth.mfa.generateQRCode(secret, 'user@example.com');

// Verify token
const valid = auth.mfa.verifyToken(secret, userProvidedToken);

// Generate backup codes
const backupCodes = auth.mfa.generateBackupCodes(); // Returns 10 codes
```

### Social Login
```javascript
const auth = await createAuth({
  plugins: {
    social: {
      google: {
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: 'http://localhost:3000/auth/google/callback'
      },
      github: {
        clientId: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET
      }
    }
  }
});

// Routes automatically created:
// GET /auth/google - Redirect to Google
// GET /auth/google/callback - Handle OAuth callback
// GET /auth/github - Redirect to GitHub
// GET /auth/github/callback - Handle OAuth callback
```

### Session Management
```javascript
const auth = await createAuth({
  plugins: {
    sessions: {
      redis: process.env.REDIS_URL,
      maxSessions: 5, // Max concurrent sessions per user
      slidingExpiry: true
    }
  }
});

// List user sessions
const sessions = await auth.sessions.getUserSessions(userId);

// Revoke specific session
await auth.sessions.revokeSession(sessionId);

// Revoke all sessions except current
await auth.sessions.revokeOtherSessions(userId, currentSessionId);
```

### Password Validation
```javascript
const auth = await createAuth({
  plugins: {
    password: {
      minStrength: 3, // 0-4 (zxcvbn score)
      minLength: 8,
      requireUppercase: true,
      requireNumbers: true,
      requireSpecialChars: true,
      blacklist: ['password', 'myapp', 'company']
    }
  }
});

// Validate password
try {
  await auth.password.validatePassword('weakpass', 'username', 'user@example.com');
} catch (err) {
  console.log(err.message); // "Password too weak"
}

// Check password strength
const strength = auth.password.checkStrength('MyP@ssw0rd123');
// Returns: { score: 3, feedback: [...] }
```

### Security & Rate Limiting
```javascript
const auth = await createAuth({
  plugins: {
    security: {
      rateLimit: true,
      maxAttempts: 5,
      windowMs: 15 * 60 * 1000, // 15 minutes
      blockDuration: 60 * 60 * 1000, // 1 hour
      ipWhitelist: ['127.0.0.1', '10.0.0.0/8']
    }
  }
});
```

### Audit Logging
```javascript
const auth = await createAuth({
  plugins: {
    audit: {
      events: ['login', 'register', 'refresh', 'logout', 'mfa'],
      storage: 'database', // or 'file', 'console'
      retentionDays: 90
    }
  }
});

// Query audit logs
const logs = await auth.audit.query({
  userId: 'user123',
  event: 'login',
  startDate: new Date('2024-01-01'),
  endDate: new Date()
});
```

---

## 🛡️ API Reference

### `createAuth(config)`

Returns an auth instance with the following properties:

#### **Core**
- `routes` - Express router with auth endpoints
- `protect` - Middleware to protect routes
- `auth` - Direct access to AuthManager
- `adapter` - Storage adapter instance

#### **Plugins** (if configured)
- `mfa` - MFA/2FA provider
- `social` - Social auth provider
- `sessions` - Session manager
- `security` - Security manager
- `password` - Password validator
- `audit` - Audit logger

#### **Utility Methods**
- `generateTokens(payload)` - Create access + refresh tokens
- `verifyAccess(token)` - Verify access token
- `close()` - Close database connections

### Default Routes

#### `POST /auth/register`
```json
// Request
{
  "username": "alice",
  "password": "secret123"
}

// Response
{
  "user": {
    "id": "1",
    "username": "alice"
  },
  "accessToken": "eyJhbG...",
  "refreshToken": "eyJhbG..." // (if not using cookies)
}
```

#### `POST /auth/login`
```json
// Request
{
  "username": "alice",
  "password": "secret123"
}

// Response
{
  "accessToken": "eyJhbG...",
  "refreshToken": "eyJhbG..." // (if not using cookies)
}
```

#### `POST /auth/refresh`
```json
// Request (if not using cookies)
{
  "refreshToken": "eyJhbG..."
}

// Response
{
  "accessToken": "eyJhbG...",
  "refreshToken": "eyJhbG..." // New rotated token
}
```

#### `POST /auth/logout`
```json
// Request (if not using cookies)
{
  "refreshToken": "eyJhbG..."
}

// Response
{
  "message": "Logged out successfully"
}
```

### Protect Middleware

```javascript
app.get('/protected', auth.protect, (req, res) => {
  // req.user contains decoded token payload
  res.json({ user: req.user });
});

// With role check
import { requireRole } from 'simple-authx';

app.get('/admin', auth.protect, requireRole('admin'), (req, res) => {
  res.json({ message: 'Admin only' });
});
```

---

## 🔒 Security Features

### ✅ **Secure by Default**
- Passwords hashed with bcrypt (cost factor 10)
- JWTs signed with strong secrets
- Refresh token rotation on every use
- Token reuse detection & automatic revocation
- httpOnly cookies for refresh tokens
- CSRF protection with double-submit pattern
- Rate limiting on auth endpoints
- SQL injection prevention (parameterized queries)
- XSS prevention (no user input in tokens)

### ✅ **Token Rotation & Reuse Detection**
```
User Login
  ↓
Issue RT1 → Store RT1
  ↓
User Refresh with RT1
  ↓
Delete RT1, Issue RT2 → Store RT2
  ↓
Attacker tries RT1 (reuse!)
  ↓
Detect reuse → Revoke all tokens for user
```

### ✅ **Production Checklist**
- ✅ Use environment variables for secrets
- ✅ Enable HTTPS (`cookies.secure = true`)
- ✅ Enable CSRF protection
- ✅ Use strong JWT secrets (32+ characters, random)
- ✅ Set appropriate token expiry (15m access, 7d refresh)
- ✅ Enable rate limiting
- ✅ Use production database (Postgres/MongoDB)
- ✅ Enable audit logging
- ✅ Regular security updates (`npm audit`)

---

## 🎨 Examples

### Basic Example
See [`examples/01-basic.js`](./examples/01-basic.js)

### Production Example
See [`examples/02-production.js`](./examples/02-production.js)

### Full-Featured Example
See [`examples/03-full-featured.js`](./examples/03-full-featured.js)

### SPA Example (React + Express)
See [`examples/spa-app/`](./examples/spa-app/)

---

## 🔄 Migration from v1.x

See [MIGRATION.md](./MIGRATION.md) for detailed migration guide.

**Quick Summary:**
```javascript
// v1.x (old)
import AuthX from 'simple-authx';
const authx = AuthX({ secret: 'mysecret' });

// v2.0 (new)
import { createAuth } from 'simple-authx';
const auth = await createAuth({
  secret: 'mysecret',
  storage: 'memory'
});
```

---

## 📖 Advanced Usage

### Custom Hooks
```javascript
const auth = await createAuth({
  hooks: {
    async onRegister(user) {
      console.log('New user registered:', user.username);
      await sendWelcomeEmail(user.email);
    },
    async onLogin(user) {
      console.log('User logged in:', user.username);
      await trackAnalytics('login', user.id);
    },
    async onError(error) {
      console.error('Auth error:', error);
      await sendErrorToSentry(error);
    }
  }
});
```

### Direct AuthManager Usage
```javascript
const auth = await createAuth();

// Register user programmatically
const result = await auth.auth.register('bob', 'password123');

// Verify password
const user = await auth.adapter.verifyUser('bob', 'password123');

// Generate tokens manually
const tokens = auth.generateTokens({ userId: user.id, role: 'admin' });
```

### Custom Storage Adapter
```javascript
class MyCustomAdapter {
  async findUser(username) { /* ... */ }
  async createUser(username, password) { /* ... */ }
  async verifyUser(username, password) { /* ... */ }
  async storeRefreshToken(userId, token, expiry) { /* ... */ }
  async findRefreshToken(token) { /* ... */ }
  async invalidateRefreshToken(token) { /* ... */ }
  async invalidateAllRefreshTokens(userId) { /* ... */ }
}

const auth = await createAuth({
  adapter: new MyCustomAdapter()
});
```

---

## 🧪 Testing

```bash
# Run all tests
npm test

# Run specific test
node tests/test-unified-api.js

# With coverage
npm run test:coverage
```

---

## 🤝 Contributing

Contributions welcome! Please read [CONTRIBUTING.md](./CONTRIBUTING.md) first.

---

## 📝 License

MIT © [Antonymwangi20](https://github.com/Antonymwangi20)

---

## 🙋 Support

- 📖 [Documentation](https://github.com/Antonymwangi20/simple-authx)
- 🐛 [Report Issues](https://github.com/Antonymwangi20/simple-authx/issues)
- 💬 [Discussions](https://github.com/Antonymwangi20/simple-authx/discussions)
- 📧 Email: support@simple-authx.dev

---

## 🌟 Star History

If you find this library useful, please star it on GitHub! ⭐

---

**Made with ❤️ by developers, for developers**

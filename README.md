# 🔐 simple-authx v2.0.6

**The simplest, most powerful authentication library for Node.js**

Zero config to production-ready in seconds. One initialization. All the features.

[![npm version](https://img.shields.io/npm/v/simple-authx.svg?style=flat-square)](https://www.npmjs.com/package/simple-authx)
[![npm downloads](https://img.shields.io/npm/dm/simple-authx.svg?style=flat-square)](https://www.npmjs.com/package/simple-authx)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/github/actions/workflow/status/Antonymwangi20/simple-authx/ci.yml?branch=main&style=flat-square)](https://github.com/Antonymwangi20/simple-authx/actions)
[![codecov](https://img.shields.io/codecov/c/github/Antonymwangi20/simple-authx?style=flat-square)](https://codecov.io/gh/Antonymwangi20/simple-authx)
[![Node.js Version](https://img.shields.io/node/v/simple-authx.svg?style=flat-square)](https://nodejs.org)

---

## 🚀 Quick Start (Modern Pattern)

```bash
npm install simple-authx
```

### **Singleton Pattern** (Recommended)

Initialize once in your main server file, then use `protect` anywhere:

```javascript
// server.js - Initialize ONCE
import express from 'express';
import { initializeAuth, protect, getAuth } from 'simple-authx';

const app = express();
app.use(express.json());

// Initialize authentication (async operation)
await initializeAuth({
  storage: 'mongodb',
  mongodb: process.env.MONGODB_URI,
});

// Mount auth routes ONCE
app.use('/auth', getAuth().routes);

app.listen(3000);
```

```javascript
// routes/api.js - Use protect ANYWHERE
import { protect } from 'simple-authx';

router.get('/profile', protect, (req, res) => {
  res.json({ user: req.user }); // ✅ Works automatically
});

router.get('/admin', protect, requireRole('admin'), (req, res) => {
  res.json({ message: 'Admin only' });
});
```

**Benefits:**

- ✅ Initialize once, use everywhere
- ✅ No auth instance passing between files
- ✅ Cleaner, more maintainable code
- ✅ Perfect for 95% of applications

---

## 🎯 Usage Patterns

### Pattern 1: Singleton (Recommended)

**Best for:** Most applications, microservices, standard REST APIs

```javascript
import { initializeAuth, protect, getAuth } from 'simple-authx';

// server.js
await initializeAuth({
  storage: 'mongodb',
  mongodb: process.env.MONGODB_URI,
  secret: process.env.JWT_SECRET,
});

app.use('/auth', getAuth().routes);

// Any route file
import { protect } from 'simple-authx';
app.get('/protected', protect, handler);
```

---

### Pattern 2: Instance-Based (Advanced)

**Best for:** Multi-tenant apps, multiple auth configs, complex setups

```javascript
import { createAuth } from 'simple-authx';

// auth.js - Create and export
export const auth = await createAuth({
  storage: 'mongodb',
  mongodb: process.env.MONGODB_URI,
});

// routes/api.js - Import and use
import { auth } from '../auth.js';
app.get('/protected', auth.protect, handler);
```

**When to use:**

- Multiple auth instances needed
- Different auth configs per tenant
- Complex microservice architectures

---

## ✨ Features

### 🎯 **Core Features**

- 🔑 JWT-based authentication (access + refresh tokens)
- 🔄 Automatic token rotation & reuse detection
- 🍪 Cookie-based auth with CSRF protection
- 📦 Multiple storage (Memory, File, Postgres, MongoDB, Redis)
- 👤 **Flexible User Schema** - Use email, username, phone, or custom fields
- 🔐 Multi-identifier login - Login with email OR username OR phone

### 🔌 **Optional Plugins**

- 🛡️ MFA/2FA support (TOTP, backup codes)
- 🌐 Social login (Google, GitHub, Facebook, Twitter)
- 👥 Session management with device tracking
- 🔒 Password strength validation
- 📊 Audit logging
- 🚦 Rate limiting & security

---

## 📦 Storage Options

### In-Memory (Development/Testing)

```javascript
await initializeAuth(); // Zero config!
```

### MongoDB (Recommended for Production)

```javascript
await initializeAuth({
  storage: 'mongodb',
  mongodb: process.env.MONGODB_URI,
});
```

### PostgreSQL

```javascript
await initializeAuth({
  storage: 'postgres',
  postgres: {
    connectionString: process.env.DATABASE_URL,
  },
});
```

### File Storage (Single Instance Apps)

```javascript
await initializeAuth({
  storage: 'file',
  file: './data/auth.json',
});
```

### Redis (High Performance)

```javascript
await initializeAuth({
  storage: 'redis',
  redis: { url: process.env.REDIS_URL },
  file: './data/users.json', // User data storage
});
```

---

## 👤 Flexible User Schema

**NEW in v2.0:** Support for email, username, phone number, and custom fields!

### Register with Email

```javascript
POST /auth/register
{
  "email": "user@example.com",
  "password": "SecureP@ss123"
}
```

### Register with Username

```javascript
POST /auth/register
{
  "username": "johndoe",
  "password": "SecureP@ss123"
}
```

### Register with Phone Number

```javascript
POST /auth/register
{
  "phoneNumber": "+1234567890",
  "password": "SecureP@ss123"
}
```

### Register with Multiple Identifiers

```javascript
POST /auth/register
{
  "email": "user@example.com",
  "username": "johndoe",
  "phoneNumber": "+1234567890",
  "password": "SecureP@ss123"
}
```

### Register with Custom Fields

```javascript
POST /auth/register
{
  "email": "user@example.com",
  "password": "SecureP@ss123",
  "firstName": "John",
  "lastName": "Doe",
  "age": 30,
  "role": "user"
}
```

### Configure Required Fields

```javascript
await initializeAuth({
  storage: 'mongodb',
  mongodb: process.env.MONGODB_URI,
  userFields: {
    identifiers: ['email', 'username', 'phoneNumber'],
    required: ['email'], // Only email required
    unique: ['email', 'username'], // Must be unique
  },
});
```

---

## 🔐 Multi-Identifier Login

Login with **any** identifier - no need to specify which one!

```javascript
// Login with email
POST /auth/login
{
  "identifier": "user@example.com",
  "password": "SecureP@ss123"
}

// Login with username
POST /auth/login
{
  "identifier": "johndoe",
  "password": "SecureP@ss123"
}

// Login with phone
POST /auth/login
{
  "identifier": "+1234567890",
  "password": "SecureP@ss123"
}

// Legacy format still supported
POST /auth/login
{
  "username": "johndoe", // or "email" or "phoneNumber"
  "password": "SecureP@ss123"
}
```

The system automatically detects which field you're using!

---

## 🍪 Cookie-Based Auth (Recommended for Web Apps)

Perfect for SPAs with same-domain backend:

```javascript
await initializeAuth({
  storage: 'mongodb',
  mongodb: process.env.MONGODB_URI,
  cookies: {
    refresh: true, // Store refresh token in httpOnly cookie
    secure: true, // HTTPS only (production)
    sameSite: 'strict', // CSRF protection
  },
  csrf: {
    enabled: true, // Enable CSRF protection
    headerName: 'x-csrf-token',
  },
});
```

**Frontend Usage:**

```javascript
// Login - refresh token stored in cookie automatically
const response = await fetch('/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    identifier: 'user@example.com',
    password: 'SecureP@ss123',
  }),
  credentials: 'include', // ⚠️ IMPORTANT for cookies
});

const { accessToken } = await response.json();

// Refresh - uses cookie automatically
const refreshResponse = await fetch('/auth/refresh', {
  method: 'POST',
  credentials: 'include',
  headers: {
    'x-csrf-token': getCsrfTokenFromCookie(),
  },
});
```

---

## 🔌 Plugins

### MFA/2FA

```javascript
await initializeAuth({
  plugins: {
    mfa: {
      issuer: 'MyApp',
      algorithm: 'sha256',
    },
  },
});

// In your routes
import { getAuth } from 'simple-authx';
const auth = getAuth();

// Generate MFA secret
const secret = auth.mfa.generateSecret();
const qrCode = await auth.mfa.generateQRCode('user@example.com', secret);
const backupCodes = auth.mfa.generateBackupCodes(); // 10 codes

// Verify token
const valid = auth.mfa.verifyToken(userToken, secret);
```

### Social Login

```javascript
await initializeAuth({
  plugins: {
    social: {
      google: {
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: 'http://localhost:3000/auth/google/callback',
      },
      github: {
        clientId: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
      },
    },
  },
});

// Routes automatically created:
// GET /auth/google
// GET /auth/google/callback
// GET /auth/github
// GET /auth/github/callback
```

### Password Validation

```javascript
await initializeAuth({
  plugins: {
    password: {
      minStrength: 3, // 0-4 (zxcvbn score)
      minLength: 10,
      requireUppercase: true,
      requireNumbers: true,
      requireSpecialChars: true,
    },
  },
});

// Check password strength
import { getAuth } from 'simple-authx';
const strength = getAuth().password.checkStrength('MyP@ssw0rd123');
// Returns: { score: 3, feedback: {...}, crackTime: '...' }
```

### Session Management

```javascript
await initializeAuth({
  plugins: {
    sessions: {
      maxSessions: 5, // Max concurrent sessions
      trackLocation: true, // Track IP/location
      trackDevice: true, // Track device info
    },
  },
});

// List user sessions
const auth = getAuth();
const sessions = await auth.sessions.getUserSessions(userId);

// Revoke specific session
await auth.sessions.revokeSession(sessionId);

// Revoke all other sessions
await auth.sessions.revokeOtherSessions(userId, currentSessionId);
```

### Security & Rate Limiting

```javascript
await initializeAuth({
  plugins: {
    security: {
      rateLimit: true,
      maxFailedAttempts: 5,
      windowMs: 15 * 60 * 1000, // 15 minutes
      blockDuration: 60 * 60 * 1000, // 1 hour
    },
  },
});
```

### Audit Logging

```javascript
await initializeAuth({
  plugins: {
    audit: {
      events: ['login', 'register', 'refresh', 'logout'],
      storage: 'database',
      retentionDays: 90,
    },
  },
});

// Query audit logs
const auth = getAuth();
const logs = await auth.audit.query({
  userId: 'user123',
  event: 'login',
  startDate: new Date('2024-01-01'),
});
```

---

## 🛡️ Built-in Routes

### Core Routes (Always Available)

#### `POST /auth/register`

```json
// Request
{
  "email": "user@example.com",
  "username": "johndoe",
  "password": "SecureP@ss123",
  "firstName": "John", // Custom field
  "lastName": "Doe"    // Custom field
}

// Response
{
  "user": {
    "id": "1",
    "email": "user@example.com",
    "username": "johndoe",
    "firstName": "John",
    "lastName": "Doe"
  },
  "accessToken": "eyJhbG...",
  "refreshToken": "eyJhbG..." // (if not using cookies)
}
```

#### `POST /auth/login`

```json
// Request (use any identifier)
{
  "identifier": "user@example.com", // email, username, or phone
  "password": "SecureP@ss123"
}

// Response
{
  "user": {
    "id": "1",
    "email": "user@example.com",
    "username": "johndoe"
  },
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

// With cookies - just send CSRF token in header
// x-csrf-token: abc123...

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

---

## 🛡️ Protecting Routes

### Basic Protection

```javascript
import { protect } from 'simple-authx';

app.get('/profile', protect, (req, res) => {
  res.json({ user: req.user }); // Access decoded token
});
```

### Role-Based Access Control (RBAC)

```javascript
import { protect, requireRole, requireAnyRole } from 'simple-authx';

// Single role required
app.get('/admin', protect, requireRole('admin'), (req, res) => {
  res.json({ message: 'Admin only' });
});

// Any of multiple roles
app.get('/staff', protect, requireAnyRole(['admin', 'moderator', 'editor']), (req, res) => {
  res.json({ message: 'Staff access' });
});
```

---

## 🔧 Configuration Options

```javascript
await initializeAuth({
  // Storage
  storage: 'mongodb',
  mongodb: process.env.MONGODB_URI,

  // User Schema (NEW!)
  userFields: {
    identifiers: ['email', 'username', 'phoneNumber'],
    required: ['email'],
    unique: ['email', 'username', 'phoneNumber'],
    custom: {
      firstName: { type: 'string', required: false },
      lastName: { type: 'string', required: false },
      role: { type: 'string', default: 'user' }
    }
  },

  // JWT Settings
  secret: process.env.JWT_SECRET,
  refreshSecret: process.env.JWT_REFRESH_SECRET,
  accessExpiry: '15m',
  refreshExpiry: '7d',

  // Cookie Settings
  cookies: {
    refresh: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    domain: '.myapp.com'
  },

  // CSRF Protection
  csrf: {
    enabled: true,
    headerName: 'x-csrf-token'
  },

  // Plugins
  plugins: {
    mfa: { issuer: 'MyApp' },
    social: { google: {...} },
    sessions: {},
    security: { rateLimit: true },
    password: { minStrength: 3 },
    audit: { events: ['login', 'register'] }
  },

  // Lifecycle Hooks
  hooks: {
    async onRegister(user) {
      await sendWelcomeEmail(user.email);
    },
    async onLogin(user) {
      await trackAnalytics('login', user.id);
    }
  }
});
```

---

## 📚 Complete Examples

### Basic Setup (Development)

```javascript
import express from 'express';
import { initializeAuth, protect, getAuth } from 'simple-authx';

const app = express();
app.use(express.json());

// Zero config - uses in-memory storage
await initializeAuth();

app.use('/auth', getAuth().routes);
app.get('/profile', protect, (req, res) => {
  res.json({ user: req.user });
});

app.listen(3000);
```

### Production Setup (MongoDB)

```javascript
import express from 'express';
import { initializeAuth, protect, getAuth } from 'simple-authx';
import 'dotenv/config';

const app = express();
app.use(express.json());

await initializeAuth({
  storage: 'mongodb',
  mongodb: process.env.MONGODB_URI,
  secret: process.env.JWT_SECRET,
  refreshSecret: process.env.JWT_REFRESH_SECRET,

  userFields: {
    identifiers: ['email', 'username'],
    required: ['email'],
    custom: {
      firstName: { type: 'string' },
      lastName: { type: 'string' },
      role: { type: 'string', default: 'user' },
    },
  },

  cookies: {
    refresh: true,
    secure: true,
    sameSite: 'strict',
  },

  csrf: { enabled: true },

  plugins: {
    password: {
      minStrength: 3,
      minLength: 10,
    },
    security: {
      rateLimit: true,
      maxFailedAttempts: 5,
    },
    audit: {
      events: ['login', 'register', 'failed_login'],
    },
  },
});

app.use('/auth', getAuth().routes);
app.get('/profile', protect, (req, res) => {
  res.json({ user: req.user });
});

app.listen(3000);
```

---

## 🔄 Migration from v1.x / Old Pattern

### Old Pattern (Deprecated)

```javascript
import { createAuth } from 'simple-authx';

const auth = await createAuth({ ... });
app.use('/auth', auth.routes);
app.get('/protected', auth.protect, handler);
```

### New Pattern (Recommended)

```javascript
import { initializeAuth, protect, getAuth } from 'simple-authx';

await initializeAuth({ ... });
app.use('/auth', getAuth().routes);
app.get('/protected', protect, handler);
```

See [MIGRATION.md](./MIGRATION.md) for detailed guide.

---

## 🧪 Testing

```javascript
import { initializeAuth, protect, resetAuth } from 'simple-authx';

describe('Auth Tests', () => {
  beforeEach(async () => {
    resetAuth(); // Clear singleton
    await initializeAuth(); // In-memory for tests
  });

  it('should register and login', async () => {
    const auth = getAuth();
    await auth.auth.register({
      email: 'test@example.com',
      password: 'TestP@ss123',
    });

    const result = await auth.auth.login('test@example.com', 'TestP@ss123');
    assert(result.accessToken);
  });
});
```

---

## 🔒 Security Best Practices

### Production Checklist

- ✅ Use strong random secrets (32+ characters)
- ✅ Enable HTTPS (`cookies.secure = true`)
- ✅ Enable CSRF protection
- ✅ Use production database (MongoDB/Postgres)
- ✅ Enable rate limiting
- ✅ Set appropriate token expiry (15m access, 7d refresh)
- ✅ Enable audit logging
- ✅ Regular security updates (`npm audit`)
- ✅ Use environment variables for secrets
- ✅ Monitor authentication events

### Security Features

- 🔐 Password hashing (bcrypt/argon2)
- 🔄 Automatic token rotation
- 🚫 Token reuse detection
- 🍪 httpOnly cookies
- 🛡️ CSRF protection
- 🚦 Rate limiting
- 📊 Audit logging
- 💉 SQL injection prevention
- 🔓 XSS prevention

---

## 📖 API Reference

### Singleton Exports

```typescript
// Initialize auth (call once in main server file)
await initializeAuth(config?: AuthConfig): Promise<AuthInstance>

// Get initialized instance
getAuth(): AuthInstance

// Protection middleware (use anywhere)
protect: RequestHandler

// Check if initialized
isAuthInitialized(): boolean

// Reset (for testing)
resetAuth(): void

// Role-based access
requireRole(role: string): RequestHandler
requireAnyRole(roles: string[]): RequestHandler
```

### Instance Methods (from `getAuth()`)

```typescript
interface AuthInstance {
  routes: Router; // Express router with auth endpoints
  protect: RequestHandler; // Protection middleware
  auth: AuthManager; // Core auth manager
  adapter: Adapter; // Storage adapter

  // Plugins (if configured)
  mfa: MFAProvider | null;
  social: SocialAuthProvider | null;
  sessions: SessionManager | null;
  security: SecurityManager | null;
  password: PasswordManager | null;
  audit: AuditLogger | null;

  // Utility methods
  generateTokens(payload: TokenPayload): TokenPair;
  verifyAccess(token: string): DecodedToken;
  close(): Promise<void>;
}
```

---

## 🐛 Troubleshooting

### "Auth not initialized"

```javascript
// ❌ Wrong - didn't call initializeAuth
import { protect } from 'simple-authx';
app.get('/protected', protect, handler);

// ✅ Correct - initialize first
await initializeAuth();
app.get('/protected', protect, handler);
```

### "Cannot use await outside async function"

```javascript
// ❌ Wrong
const app = express();
await initializeAuth();

// ✅ Correct - wrap in async function
async function startServer() {
  const app = express();
  await initializeAuth();
  app.listen(3000);
}
startServer();

// ✅ Or use top-level await (Node.js 14.8+)
```

### Database connection issues

```bash
# MongoDB
docker run -d -p 27017:27017 mongo

# Postgres
docker run -d -p 5432:5432 \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=authx \
  postgres

# Redis
docker run -d -p 6379:6379 redis
```

---

## 🤝 Contributing

Contributions welcome! Please read [CONTRIBUTING.md](./CONTRIBUTING.md).

---

## 📄 License

MIT © [Antonymwangi20](https://github.com/Antonymwangi20)

---

## 🔗 Links

- **GitHub**: https://github.com/Antonymwangi20/simple-authx
- **npm**: https://www.npmjs.com/package/simple-authx
- **Issues**: https://github.com/Antonymwangi20/simple-authx/issues
- **Examples**: See `examples/` folder
- **Changelog**: [CHANGELOG.md](./CHANGELOG.md)
- **Migration Guide**: [MIGRATION.md](./MIGRATION.md)
- **Documentation**: https://simple-authx-lp.vercel.app/docs
- **Contact**: antony254mm@gmail.com
- **LinkedIn**: https://www.linkedin.com/in/antonymwangi20/

---

## 🌟 Support

If you find this library useful, please star it on GitHub! ⭐

---

**Made with ❤️ for developers who hate auth boilerplate**

**WANTAM!!!! 🔥✊🏽**

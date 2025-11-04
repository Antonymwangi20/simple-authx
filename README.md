# simple-authx

> **One Auth Package. Zero Boilerplate. Maximum Power.**

A complete, production-ready authentication system for Express applications. From zero-config dev setup to enterprise-scale deployment in one API.

[![npm version](https://img.shields.io/npm/v/simple-authx.svg)](https://www.npmjs.com/package/simple-authx)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## ✨ Features

- 🚀 **Plug & Play** - Works out of the box with zero config
- 🔐 **JWT Tokens** - Access + refresh token system with automatic rotation
- 🔄 **Token Rotation** - Secure refresh token reuse detection
- 🏪 **Multiple Storage** - Memory, File, Postgres, MongoDB, Redis
- 🍪 **Cookie Auth** - HttpOnly cookies + CSRF protection
- 📱 **MFA/2FA** - TOTP-based two-factor authentication
- 🌐 **Social Login** - Google & GitHub OAuth presets
- 📊 **Session Tracking** - Device fingerprinting & geo-IP
- 🛡️ **Security** - Rate limiting, IP blocking, brute-force protection
- 🔒 **Password Security** - Argon2/bcrypt with strength validation
- 📝 **Audit Logging** - Complete activity tracking
- 🎨 **Plugin System** - Enable only what you need

---

## 📦 Installation

```bash
npm install simple-authx
```

**Requirements:** Node.js >= 18

---

## 🚀 Quick Start

### **Zero Config** (Perfect for development)

```javascript
import express from 'express';
import { createAuth } from 'simple-authx';

const app = express();
app.use(express.json());

const auth = await createAuth();

app.use('/auth', auth.routes);
app.get('/profile', auth.protect, (req, res) => {
  res.json({ user: req.user });
});

app.listen(3000);
```
---

## 🏗️ Production Setup

### **PostgreSQL** (Recommended for most apps)

```javascript
const auth = await createAuth({
  storage: 'postgres',
  postgres: {
    connectionString: process.env.DATABASE_URL
  },
  secret: process.env.JWT_SECRET,
  refreshSecret: process.env.JWT_REFRESH_SECRET
});
```

**Setup database:**
```bash
npm run init-db  # Creates users & refresh_tokens tables
```

### **MongoDB**

```javascript
const auth = await createAuth({
  storage: 'mongodb',
  mongodb: process.env.MONGODB_URI
});
```

### **Redis** (High-performance tokens)

```javascript
const auth = await createAuth({
  storage: 'redis',
  redis: { url: process.env.REDIS_URL },
  file: './data/users.json' // User storage
});
```

### **File** (Single-instance apps)

```javascript
const auth = await createAuth({
  storage: 'file',
  file: './data/auth.json'
});

// Or shorthand:
const auth = await createAuth('./data/auth.json');
```

---

## 🍪 Cookie-Based Auth (Web Apps)

Perfect for SPAs, eliminates XSS vulnerabilities:

```javascript
const auth = await createAuth({
  storage: 'postgres',
  postgres: { connectionString: process.env.DATABASE_URL },
  
  cookies: {
    refresh: true,        // Store refresh token in HttpOnly cookie
    secure: true,         // HTTPS only (false for localhost)
    sameSite: 'strict'    // CSRF protection
  },
  
  csrf: {
    enabled: true,
    headerName: 'x-csrf-token'
  }
});
```

**Client-side usage:**
```javascript
// Login
const res = await fetch('/auth/login', {
  method: 'POST',
  credentials: 'include', // Important!
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: 'alice', password: 'secret' })
});

const { accessToken } = await res.json();

// Refresh (auto-sends cookie)
const refresh = await fetch('/auth/refresh', {
  method: 'POST',
  credentials: 'include',
  headers: { 'x-csrf-token': getCsrfToken() }
});
```

---

## 🎨 Advanced Features (Plugins)

Enable only the features you need:

```javascript
const auth = await createAuth({
  storage: 'postgres',
  postgres: { connectionString: process.env.DATABASE_URL },
  
  plugins: {
    // 📱 Two-Factor Authentication
    mfa: {
      issuer: 'MyApp'
    },
    
    // 🌐 Social Login
    social: {
      google: {
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: 'https://myapp.com/auth/google/callback'
      },
      github: {
        clientId: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackURL: 'https://myapp.com/auth/github/callback'
      }
    },
    
    // 📊 Session Tracking
    sessions: {
      trackDevices: true
    },
    
    // 🛡️ Security (Rate Limiting, IP Blocking)
    security: {
      redis: { url: process.env.REDIS_URL },
      maxFailedAttempts: 5,
      attemptWindow: '15m'
    },
    
    // 🔒 Password Strength & History
    password: {
      minStrength: 3,      // zxcvbn score 0-4
      historyLimit: 5,     // Prevent reuse
      hashAlgo: 'argon2'   // or 'bcrypt'
    },
    
    // 📝 Audit Logging
    audit: {
      level: 'info'
    }
  }
});
```

---

## 🔐 Built-in Routes

### **Core Routes** (Always Available)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Register new user |
| POST | `/auth/login` | Login with credentials |
| POST | `/auth/refresh` | Refresh access token |
| POST | `/auth/logout` | Logout & invalidate tokens |

### **MFA Routes** (If plugin enabled)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/mfa/enable` | Generate QR code & backup codes |
| POST | `/auth/mfa/verify` | Verify TOTP token |

### **Social Routes** (If plugin enabled)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/auth/google` | Redirect to Google OAuth |
| GET | `/auth/google/callback` | Google OAuth callback |
| GET | `/auth/github` | Redirect to GitHub OAuth |
| GET | `/auth/github/callback` | GitHub OAuth callback |

### **Session Routes** (If plugin enabled)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/auth/sessions` | List all user sessions |
| DELETE | `/auth/sessions/:id` | Revoke specific session |

---

## 🛡️ Protecting Routes

```javascript
// Simple protection
app.get('/profile', auth.protect, (req, res) => {
  res.json({ user: req.user }); // { userId, username, ... }
});

// Role-based access
import { requireRole, requireAnyRole } from 'simple-authx';

app.get('/admin', 
  auth.protect, 
  requireRole('admin'), 
  (req, res) => {
    res.json({ message: 'Admin only' });
  }
);

app.get('/staff',
  auth.protect,
  requireAnyRole(['admin', 'moderator']),
  (req, res) => {
    res.json({ message: 'Staff access' });
  }
);
```

---

## 📱 MFA Implementation Example

```javascript
// 1. Enable MFA for user
app.post('/user/mfa/setup', auth.protect, async (req, res) => {
  const secret = auth.mfa.generateSecret();
  const qr = await auth.mfa.generateQRCode(req.user.username, secret);
  const backupCodes = auth.mfa.generateBackupCodes();
  
  // Store in your database
  await db.users.update(req.user.userId, {
    mfaSecret: secret,
    backupCodes
  });
  
  res.json({ qr, backupCodes });
});

// 2. Verify during login
app.post('/auth/login-with-mfa', async (req, res) => {
  const { username, password, mfaToken } = req.body;
  
  const user = await auth.adapter.verifyUser(username, password);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  
  const valid = auth.mfa.verifyToken(mfaToken, user.mfaSecret);
  if (!valid) return res.status(401).json({ error: 'Invalid MFA token' });
  
  const tokens = auth.generateTokens({ userId: user.id });
  res.json(tokens);
});
```

---

## 🌐 Social Login Example

```javascript
// Auto-wired routes: /auth/google and /auth/google/callback

// Custom callback handler
app.get('/auth/google/callback', async (req, res) => {
  const { code } = req.query;
  const result = await auth.social.exchangeCode('google', code);
  const profile = await auth.social.getUserProfile('google', result.access_token);
  
  // Find or create user
  let user = await auth.adapter.findUser(profile.email);
  if (!user) {
    user = await auth.adapter.createUser(profile.email, randomPassword());
  }
  
  const tokens = auth.generateTokens({ userId: user.id });
  
  // Redirect to frontend
  res.redirect(`https://myapp.com/auth/callback?token=${tokens.accessToken}`);
});
```

---

## 📊 Session Tracking Example

```javascript
// List all user devices
app.get('/devices', auth.protect, async (req, res) => {
  const sessions = await auth.sessions.getSessions(req.user.userId);
  res.json({ devices: sessions });
});

// Revoke all other devices
app.post('/devices/logout-all', auth.protect, async (req, res) => {
  await auth.sessions.invalidateAllSessions(
    req.user.userId,
    req.headers['x-session-id'] // Keep current
  );
  res.json({ message: 'All other devices logged out' });
});
```

---

## 🛡️ Rate Limiting Example

```javascript
// Global API rate limit
const apiLimiter = auth.security.createRateLimiter({
  window: '15m',
  max: 100
});

app.use('/api', apiLimiter);

// Login-specific rate limit
const loginLimiter = auth.security.createRateLimiter({
  window: '15m',
  max: 5,
  skipSuccessful: true
});

app.post('/auth/login', loginLimiter, /* handler */);

// Check IP reputation
app.post('/auth/login', async (req, res) => {
  const reputation = await auth.security.getIPReputation(req.ip);
  
  if (reputation === 'blocked') {
    return res.status(403).json({ error: 'IP blocked' });
  }
  
  // Continue...
});
```

---

## 🔧 Configuration Options

```javascript
const auth = await createAuth({
  // Storage
  storage: 'postgres',              // 'memory' | 'file' | 'postgres' | 'mongodb' | 'redis'
  postgres: { connectionString },
  mongodb: 'mongodb://...',
  redis: { url: 'redis://...' },
  file: './data/auth.json',
  
  // JWT Settings
  secret: process.env.JWT_SECRET,
  refreshSecret: process.env.JWT_REFRESH_SECRET,
  accessExpiry: '15m',
  refreshExpiry: '7d',
  
  // Cookie Settings
  cookies: {
    refresh: true,
    secure: true,
    sameSite: 'strict',
    name: 'refreshToken'
  },
  
  // CSRF Protection
  csrf: {
    enabled: true,
    cookieName: 'csrfToken',
    headerName: 'x-csrf-token'
  },
  
  // Plugins
  plugins: {
    mfa: { issuer: 'MyApp' },
    social: { google: {...}, github: {...} },
    sessions: {},
    security: { redis: {...}, maxFailedAttempts: 5 },
    password: { minStrength: 3, hashAlgo: 'argon2' },
    audit: { level: 'info' }
  },
  
  // Hooks
  hooks: {
    async onRegister(user) { /* ... */ },
    async onLogin(user) { /* ... */ }
  }
});
```

---

## 🧪 Testing

```javascript
import { createAuth } from 'simple-authx';

describe('Auth Tests', () => {
  let auth;
  
  before(async () => {
    auth = await createAuth(); // In-memory
  });
  
  it('should register and login', async () => {
    await auth.auth.register('test', 'password');
    const result = await auth.auth.login('test', 'password');
    assert(result.accessToken);
  });
});
```

---

## 📚 API Reference

### **`createAuth(config)`** → `Promise<AuthInstance>`

Returns:
```typescript
{
  routes: Router            // Express router
  router: Router            // Alias
  protect: Middleware       // JWT verification
  auth: AuthManager         // Core manager
  adapter: Adapter          // Storage adapter
  
  // Plugins (if configured)
  mfa: MFAProvider | null
  social: SocialAuthProvider | null
  sessions: SessionManager | null
  security: SecurityManager | null
  password: PasswordManager | null
  audit: AuditLogger | null
  
  // Utilities
  generateTokens(payload)
  verifyAccess(token)
  close()                   // Cleanup connections
}
```

---

## 🔄 Migration Guide

### **From Legacy API**

```javascript
import { createAuth } from 'simple-authx';
const auth = await createAuth({ secret: '...' });
app.use('/auth', auth.routes);
```

**Changes:**
- ✅ Function is now async
- ✅ Better storage options
- ✅ Plugin system
- ✅ Same route signatures

---

## 🏆 Best Practices

1. ✅ **Always use environment variables for secrets**
2. ✅ **Use Postgres/MongoDB in production**
3. ✅ **Enable rate limiting**
4. ✅ **Implement MFA for sensitive apps**
5. ✅ **Use cookies + CSRF for web apps**
6. ✅ **Enable audit logging for compliance**
7. ✅ **Track sessions for security**

---

## 🐛 Troubleshooting

### **"router is not a function"**
```javascript
// Wrong
app.use('/auth', auth.router());

// Correct
app.use('/auth', auth.routes);
```

### **Database not initialized**
```bash
npm run init-db
```

### **Redis connection failed**
```bash
docker run -d -p 6379:6379 redis
```

---

## 📄 License

MIT © [Antony Mwangi](https://github.com/Antonymwangi20)

---

## 🤝 Contributing

Contributions welcome! Please read our [Contributing Guide](CONTRIBUTING.md).

---

## 🔗 Links

- **GitHub**: https://github.com/Antonymwangi20/simple-authx
- **npm**: https://www.npmjs.com/package/simple-authx
- **Issues**: https://github.com/Antonymwangi20/simple-authx/issues
- **Examples**: See `examples/` folder

---

**Built with 🔥 by a GENZ developer who hates auth boilerplate**

**Package is still in BETA**

## WANTAM!!!! WADAU TAM NI JAMO SIKU ZOMBO😂😂✊🏽✊🏽✊🏽

**WANTAM!!!! 😡😤**

**ENJOY!  😁😊🎉**
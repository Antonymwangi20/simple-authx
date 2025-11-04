# 🔄 Migration Guide: v1.x → v2.0

This guide will help you migrate from **simple-authx v1.x** to **v2.0**.

---

## 📊 What's New in v2.0?

### ✨ Major Improvements
- 🎯 **Unified API** - One `createAuth()` function for everything
- 📦 **Multiple Storage Options** - Memory, File, Postgres, MongoDB, Redis
- 🍪 **Cookie-Based Auth** - Perfect for SPAs
- 🔒 **Enhanced Security** - Token rotation, reuse detection, CSRF protection
- 🔌 **Plugin System** - MFA, Social Login, Sessions, Security, Password Validation
- 🚀 **Better DX** - Async/await, better error messages, comprehensive docs

### ⚠️ Breaking Changes
- Default export changed from `AuthX()` to named export `createAuth()`
- API is now async (returns Promise)
- Different configuration format
- Routes structure slightly different
- Token response format updated

---

## 🚀 Quick Migration

### Before (v1.x)
```javascript
import AuthX from 'simple-authx';

const authx = AuthX({
  secret: 'my_access_secret',
  refreshSecret: 'my_refresh_secret',
  accessExpiresIn: '1h',
  refreshExpiresIn: '7d'
});

app.use(authx.middleware);
app.use('/auth', authx.router);
app.get('/protected', authx.protect, (req, res) => {
  res.json({ user: req.user });
});
```

### After (v2.0)
```javascript
import { createAuth } from 'simple-authx';

const auth = await createAuth({
  secret: 'my_access_secret',
  refreshSecret: 'my_refresh_secret',
  accessExpiry: '1h',  // Note: 'accessExpiry' instead of 'accessExpiresIn'
  refreshExpiry: '7d', // Note: 'refreshExpiry' instead of 'refreshExpiresIn'
  storage: 'memory'    // Explicit storage option
});

// No middleware needed in v2
app.use('/auth', auth.routes);
app.get('/protected', auth.protect, (req, res) => {
  res.json({ user: req.user });
});
```

---

## 📋 Step-by-Step Migration

### Step 1: Update Import

```diff
- import AuthX from 'simple-authx';
+ import { createAuth } from 'simple-authx';
```

### Step 2: Update Configuration

```diff
- const authx = AuthX({
+ const auth = await createAuth({
    secret: 'my_access_secret',
    refreshSecret: 'my_refresh_secret',
-   accessExpiresIn: '1h',
+   accessExpiry: '1h',
-   refreshExpiresIn: '7d',
+   refreshExpiry: '7d',
+   storage: 'memory'  // Explicit storage option
  });
```

### Step 3: Remove Middleware (No Longer Needed)

```diff
- app.use(authx.middleware);  // cookieParser - not needed in v2
  app.use('/auth', auth.routes);
```

### Step 4: Update Route References

```diff
- app.use('/auth', authx.router);
+ app.use('/auth', auth.routes);  // or auth.router (both work)
```

### Step 5: Update Protection Middleware

```diff
- app.get('/protected', authx.protect, (req, res) => {
+ app.get('/protected', auth.protect, (req, res) => {
    res.json({ user: req.user });
  });
```

---

## 🔄 API Changes

### Configuration Changes

| v1.x | v2.0 | Notes |
|------|------|-------|
| `accessExpiresIn` | `accessExpiry` | Renamed for consistency |
| `refreshExpiresIn` | `refreshExpiry` | Renamed for consistency |
| `saltRounds` | Removed | Now uses bcrypt default (10) |
| `cookieName` | `cookies.name` | Nested under cookies config |
| `userStore` | `adapter` | Custom storage now uses adapter interface |
| `tokenStore` | `adapter` | Combined with userStore in adapter |
| - | `storage` | New: specify storage type |
| - | `plugins` | New: plugin configuration |

### Method Changes

| v1.x | v2.0 | Notes |
|------|------|-------|
| `authx.signAccess()` | `auth.generateTokens()` | Generates both tokens |
| `authx.signRefresh()` | `auth.generateTokens()` | Generates both tokens |
| `authx.verifyAccess()` | `auth.verifyAccess()` | Same |
| `authx.verifyRefresh()` | Internal only | Not exposed in v2 |
| `authx.hashPassword()` | `auth.adapter.createUser()` | Now internal |
| `authx.verifyPassword()` | `auth.adapter.verifyUser()` | Now internal |
| `authx.registerHandler()` | `auth.routes` | Now automatic |
| `authx.loginHandler()` | `auth.routes` | Now automatic |

### Response Format Changes

#### Register Endpoint

**v1.x:**
```json
{
  "message": "User registered",
  "user": { "username": "alice" },
  "tokens": {
    "accessToken": "eyJhbG..."
  }
}
```

**v2.0:**
```json
{
  "user": {
    "id": "1",
    "username": "alice"
  },
  "accessToken": "eyJhbG...",
  "refreshToken": "eyJhbG..."
}
```

#### Login Endpoint

**v1.x:**
```json
{
  "message": "Login successful",
  "accessToken": "eyJhbG..."
}
```

**v2.0:**
```json
{
  "accessToken": "eyJhbG...",
  "refreshToken": "eyJhbG..."
}
```

---

## 📦 Custom Storage Migration

### v1.x Custom Store

```javascript
const userStore = {
  _map: new Map(),
  async get(username) { return this._map.get(username); },
  async set(username, user) { this._map.set(username, user); }
};

const authx = AuthX({ userStore });
```

### v2.0 Custom Adapter

```javascript
class MyAdapter {
  async findUser(username) { /* ... */ }
  async createUser(username, password) { /* ... */ }
  async verifyUser(username, password) { /* ... */ }
  async storeRefreshToken(userId, token, expiry) { /* ... */ }
  async findRefreshToken(token) { /* ... */ }
  async invalidateRefreshToken(token) { /* ... */ }
  async invalidateAllRefreshTokens(userId) { /* ... */ }
}

const auth = await createAuth({
  adapter: new MyAdapter()
});
```

**Required Methods:**
- `findUser(username)` - Find user by username
- `createUser(username, password)` - Create new user (hash password internally)
- `verifyUser(username, password)` - Verify credentials
- `storeRefreshToken(userId, token, expiry)` - Store refresh token (hash it!)
- `findRefreshToken(token)` - Find refresh token (hash before lookup)
- `invalidateRefreshToken(token)` - Delete refresh token
- `invalidateAllRefreshTokens(userId)` - Delete all tokens for user

---

## 🍪 Cookie-Based Auth

v2.0 introduces cookie-based authentication for SPAs:

```javascript
const auth = await createAuth({
  cookies: {
    refresh: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    domain: '.myapp.com'
  },
  csrf: {
    enabled: true
  }
});
```

**Benefits:**
- ✅ Refresh token never exposed to JavaScript
- ✅ httpOnly cookies prevent XSS attacks
- ✅ Automatic CSRF protection
- ✅ Better security for SPAs

**Frontend Changes:**
```javascript
// Old way (v1.x)
const response = await fetch('/auth/login', {
  method: 'POST',
  body: JSON.stringify({ username, password })
});
const { accessToken, refreshToken } = await response.json();
localStorage.setItem('refreshToken', refreshToken); // ❌ Insecure

// New way (v2.0 with cookies)
const response = await fetch('/auth/login', {
  method: 'POST',
  credentials: 'include', // ✅ Include cookies
  body: JSON.stringify({ username, password })
});
const { accessToken } = await response.json();
// Refresh token automatically stored in httpOnly cookie
```

---

## 🚀 Using New Features

### File Storage (Persistence)

```javascript
// Store auth data in a JSON file
const auth = await createAuth('./data/auth.json');
```

### Database Storage

```javascript
// PostgreSQL
const auth = await createAuth({
  storage: 'postgres',
  postgres: {
    connectionString: process.env.DATABASE_URL
  }
});

// MongoDB
const auth = await createAuth({
  storage: 'mongodb',
  mongodb: process.env.MONGO_URL
});

// Redis
const auth = await createAuth({
  storage: 'redis',
  redis: {
    host: 'localhost',
    port: 6379
  }
});
```

### MFA/2FA

```javascript
const auth = await createAuth({
  plugins: {
    mfa: {
      issuer: 'MyApp'
    }
  }
});

// Generate secret
const secret = auth.mfa.generateSecret();
const qrCode = await auth.mfa.generateQRCode(secret, 'user@example.com');

// Verify token
const valid = auth.mfa.verifyToken(secret, userToken);
```

### Social Login

```javascript
const auth = await createAuth({
  plugins: {
    social: {
      google: {
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET
      }
    }
  }
});

// Routes automatically added:
// GET /auth/google
// GET /auth/google/callback
```

---

## ⚠️ Common Issues

### Issue 1: "createAuth is not a function"

**Problem:**
```javascript
import createAuth from 'simple-authx'; // ❌ Wrong
```

**Solution:**
```javascript
import { createAuth } from 'simple-authx'; // ✅ Correct
```

### Issue 2: "auth is not awaited"

**Problem:**
```javascript
const auth = createAuth(); // ❌ Missing await
```

**Solution:**
```javascript
const auth = await createAuth(); // ✅ Correct
```

### Issue 3: "Cannot use await outside async function"

**Problem:**
```javascript
const auth = await createAuth(); // ❌ Not in async function
app.listen(3000);
```

**Solution:**
```javascript
async function startServer() {
  const auth = await createAuth();
  app.use('/auth', auth.routes);
  app.listen(3000);
}
startServer();

// Or use top-level await (Node.js 14.8+)
```

### Issue 4: "Middleware not found"

**Problem:**
```javascript
app.use(auth.middleware); // ❌ Not needed in v2
```

**Solution:**
```javascript
// Remove this line - cookieParser is automatic in v2
```

### Issue 5: "Token format different"

v2.0 returns both tokens in response by default (unless using cookies):

```javascript
// v1.x response
{ "accessToken": "..." }

// v2.0 response
{ "accessToken": "...", "refreshToken": "..." }
```

If your frontend expects v1 format, update it or use cookie mode.

---

## 🔒 Security Improvements

v2.0 includes several security enhancements:

1. **Token Rotation** - Refresh tokens are automatically rotated
2. **Reuse Detection** - If a token is reused, all tokens are revoked
3. **CSRF Protection** - Double-submit cookie pattern for SPAs
4. **Rate Limiting** - Built-in rate limiting (via plugin)
5. **Audit Logging** - Track all auth events (via plugin)

**Enable all security features:**
```javascript
const auth = await createAuth({
  storage: 'postgres',
  postgres: { connectionString: process.env.DATABASE_URL },
  cookies: { refresh: true, secure: true },
  csrf: { enabled: true },
  plugins: {
    security: {
      rateLimit: true,
      maxAttempts: 5
    },
    audit: {
      events: ['login', 'register', 'refresh', 'logout']
    }
  }
});
```

---

## 📊 Testing Your Migration

### 1. Basic Flow Test
```bash
# Register
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"password123"}'

# Login
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"password123"}'

# Refresh
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"YOUR_REFRESH_TOKEN"}'

# Logout
curl -X POST http://localhost:3000/auth/logout \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"YOUR_REFRESH_TOKEN"}'
```

### 2. Protected Route Test
```bash
curl http://localhost:3000/protected \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 3. Cookie Mode Test
```bash
# Login (get cookies)
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"password123"}' \
  -c cookies.txt

# Refresh (use cookies)
curl -X POST http://localhost:3000/auth/refresh \
  -b cookies.txt \
  -H "x-csrf-token: CSRF_TOKEN_FROM_COOKIE"
```

---

## 🎯 Migration Checklist

- [ ] Update package version: `npm install simple-authx@^2.0.0`
- [ ] Change import from default to named export
- [ ] Add `await` to `createAuth()` call
- [ ] Update configuration keys (`accessExpiresIn` → `accessExpiry`)
- [ ] Add `storage` option to config
- [ ] Remove `authx.middleware` line
- [ ] Update route references (`authx.router` → `auth.routes`)
- [ ] Update custom handlers to use adapter interface (if any)
- [ ] Update frontend to handle new response format
- [ ] Test register flow
- [ ] Test login flow
- [ ] Test refresh flow
- [ ] Test logout flow
- [ ] Test protected routes
- [ ] Update environment variables (if needed)
- [ ] Update documentation
- [ ] Deploy to staging
- [ ] Test in staging
- [ ] Deploy to production

---

## 💡 Backward Compatibility

v2.0 still exports the legacy `AuthX()` function for backward compatibility:

```javascript
import AuthX from 'simple-authx';

const authx = AuthX({ secret: 'my_secret' });
// ⚠️ Warning: You are using the legacy API. Consider migrating to createAuth()
```

**However:**
- Legacy API is deprecated and will be removed in v3.0
- Legacy API doesn't support new features (plugins, multiple storage, etc.)
- Migrate to `createAuth()` as soon as possible

---

## 📞 Need Help?

- 📖 [Full Documentation](./README.md)
- 🐛 [Report Issues](https://github.com/Antonymwangi20/simple-authx/issues)
- 💬 [Ask Questions](https://github.com/Antonymwangi20/simple-authx/discussions)

---

**Happy migrating! 🚀**

# 🔄 Simple-AuthX v2.0.6 Complete Migration & Pattern Guide

**Updated:** November 8, 2025  
**Version:** 2.0.6

---

## 📊 Overview

Simple-AuthX v2.0.6 supports **TWO usage patterns**:

1. **Singleton Pattern** (Recommended) - Initialize once, use everywhere
2. **Instance Pattern** (Advanced) - Create and pass instances

This guide explains both patterns, when to use each, and how to migrate.

---

## 🎯 Pattern Comparison

### Singleton Pattern (✅ Recommended)

**Best for:** 95% of applications

```javascript
// server.js - Initialize ONCE
import { initializeAuth, protect, getAuth } from 'simple-authx';

await initializeAuth({ storage: 'mongodb', ... });
app.use('/auth', getAuth().routes);

// routes/api.js - Use ANYWHERE
import { protect } from 'simple-authx';
app.get('/protected', protect, handler);
```

**Pros:**

- ✅ No instance passing between files
- ✅ Cleaner imports
- ✅ Less boilerplate
- ✅ Single source of truth
- ✅ Perfect for most apps

**Cons:**

- ❌ Only one auth config per process
- ❌ Requires initialization before use

---

### Instance Pattern (🔧 Advanced)

**Best for:** Multi-tenant apps, complex setups

```javascript
// auth.js - Create and export
import { createAuth } from 'simple-authx';
export const auth = await createAuth({ storage: 'mongodb', ... });

// routes/api.js - Import instance
import { auth } from '../auth.js';
app.get('/protected', auth.protect, handler);
```

**Pros:**

- ✅ Multiple auth instances possible
- ✅ More flexible for complex apps
- ✅ Explicit dependencies

**Cons:**

- ❌ Must import instance everywhere
- ❌ More boilerplate
- ❌ Requires instance passing

---

## 🚀 Quick Migration

### From v1.x to v2.0

#### ❌ Old (v1.x)

```javascript
import AuthX from 'simple-authx';

const authx = AuthX({
  secret: 'my_secret',
  refreshSecret: 'my_refresh',
  accessExpiresIn: '1h',
  refreshExpiresIn: '7d',
});

app.use(authx.middleware);
app.use('/auth', authx.router);
app.get('/protected', authx.protect, handler);
```

#### ✅ New (v2.0 - Singleton)

```javascript
import { initializeAuth, protect, getAuth } from 'simple-authx';

await initializeAuth({
  storage: 'mongodb',
  mongodb: process.env.MONGODB_URI,
  secret: 'my_secret',
  refreshSecret: 'my_refresh',
  accessExpiry: '1h', // Note: renamed
  refreshExpiry: '7d', // Note: renamed
});

// No middleware needed!
app.use('/auth', getAuth().routes);
app.get('/protected', protect, handler); // Direct import!
```

#### ✅ Alternative (v2.0 - Instance)

```javascript
import { createAuth } from 'simple-authx';

const auth = await createAuth({
  storage: 'mongodb',
  mongodb: process.env.MONGODB_URI,
  secret: 'my_secret',
  refreshSecret: 'my_refresh',
  accessExpiry: '1h',
  refreshExpiry: '7d',
});

app.use('/auth', auth.routes);
app.get('/protected', auth.protect, handler);
```

---

## 📋 Breaking Changes

### 1. **API is now async**

```javascript
// ❌ Old (synchronous)
const authx = AuthX({ ... });

// ✅ New (asynchronous)
const auth = await createAuth({ ... });
// or
await initializeAuth({ ... });
```

### 2. **Configuration keys renamed**

| Old                | New                       |
| ------------------ | ------------------------- |
| `accessExpiresIn`  | `accessExpiry`            |
| `refreshExpiresIn` | `refreshExpiry`           |
| `saltRounds`       | Removed (uses default 10) |
| `cookieName`       | `cookies.name`            |
| `userStore`        | `adapter`                 |
| `tokenStore`       | `adapter`                 |

### 3. **Middleware removed**

```javascript
// ❌ Old - required cookieParser middleware
app.use(authx.middleware);

// ✅ New - no middleware needed!
// Cookie parsing is automatic
```

### 4. **Router property renamed (alias available)**

```javascript
// ❌ Old
app.use('/auth', authx.router);

// ✅ New (both work)
app.use('/auth', auth.routes); // Primary
app.use('/auth', auth.router); // Alias (backward compat)
```

### 5. **Response format changed**

#### Register/Login Response

**Old (v1.x):**

```json
{
  "message": "User registered",
  "user": { "username": "alice" },
  "tokens": {
    "accessToken": "eyJhbG..."
  }
}
```

**New (v2.0):**

```json
{
  "user": {
    "id": "1",
    "email": "alice@example.com",
    "username": "alice"
  },
  "accessToken": "eyJhbG...",
  "refreshToken": "eyJhbG..." // (if not using cookies)
}
```

---

## 🔧 Step-by-Step Migration

### Step 1: Update Imports

```diff
- import AuthX from 'simple-authx';
+ import { initializeAuth, protect, getAuth } from 'simple-authx';

// Or for instance pattern:
+ import { createAuth } from 'simple-authx';
```

### Step 2: Update Configuration

```diff
- const authx = AuthX({
+ await initializeAuth({
+   storage: 'mongodb',
+   mongodb: process.env.MONGODB_URI,
    secret: process.env.JWT_SECRET,
    refreshSecret: process.env.JWT_REFRESH_SECRET,
-   accessExpiresIn: '15m',
+   accessExpiry: '15m',
-   refreshExpiresIn: '7d',
+   refreshExpiry: '7d'
  });
```

### Step 3: Remove Middleware

```diff
- app.use(authx.middleware);
```

### Step 4: Update Route Mounting

```diff
// Singleton pattern
- app.use('/auth', authx.router);
+ app.use('/auth', getAuth().routes);

// Instance pattern
- app.use('/auth', authx.router);
+ app.use('/auth', auth.routes);
```

### Step 5: Update Protected Routes

```diff
// Singleton pattern
- app.get('/protected', authx.protect, (req, res) => {
+ app.get('/protected', protect, (req, res) => {
    res.json({ user: req.user });
  });

// Instance pattern
- app.get('/protected', authx.protect, (req, res) => {
+ app.get('/protected', auth.protect, (req, res) => {
    res.json({ user: req.user });
  });
```

### Step 6: Update Registration/Login

**Registration:**

```diff
// Old - register(username, password)
- await auth.register('alice', 'password123');

// New - register(userData object)
+ await auth.auth.register({
+   email: 'alice@example.com',
+   username: 'alice',
+   password: 'password123'
+ });

// Or (backward compatible)
+ await auth.auth.register('alice', 'password123');
```

**Login:**

```diff
// Old - login(username, password)
- await auth.login('alice', 'password123');

// New - login with any identifier
+ await auth.auth.loginWithIdentifier('alice@example.com', 'password123');

// Or (backward compatible)
+ await auth.auth.login('alice', 'password123');
```

---

## 🆕 New Features in v2.0

### 1. **Multi-Identifier Login**

Users can now register and login with email, username, or phone number:

```javascript
// Register with email
POST /auth/register
{
  "email": "user@example.com",
  "password": "SecureP@ss123"
}

// Login with any identifier
POST /auth/login
{
  "identifier": "user@example.com", // or username or phone
  "password": "SecureP@ss123"
}
```

### 2. **Flexible User Schema**

Add custom fields to users:

```javascript
await initializeAuth({
  userFields: {
    identifiers: ['email', 'username', 'phoneNumber'],
    required: ['email'],
    custom: {
      firstName: { type: 'string' },
      lastName: { type: 'string' },
      age: { type: 'number' },
      role: { type: 'string', default: 'user' }
    }
  }
});

// Register with custom fields
POST /auth/register
{
  "email": "user@example.com",
  "password": "SecureP@ss123",
  "firstName": "John",
  "lastName": "Doe",
  "age": 30
}
```

### 3. **Plugin System**

Enable only the features you need:

```javascript
await initializeAuth({
  plugins: {
    mfa: { issuer: 'MyApp' },
    social: { google: {...} },
    sessions: {},
    security: { rateLimit: true },
    password: { minStrength: 3 },
    audit: { events: ['login', 'register'] }
  }
});
```

### 4. **Environment-Based Configuration**

```javascript
// No config needed - reads from environment
await initializeAuth();

// Requires these environment variables:
// - MONGODB_URI (or DATABASE_URL for Postgres)
// - JWT_SECRET
// - JWT_REFRESH_SECRET
```

---

## 🏗️ Architecture Patterns

### Pattern 1: Single File (Simple Apps)

```javascript
// server.js
import express from 'express';
import { initializeAuth, protect, getAuth } from 'simple-authx';

const app = express();
app.use(express.json());

await initializeAuth({
  storage: 'mongodb',
  mongodb: process.env.MONGODB_URI,
});

app.use('/auth', getAuth().routes);
app.get('/profile', protect, (req, res) => {
  res.json({ user: req.user });
});

app.listen(3000);
```

### Pattern 2: Multi-File (Medium Apps)

```javascript
// server.js
import express from 'express';
import { initializeAuth, getAuth } from 'simple-authx';
import apiRoutes from './routes/api.js';

const app = express();
app.use(express.json());

await initializeAuth({
  storage: 'mongodb',
  mongodb: process.env.MONGODB_URI,
});

app.use('/auth', getAuth().routes);
app.use('/api', apiRoutes);

app.listen(3000);
```

```javascript
// routes/api.js
import { Router } from 'express';
import { protect, requireRole } from 'simple-authx';

const router = Router();

router.get('/profile', protect, (req, res) => {
  res.json({ user: req.user });
});

router.get('/admin', protect, requireRole('admin'), (req, res) => {
  res.json({ message: 'Admin only' });
});

export default router;
```

### Pattern 3: Modular (Large Apps)

```javascript
// config/auth.js
import { initializeAuth } from 'simple-authx';

export async function setupAuth() {
  await initializeAuth({
    storage: 'mongodb',
    mongodb: process.env.MONGODB_URI,
    userFields: {
      identifiers: ['email', 'username'],
      required: ['email'],
      custom: {
        firstName: { type: 'string' },
        lastName: { type: 'string' },
        role: { type: 'string', default: 'user' },
      },
    },
    plugins: {
      password: { minStrength: 3 },
      security: { rateLimit: true },
      audit: { events: ['login', 'register'] },
    },
  });
}
```

```javascript
// server.js
import express from 'express';
import { setupAuth } from './config/auth.js';
import { getAuth } from 'simple-authx';
import routes from './routes/index.js';

const app = express();
app.use(express.json());

await setupAuth();

app.use('/auth', getAuth().routes);
app.use('/api', routes);

app.listen(3000);
```

```javascript
// routes/users.js
import { Router } from 'express';
import { protect } from 'simple-authx';

const router = Router();

router.get('/users', protect, async (req, res) => {
  // Handler
});

export default router;
```

---

## 🐛 Common Migration Issues

### Issue 1: "Auth not initialized"

**Problem:**

```javascript
import { protect } from 'simple-authx';
app.get('/protected', protect, handler); // ❌ Error!
```

**Solution:**

```javascript
import { initializeAuth, protect } from 'simple-authx';

await initializeAuth(); // ✅ Initialize first!
app.get('/protected', protect, handler);
```

### Issue 2: "Cannot use await outside async function"

**Problem:**

```javascript
const app = express();
await initializeAuth(); // ❌ Error!
```

**Solution A - Wrap in async function:**

```javascript
async function startServer() {
  const app = express();
  await initializeAuth();
  app.listen(3000);
}
startServer();
```

**Solution B - Use top-level await (Node.js 14.8+):**

```javascript
// Add to package.json: "type": "module"
const app = express();
await initializeAuth(); // ✅ Works!
app.listen(3000);
```

### Issue 3: MongoDB connection timeout

**Problem:**

```javascript
await initializeAuth({
  storage: 'mongodb',
  mongodb: 'mongodb://localhost:27017/authx',
});
// Times out after 5 seconds
```

**Solution:**

```javascript
// Make sure MongoDB is running
docker run -d -p 27017:27017 mongo

// Or use MongoDB Atlas
await initializeAuth({
  storage: 'mongodb',
  mongodb: process.env.MONGODB_ATLAS_URI
});
```

### Issue 4: "routes is not a function"

**Problem:**

```javascript
app.use('/auth', auth.routes()); // ❌ Error!
```

**Solution:**

```javascript
app.use('/auth', auth.routes); // ✅ Correct!
// routes is a Router object, not a function
```

---

## 🎯 Migration Checklist

- [ ] Update package: `npm install simple-authx@latest`
- [ ] Change import from default to named export
- [ ] Add `await` to initialization
- [ ] Update configuration keys (`accessExpiresIn` → `accessExpiry`)
- [ ] Add `storage` option to config
- [ ] Remove `authx.middleware` line
- [ ] Update route references (`authx.router` → `auth.routes` or `getAuth().routes`)
- [ ] Update protected routes to use `protect` directly (singleton) or `auth.protect` (instance)
- [ ] Update custom handlers to use adapter interface (if any)
- [ ] Update frontend to handle new response format
- [ ] Test register flow
- [ ] Test login flow
- [ ] Test refresh flow
- [ ] Test logout flow
- [ ] Test protected routes
- [ ] Update environment variables
- [ ] Update documentation
- [ ] Deploy to staging
- [ ] Test in staging
- [ ] Deploy to production

---

## 📊 Feature Comparison

| Feature                | v1.x    | v2.0                                        |
| ---------------------- | ------- | ------------------------------------------- |
| Multiple storage       | ❌      | ✅ (Memory, File, Postgres, MongoDB, Redis) |
| Token rotation         | ✅      | ✅ (Improved)                               |
| Cookie auth            | ✅      | ✅ (Enhanced with CSRF)                     |
| MFA/2FA                | ❌      | ✅ (Plugin)                                 |
| Social login           | ❌      | ✅ (Plugin)                                 |
| Session management     | ❌      | ✅ (Plugin)                                 |
| Password validation    | ❌      | ✅ (Plugin)                                 |
| Audit logging          | ❌      | ✅ (Plugin)                                 |
| Rate limiting          | ❌      | ✅ (Plugin)                                 |
| Multi-identifier login | ❌      | ✅ (email, username, phone)                 |
| Custom user fields     | ❌      | ✅ (Flexible schema)                        |
| TypeScript types       | Partial | ✅ (Complete)                               |

---

## 💡 Tips & Best Practices

### 1. **Choose the Right Pattern**

**Use Singleton when:**

- Building a standard web app
- Single auth configuration
- Want cleaner code
- 95% of apps should use this

**Use Instance when:**

- Building multi-tenant app
- Need multiple auth configs
- Complex microservice setup
- 5% of apps need this

### 2. **Environment-Based Config**

```javascript
// Set these in .env
MONGODB_URI=mongodb://localhost:27017/authx
JWT_SECRET=your_secret_here
JWT_REFRESH_SECRET=your_refresh_secret

// Then initialize with no config
await initializeAuth(); // Reads from environment!
```

### 3. **Use Plugins Selectively**

```javascript
// Don't enable everything if you don't need it!
await initializeAuth({
  plugins: {
    // Only enable what you need
    password: { minStrength: 3 }, // For password validation
    security: { rateLimit: true }, // For rate limiting
    // Don't enable MFA if you don't use it
  },
});
```

### 4. **Handle Initialization Errors**

```javascript
try {
  await initializeAuth({
    storage: 'mongodb',
    mongodb: process.env.MONGODB_URI,
  });
} catch (error) {
  console.error('Auth initialization failed:', error);
  process.exit(1); // Fail fast in production
}
```

---

## 📞 Need Help?

- 📖 [Documentation](https://github.com/Antonymwangi20/simple-authx)
- 🐛 [Report Issues](https://github.com/Antonymwangi20/simple-authx/issues)
- 💬 [Discussions](https://github.com/Antonymwangi20/simple-authx/discussions)

---

**Happy migrating! 🚀**

**WANTAM!!!! 🔥✊🏽**

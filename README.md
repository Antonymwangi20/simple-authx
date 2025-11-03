# simple-authx

A simplified, secure authentication package for Express applications with support for MongoDB, Redis, Postgres, and file-based storage. ESM-only; Node >= 18.

## What this package does

- Plug-and-play authentication for Express apps
- Core: JWT access tokens + secure refresh token rotation
- Built-in routes via `createAuth`:
  - `POST /auth/register`, `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`
  - `auth.protect` middleware to secure routes (e.g. `app.get('/profile', auth.protect, ...)`)
- Storage options: File (default), Postgres, MongoDB, or Redis (tokens) with a file-backed user store
- Passwords: bcrypt or argon2; policy/strength helpers available if using modules directly
- Extra modules (manual wiring): MFA (TOTP), Social login (Google/GitHub presets), Session tracking with device/IP insights, rate limiting/IP reputation utilities


## Features

- 🔐 Simple JWT-based authentication *(implemented)*
- 🔄 Secure refresh token rotation *(implemented)*
- 🔒 Password security with **bcrypt** and **argon2** *(both supported, configurable)*
- 🚀 Multiple storage adapters: MongoDB, Redis, Postgres, File *(all implemented)*
- 📱 MFA, 🌐 Social login, 📊 Sessions, 🛡️ Security modules available (manual wiring)

## Limitations / Notes

- `createAuth` focuses on core auth (register/login/refresh/logout) and JWT protection. MFA/Social/Sessions/Security managers are available but not auto-wired.
- Only Google and GitHub OAuth strategies are provided as presets.
- Redis adapter stores refresh tokens; example setup uses File storage for users by default. For large scale, provide a real user store.


## Installation

```bash
npm install simple-authx
```

## Usage Example

See `examples/demo.js` for a full Express integration example.

```js
import express from 'express';
import { createAuth } from 'simple-authx';

const app = express();
app.use(express.json());

// Choose one storage option

// 1) MongoDB (users + refresh tokens)
const auth = await createAuth({
  mongodb: 'mongodb://localhost:27017/myapp'
});

// 2) Postgres (users + refresh tokens)
// const auth = await createAuth({
//   postgres: { connectionString: process.env.DATABASE_URL }
// });

// 3) Redis (refresh tokens) + File (users)
// const auth = await createAuth({
//   redis: { url: 'redis://localhost:6379' },
//   file: './data/users.json'
// });

// 4) File-only (good for local/dev)
// const auth = await createAuth({ file: './data/auth-data.json' });

## Wiring optional modules

These modules are available but not auto-wired by `createAuth`. Import directly and use alongside `auth`.

### MFA (TOTP)

```js
import { MFAProvider } from 'simple-authx';

const mfa = new MFAProvider({ issuer: 'MyApp' });

// Enable for a user
app.post('/auth/mfa/enable', auth.protect, async (req, res) => {
  const secret = mfa.generateSecret();
  const qr = await mfa.generateQRCode(req.user.userId || req.user.username, secret);
  const backupCodes = mfa.generateBackupCodes();
  // Persist `secret` server-side associated with user
  res.json({ qr, backupCodes });
});

// Verify a token
app.post('/auth/mfa/verify', auth.protect, async (req, res) => {
  const { token } = req.body;
  const secret = /* load user's saved secret */ '';
  const ok = mfa.verifyToken(token, secret);
  res.json({ valid: ok });
});
```

### Social login (Google/GitHub presets)

```js
import { SocialAuthProvider } from 'simple-authx';

const social = new SocialAuthProvider();
await social.setupProvider('google', {
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: 'http://localhost:3000/auth/google/callback'
});

app.get('/auth/google', (req, res) => {
  const url = social.getAuthorizationUrl('google');
  res.redirect(url);
});

app.get('/auth/google/callback', async (req, res) => {
  const { code } = req.query;
  const { tokens, profile } = await social.exchangeCode('google', code);
  // Map profile → local user; then issue JWTs with auth.authManager
  res.json({ profile, tokens });
});
```

### Sessions and suspicious activity

```js
import { SessionManager } from 'simple-authx';

// Use the same adapter used by createAuth (file/postgres/mongo/redis-backed user store)
const sessions = new SessionManager(auth.auth.adapter || auth.adapter);

app.post('/auth/sessions', auth.protect, async (req, res) => {
  const session = await sessions.createSession(req.user.userId, req);
  res.json(session);
});

app.get('/auth/sessions', auth.protect, async (req, res) => {
  res.json(await sessions.getSessions(req.user.userId));
});
```

### Basic rate limiting with Redis

```js
import { SecurityManager, connectRedis } from 'simple-authx';

const redis = await connectRedis({ url: 'redis://localhost:6379' });
const security = new SecurityManager({ redis });

const loginLimiter = security.createRateLimiter({ window: '15m', max: 20, skipSuccessful: true });
app.post('/auth/login', loginLimiter, /* your handler */);
```

### Cookie-based refresh with CSRF protection

Enable cookies and CSRF when creating auth:

```js
const auth = await createAuth({
  file: './data/auth-data.json',
  cookies: { refresh: true, secure: false, sameSite: 'strict', name: 'refreshToken' },
  csrf: { enabled: true, cookieName: 'csrfToken', headerName: 'x-csrf-token' }
});

// On login/register, refresh token is set in an HttpOnly cookie.
// On /auth/refresh, client must send header 'x-csrf-token' matching the 'csrfToken' cookie.
```

### Roles helper

```js
import { requireRole, requireAnyRole } from 'simple-authx';

app.get('/admin', auth.protect, requireRole('admin'), (req, res) => {
  res.json({ ok: true });
});

app.get('/staff', auth.protect, requireAnyRole(['admin', 'moderator']), (req, res) => {
  res.json({ ok: true });
});
```
```
app.use('/auth', auth.routes);
app.get('/profile', auth.protect, (req, res) => {
	res.json({ user: req.user });
});
```

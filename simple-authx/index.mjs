// 🎯 PRIMARY API (Recommended)
export { createAuth } from './src/core/unified-api.js';

// 🔧 Core Components (for advanced usage)
export { AuthManager } from './src/core/auth.js';
export { defaultHooks } from './src/core/hooks.js';
export { initializeAuth, getAuth, protect, isAuthInitialized } from './src/core/singleton.js';

// 📦 Adapters
export { PostgresAdapter } from './src/adapters/postgresAdapter.mjs';
export { FileAdapter } from './src/adapters/file-adapter.js';
export { connectMongo, MongoAdapter } from './src/adapters/mongoAdapters.mjs';
export { connectRedis, RedisAdapter } from './src/adapters/redisAdapter.mjs';

// 🔐 Security Modules
export { MFAProvider } from './src/security/mfa.js';
export { SocialAuthProvider } from './src/security/social.js';
export { SessionManager } from './src/security/sessions.js';
export { SecurityManager } from './src/security/security.js';
export { PasswordManager } from './src/security/password.js';
export { AuditLogger } from './src/security/audit.js';

// 🛡️ Utilities
export { requireRole, requireAnyRole } from './src/core/rbac.js';
export { hashPassword, verifyPassword } from './src/utils/hash.js';

// ⚠️ LEGACY API (Backwards Compatibility)
// This is the old in-memory implementation
// Still exported for existing users, but createAuth() is recommended
import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookie from 'cookie';
import cookieParser from 'cookie-parser';

export default function AuthX(config = {}) {
  console.warn(
    '[AuthX] You are using the legacy API. Consider migrating to createAuth() for better features.\n' +
    'See: https://github.com/Antonymwangi20/simple-authx#migration-guide'
  );

  const {
    secret = process.env.JWT_SECRET || 'default_access_secret',
    refreshSecret = process.env.REFRESH_SECRET || 'default_refresh_secret',
    accessExpiresIn = config.accessExpiresIn || '1h',
    refreshExpiresIn = config.refreshExpiresIn || '7d',
    saltRounds = config.saltRounds || 10,
    cookieName = config.cookieName || 'refreshToken'
  } = config;

  // Default in-memory user store
  const userStore = config.userStore || {
    _map: new Map(),
    async get(username) { return this._map.get(username) || null; },
    async set(username, user) { this._map.set(username, user); return user; }
  };

  // Default in-memory token store
  const tokenStore = config.tokenStore || {
    _map: new Map(),
    async get(username) { return this._map.get(username) || null; },
    async set(username, token) { this._map.set(username, token); return token; },
    async delete(username) { return this._map.delete(username); }
  };

  async function hashPassword(password) {
    const salt = await bcrypt.genSalt(saltRounds);
    return bcrypt.hash(password, salt);
  }

  async function verifyPassword(password, hash) {
    return bcrypt.compare(password, hash);
  }

  function signAccess(payload) {
    return jwt.sign(payload, secret, { expiresIn: accessExpiresIn });
  }

  function signRefresh(payload) {
    return jwt.sign(payload, refreshSecret, { expiresIn: refreshExpiresIn });
  }

  function verifyAccess(token) {
    try { return jwt.verify(token, secret); } catch { return null; }
  }

  function verifyRefresh(token) {
    try { return jwt.verify(token, refreshSecret); } catch { return null; }
  }

  async function issueTokens(res, username, cookieOptions = {}) {
    const accessToken = signAccess({ username });
    const refreshToken = signRefresh({ username });
    await tokenStore.set(username, refreshToken);

    const cookieStr = cookie.serialize(cookieName, refreshToken, {
      httpOnly: true,
      secure: cookieOptions.secure || false,
      sameSite: cookieOptions.sameSite || 'strict',
      path: '/',
      maxAge: cookieOptions.maxAge || 7 * 24 * 60 * 60
    });
    res.setHeader('Set-Cookie', cookieStr);
    return { accessToken, refreshToken };
  }

  function protect(req, res, next) {
    const token =
      (req.headers.authorization && req.headers.authorization.split(' ')[1]) ||
      (req.cookies && req.cookies[cookieName]) ||
      (req.cookies && req.cookies.token);
    if (!token) return res.status(401).json({ error: 'Missing access token' });

    const decoded = verifyAccess(token);
    if (!decoded) return res.status(403).json({ error: 'Invalid or expired access token' });

    req.user = decoded;
    next();
  }

  function registerHandler(saveUserFn) {
    const saver = saveUserFn || (async (u, h) => userStore.set(u, { username: u, password: h }));
    return async (req, res) => {
      const { username, password } = req.body || {};
      if (!username || !password) return res.status(400).json({ error: 'username and password required' });
      const existing = await userStore.get(username);
      if (existing) return res.status(400).json({ error: 'User already exists' });

      const hashed = await hashPassword(password);
      const user = await saver(username, hashed);
      const tokens = await issueTokens(res, username);
      res.json({ message: 'User registered', user, tokens: { accessToken: tokens.accessToken } });
    };
  }

  function loginHandler(getUserFn) {
    const getter = getUserFn || (async (u) => userStore.get(u));
    return async (req, res) => {
      const { username, password } = req.body || {};
      if (!username || !password) return res.status(400).json({ error: 'username and password required' });
      const user = await getter(username);
      if (!user) return res.status(404).json({ error: 'User not found' });

      const ok = await verifyPassword(password, user.password);
      if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

      const tokens = await issueTokens(res, username);
      res.json({ message: 'Login successful', accessToken: tokens.accessToken });
    };
  }

  async function refreshHandler(req, res) {
    const cookies = req.headers.cookie ? cookie.parse(req.headers.cookie) : req.cookies || {};
    const oldRefresh = req.body?.refreshToken || cookies[cookieName];
    if (!oldRefresh) return res.status(400).json({ error: 'Refresh token required' });

    const decoded = verifyRefresh(oldRefresh);
    if (!decoded) return res.status(403).json({ error: 'Invalid refresh token' });

    const username = decoded.username;
    const stored = await tokenStore.get(username);
    if (stored !== oldRefresh) return res.status(403).json({ error: 'Refresh token not recognized' });

    const newAccess = signAccess({ username });
    const newRefresh = signRefresh({ username });

    const rotated = tokenStore.rotate
      ? await tokenStore.rotate(username, oldRefresh, newRefresh)
      : (await tokenStore.set(username, newRefresh), true);

    if (!rotated) return res.status(403).json({ error: 'Token reuse detected. Re-login required.' });

    const cookieStr = cookie.serialize(cookieName, newRefresh, {
      httpOnly: true,
      secure: false,
      sameSite: 'strict',
      path: '/',
      maxAge: 7 * 24 * 60 * 60
    });
    res.setHeader('Set-Cookie', cookieStr);
    res.json({ accessToken: newAccess });
  }

  async function logoutHandler(req, res) {
    const cookies = (req.headers.cookie) ? cookie.parse(req.headers.cookie) : (req.cookies || {});
    const refreshToken = req.body?.refreshToken || cookies[cookieName];
    if (!refreshToken) return res.status(400).json({ error: 'Refresh token required' });

    const decoded = verifyRefresh(refreshToken);
    if (!decoded) return res.status(400).json({ error: 'Invalid refresh token' });

    await tokenStore.delete(decoded.username);
    const clear = cookie.serialize(cookieName, '', { httpOnly: true, path: '/', expires: new Date(0) });
    res.setHeader('Set-Cookie', clear);
    res.json({ message: 'Logged out' });
  }

  const router = express.Router();

  router.post("/register", registerHandler());
  router.post("/login", loginHandler());
  router.post("/refresh", refreshHandler);
  router.post("/logout", logoutHandler);
  router.get("/me", protect, (req, res) => {
    res.json({ user: req.user });
  });

  return {
    hashPassword,
    verifyPassword,
    signAccess,
    signRefresh,
    verifyAccess,
    verifyRefresh,
    protect,
    registerHandler,
    loginHandler,
    refreshHandler,
    logoutHandler,
    middleware: [cookieParser()],
    router,
    routes: router // Alias for consistency
  };
}
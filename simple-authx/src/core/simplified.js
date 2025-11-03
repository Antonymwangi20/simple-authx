import { Router } from 'express';
<<<<<<< HEAD
import { connectMongo, MongoUserStore, MongoTokenStore } from './adapters/mongoAdapters.mjs';
import { connectRedis, RedisTokenStore } from './adapters/redisAdapter.mjs';
import { FileAdapter } from './adapters/file-adapter.js';
import cookieParser from 'cookie-parser';

export async function createSimplifiedAuth(config) {
  const router = Router();
  let adapter;

  // Setup adapter based on connection string
  if (typeof config === 'string') {
    config = { mongodb: config };
  }

  if (config.mongodb) {
    await connectMongo(config.mongodb);
    adapter = {
      ...MongoUserStore(),
      ...MongoTokenStore()
    };
  } else if (config.redis) {
    await connectRedis(config.redis);
    adapter = {
      ...FileAdapter('./data/users.json'),
      ...RedisTokenStore(config.prefix || 'authx:')
    };
  } else if (config.file) {
    adapter = FileAdapter(config.file);
    await adapter.init();
  }

  const auth = new AuthX({
    ...config,
    adapter,
    secret: config.secret || process.env.JWT_SECRET || 'dev-secret-change-me',
    refreshSecret: config.refreshSecret || process.env.REFRESH_SECRET || 'dev-refresh-secret-change-me'
  });

  // Simplified protect middleware
  const protect = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    auth.verify(token)
      .then(user => {
        req.user = user;
        next();
      })
      .catch(() => res.status(401).json({ 
        error: 'Invalid or expired token',
        code: 'AUTH_INVALID_TOKEN'
      }));
  };

  // Auto-created routes with better error handling
  router.post('/register', async (req, res) => {
    try {
      const { username, password, ...extras } = req.body;
      
      // Custom validation if provided
      if (auth.options.validate?.register) {
        const valid = await auth.options.validate.register(username, password, extras);
        if (!valid) {
          return res.status(400).json({ 
            error: 'Validation failed',
            code: 'AUTH_VALIDATION_FAILED'
          });
        }
      }

      const result = await auth.register(username, password);
      
      // Custom extension if provided
      if (auth.options.extend?.register) {
        await auth.options.extend.register(result.user, extras);
      }

      res.json({ 
        user: { username: result.user.username, ...extras },
        message: 'Registration successful',
        tokens: {
          access: result.accessToken,
          refresh: result.refreshToken
        }
      });
    } catch (err) {
      res.status(400).json({ 
        error: err.message,
        code: 'AUTH_REGISTRATION_FAILED'
      });
=======
import { AuthManager } from './auth.js';
import { PostgresAdapter } from '../adapters/postgresAdapter.mjs';
import { FileAdapter } from '../adapters/file-adapter.js';
import { connectMongo, MongoAdapter } from '../adapters/mongoAdapters.mjs';
import { connectRedis, RedisAdapter } from '../adapters/redisAdapter.mjs';
import cookie from 'cookie';

export async function createSimplifiedAuth(config = {}) {
  const router = Router();

  // Normalize string config to file path for convenience
  if (typeof config === 'string') {
    config = { file: config };
  }

  // Choose adapter: Mongo, Postgres, Redis, or File (default)
  let adapter;
  if (config.mongodb) {
    await connectMongo(config.mongodb)
    adapter = new MongoAdapter()
  } else if (config.postgres) {
    adapter = new PostgresAdapter(config.postgres);
  } else if (config.redis) {
    const client = await connectRedis(config.redis)
    const userStore = new FileAdapter(config.file || './data/auth-data.json')
    await userStore.init()
    adapter = new RedisAdapter(userStore, { prefix: config.prefix || 'authx:refresh:' })
  } else {
    adapter = new FileAdapter(config.file || './data/auth-data.json');
    await adapter.init();
  }

  const auth = new AuthManager({
    adapter,
    secret: config.secret || process.env.JWT_SECRET || 'dev_secret',
    refreshSecret: config.refreshSecret || process.env.JWT_REFRESH_SECRET || 'dev_refresh_secret',
    accessExpiry: config.accessExpiresIn || '15m',
    refreshExpiry: config.refreshExpiresIn || '7d'
  });

  const useCookies = !!(config.cookies && config.cookies.refresh);
  const cookieName = (config.cookies && config.cookies.name) || 'refreshToken';
  const cookieOptions = {
    httpOnly: true,
    secure: !!(config.cookies && config.cookies.secure),
    sameSite: (config.cookies && config.cookies.sameSite) || 'strict',
    path: '/',
  };
  const csrfEnabled = !!(config.csrf && config.csrf.enabled);
  const csrfCookieName = (config.csrf && config.csrf.cookieName) || 'csrfToken';
  const csrfHeaderName = (config.csrf && config.csrf.headerName) || 'x-csrf-token';

  // Protect middleware using access token
  const protect = (req, res, next) => {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Authentication required' });
    try {
      const decoded = auth.verifyAccess(token);
      req.user = decoded;
      next();
    } catch {
      res.status(401).json({ error: 'Invalid or expired token' });
    }
  };

  // Routes
  router.post('/register', async (req, res) => {
    try {
      const { username, password } = req.body || {};
      if (!username || !password) return res.status(400).json({ error: 'username and password required' });
      const result = await auth.register(username, password);
      if (useCookies) {
        // set refresh token cookie and optional CSRF token cookie
        const refreshCookie = cookie.serialize(cookieName, result.refreshToken, {
          ...cookieOptions
        });
        const csrfToken = csrfEnabled ? Math.random().toString(36).slice(2) : null;
        const headers = [];
        headers.push(refreshCookie);
        if (csrfEnabled) {
          headers.push(cookie.serialize(csrfCookieName, csrfToken, { httpOnly: false, sameSite: cookieOptions.sameSite, path: '/' }));
        }
        res.setHeader('Set-Cookie', headers);
        return res.json({ user: { id: result.user.id, username: result.user.username }, tokens: { access: result.accessToken } });
      }
      res.json({ user: { id: result.user.id, username: result.user.username }, tokens: { access: result.accessToken, refresh: result.refreshToken } });
    } catch (err) {
      res.status(400).json({ error: err.message });
>>>>>>> f63ac94 (Add working createAuth wrapper with File/Postgres/Mongo/Redis support)
    }
  });

  router.post('/login', async (req, res) => {
    try {
<<<<<<< HEAD
      const { username, password } = req.body;
      const result = await auth.login(username, password);
      
      // Get extended user data if available
      let userData = { username };
      if (auth.options.extend?.getUser) {
        userData = await auth.options.extend.getUser(username);
      }

      res.json({
        user: userData,
        tokens: {
          access: result.accessToken,
          refresh: result.refreshToken
        }
      });
    } catch (err) {
      res.status(401).json({ 
        error: err.message,
        code: 'AUTH_LOGIN_FAILED'
      });
=======
      const { username, password } = req.body || {};
      if (!username || !password) return res.status(400).json({ error: 'username and password required' });
      const result = await auth.login(username, password);
      if (useCookies) {
        const refreshCookie = cookie.serialize(cookieName, result.refreshToken, {
          ...cookieOptions
        });
        const csrfToken = csrfEnabled ? Math.random().toString(36).slice(2) : null;
        const headers = [];
        headers.push(refreshCookie);
        if (csrfEnabled) {
          headers.push(cookie.serialize(csrfCookieName, csrfToken, { httpOnly: false, sameSite: cookieOptions.sameSite, path: '/' }));
        }
        res.setHeader('Set-Cookie', headers);
        return res.json({ user: { id: result.user.id, username: result.user.username }, tokens: { access: result.accessToken } });
      }
      res.json({ user: { id: result.user.id, username: result.user.username }, tokens: { access: result.accessToken, refresh: result.refreshToken } });
    } catch (err) {
      res.status(401).json({ error: err.message });
>>>>>>> f63ac94 (Add working createAuth wrapper with File/Postgres/Mongo/Redis support)
    }
  });

  router.post('/refresh', async (req, res) => {
    try {
<<<<<<< HEAD
      const result = await auth.refresh(req.body.refreshToken);
      res.json({
        tokens: {
          access: result.accessToken,
          refresh: result.refreshToken
        }
      });
    } catch (err) {
      res.status(401).json({ 
        error: err.message,
        code: 'AUTH_REFRESH_FAILED'
      });
=======
      let refreshToken = req.body && req.body.refreshToken;
      if (useCookies) {
        const cookies = req.headers.cookie ? cookie.parse(req.headers.cookie) : {};
        refreshToken = refreshToken || cookies[cookieName];
        if (csrfEnabled) {
          const headerVal = req.headers[csrfHeaderName];
          const cookieVal = cookies[csrfCookieName];
          if (!headerVal || !cookieVal || headerVal !== cookieVal) {
            return res.status(403).json({ error: 'CSRF validation failed' });
          }
        }
      }
      if (!refreshToken) return res.status(400).json({ error: 'refreshToken required' });
      const tokens = await auth.refresh(refreshToken);
      if (useCookies) {
        const refreshCookie = cookie.serialize(cookieName, tokens.refreshToken, {
          ...cookieOptions
        });
        const headers = [refreshCookie];
        res.setHeader('Set-Cookie', headers);
        return res.json({ tokens: { access: tokens.accessToken } });
      }
      res.json({ tokens: { access: tokens.accessToken, refresh: tokens.refreshToken } });
    } catch (err) {
      res.status(401).json({ error: err.message });
>>>>>>> f63ac94 (Add working createAuth wrapper with File/Postgres/Mongo/Redis support)
    }
  });

  router.post('/logout', async (req, res) => {
    try {
<<<<<<< HEAD
      await auth.invalidateRefreshToken(req.body.refreshToken);
      res.json({ 
        message: 'Logged out successfully',
        code: 'AUTH_LOGOUT_SUCCESS'
      });
    } catch (err) {
      res.status(500).json({ 
        error: err.message,
        code: 'AUTH_LOGOUT_FAILED'
      });
    }
  });

  // Method to create custom registration handlers
  router.register = (options = {}) => {
    return async (req, res) => {
      try {
        const { username, password, ...extras } = req.body;
        
        if (options.validate && !await options.validate(username, password, extras)) {
          return res.status(400).json({ 
            error: 'Custom validation failed',
            code: 'AUTH_CUSTOM_VALIDATION_FAILED'
          });
        }

        const result = await auth.register(username, password);
        const extendedUser = options.extend ? 
          await options.extend(result.user, extras) : 
          result.user;

        res.json({
          user: extendedUser,
          tokens: {
            access: result.accessToken,
            refresh: result.refreshToken
          }
        });
      } catch (err) {
        res.status(400).json({ 
          error: err.message,
          code: 'AUTH_CUSTOM_REGISTRATION_FAILED'
        });
      }
    };
  };

  // Initialize additional features if configured
  const mfa = config.mfa ? new MFAProvider(config.mfa) : null;
  const social = config.social ? new SocialAuthProvider(config.social) : null;
  const sessions = config.sessions ? new SessionManager(adapter) : null;

  return {
    routes: router,
    protect,
    auth,
    // Convenience methods
    verify: auth.verify.bind(auth),
    invalidateUser: auth.invalidateAllRefreshTokens.bind(auth),
    getUser: auth.getUser.bind(auth),
    // Extension points
    extend: (handlers) => {
      auth.options.extend = { ...auth.options.extend, ...handlers };
    },
    validate: (validators) => {
      auth.options.validate = { ...auth.options.validate, ...validators };
    },
    // New feature methods
    mfa: mfa ? {
      enable: async (username) => {
        const secret = mfa.generateSecret();
        const qr = await mfa.generateQRCode(username, secret);
        const backupCodes = mfa.generateBackupCodes();
        return { secret, qr, backupCodes };
      },
      verify: (token, secret) => mfa.verifyToken(token, secret),
      recovery: {
        generateKey: () => mfa.generateRecoveryKey(),
        encryptSecret: (secret, key) => mfa.encryptSecret(secret, key),
        decryptSecret: (data, key) => mfa.decryptSecret(data, key)
      }
    } : null,
    social: social ? {
      setup: (provider, config) => social.setupProvider(provider, config),
      getAuthUrl: (provider, state) => social.getAuthorizationUrl(provider, state),
      authenticate: async (provider, code) => {
        const tokens = await social.exchangeCode(provider, code);
        const profile = await social.getUserProfile(provider, tokens.access_token);
        return { tokens, profile };
      }
    } : null,
    sessions: sessions ? {
      create: (userId, req) => sessions.createSession(userId, req),
      list: (userId) => sessions.getSessions(userId),
      invalidate: (sessionId) => sessions.invalidateSession(sessionId),
      invalidateAll: (userId, except) => sessions.invalidateAllSessions(userId, except),
      security: {
        checkSuspicious: (session, req) => sessions.detectSuspiciousActivity(session, req)
      }
    } : null
  };
=======
      let refreshToken = req.body && req.body.refreshToken;
      if (useCookies) {
        const cookies = req.headers.cookie ? cookie.parse(req.headers.cookie) : {};
        refreshToken = refreshToken || cookies[cookieName];
      }
      if (!refreshToken) return res.status(400).json({ error: 'refreshToken required' });
      await adapter.invalidateRefreshToken(refreshToken);
      if (useCookies) {
        const clear = cookie.serialize(cookieName, '', { httpOnly: true, path: '/', expires: new Date(0) });
        const clears = [clear];
        if (csrfEnabled) clears.push(cookie.serialize(csrfCookieName, '', { httpOnly: false, path: '/', expires: new Date(0) }));
        res.setHeader('Set-Cookie', clears);
      }
      res.json({ message: 'Logged out successfully' });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  return { routes: router, protect, auth };
>>>>>>> f63ac94 (Add working createAuth wrapper with File/Postgres/Mongo/Redis support)
}
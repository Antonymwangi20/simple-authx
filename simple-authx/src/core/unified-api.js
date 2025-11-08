import { Router } from 'express';
import { AuthManager } from './auth.js';
import { PostgresAdapter } from '../adapters/postgresAdapter.mjs';
import { FileAdapter } from '../adapters/file-adapter.js';
import { connectMongo, MongoAdapter } from '../adapters/mongoAdapters.mjs';
import { connectRedis, RedisAdapter } from '../adapters/redisAdapter.mjs';
import { MFAProvider } from '../security/mfa.js';
import { SocialAuthProvider } from '../security/social.js';
import { SessionManager } from '../security/sessions.js';
import { SecurityManager } from '../security/security.js';
import { PasswordManager } from '../security/password.js';
import { AuditLogger } from '../security/audit.js';
import cookie from 'cookie';
import crypto from 'crypto';

/**
 * Unified Auth API - One function to rule them all
 * 
 * @example Simple in-memory (dev/testing)
 * const auth = createAuth();
 * 
 * @example File storage
 * const auth = createAuth({ storage: 'file', file: './data/auth.json' });
 * 
 * @example Production Postgres
 * const auth = await createAuth({
 *   storage: 'postgres',
 *   postgres: { connectionString: process.env.DATABASE_URL },
 *   plugins: {
 *     mfa: { issuer: 'MyApp' },
 *     social: { google: { clientId: '...', clientSecret: '...' } }
 *   }
 * });
 */
export async function createAuth(config = {}) {
  // Normalize config - support legacy formats
  config = normalizeConfig(config);
  
  // 1. Setup storage adapter
  const adapter = await setupAdapter(config);
  
  // 2. Initialize core auth
  const authManager = new AuthManager({
    adapter,
    secret: config.secret || process.env.JWT_SECRET || 'dev_secret',
    refreshSecret: config.refreshSecret || process.env.JWT_REFRESH_SECRET || 'dev_refresh_secret',
    accessExpiry: config.accessExpiresIn || config.accessExpiry || '15m',
    refreshExpiry: config.refreshExpiresIn || config.refreshExpiry || '7d',
    hooks: config.hooks || {}
  });
  
  // 3. Setup plugins (optional advanced features)
  const plugins = await setupPlugins(config.plugins || {}, adapter, authManager);
  
  // 4. Create Express router with all routes
  const router = createRouter(authManager, plugins, config);
  
  // 5. Create protection middleware
  const protect = createProtectMiddleware(authManager, config);
  
  // 6. Return unified interface
  return {
    // Core
    routes: router,
    router, // Alias for backwards compatibility
    protect,
    
    // Direct access to managers
    auth: authManager,
    adapter,
    
    // Plugins (available if configured)
    mfa: plugins.mfa || null,
    social: plugins.social || null,
    sessions: plugins.sessions || null,
    security: plugins.security || null,
    password: plugins.password || null,
    audit: plugins.audit || null,
    
    // Utility methods
    generateTokens: (payload) => authManager.generateTokens(payload),
    verifyAccess: (token) => authManager.verifyAccess(token),
    
    // Lifecycle
    async close() {
      if (adapter.close) await adapter.close();
      if (plugins.redis) await plugins.redis.quit();
    }
  };
}

/**
 * Normalize configuration from various formats
 */
function normalizeConfig(config) {
  // Handle string shorthand: createAuth('./data/auth.json')
  if (typeof config === 'string') {
    return { storage: 'file', file: config };
  }
  
  // Auto-detect storage type from config keys
  if (!config.storage) {
    if (config.mongodb) config.storage = 'mongodb';
    else if (config.postgres) config.storage = 'postgres';
    else if (config.redis) config.storage = 'redis';
    else if (config.file) config.storage = 'file';
    else config.storage = 'memory';
  }
  
  // Set defaults
  return {
    storage: 'memory',
    cookies: config.cookies || {},
    csrf: config.csrf || {},
    plugins: config.plugins || {},
    ...config
  };
}

/**
 * Setup storage adapter based on config
 */
async function setupAdapter(config) {
  const { storage } = config;
  
  switch (storage) {
    case 'mongodb':
      await connectMongo(config.mongodb || config.uri || 'mongodb://localhost:27017/authx');
      return new MongoAdapter();
      
    case 'postgres':
      return new PostgresAdapter(
        config.postgres || { connectionString: process.env.DATABASE_URL }
      );
      
    case 'redis':
      await connectRedis(config.redis || { url: 'redis://localhost:6379' });
      // Redis needs a user store - default to file
      const userStore = new FileAdapter(config.file || './data/users.json');
      await userStore.init();
      return new RedisAdapter(userStore, { prefix: config.prefix || 'authx:' });
      
    case 'file':
      const fileAdapter = new FileAdapter(config.file || './data/auth.json');
      await fileAdapter.init();
      return fileAdapter;
      
    case 'memory':
    default:
      return createMemoryAdapter();
  }
}

/**
 * In-memory adapter for dev/testing
 */
function createMemoryAdapter() {
  const users = new Map();
  const tokens = new Map();
  
  return {
    async findUser(username) {
      return users.get(username) || null;
    },
    
    async createUser(username, password) {
      const bcrypt = (await import('bcryptjs')).default;
      const hash = await bcrypt.hash(password, 10);
      const id = Date.now().toString();
      const user = { id, username, password_hash: hash };
      users.set(username, user);
      return user;
    },
    
    async verifyUser(username, password) {
      const user = users.get(username);
      if (!user) return null;
      const bcrypt = (await import('bcryptjs')).default;
      const ok = await bcrypt.compare(password, user.password_hash);
      return ok ? user : null;
    },
    
    async storeRefreshToken(userId, token, expiry) {
      const hash = crypto.createHash('sha256').update(token).digest('hex');
      tokens.set(hash, { userId, expiresAt: expiry });
    },
    
    async findRefreshToken(token) {
      const hash = crypto.createHash('sha256').update(token).digest('hex');
      return tokens.get(hash) || null;
    },
    
    async invalidateRefreshToken(token) {
      const hash = crypto.createHash('sha256').update(token).digest('hex');
      tokens.delete(hash);
    },
    
    async invalidateAllRefreshTokens(userId) {
      for (const [hash, data] of tokens.entries()) {
        if (data.userId === userId) tokens.delete(hash);
      }
    }
  };
}

/**
 * Setup optional plugins based on config
 */
async function setupPlugins(pluginConfig, adapter, authManager) {
  const plugins = {};
  
  // MFA Plugin
  if (pluginConfig.mfa) {
    plugins.mfa = new MFAProvider({
      issuer: pluginConfig.mfa.issuer || 'AuthX',
      ...pluginConfig.mfa
    });
  }
  
  // Social Login Plugin
  if (pluginConfig.social) {
    plugins.social = new SocialAuthProvider();
    for (const [provider, config] of Object.entries(pluginConfig.social)) {
      await plugins.social.setupProvider(provider, config);
    }
  }
  
  // Session Manager Plugin
  if (pluginConfig.sessions) {
    plugins.sessions = new SessionManager(adapter);
  }
  
  // Security Plugin (rate limiting, IP tracking)
  if (pluginConfig.security) {
    let redis = null;
    if (pluginConfig.security.redis) {
      redis = await connectRedis(pluginConfig.security.redis);
      plugins.redis = redis;
    }
    plugins.security = new SecurityManager({
      redis,
      ...pluginConfig.security
    });
  }
  
  // Password Manager Plugin
  if (pluginConfig.password) {
    plugins.password = new PasswordManager(pluginConfig.password);
  }
  
  // Audit Logger Plugin
  if (pluginConfig.audit) {
    plugins.audit = new AuditLogger(pluginConfig.audit);
  }
  
  return plugins;
}

/**
 * Create Express router with all auth routes
 */
function createRouter(authManager, plugins, config) {
  const router = Router();
  
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
  
  // Helper to set cookies + CSRF
  function setCookies(res, refreshToken) {
    const cookies = [];
    cookies.push(cookie.serialize(cookieName, refreshToken, cookieOptions));
    
    if (csrfEnabled) {
      const csrfToken = crypto.randomBytes(32).toString('hex');
      cookies.push(cookie.serialize(csrfCookieName, csrfToken, {
        httpOnly: false,
        sameSite: cookieOptions.sameSite,
        path: '/'
      }));
    }
    
    res.setHeader('Set-Cookie', cookies);
  }
  
  // Helper to validate CSRF
  function validateCSRF(req) {
    if (!csrfEnabled) return true;
    const cookies = req.headers.cookie ? cookie.parse(req.headers.cookie) : {};
    const headerVal = req.headers[csrfHeaderName];
    const cookieVal = cookies[csrfCookieName];
    return headerVal && cookieVal && headerVal === cookieVal;
  }
  
  // Core Routes
  router.post('/register', async (req, res) => {
    try {
      const { password, ...userData } = req.body || {};
      
      if (!password) {
        return res.status(400).json({ error: 'password required' });
      }
      
      // Validate required fields based on config
      const config = authManager.config?.userFields || { required: ['username'] };
      for (const field of config.required || ['username']) {
        if (!req.body[field]) {
          return res.status(400).json({ 
            error: `${field} is required` 
          });
        }
      }
      
      // Optional: Password strength validation
      if (plugins.password) {
        await plugins.password.validatePassword(
          password, 
          userData.username, 
          userData.email
        );
      }
      
      const result = await authManager.register({ password, ...userData });
      
      // Optional: Audit log
      if (plugins.audit) {
        await plugins.audit.log({
          type: 'register',
          username: userData.username || userData.email || userData.phoneNumber,
          success: true,
          ip: req.ip,
          userAgent: req.headers['user-agent']
        });
      }
      
      if (useCookies) {
        setCookies(res, result.refreshToken);
        return res.json({
          user: {
            id: result.user.id,
            username: result.user.username,
            email: result.user.email,
            phoneNumber: result.user.phoneNumber
          },
          accessToken: result.accessToken
        });
      }
      
      res.json({
        user: {
          id: result.user.id,
          username: result.user.username,
          email: result.user.email,
          phoneNumber: result.user.phoneNumber
        },
        accessToken: result.accessToken,
        refreshToken: result.refreshToken
      });
    } catch (err) {
      if (plugins.audit) {
        await plugins.audit.log({
          type: 'register',
          username: req.body?.username || req.body?.email,
          success: false,
          ip: req.ip,
          details: err.message
        });
      }
      res.status(400).json({ error: err.message });
    }
  });

  // Update login route to support any identifier
  // Fixed login route for unified-api.js
// Replace the existing login route with this implementation

router.post('/login', async (req, res) => {
  console.log('[LOGIN] Request received');
  console.log('[LOGIN] Body:', JSON.stringify(req.body, null, 2));
  
  try {
    const { identifier, username, email, phoneNumber, password } = req.body || {};
    
    // Support both old format (username/email/phoneNumber) and new format (identifier)
    const loginIdentifier = identifier || username || email || phoneNumber;
    
    console.log('[LOGIN] Login identifier:', loginIdentifier);
    console.log('[LOGIN] Password provided:', !!password);
    
    if (!loginIdentifier || !password) {
      console.log('[LOGIN] Missing credentials');
      return res.status(400).json({ 
        error: 'identifier (or username/email/phoneNumber) and password required',
        received: {
          identifier: !!loginIdentifier,
          password: !!password
        }
      });
    }
    
    // Optional: Check if blocked
    if (plugins.security) {
      console.log('[LOGIN] Checking security blocks...');
      const blocked = await plugins.security.isBlocked(loginIdentifier, req.ip);
      if (blocked.userBlocked || blocked.ipBlocked) {
        console.log('[LOGIN] User/IP blocked');
        return res.status(429).json({
          error: 'Too many failed attempts. Please try again later.',
          remainingAttempts: blocked.remainingAttempts
        });
      }
    }
    
    console.log('[LOGIN] Attempting login via AuthManager...');
    
    // Try loginWithIdentifier first (supports email/username/phone)
    let result;
    try {
      if (authManager.loginWithIdentifier) {
        console.log('[LOGIN] Using loginWithIdentifier method');
        result = await authManager.loginWithIdentifier(loginIdentifier, password);
      } else {
        console.log('[LOGIN] Falling back to login method');
        result = await authManager.login(loginIdentifier, password);
      }
    } catch (loginError) {
      console.error('[LOGIN] Login failed:', loginError.message);
      console.error('[LOGIN] Stack:', loginError.stack);
      
      // Track failure
      if (plugins.security) {
        await plugins.security.trackLoginAttempt(loginIdentifier, req.ip, false);
      }
      
      if (plugins.audit) {
        await plugins.audit.log({
          type: 'login',
          username: loginIdentifier,
          success: false,
          ip: req.ip,
          details: loginError.message
        });
      }
      
      return res.status(401).json({ 
        error: 'Invalid credentials',
        debug: process.env.NODE_ENV === 'development' ? {
          message: loginError.message,
          identifier: loginIdentifier
        } : undefined
      });
    }
    
    console.log('[LOGIN] Login successful');
    console.log('[LOGIN] User ID:', result.user.id);
    
    // Track success
    if (plugins.security) {
      await plugins.security.trackLoginAttempt(loginIdentifier, req.ip, true);
    }
    
    // Create session
    if (plugins.sessions) {
      try {
        await plugins.sessions.createSession(result.user.id, req);
      } catch (sessionError) {
        console.error('[LOGIN] Session creation failed:', sessionError.message);
        // Don't fail the login if session creation fails
      }
    }
    
    // Audit log
    if (plugins.audit) {
      await plugins.audit.log({
        type: 'login',
        username: loginIdentifier,
        success: true,
        ip: req.ip,
        userAgent: req.headers['user-agent']
      });
    }
    
    if (useCookies) {
      console.log('[LOGIN] Setting cookies...');
      setCookies(res, result.refreshToken);
      return res.json({
        user: { 
          id: result.user.id, 
          username: result.user.username,
          email: result.user.email,
          phoneNumber: result.user.phoneNumber
        },
        accessToken: result.accessToken
      });
    }
    
    console.log('[LOGIN] Sending response...');
    res.json({
      user: { 
        id: result.user.id, 
        username: result.user.username,
        email: result.user.email,
        phoneNumber: result.user.phoneNumber
      },
      accessToken: result.accessToken,
      refreshToken: result.refreshToken
    });
  } catch (err) {
    console.error('[LOGIN] Unexpected error:', err.message);
    console.error('[LOGIN] Stack:', err.stack);
    
    // Track failure
    if (plugins.security) {
      try {
        await plugins.security.trackLoginAttempt(req.body?.username || req.body?.identifier, req.ip, false);
      } catch (secError) {
        console.error('[LOGIN] Security tracking failed:', secError.message);
      }
    }
    
    if (plugins.audit) {
      try {
        await plugins.audit.log({
          type: 'login',
          username: req.body?.username || req.body?.identifier,
          success: false,
          ip: req.ip,
          details: err.message
        });
      } catch (auditError) {
        console.error('[LOGIN] Audit logging failed:', auditError.message);
      }
    }
    
    res.status(500).json({ 
      error: 'Login failed',
      debug: process.env.NODE_ENV === 'development' ? {
        message: err.message,
        stack: err.stack
      } : undefined
    });
  }
});
  
  router.post('/refresh', async (req, res) => {
    try {
      let refreshToken = req.body?.refreshToken;
      
      if (useCookies) {
        const cookies = req.headers.cookie ? cookie.parse(req.headers.cookie) : {};
        refreshToken = refreshToken || cookies[cookieName];
        
        if (!validateCSRF(req)) {
          return res.status(403).json({ error: 'CSRF validation failed' });
        }
      }
      
      if (!refreshToken) {
        return res.status(400).json({ error: 'Refresh token required' });
      }
      
      const tokens = await authManager.refresh(refreshToken);
      
      if (useCookies) {
        setCookies(res, tokens.refreshToken);
        return res.json({ accessToken: tokens.accessToken });
      }
      
      res.json({
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken
      });
    } catch (err) {
      res.status(401).json({ error: err.message });
    }
  });
  
  router.post('/logout', async (req, res) => {
    try {
      let refreshToken = req.body?.refreshToken;
      
      if (useCookies) {
        const cookies = req.headers.cookie ? cookie.parse(req.headers.cookie) : {};
        refreshToken = refreshToken || cookies[cookieName];
      }
      
      if (refreshToken) {
        await authManager.adapter.invalidateRefreshToken(refreshToken);
      }
      
      if (useCookies) {
        const clear = cookie.serialize(cookieName, '', {
          httpOnly: true,
          path: '/',
          expires: new Date(0)
        });
        const clears = [clear];
        
        if (csrfEnabled) {
          clears.push(cookie.serialize(csrfCookieName, '', {
            httpOnly: false,
            path: '/',
            expires: new Date(0)
          }));
        }
        
        res.setHeader('Set-Cookie', clears);
      }
      
      res.json({ message: 'Logged out successfully' });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
  
  // Plugin-specific routes
  if (plugins.mfa) {
    addMFARoutes(router, plugins.mfa, authManager);
  }
  
  if (plugins.social) {
    addSocialRoutes(router, plugins.social, authManager, config);
  }
  
  if (plugins.sessions) {
    addSessionRoutes(router, plugins.sessions);
  }
  
  return router;
}

/**
 * Add MFA routes if plugin enabled
 */
function addMFARoutes(router, mfa, authManager) {
  router.post('/mfa/enable', async (req, res) => {
    try {
      // Requires authentication
      const token = req.headers.authorization?.split(' ')[1];
      if (!token) return res.status(401).json({ error: 'Authentication required' });
      
      const decoded = authManager.verifyAccess(token);
      const secret = mfa.generateSecret();
      const qr = await mfa.generateQRCode(decoded.username || decoded.userId, secret);
      const backupCodes = mfa.generateBackupCodes();
      
      // Note: Secret must be persisted server-side by the application
      res.json({ secret, qr, backupCodes });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
  
  router.post('/mfa/verify', async (req, res) => {
    try {
      const { token, secret } = req.body || {};
      if (!token || !secret) {
        return res.status(400).json({ error: 'token and secret required' });
      }
      
      const valid = mfa.verifyToken(token, secret);
      res.json({ valid });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
}

/**
 * Add social login routes if plugin enabled
 */
function addSocialRoutes(router, social, authManager, config) {
  const providers = Array.from(social.providers.keys());
  
  for (const provider of providers) {
    router.get(`/${provider}`, (req, res) => {
      const state = crypto.randomBytes(16).toString('hex');
      // Note: State should be stored in session for CSRF protection
      const url = social.getAuthorizationUrl(provider, state);
      res.redirect(url);
    });
    
    router.get(`/${provider}/callback`, async (req, res) => {
      try {
        const { code, state } = req.query;
        if (!code) return res.status(400).json({ error: 'Code required' });
        
        const result = await social.exchangeCode(provider, code);
        const profile = await social.getUserProfile(provider, result.access_token);
        
        // Note: Application must map social profile to local user
        res.json({ profile, tokens: result });
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });
  }
}

/**
 * Add session management routes if plugin enabled
 */
function addSessionRoutes(router, sessions) {
  router.get('/sessions', async (req, res) => {
    try {
      const token = req.headers.authorization?.split(' ')[1];
      if (!token) return res.status(401).json({ error: 'Authentication required' });
      
      // Extract userId from token (requires authManager access)
      const decoded = JSON.parse(
        Buffer.from(token.split('.')[1], 'base64').toString()
      );
      
      const userSessions = await sessions.getSessions(decoded.userId);
      res.json({ sessions: userSessions });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
  
  router.delete('/sessions/:sessionId', async (req, res) => {
    try {
      await sessions.invalidateSession(req.params.sessionId);
      res.json({ message: 'Session invalidated' });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
}

/**
 * Protection middleware
 */
function createProtectMiddleware(authManager, config) {
  return (req, res, next) => {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    try {
      const decoded = authManager.verifyAccess(token);
      req.user = decoded;
      next();
    } catch (err) {
      res.status(401).json({ error: 'Invalid or expired token' });
    }
  };
}


export { normalizeConfig, setupAdapter, createMemoryAdapter };
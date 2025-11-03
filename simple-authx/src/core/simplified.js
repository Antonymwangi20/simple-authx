import { Router } from 'express';
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
    }
  });

  router.post('/login', async (req, res) => {
    try {
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
    }
  });

  router.post('/refresh', async (req, res) => {
    try {
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
    }
  });

  router.post('/logout', async (req, res) => {
    try {
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
}
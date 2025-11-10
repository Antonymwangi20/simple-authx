import { Router } from 'express';
import cookie from 'cookie';
import { AuthManager } from './auth.js';
import { PostgresAdapter } from '../adapters/postgresAdapter.mjs';
import { FileAdapter } from '../adapters/file-adapter.js';
import { connectMongo, MongoAdapter } from '../adapters/mongoAdapters.mjs';
import { connectRedis, RedisAdapter } from '../adapters/redisAdapter.mjs';

export async function createSimplifiedAuth(config = {}) {
  const router = Router();

  // Normalize string config to file path for convenience
  if (typeof config === 'string') {
    config = { file: config };
  }

  // Choose adapter: Mongo, Postgres, Redis, or File (default)
  let adapter;
  if (config.mongodb) {
    await connectMongo(config.mongodb);
    adapter = new MongoAdapter();
  } else if (config.postgres) {
    adapter = new PostgresAdapter(config.postgres);
  } else if (config.redis) {
    await connectRedis(config.redis);
    const userStore = new FileAdapter(config.file || './data/auth-data.json');
    await userStore.init();
    adapter = new RedisAdapter(userStore, { prefix: config.prefix || 'authx:refresh:' });
  } else {
    adapter = new FileAdapter(config.file || './data/auth-data.json');
    await adapter.init();
  }

  const auth = new AuthManager({
    adapter,
    secret: config.secret || process.env.JWT_SECRET || 'dev_secret',
    refreshSecret: config.refreshSecret || process.env.JWT_REFRESH_SECRET || 'dev_refresh_secret',
    accessExpiry: config.accessExpiresIn || '15m',
    refreshExpiry: config.refreshExpiresIn || '7d',
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
      if (!username || !password)
        return res.status(400).json({ error: 'username and password required' });
      const result = await auth.register(username, password);
      if (useCookies) {
        // set refresh token cookie and optional CSRF token cookie
        const refreshCookie = cookie.serialize(cookieName, result.refreshToken, {
          ...cookieOptions,
        });
        const csrfToken = csrfEnabled ? Math.random().toString(36).slice(2) : null;
        const headers = [];
        headers.push(refreshCookie);
        if (csrfEnabled) {
          headers.push(
            cookie.serialize(csrfCookieName, csrfToken, {
              httpOnly: false,
              sameSite: cookieOptions.sameSite,
              path: '/',
            })
          );
        }
        res.setHeader('Set-Cookie', headers);
        return res.json({
          user: { id: result.user.id, username: result.user.username },
          tokens: { access: result.accessToken },
        });
      }
      res.json({
        user: { id: result.user.id, username: result.user.username },
        tokens: { access: result.accessToken, refresh: result.refreshToken },
      });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  router.post('/login', async (req, res) => {
    try {
      const { username, password } = req.body || {};
      if (!username || !password)
        return res.status(400).json({ error: 'username and password required' });
      const result = await auth.login(username, password);
      if (useCookies) {
        const refreshCookie = cookie.serialize(cookieName, result.refreshToken, {
          ...cookieOptions,
        });
        const csrfToken = csrfEnabled ? Math.random().toString(36).slice(2) : null;
        const headers = [];
        headers.push(refreshCookie);
        if (csrfEnabled) {
          headers.push(
            cookie.serialize(csrfCookieName, csrfToken, {
              httpOnly: false,
              sameSite: cookieOptions.sameSite,
              path: '/',
            })
          );
        }
        res.setHeader('Set-Cookie', headers);
        return res.json({
          user: { id: result.user.id, username: result.user.username },
          tokens: { access: result.accessToken },
        });
      }
      res.json({
        user: { id: result.user.id, username: result.user.username },
        tokens: { access: result.accessToken, refresh: result.refreshToken },
      });
    } catch (err) {
      res.status(401).json({ error: err.message });
    }
  });

  router.post('/refresh', async (req, res) => {
    try {
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
          ...cookieOptions,
        });
        const headers = [refreshCookie];
        res.setHeader('Set-Cookie', headers);
        return res.json({ tokens: { access: tokens.accessToken } });
      }
      res.json({ tokens: { access: tokens.accessToken, refresh: tokens.refreshToken } });
    } catch (err) {
      res.status(401).json({ error: err.message });
    }
  });

  router.post('/logout', async (req, res) => {
    try {
      let refreshToken = req.body && req.body.refreshToken;
      if (useCookies) {
        const cookies = req.headers.cookie ? cookie.parse(req.headers.cookie) : {};
        refreshToken = refreshToken || cookies[cookieName];
      }
      if (!refreshToken) return res.status(400).json({ error: 'refreshToken required' });
      await adapter.invalidateRefreshToken(refreshToken);
      if (useCookies) {
        const clear = cookie.serialize(cookieName, '', {
          httpOnly: true,
          path: '/',
          expires: new Date(0),
        });
        const clears = [clear];
        if (csrfEnabled)
          clears.push(
            cookie.serialize(csrfCookieName, '', {
              httpOnly: false,
              path: '/',
              expires: new Date(0),
            })
          );
        res.setHeader('Set-Cookie', clears);
      }
      res.json({ message: 'Logged out successfully' });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  return { routes: router, protect, auth };
}

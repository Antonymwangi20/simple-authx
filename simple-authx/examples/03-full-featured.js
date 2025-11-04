// examples/03-full-featured.js
// Full-featured example with MFA, Social Login, Sessions, and all plugins

import express from 'express';
import { createAuth } from '../index.mjs';
import 'dotenv/config';

const app = express();
app.use(express.json());

console.log('🚀 Starting Full-Featured Example...\n');

// Full-featured configuration with all plugins
const auth = await createAuth({
  // Storage
  storage: process.env.DATABASE_URL ? 'postgres' : 'file',
  postgres: {
    connectionString: process.env.DATABASE_URL
  },
  file: './data/full-featured-auth.json',
  
  // JWT configuration
  secret: process.env.JWT_SECRET || 'dev_access_secret_change_in_production',
  refreshSecret: process.env.JWT_REFRESH_SECRET || 'dev_refresh_secret_change_in_production',
  accessExpiry: '15m',
  refreshExpiry: '30d',
  
  // Cookie-based auth
  cookies: {
    refresh: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    domain: process.env.COOKIE_DOMAIN
  },
  
  // CSRF protection
  csrf: {
    enabled: true,
    cookieName: 'csrfToken',
    headerName: 'x-csrf-token'
  },
  
  // ALL PLUGINS ENABLED
  plugins: {
    // Multi-Factor Authentication (MFA/2FA)
    mfa: {
      issuer: process.env.MFA_ISSUER || 'SimpleAuthX',
      algorithm: 'sha256',
      window: 1  // Allow 1 time-step before/after
    },
    
    // Social Authentication (OAuth)
    social: {
      google: process.env.GOOGLE_CLIENT_ID ? {
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback'
      } : undefined,
      
      github: process.env.GITHUB_CLIENT_ID ? {
        clientId: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackURL: process.env.GITHUB_CALLBACK_URL || 'http://localhost:3000/auth/github/callback'
      } : undefined,
      
      facebook: process.env.FACEBOOK_CLIENT_ID ? {
        clientId: process.env.FACEBOOK_CLIENT_ID,
        clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
        callbackURL: process.env.FACEBOOK_CALLBACK_URL || 'http://localhost:3000/auth/facebook/callback'
      } : undefined
    },
    
    // Session Management
    sessions: {
      redis: process.env.REDIS_URL,
      maxSessions: 5,           // Max 5 concurrent sessions per user
      slidingExpiry: true,      // Extend session on activity
      trackLocation: true,      // Track IP/location
      trackDevice: true         // Track device info
    },
    
    // Security & Rate Limiting
    security: {
      rateLimit: true,
      maxAttempts: 5,
      windowMs: 15 * 60 * 1000,
      blockDuration: 60 * 60 * 1000,
      ipWhitelist: ['127.0.0.1', '::1']
    },
    
    // Password Strength Validation
    password: {
      minStrength: 3,              // Strong passwords required
      minLength: 10,
      requireUppercase: true,
      requireNumbers: true,
      requireSpecialChars: true,
      blacklist: ['password', 'admin', '12345678', 'qwerty']
    },
    
    // Audit Logging
    audit: {
      events: [
        'login', 
        'register', 
        'refresh', 
        'logout', 
        'failed_login',
        'mfa_enabled',
        'mfa_disabled',
        'social_login',
        'session_created',
        'session_revoked'
      ],
      storage: 'database',
      retentionDays: 365,  // Keep logs for 1 year
      includeMetadata: true // Include IP, user agent, etc.
    }
  },
  
  // Hooks
  hooks: {
    async onRegister(user) {
      console.log(`📝 New user: ${user.username} (${user.id})`);
      // Welcome email, analytics, etc.
    },
    
    async onLogin(user) {
      console.log(`✅ Login: ${user.username}`);
      // Track login, security alerts, etc.
    },
    
    async onError(error) {
      console.error('❌ Error:', error.message);
      // Error tracking (Sentry, etc.)
    }
  }
});

// Mount auth routes
app.use('/auth', auth.routes);

// ==================== MFA Routes ====================

// Enable MFA for user
app.post('/api/mfa/enable', auth.protect, async (req, res) => {
  try {
    const userId = req.user.userId;
    const username = req.user.username || `user${userId}`;
    
    // Generate secret
    const secret = auth.mfa.generateSecret();
    
    // Generate QR code
    const qrCode = await auth.mfa.generateQRCode(secret, username);
    
    // Generate backup codes
    const backupCodes = auth.mfa.generateBackupCodes();
    
    // TODO: Store secret and backup codes in user record
    
    res.json({
      secret,
      qrCode,
      backupCodes,
      message: 'Scan the QR code with your authenticator app'
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Verify MFA token
app.post('/api/mfa/verify', auth.protect, (req, res) => {
  try {
    const { secret, token } = req.body;
    
    if (!secret || !token) {
      return res.status(400).json({ error: 'secret and token required' });
    }
    
    const valid = auth.mfa.verifyToken(secret, token);
    
    if (valid) {
      res.json({ message: 'MFA enabled successfully', verified: true });
    } else {
      res.status(401).json({ error: 'Invalid token', verified: false });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== Session Management Routes ====================

// List user sessions
app.get('/api/sessions', auth.protect, async (req, res) => {
  try {
    if (!auth.sessions) {
      return res.status(501).json({ error: 'Session management not enabled' });
    }
    
    const userId = req.user.userId;
    const sessions = await auth.sessions.getUserSessions(userId);
    
    res.json({ sessions });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Revoke specific session
app.delete('/api/sessions/:sessionId', auth.protect, async (req, res) => {
  try {
    if (!auth.sessions) {
      return res.status(501).json({ error: 'Session management not enabled' });
    }
    
    const { sessionId } = req.params;
    await auth.sessions.revokeSession(sessionId);
    
    res.json({ message: 'Session revoked successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Revoke all other sessions
app.post('/api/sessions/revoke-others', auth.protect, async (req, res) => {
  try {
    if (!auth.sessions) {
      return res.status(501).json({ error: 'Session management not enabled' });
    }
    
    const userId = req.user.userId;
    const currentSessionId = req.user.sessionId; // Assuming this is in token
    
    await auth.sessions.revokeOtherSessions(userId, currentSessionId);
    
    res.json({ message: 'All other sessions revoked' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== Password Management Routes ====================

// Check password strength
app.post('/api/password/strength', (req, res) => {
  try {
    if (!auth.password) {
      return res.status(501).json({ error: 'Password validation not enabled' });
    }
    
    const { password } = req.body;
    
    if (!password) {
      return res.status(400).json({ error: 'password required' });
    }
    
    const strength = auth.password.checkStrength(password);
    
    res.json({ strength });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Change password
app.post('/api/password/change', auth.protect, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.userId;
    
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'currentPassword and newPassword required' });
    }
    
    // Verify current password
    // TODO: Implement password verification
    
    // Validate new password
    if (auth.password) {
      await auth.password.validatePassword(newPassword, req.user.username);
    }
    
    // Update password
    // TODO: Implement password update
    
    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ==================== Audit Logs Routes ====================

// Query audit logs (admin only)
app.get('/api/audit/logs', auth.protect, async (req, res) => {
  try {
    if (!auth.audit) {
      return res.status(501).json({ error: 'Audit logging not enabled' });
    }
    
    const { userId, event, startDate, endDate } = req.query;
    
    const logs = await auth.audit.query({
      userId,
      event,
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined
    });
    
    res.json({ logs });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== Protected Routes ====================

app.get('/api/profile', auth.protect, (req, res) => {
  res.json({ 
    message: 'Your profile',
    user: req.user 
  });
});

// Admin-only route
import { requireRole } from '../index.mjs';

app.get('/api/admin', auth.protect, requireRole('admin'), (req, res) => {
  res.json({ 
    message: 'Admin dashboard',
    user: req.user 
  });
});

// ==================== Public Routes ====================

app.get('/', (req, res) => {
  const socialProviders = [];
  if (auth.social) {
    if (auth.social.providers?.google) socialProviders.push('Google');
    if (auth.social.providers?.github) socialProviders.push('GitHub');
    if (auth.social.providers?.facebook) socialProviders.push('Facebook');
  }
  
  res.json({ 
    message: 'simple-authx full-featured example',
    environment: process.env.NODE_ENV || 'development',
    features: {
      storage: process.env.DATABASE_URL ? 'PostgreSQL' : 'File',
      cookieAuth: true,
      csrfProtection: true,
      mfa: !!auth.mfa,
      socialAuth: socialProviders,
      sessionManagement: !!auth.sessions,
      rateLimit: !!auth.security,
      passwordValidation: !!auth.password,
      auditLogging: !!auth.audit
    },
    endpoints: {
      auth: {
        register: 'POST /auth/register',
        login: 'POST /auth/login',
        refresh: 'POST /auth/refresh',
        logout: 'POST /auth/logout'
      },
      social: socialProviders.length > 0 ? {
        google: 'GET /auth/google',
        github: 'GET /auth/github',
        facebook: 'GET /auth/facebook'
      } : undefined,
      mfa: {
        enable: 'POST /api/mfa/enable',
        verify: 'POST /api/mfa/verify'
      },
      sessions: {
        list: 'GET /api/sessions',
        revoke: 'DELETE /api/sessions/:sessionId',
        revokeOthers: 'POST /api/sessions/revoke-others'
      },
      password: {
        strength: 'POST /api/password/strength',
        change: 'POST /api/password/change'
      },
      audit: {
        logs: 'GET /api/audit/logs'
      },
      protected: {
        profile: 'GET /api/profile',
        admin: 'GET /api/admin (admin only)'
      }
    }
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok',
    timestamp: new Date().toISOString()
  });
});

// Error handling
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production' 
      ? 'Internal server error' 
      : err.message
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log('');
  console.log('🎯 Enabled Features:');
  console.log(`   💾 Storage: ${process.env.DATABASE_URL ? 'PostgreSQL' : 'File'}`);
  console.log(`   🍪 Cookie Auth: enabled`);
  console.log(`   🛡️  CSRF: enabled`);
  console.log(`   🔐 MFA: ${auth.mfa ? 'enabled' : 'disabled'}`);
  console.log(`   🌐 Social Auth: ${auth.social ? 'enabled' : 'disabled'}`);
  if (auth.social) {
    if (auth.social.providers?.google) console.log('      - Google');
    if (auth.social.providers?.github) console.log('      - GitHub');
    if (auth.social.providers?.facebook) console.log('      - Facebook');
  }
  console.log(`   👥 Sessions: ${auth.sessions ? 'enabled' : 'disabled'}`);
  console.log(`   🚦 Rate Limit: ${auth.security ? 'enabled' : 'disabled'}`);
  console.log(`   🔒 Password Validation: ${auth.password ? 'enabled' : 'disabled'}`);
  console.log(`   📊 Audit Logs: ${auth.audit ? 'enabled' : 'disabled'}`);
  console.log('');
  console.log('📚 Visit http://localhost:3000 for all endpoints');
  console.log('');
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM signal received: closing HTTP server');
  await auth.close();
  process.exit(0);
});

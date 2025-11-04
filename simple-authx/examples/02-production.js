// examples/02-production.js
// Production-ready setup with PostgreSQL, cookies, CSRF, and security features

import express from 'express';
import { createAuth } from '../index.mjs';
import 'dotenv/config';

const app = express();
app.use(express.json());

console.log('🚀 Starting Production Example...\n');

// Production configuration
const auth = await createAuth({
  // Database storage (PostgreSQL recommended for production)
  storage: process.env.DATABASE_URL ? 'postgres' : 'file',
  
  // PostgreSQL configuration
  postgres: {
    connectionString: process.env.DATABASE_URL
  },
  
  // File fallback (if no DATABASE_URL)
  file: './data/production-auth.json',
  
  // JWT secrets (MUST use environment variables in production)
  secret: process.env.JWT_SECRET || 'dev_access_secret_change_in_production',
  refreshSecret: process.env.JWT_REFRESH_SECRET || 'dev_refresh_secret_change_in_production',
  
  // Token expiry
  accessExpiry: '15m',  // Short-lived access tokens
  refreshExpiry: '7d',   // Longer-lived refresh tokens
  
  // Cookie-based auth (recommended for SPAs)
  cookies: {
    refresh: true,                              // Store refresh token in cookie
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    sameSite: 'strict',                         // CSRF protection
    domain: process.env.COOKIE_DOMAIN || undefined,
    maxAge: 7 * 24 * 60 * 60 * 1000            // 7 days
  },
  
  // CSRF protection (important for cookie-based auth)
  csrf: {
    enabled: process.env.CSRF_ENABLED !== 'false', // Enable by default
    cookieName: 'csrfToken',
    headerName: 'x-csrf-token'
  },
  
  // Security plugins
  plugins: {
    // Rate limiting
    security: {
      rateLimit: true,
      maxAttempts: 5,                    // 5 attempts
      windowMs: 15 * 60 * 1000,          // per 15 minutes
      blockDuration: 60 * 60 * 1000,     // block for 1 hour
      ipWhitelist: ['127.0.0.1', '::1']  // Localhost bypass
    },
    
    // Password strength validation
    password: {
      minStrength: 2,              // 0-4 (zxcvbn score)
      minLength: 8,
      requireUppercase: true,
      requireNumbers: true,
      requireSpecialChars: false,  // Optional but recommended
      blacklist: ['password', 'admin', '12345678']
    },
    
    // Audit logging (track all auth events)
    audit: {
      events: ['login', 'register', 'refresh', 'logout', 'failed_login'],
      storage: 'database',           // Store in database
      retentionDays: 90              // Keep logs for 90 days
    }
  },
  
  // Custom hooks
  hooks: {
    async onRegister(user) {
      console.log(`📝 New user registered: ${user.username} (${user.id})`);
      // Send welcome email, track analytics, etc.
    },
    
    async onLogin(user) {
      console.log(`✅ User logged in: ${user.username}`);
      // Track login, notify user, etc.
    },
    
    async onError(error) {
      console.error('❌ Auth error:', error.message);
      // Send to error tracking service (Sentry, etc.)
    }
  }
});

// Mount auth routes
app.use('/auth', auth.routes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Protected route example
app.get('/api/profile', auth.protect, (req, res) => {
  res.json({ 
    message: 'Your profile',
    user: req.user 
  });
});

// Admin-only route example
import { requireRole } from '../index.mjs';

app.get('/api/admin', auth.protect, requireRole('admin'), (req, res) => {
  res.json({ 
    message: 'Admin dashboard',
    user: req.user 
  });
});

// Public route
app.get('/', (req, res) => {
  res.json({ 
    message: 'simple-authx production example',
    environment: process.env.NODE_ENV || 'development',
    storage: process.env.DATABASE_URL ? 'PostgreSQL' : 'File',
    features: {
      cookieAuth: true,
      csrfProtection: true,
      rateLimit: true,
      passwordValidation: true,
      auditLogging: true
    },
    endpoints: {
      register: 'POST /auth/register',
      login: 'POST /auth/login',
      refresh: 'POST /auth/refresh',
      logout: 'POST /auth/logout',
      profile: 'GET /api/profile (protected)',
      admin: 'GET /api/admin (admin only)'
    }
  });
});

// Error handling middleware
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
  console.log(`💾 Storage: ${process.env.DATABASE_URL ? 'PostgreSQL' : 'File'}`);
  console.log(`🍪 Cookie mode: enabled`);
  console.log(`🛡️  CSRF protection: ${process.env.CSRF_ENABLED !== 'false' ? 'enabled' : 'disabled'}`);
  console.log('');
  
  if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET) {
    console.log('⚠️  WARNING: Using development secrets!');
    console.log('   Set JWT_SECRET and JWT_REFRESH_SECRET environment variables for production.');
    console.log('');
  }
  
  if (!process.env.DATABASE_URL) {
    console.log('⚠️  WARNING: Using file storage!');
    console.log('   Set DATABASE_URL for PostgreSQL in production.');
    console.log('');
  }
  
  console.log('📚 Example usage with cookies:');
  console.log('');
  console.log('1. Register (refresh token set in cookie):');
  console.log(`   curl -X POST http://localhost:${PORT}/auth/register \\`);
  console.log('     -H "Content-Type: application/json" \\');
  console.log('     -d \'{"username":"alice","password":"SecureP@ss123"}\' \\');
  console.log('     -c cookies.txt');
  console.log('');
  console.log('2. Refresh (using cookie):');
  console.log(`   curl -X POST http://localhost:${PORT}/auth/refresh \\`);
  console.log('     -b cookies.txt \\');
  console.log('     -H "x-csrf-token: CSRF_TOKEN"');
  console.log('');
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM signal received: closing HTTP server');
  await auth.close();
  process.exit(0);
});

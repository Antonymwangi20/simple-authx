// 🔐 Simple-AuthX - Modern Singleton Pattern Example
// This demonstrates the RECOMMENDED way to use simple-authx

import express from 'express';
import { initializeAuth, protect, getAuth, requireRole } from 'simple-authx';
import 'dotenv/config';

// ✅ Multiple roles allowed
import { requireAnyRole } from 'simple-authx';

const app = express();
app.use(express.json());

console.log('🚀 Starting Simple-AuthX Modern Example\n');

// ============================================
// STEP 1: Initialize Authentication (ONCE)
// ============================================
console.log('📝 Initializing authentication...');

await initializeAuth({
  // Storage Configuration
  storage: process.env.STORAGE || 'mongodb',
  mongodb: process.env.MONGODB_URL || 'mongodb://localhost:27017/authx',

  // JWT Secrets
  secret: process.env.JWT_SECRET || 'dev_secret_change_in_production',
  refreshSecret: process.env.JWT_REFRESH_SECRET || 'dev_refresh_secret',
  accessExpiry: '15m',
  refreshExpiry: '7d',

  // User Schema Configuration (NEW!)
  userFields: {
    identifiers: ['email', 'username', 'phoneNumber'],
    required: ['email'], // Only email is required
    unique: ['email', 'username', 'phoneNumber'],
    custom: {
      firstName: { type: 'string', required: false },
      lastName: { type: 'string', required: false },
      role: { type: 'string', default: 'user' },
      age: { type: 'number', required: false },
    },
  },

  // Cookie Configuration
  cookies: {
    refresh: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  },

  // CSRF Protection
  csrf: {
    enabled: true,
  },

  // Plugins
  plugins: {
    password: {
      minStrength: 2,
      minLength: 8,
    },
    security: {
      rateLimit: true,
      maxFailedAttempts: 5,
    },
    audit: {
      events: ['login', 'register', 'failed_login'],
    },
  },

  // Lifecycle Hooks
  hooks: {
    async onRegister(user) {
      console.log(`✅ New user registered: ${user.email || user.username}`);
    },
    async onLogin(user) {
      console.log(`✅ User logged in: ${user.email || user.username}`);
    },
  },
});

console.log('✅ Authentication initialized\n');

// ============================================
// STEP 2: Mount Auth Routes (ONCE)
// ============================================
const auth = getAuth();
app.use('/auth', auth.routes);

console.log('✅ Auth routes mounted at /auth\n');

// ============================================
// STEP 3: Define Protected Routes
// ============================================

// Public route
app.get('/', (req, res) => {
  res.json({
    message: '🔐 Simple-AuthX Modern Pattern Demo',
    endpoints: {
      public: {
        info: 'GET /',
        health: 'GET /health',
      },
      auth: {
        register: 'POST /auth/register',
        login: 'POST /auth/login',
        refresh: 'POST /auth/refresh',
        logout: 'POST /auth/logout',
      },
      protected: {
        profile: 'GET /profile (requires auth)',
        dashboard: 'GET /dashboard (requires auth)',
        admin: 'GET /admin (requires admin role)',
        users: 'GET /users (requires admin/moderator role)',
      },
    },
    examples: {
      register: {
        method: 'POST',
        url: '/auth/register',
        body: {
          email: 'user@example.com',
          username: 'johndoe',
          password: 'SecureP@ss123',
          firstName: 'John',
          lastName: 'Doe',
        },
      },
      login: {
        method: 'POST',
        url: '/auth/login',
        body: {
          identifier: 'user@example.com',
          password: 'SecureP@ss123',
        },
      },
    },
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development',
  });
});

// ============================================
// Protected Routes - Notice no auth instance!
// ============================================

// ✅ Simple protected route
app.get('/profile', protect, (req, res) => {
  res.json({
    message: 'Your profile',
    user: req.user,
    note: 'Notice how we imported protect directly, no auth instance needed!',
  });
});

// ✅ Another protected route in same file
app.get('/dashboard', protect, (req, res) => {
  res.json({
    message: 'Your dashboard',
    user: {
      id: req.user.userId,
      email: req.user.email,
      username: req.user.username,
      role: req.user.role,
    },
    stats: {
      loginCount: 42,
      lastLogin: new Date(),
    },
  });
});

// ✅ Role-based protected route
app.get('/admin', protect, requireRole('admin'), (req, res) => {
  res.json({
    message: 'Admin dashboard',
    user: req.user,
    adminFeatures: ['User management', 'System settings', 'Audit logs'],
  });
});

app.get('/users', protect, requireAnyRole(['admin', 'moderator']), (req, res) => {
  res.json({
    message: 'User list (admin or moderator)',
    users: [
      { id: 1, email: 'user1@example.com', role: 'user' },
      { id: 2, email: 'admin@example.com', role: 'admin' },
    ],
  });
});

// ============================================
// Advanced Features Examples
// ============================================

// Check password strength (if plugin enabled)
app.post('/check-password', (req, res) => {
  try {
    const { password } = req.body;

    if (!auth.password) {
      return res.status(501).json({
        error: 'Password validation plugin not enabled',
      });
    }

    const strength = auth.password.checkStrength(password);

    res.json({
      password: '***hidden***',
      strength: {
        score: strength.score,
        scoreLabel: ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'][strength.score],
        feedback: strength.feedback,
        crackTime: strength.crackTime,
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get audit logs (if plugin enabled)
app.get('/audit/logs', protect, requireRole('admin'), async (req, res) => {
  try {
    if (!auth.audit) {
      return res.status(501).json({
        error: 'Audit logging plugin not enabled',
      });
    }

    const logs = await auth.audit.query({
      userId: req.query.userId,
      event: req.query.event,
      startDate: req.query.startDate ? new Date(String(req.query.startDate)) : undefined,
    });

    res.json({ logs });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// Error Handling
// ============================================

app.use((err, req, res, next) => {
  console.error('❌ Error:', err.message);

  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
  });
});

// ============================================
// Start Server
// ============================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log('='.repeat(60));
  console.log(`✅ Server running on http://localhost:${PORT}`);
  console.log('='.repeat(60));
  console.log('');
  console.log('📊 Configuration:');
  console.log(`   Storage: ${process.env.STORAGE || 'mongodb'}`);
  console.log(`   Cookie Auth: enabled`);
  console.log(`   CSRF Protection: enabled`);
  console.log(`   Password Validation: ${auth.password ? 'enabled' : 'disabled'}`);
  console.log(`   Security/Rate Limit: ${auth.security ? 'enabled' : 'disabled'}`);
  console.log(`   Audit Logging: ${auth.audit ? 'enabled' : 'disabled'}`);
  console.log('');
  console.log('🔑 Key Features:');
  console.log('   ✅ Multi-identifier login (email, username, or phone)');
  console.log('   ✅ Custom user fields (firstName, lastName, etc.)');
  console.log('   ✅ Token rotation & reuse detection');
  console.log('   ✅ httpOnly cookies + CSRF protection');
  console.log('');
  console.log('📚 Try these commands:');
  console.log('');
  console.log('1️⃣  Register with email:');
  console.log(`   curl -X POST http://localhost:${PORT}/auth/register \\`);
  console.log('     -H "Content-Type: application/json" \\');
  console.log(
    '     -d \'{"email":"user@example.com","password":"SecureP@ss123","firstName":"John"}\''
  );
  console.log('');
  console.log('2️⃣  Login with email:');
  console.log(`   curl -X POST http://localhost:${PORT}/auth/login \\`);
  console.log('     -H "Content-Type: application/json" \\');
  console.log('     -d \'{"identifier":"user@example.com","password":"SecureP@ss123"}\'');
  console.log('');
  console.log('3️⃣  Access protected route:');
  console.log(`   curl http://localhost:${PORT}/profile \\`);
  console.log('     -H "Authorization: Bearer YOUR_ACCESS_TOKEN"');
  console.log('');
  console.log('4️⃣  Check password strength:');
  console.log(`   curl -X POST http://localhost:${PORT}/check-password \\`);
  console.log('     -H "Content-Type: application/json" \\');
  console.log('     -d \'{"password":"TestPassword123"}\'');
  console.log('');
  console.log('💡 Visit https://simple-authx-lp.vercel.app/docs for full API documentation');
  console.log('');
  console.log('🔥 WANTAM!!!! Authentication is ready!');
  console.log('');
});

// ============================================
// Graceful Shutdown
// ============================================

process.on('SIGTERM', async () => {
  console.log('\n🛑 SIGTERM signal received: closing server...');

  try {
    await auth.close();
    console.log('✅ Auth connections closed');
    process.exit(0);
  } catch (error) {
    console.error('❌ Error during shutdown:', error);
    process.exit(1);
  }
});

process.on('SIGINT', async () => {
  console.log('\n🛑 SIGINT signal received: closing server...');

  try {
    await auth.close();
    console.log('✅ Auth connections closed');
    process.exit(0);
  } catch (error) {
    console.error('❌ Error during shutdown:', error);
    process.exit(1);
  }
});

// ============================================
// Example: Simulating Routes in Separate Files
// ============================================

// This shows how you would use protect in other files
// Just import { protect } and use it!

// routes/api.js
/*
import { protect, requireRole } from 'simple-authx';
import express from 'express';

const router = express.Router();

router.get('/api/data', protect, (req, res) => {
  res.json({ data: 'Protected data', user: req.user });
});

router.get('/api/admin', protect, requireRole('admin'), (req, res) => {
  res.json({ message: 'Admin only' });
});

export default router;
*/

// Then in server.js:
/*
import apiRoutes from './routes/api.js';
app.use(apiRoutes);
*/

console.log('📝 See comments in code for multi-file route examples\n');

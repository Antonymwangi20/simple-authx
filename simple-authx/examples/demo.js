import express from 'express';
import { createAuth } from 'simple-authx';

const app = express();
app.use(express.json());

// Basic setup with MongoDB
const auth = await createAuth({
  mongodb: 'mongodb://localhost:27017/myapp',
  
  // Optional security features
  security: {
    rateLimit: true,
    password: { minStrength: 3 }
  },
  
  // Optional MFA
  mfa: {
    issuer: 'MyApp'
  },
  
  // Optional session tracking
  sessions: true
});

// Mount all auth routes
app.use('/auth', auth.routes);

// Protected route example
app.get('/profile', auth.protect, (req, res) => {
  res.json({ user: req.user });
});

// Example with role-based access
const requireRole = (role) => (req, res, next) => {
  if (req.user.role !== role) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  next();
};

app.get('/admin', auth.protect, requireRole('admin'), (req, res) => {
  res.json({ message: 'Admin access granted' });
});

// Social login example
if (process.env.GOOGLE_CLIENT_ID) {
  auth.social.setup('google', {
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/auth/google/callback'
  });

  app.get('/auth/google', (req, res) => {
    const url = auth.social.getAuthUrl('google');
    res.redirect(url);
  });
}

// MFA example
app.post('/auth/mfa/enable', auth.protect, async (req, res) => {
  const { qr, backupCodes } = await auth.mfa.enable(req.user.username);
  res.json({ qr, backupCodes });
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
  console.log('\nAvailable endpoints:');
  console.log('  POST /auth/register      - Register new user');
  console.log('  POST /auth/login         - Login');
  console.log('  POST /auth/refresh       - Refresh token');
  console.log('  POST /auth/logout        - Logout');
  console.log('  GET  /profile           - Get user profile');
  console.log('  GET  /admin             - Admin only route');
  console.log('  POST /auth/mfa/enable   - Enable 2FA');
  process.env.GOOGLE_CLIENT_ID && console.log('  GET  /auth/google        - Google Sign In');
});
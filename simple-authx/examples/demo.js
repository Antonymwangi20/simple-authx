import express from 'express';
<<<<<<< HEAD
import { createAuth } from 'simple-authx';
=======
import { createAuth, requireRole } from 'simple-authx';
>>>>>>> f63ac94 (Add working createAuth wrapper with File/Postgres/Mongo/Redis support)

const app = express();
app.use(express.json());

<<<<<<< HEAD
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
=======
// Example setup with cookie-based refresh + CSRF (File storage for demo)
const auth = await createAuth({
  file: './data/auth-data.json',
  cookies: { refresh: true, secure: false, sameSite: 'strict', name: 'refreshToken' },
  csrf: { enabled: true, cookieName: 'csrfToken', headerName: 'x-csrf-token' }
>>>>>>> f63ac94 (Add working createAuth wrapper with File/Postgres/Mongo/Redis support)
});

// Mount all auth routes
app.use('/auth', auth.routes);

// Protected route example
app.get('/profile', auth.protect, (req, res) => {
  res.json({ user: req.user });
});

<<<<<<< HEAD
// Example with role-based access
const requireRole = (role) => (req, res, next) => {
  if (req.user.role !== role) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  next();
};

=======
>>>>>>> f63ac94 (Add working createAuth wrapper with File/Postgres/Mongo/Redis support)
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
<<<<<<< HEAD
=======
  console.log('  Cookies mode: refresh token is HttpOnly cookie; use x-csrf-token header on /auth/refresh');
>>>>>>> f63ac94 (Add working createAuth wrapper with File/Postgres/Mongo/Redis support)
  console.log('  GET  /profile           - Get user profile');
  console.log('  GET  /admin             - Admin only route');
  console.log('  POST /auth/mfa/enable   - Enable 2FA');
  process.env.GOOGLE_CLIENT_ID && console.log('  GET  /auth/google        - Google Sign In');
});
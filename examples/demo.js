import express from 'express';
import { createAuth, requireRole } from 'simple-authx';

const app = express();
app.use(express.json());

// Example setup with cookie-based refresh + CSRF (File storage for demo)
const auth = await createAuth({
  file: './data/auth-data.json',
  cookies: { refresh: true, secure: false, sameSite: 'strict', name: 'refreshToken' },
  csrf: { enabled: true, cookieName: 'csrfToken', headerName: 'x-csrf-token' },
});

// Mount all auth routes
app.use('/auth', auth.routes);

// Protected route example
app.get('/profile', auth.protect, (req, res) => {
  res.json({ user: req.user });
});

app.get('/admin', auth.protect, requireRole('admin'), (req, res) => {
  res.json({ message: 'Admin access granted' });
});

// Social login example
if (process.env.GOOGLE_CLIENT_ID) {
  auth.social.setup('google', {
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/auth/google/callback',
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
  console.log(
    '  Cookies mode: refresh token is HttpOnly cookie; use x-csrf-token header on /auth/refresh'
  );
  console.log(
    '  Cookies mode: refresh token is HttpOnly cookie; use x-csrf-token header on /auth/refresh'
  );
  console.log('  GET  /profile           - Get user profile');
  console.log('  GET  /admin             - Admin only route');
  console.log('  POST /auth/mfa/enable   - Enable 2FA');
  if (process.env.GOOGLE_CLIENT_ID) {
    console.log('  GET  /auth/google        - Google Sign In');
  }
});

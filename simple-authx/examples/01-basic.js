// Basic usage of simple-authx with in-memory storage

import express from 'express';
import { createAuth } from '../index.mjs';

const app = express();
app.use(express.json());

console.log('🚀 Starting Basic Example...\n');

// Create auth instance with zero config (in-memory storage)
const auth = await createAuth();

// Mount auth routes
app.use('/auth', auth.routes);

// Protected route example
app.get('/protected', auth.protect, (req, res) => {
  res.json({ 
    message: 'This is a protected route',
    user: req.user 
  });
});

// Public route
app.get('/', (req, res) => {
  res.json({ 
    message: 'Welcome to simple-authx basic example',
    endpoints: {
      register: 'POST /auth/register',
      login: 'POST /auth/login',
      refresh: 'POST /auth/refresh',
      logout: 'POST /auth/logout',
      protected: 'GET /protected (requires Authorization header)'
    }
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
  console.log('');
  console.log('📚 Try these commands:');
  console.log('');
  console.log('1. Register a user:');
  console.log(`   curl -X POST http://localhost:${PORT}/auth/register \\`);
  console.log('     -H "Content-Type: application/json" \\');
  console.log('     -d \'{"username":"alice","password":"secret123"}\'');
  console.log('');
  console.log('2. Login:');
  console.log(`   curl -X POST http://localhost:${PORT}/auth/login \\`);
  console.log('     -H "Content-Type: application/json" \\');
  console.log('     -d \'{"username":"alice","password":"secret123"}\'');
  console.log('');
  console.log('3. Access protected route:');
  console.log(`   curl http://localhost:${PORT}/protected \\`);
  console.log('     -H "Authorization: Bearer YOUR_ACCESS_TOKEN"');
  console.log('');
});

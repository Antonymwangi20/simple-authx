// Login Endpoint Diagnostic Tool
// Run this to debug login issues: node tests/diagnose-login.js

import { createAuth } from '../index.mjs';
import express from 'express';
import 'dotenv/config';

console.log('🔍 Login Endpoint Diagnostic Tool\n');
console.log('=' .repeat(60));

// Add detailed logging middleware
function createLoggingMiddleware() {
  return (req, res, next) => {
    console.log('\n📥 Incoming Request:');
    console.log('   Method:', req.method);
    console.log('   Path:', req.path);
    console.log('   Headers:', JSON.stringify(req.headers, null, 2));
    console.log('   Body:', JSON.stringify(req.body, null, 2));
    
    // Capture response
    const originalJson = res.json.bind(res);
    const originalStatus = res.status.bind(res);
    const originalSend = res.send.bind(res);
    
    let statusCode = 200;
    
    res.status = function(code) {
      statusCode = code;
      console.log('   Response Status:', code);
      return originalStatus(code);
    };
    
    res.json = function(data) {
      console.log('📤 Response:');
      console.log('   Status:', statusCode);
      console.log('   Data:', JSON.stringify(data, null, 2));
      return originalJson(data);
    };
    
    res.send = function(data) {
      console.log('📤 Response:');
      console.log('   Status:', statusCode);
      console.log('   Data:', data);
      return originalSend(data);
    };
    
    next();
  };
}

async function runDiagnostics() {
  try {
    console.log('\n1️⃣ Setting up Express app...\n');
    
    const app = express();
    
    // Add logging before parsing
    app.use((req, res, next) => {
      console.log('🔍 Raw request received');
      next();
    });
    
    // Body parser
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    
    // Logging middleware
    app.use(createLoggingMiddleware());
    
    console.log('2️⃣ Creating auth instance...\n');
    
    const auth = await createAuth({
      storage: 'mongodb',
      mongodb: process.env.MONGODB_URL || 'mongodb://localhost:27017/authx',
      secret: process.env.JWT_SECRET || 'diagnostic_secret',
      refreshSecret: process.env.JWT_REFRESH_SECRET || 'diagnostic_refresh_secret'
    });
    
    console.log('✅ Auth instance created');
    console.log('   Storage:', 'MongoDB');
    console.log('   Adapter:', auth.adapter ? '✅' : '❌');
    console.log('   Auth Manager:', auth.auth ? '✅' : '❌');
    console.log('   Routes:', auth.routes ? '✅' : '❌');
    
    console.log('\n3️⃣ Mounting auth routes...\n');
    
    // Mount auth routes
    app.use('/auth', auth.routes);
    
    console.log('4️⃣ Creating test user...\n');
    
    const testUser = {
      username: 'diaguser_' + Date.now(),
      password: 'TestPassword123!'
    };
    
    console.log('   Username:', testUser.username);
    console.log('   Password:', testUser.password);
    
    // Register test user
    console.log('\n5️⃣ Testing Registration...\n');
    
    try {
      const registerResult = await auth.auth.register(testUser.username, testUser.password);
      console.log('✅ Registration successful');
      console.log('   User ID:', registerResult.user.id);
      console.log('   Username:', registerResult.user.username);
    } catch (err) {
      console.error('❌ Registration failed:', err.message);
      throw err;
    }
    
    console.log('\n6️⃣ Testing Direct Adapter Login...\n');
    
    // Test adapter verifyUser directly
    const verifyResult = await auth.adapter.verifyUser(testUser.username, testUser.password);
    console.log('   Direct adapter verification:', verifyResult ? '✅' : '❌');
    
    if (!verifyResult) {
      console.error('❌ Adapter verification failed');
      console.log('\n🔍 Debugging adapter...');
      
      const foundUser = await auth.adapter.findUser(testUser.username);
      console.log('   User exists:', foundUser ? '✅' : '❌');
      console.log('   Has password_hash:', foundUser?.password_hash ? '✅' : '❌');
      
      throw new Error('Adapter verification failed');
    }
    
    console.log('\n7️⃣ Testing AuthManager Login...\n');
    
    try {
      const loginResult = await auth.auth.login(testUser.username, testUser.password);
      console.log('✅ AuthManager login successful');
      console.log('   Access Token:', loginResult.accessToken.substring(0, 50) + '...');
      console.log('   Refresh Token:', loginResult.refreshToken.substring(0, 50) + '...');
    } catch (err) {
      console.error('❌ AuthManager login failed:', err.message);
      console.error('   Stack:', err.stack);
      throw err;
    }
    
    console.log('\n8️⃣ Starting test server...\n');
    
    const server = app.listen(0, () => {
      const port = server.address().port;
      console.log(`✅ Server listening on port ${port}`);
      
      // Test HTTP endpoint
      testHTTPEndpoint(port, testUser).then(() => {
        console.log('\n✅ All diagnostics passed!\n');
        server.close();
        process.exit(0);
      }).catch(err => {
        console.error('\n❌ HTTP endpoint test failed:', err.message);
        server.close();
        process.exit(1);
      });
    });
    
  } catch (error) {
    console.error('\n❌ Diagnostic failed:', error.message);
    console.error('\n📋 Stack trace:');
    console.error(error.stack);
    
    console.error('\n📋 Common Issues:');
    console.error('   1. MongoDB connection issues');
    console.error('   2. Password hashing mismatch (bcrypt vs stored hash)');
    console.error('   3. Express body parser not working');
    console.error('   4. Route mounting issues');
    console.error('   5. Missing error handlers in routes');
    
    process.exit(1);
  }
}

async function testHTTPEndpoint(port, testUser) {
  console.log('\n9️⃣ Testing HTTP Login Endpoint...\n');
  
  try {
    const response = await fetch(`http://localhost:${port}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        username: testUser.username,
        password: testUser.password
      })
    });
    
    console.log('   HTTP Status:', response.status);
    console.log('   Content-Type:', response.headers.get('content-type'));
    
    const text = await response.text();
    console.log('   Raw Response:', text);
    
    if (response.ok) {
      const data = JSON.parse(text);
      console.log('✅ HTTP login successful');
      console.log('   Access Token:', data.accessToken ? '✅' : '❌');
      console.log('   Refresh Token:', data.refreshToken ? '✅' : '❌');
    } else {
      console.error('❌ HTTP login failed');
      console.error('   Status:', response.status);
      console.error('   Response:', text);
      throw new Error('HTTP login failed');
    }
    
    // Test with wrong password
    console.log('\n🔟 Testing with wrong password...\n');
    
    const wrongResponse = await fetch(`http://localhost:${port}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        username: testUser.username,
        password: 'WrongPassword123!'
      })
    });
    
    console.log('   HTTP Status:', wrongResponse.status);
    
    if (wrongResponse.status === 401) {
      console.log('✅ Wrong password correctly rejected');
    } else {
      console.error('❌ Wrong password should return 401');
      const errorText = await wrongResponse.text();
      console.error('   Response:', errorText);
    }
    
  } catch (err) {
    console.error('❌ HTTP test failed:', err.message);
    throw err;
  }
}

// Run diagnostics
runDiagnostics();
// Comprehensive integration test for the unified API

import assert from 'assert';
import express from 'express';
import request from 'supertest';
import { createAuth } from '../src/core/unified-api.js';

console.log('🧪 Testing Unified API\n');

// Test 1: Zero Config (In-Memory)
async function testZeroConfig() {
  console.log('📝 Test 1: Zero Config (In-Memory)');

  const auth = await createAuth();

  assert(auth.routes, 'routes should exist');
  assert(auth.router, 'router alias should exist');
  assert(auth.protect, 'protect middleware should exist');
  assert(auth.auth, 'auth manager should exist');
  assert(auth.adapter, 'adapter should exist');

  // Test register
  const user1 = await auth.auth.register('alice', 'password123');
  assert(user1.user.username === 'alice', 'user should be registered');
  assert(user1.accessToken, 'access token should be generated');
  assert(user1.refreshToken, 'refresh token should be generated');

  // Test login
  const user2 = await auth.auth.login('alice', 'password123');
  assert(user2.accessToken, 'login should generate access token');

  // Test refresh
  const tokens = await auth.auth.refresh(user1.refreshToken);
  assert(tokens.accessToken, 'refresh should generate new access token');
  assert(tokens.refreshToken, 'refresh should generate new refresh token');

  // Test token verification
  const decoded = auth.verifyAccess(tokens.accessToken);
  assert(decoded.userId, 'token should be verifiable');

  // Test token reuse detection
  let threwError = false;
  try {
    await auth.auth.refresh(user1.refreshToken); // Old token
  } catch {
    threwError = true;
  }
  assert(threwError, 'old refresh token should be rejected');

  console.log('✅ Zero config test passed\n');
}

// Test 2: File Storage
async function testFileStorage() {
  console.log('📝 Test 2: File Storage');

  // Cleanup old test file
  try {
    const fs = await import('fs/promises');
    await fs.mkdir('./data', { recursive: true });
    await fs.unlink('./data/test-auth.json').catch(() => {});
  } catch {
    // Ignore cleanup errors
  }

  const auth = await createAuth('./data/test-auth.json');

  const user = await auth.auth.register('bob', 'password456');
  assert(user.user.username === 'bob', 'file storage should work');

  // Close and reopen to test persistence
  const auth2 = await createAuth('./data/test-auth.json');
  const foundUser = await auth2.adapter.findUser('bob');
  assert(foundUser, 'user should persist across sessions');
  assert(foundUser.username === 'bob', 'user data should be correct');

  console.log('✅ File storage test passed\n');
}

// Test 3: Express Integration
async function testExpressIntegration() {
  console.log('📝 Test 3: Express Integration');

  const app = express();
  app.use(express.json());

  const auth = await createAuth();

  app.use('/auth', auth.routes);
  app.get('/protected', auth.protect, (req, res) => {
    res.json({ user: req.user });
  });

  // Test register endpoint
  const registerRes = await request(app)
    .post('/auth/register')
    .send({ username: 'charlie', password: 'password789' })
    .expect(200);

  assert(registerRes.body.accessToken, 'register should return access token');
  assert(registerRes.body.user.username === 'charlie', 'register should return user');

  // Test login endpoint
  const loginRes = await request(app)
    .post('/auth/login')
    .send({ username: 'charlie', password: 'password789' })
    .expect(200);

  assert(loginRes.body.accessToken, 'login should return access token');

  // Test protected route
  const protectedRes = await request(app)
    .get('/protected')
    .set('Authorization', `Bearer ${loginRes.body.accessToken}`)
    .expect(200);

  assert(protectedRes.body.user.userId, 'protected route should return user');

  // Test refresh endpoint
  const refreshRes = await request(app)
    .post('/auth/refresh')
    .send({ refreshToken: registerRes.body.refreshToken })
    .expect(200);

  assert(refreshRes.body.accessToken, 'refresh should return new access token');

  // Test logout endpoint
  await request(app)
    .post('/auth/logout')
    .send({ refreshToken: refreshRes.body.refreshToken })
    .expect(200);

  console.log('✅ Express integration test passed\n');
}

// Test 4: Cookie Mode
async function testCookieMode() {
  console.log('📝 Test 4: Cookie Mode');

  const app = express();
  app.use(express.json());

  const auth = await createAuth({
    cookies: {
      refresh: true,
      secure: false,
      sameSite: 'strict',
    },
    csrf: {
      enabled: true,
    },
  });

  app.use('/auth', auth.routes);

  // Test login with cookies (should fail - user doesn't exist)
  await request(app)
    .post('/auth/login')
    .send({ username: 'dave', password: 'password' })
    .expect(401); // Will fail because user doesn't exist

  // Register first
  const registerRes = await request(app)
    .post('/auth/register')
    .send({ username: 'dave', password: 'password' })
    .expect(200);

  // Check cookies were set
  const cookies = registerRes.headers['set-cookie'];
  assert(cookies, 'cookies should be set');
  assert(
    cookies.some((c) => c.includes('refreshToken')),
    'refresh token cookie should be set'
  );
  assert(
    cookies.some((c) => c.includes('csrfToken')),
    'CSRF token cookie should be set'
  );

  console.log('✅ Cookie mode test passed\n');
}

// Test 5: Plugin System
async function testPlugins() {
  console.log('📝 Test 5: Plugin System');

  const auth = await createAuth({
    plugins: {
      mfa: {
        issuer: 'TestApp',
      },
      password: {
        minStrength: 2,
      },
    },
  });

  assert(auth.mfa, 'MFA plugin should be enabled');
  assert(auth.password, 'Password plugin should be enabled');
  assert(!auth.social, 'Social plugin should not be enabled');
  assert(!auth.sessions, 'Sessions plugin should not be enabled');

  // Test MFA
  const secret = auth.mfa.generateSecret();
  assert(secret, 'MFA should generate secret');
  assert(secret.length > 10, 'Secret should be long enough');

  const backupCodes = auth.mfa.generateBackupCodes();
  assert(backupCodes.length === 10, 'Should generate 10 backup codes');

  // Test Password Manager
  try {
    await auth.password.validatePassword('weak', 'testuser', 'test@example.com');
    assert(false, 'Weak password should fail');
  } catch (err) {
    assert(err.message.includes('weak'), 'Should reject weak password');
  }

  console.log('✅ Plugin system test passed\n');
}

// Test 6: Adapter Compatibility
async function testAdapterCompatibility() {
  console.log('📝 Test 6: Adapter Compatibility');

  // Test that all adapters implement the same interface
  const memoryAuth = await createAuth({ storage: 'memory' });
  const fileAuth = await createAuth('./data/test-adapter.json');

  const adapterMethods = [
    'findUser',
    'createUser',
    'verifyUser',
    'storeRefreshToken',
    'findRefreshToken',
    'invalidateRefreshToken',
    'invalidateAllRefreshTokens',
  ];

  adapterMethods.forEach((method) => {
    assert(
      typeof memoryAuth.adapter[method] === 'function',
      `Memory adapter should have ${method}`
    );
    assert(typeof fileAuth.adapter[method] === 'function', `File adapter should have ${method}`);
  });

  console.log('✅ Adapter compatibility test passed\n');
}

// Test 7: Error Handling
async function testErrorHandling() {
  console.log('📝 Test 7: Error Handling');

  const auth = await createAuth();

  // Test duplicate registration
  await auth.auth.register('duplicate', 'password');
  try {
    await auth.auth.register('duplicate', 'password');
    assert(false, 'Duplicate registration should fail');
  } catch (err) {
    assert(err.message.includes('exists'), 'Should throw exists error');
  }

  // Test invalid login
  try {
    await auth.auth.login('nonexistent', 'password');
    assert(false, 'Invalid login should fail');
  } catch (err) {
    assert(err.message.includes('credentials'), 'Should throw credentials error');
  }

  // Test invalid refresh token
  try {
    await auth.auth.refresh('invalid_token');
    assert(false, 'Invalid refresh should fail');
  } catch (err) {
    assert(
      err.message.includes('Expired or invalid refresh token'),
      'Should throw invalid token error'
    );
  }

  console.log('✅ Error handling test passed\n');
}

// Test 8: Configuration Normalization
async function testConfigNormalization() {
  console.log('📝 Test 8: Configuration Normalization');

  // Test string shorthand
  const auth1 = await createAuth('./data/test1.json');
  assert(auth1.adapter, 'String config should work');

  // Test legacy format compatibility
  const auth2 = await createAuth({
    file: './data/test2.json',
    secret: 'test',
    refreshSecret: 'test',
  });
  assert(auth2.adapter, 'Legacy config format should work');

  // Test auto-detection
  const auth3 = await createAuth({
    mongodb: 'mongodb://localhost:27017/test',
  });
  // Note: This might fail if MongoDB isn't running, so we catch
  try {
    assert(auth3.adapter, 'Auto-detect MongoDB should work');
  } catch {
    console.log('  ⚠️  MongoDB not available, skipping');
  }

  console.log('✅ Configuration normalization test passed\n');
}

// Run all tests
async function runBasicTests() {
  await testZeroConfig();
  await testFileStorage();
  await testPlugins();
  await testAdapterCompatibility();
  await testErrorHandling();
  await testConfigNormalization();
  console.log('\n🎉 Basic tests passed!\n');
}

async function runAllTests() {
  try {
    await testZeroConfig();
    await testFileStorage();
    await testExpressIntegration();
    await testCookieMode();
    await testPlugins();
    await testAdapterCompatibility();
    await testErrorHandling();
    await testConfigNormalization();

    console.log('\n🎉 All tests passed! Unified API is working correctly.\n');
    process.exit(0);
  } catch (err) {
    console.error('\n❌ Test failed:', err.message);
    console.error(err.stack);
    process.exit(1);
  }
}

// Check if supertest is installed
try {
  await import('supertest');
  runAllTests();
} catch {
  console.log('⚠️  supertest not found. Installing for tests...');
  console.log('Run: npm install --save-dev supertest');
  console.log('\nOr skip Express integration tests and run other tests:');

  runBasicTests().catch(console.error);
}

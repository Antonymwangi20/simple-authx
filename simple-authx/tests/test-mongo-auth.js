// test-mongo-auth.js
// Diagnostic tool to test MongoDB authentication

import { createAuth } from 'simple-authx';
import 'dotenv/config';

console.log('🔍 MongoDB Authentication Diagnostic Tool\n');

async function runDiagnostics() {
  try {
    console.log('1️⃣ Creating auth instance...');
    const auth = await createAuth({
      storage: 'mongodb',
      mongodb: process.env.MONGODB_URL || 'mongodb://localhost:27017/authx',
      secret: process.env.JWT_SECRET || 'test_secret',
      refreshSecret: process.env.JWT_REFRESH_SECRET || 'test_refresh_secret'
    });
    console.log('✅ Auth instance created\n');

    // Test username and password
    const testUsername = 'testuser_' + Date.now();
    const testPassword = 'TestPassword123!';

    console.log('2️⃣ Testing Registration...');
    console.log(`   Username: ${testUsername}`);
    console.log(`   Password: ${testPassword}\n`);

    try {
      const registerResult = await auth.auth.register(testUsername, testPassword);
      console.log('✅ Registration successful');
      console.log('   User ID:', registerResult.user.id);
      console.log('   Username:', registerResult.user.username);
      console.log('   Access Token:', registerResult.accessToken.substring(0, 50) + '...');
      console.log('   Refresh Token:', registerResult.refreshToken.substring(0, 50) + '...\n');
    } catch (err) {
      console.error('❌ Registration failed:', err.message);
      throw err;
    }

    console.log('3️⃣ Testing Direct Adapter Methods...');
    
    // Test findUser
    const foundUser = await auth.adapter.findUser(testUsername);
    console.log('   findUser result:', {
      found: !!foundUser,
      id: foundUser?.id,
      username: foundUser?.username,
      hasPasswordHash: !!foundUser?.password_hash,
      passwordHashLength: foundUser?.password_hash?.length
    });

    if (!foundUser) {
      console.error('❌ User not found in database!');
      throw new Error('User not found after registration');
    }

    if (!foundUser.password_hash) {
      console.error('❌ Password hash missing!');
      throw new Error('Password hash not stored properly');
    }

    console.log('✅ User found in database\n');

    console.log('4️⃣ Testing Password Verification...');
    
    // Test verifyUser with correct password
    const verifyCorrect = await auth.adapter.verifyUser(testUsername, testPassword);
    console.log('   Correct password:', {
      verified: !!verifyCorrect,
      userId: verifyCorrect?.id
    });

    if (!verifyCorrect) {
      console.error('❌ Password verification failed with correct password!');
      
      // Additional debugging
      console.log('\n🔍 Debug Info:');
      console.log('   Stored hash:', foundUser.password_hash.substring(0, 30) + '...');
      console.log('   Hash algorithm:', process.env.PASSWORD_HASHER || 'bcrypt');
      
      throw new Error('Password verification failed');
    }

    console.log('✅ Password verification successful');

    // Test verifyUser with wrong password
    const verifyWrong = await auth.adapter.verifyUser(testUsername, 'WrongPassword');
    console.log('   Wrong password:', {
      verified: !!verifyWrong,
      shouldBeFalse: !verifyWrong
    });

    if (verifyWrong) {
      console.error('❌ Wrong password was accepted!');
      throw new Error('Security issue: wrong password accepted');
    }

    console.log('✅ Wrong password correctly rejected\n');

    console.log('5️⃣ Testing Login via AuthManager...');
    
    try {
      const loginResult = await auth.auth.login(testUsername, testPassword);
      console.log('✅ Login successful');
      console.log('   User ID:', loginResult.user.id);
      console.log('   Access Token:', loginResult.accessToken.substring(0, 50) + '...');
      console.log('   Refresh Token:', loginResult.refreshToken.substring(0, 50) + '...\n');
    } catch (err) {
      console.error('❌ Login failed:', err.message);
      console.error('   Stack:', err.stack);
      throw err;
    }

    console.log('6️⃣ Testing Token Refresh...');
    
    const registerResult = await auth.auth.register(testUsername + '_2', testPassword);
    const refreshResult = await auth.auth.refresh(registerResult.refreshToken);
    console.log('✅ Token refresh successful');
    console.log('   New Access Token:', refreshResult.accessToken.substring(0, 50) + '...\n');

    console.log('7️⃣ Cleanup - Deleting test users...');
    
    const mongoose = await import('mongoose');
    const UserModel = mongoose.default.model('AuthX_User');
    await UserModel.deleteMany({ 
      username: { $regex: '^testuser_' } 
    });
    console.log('✅ Test users deleted\n');

    console.log('🎉 All diagnostics passed! MongoDB authentication is working correctly.\n');

    process.exit(0);

  } catch (error) {
    console.error('\n❌ Diagnostic failed:', error.message);
    console.error('\n📋 Troubleshooting steps:');
    console.error('   1. Verify MongoDB connection string is correct');
    console.error('   2. Check that MongoDB is running and accessible');
    console.error('   3. Ensure bcryptjs package is installed: npm install bcryptjs');
    console.error('   4. Check environment variables (JWT_SECRET, MONGODB_URI)');
    console.error('   5. Review the fixed MongoDB adapter code');
    console.error('\n💡 Try running: npm install bcryptjs mongoose');
    console.error('');
    
    process.exit(1);
  }
}

// Run diagnostics
runDiagnostics();
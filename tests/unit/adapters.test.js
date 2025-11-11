import { describe, it, beforeEach, afterEach } from 'mocha';
import { expect } from 'chai';
import fs from 'fs';
import { FileAdapter } from '../../src/adapters/file-adapter.js';
import { createAuth, resetAuth } from '../../index.mjs';

describe('File Adapter', () => {
  const testFile = './data/test-adapter-coverage.json';

  beforeEach(async () => {
    // Clean up test file if it exists
    if (fs.existsSync(testFile)) {
      fs.unlinkSync(testFile);
    }
  });

  afterEach(() => {
    // Clean up test file
    if (fs.existsSync(testFile)) {
      fs.unlinkSync(testFile);
    }
  });

  describe('Basic Operations', () => {
    it('should initialize file adapter', async () => {
      const adapter = new FileAdapter(testFile);
      await adapter.init();
      expect(adapter).to.be.instanceOf(FileAdapter);
    });

    it('should create a user', async () => {
      const adapter = new FileAdapter(testFile);
      await adapter.init();

      const user = await adapter.createUser({
        email: 'adapter@example.com',
        password: 'hashedpassword',
      });

      expect(user).to.have.property('id');
      expect(user).to.have.property('email', 'adapter@example.com');
    });

    it('should find a user by identifier', async () => {
      const adapter = new FileAdapter(testFile);
      await adapter.init();

      await adapter.createUser({
        email: 'find@example.com',
        password: 'hashedpassword',
      });

      const user = await adapter.findUser('find@example.com');
      expect(user).to.not.be.null; // eslint-disable-line no-unused-expressions
      expect(user).to.have.property('email', 'find@example.com');
    });

    it('should return null for non-existent user', async () => {
      const adapter = new FileAdapter(testFile);
      await adapter.init();

      const user = await adapter.findUser('nonexistent@example.com');
      expect(user).to.be.null; // eslint-disable-line no-unused-expressions
    });

    it('should verify user credentials', async () => {
      const adapter = new FileAdapter(testFile);
      await adapter.init();

      await adapter.createUser({
        email: 'verify@example.com',
        password: 'hashedpassword',
      });

      const user = await adapter.verifyUser('verify@example.com', 'hashedpassword');
      expect(user).to.not.be.null; // eslint-disable-line no-unused-expressions
    });

    it('should reject invalid credentials', async () => {
      const adapter = new FileAdapter(testFile);
      await adapter.init();

      await adapter.createUser({
        email: 'verify@example.com',
        password: 'correctpassword',
      });

      const user = await adapter.verifyUser('verify@example.com', 'wrongpassword');
      expect(user).to.be.null; // eslint-disable-line no-unused-expressions
    });
  });

  describe('Token Management', () => {
    let adapter;

    beforeEach(async () => {
      adapter = new FileAdapter(testFile);
      await adapter.init();
    });

    it('should store refresh token', async () => {
      await adapter.storeRefreshToken('user123', 'token123', new Date(Date.now() + 86400000));
      // Should not throw
    });

    it('should find refresh token', async () => {
      await adapter.storeRefreshToken('user123', 'token123', new Date(Date.now() + 86400000));
      const tokenData = await adapter.findRefreshToken('token123');

      expect(tokenData).to.not.be.null; // eslint-disable-line no-unused-expressions
      expect(tokenData).to.have.property('userId', 'user123');
    });

    it('should invalidate refresh token', async () => {
      await adapter.storeRefreshToken('user123', 'token123', new Date(Date.now() + 86400000));
      await adapter.invalidateRefreshToken('token123');

      const tokenData = await adapter.findRefreshToken('token123');
      expect(tokenData).to.be.null; // eslint-disable-line no-unused-expressions
    });

    it('should invalidate all refresh tokens for user', async () => {
      await adapter.storeRefreshToken('user123', 'token1', new Date(Date.now() + 86400000));
      await adapter.storeRefreshToken('user123', 'token2', new Date(Date.now() + 86400000));
      await adapter.invalidateAllRefreshTokens('user123');

      const token1 = await adapter.findRefreshToken('token1');
      const token2 = await adapter.findRefreshToken('token2');
      expect(token1).to.be.null; // eslint-disable-line no-unused-expressions
      expect(token2).to.be.null; // eslint-disable-line no-unused-expressions
    });
  });
});

describe('Adapter Integration with createAuth', () => {
  beforeEach(() => {
    resetAuth();
  });

  afterEach(() => {
    resetAuth();
  });

  it('should work with file adapter', async () => {
    const testFile = './data/test-auth-integration.json';
    if (fs.existsSync(testFile)) {
      fs.unlinkSync(testFile);
    }

    const auth = await createAuth({
      storage: 'file',
      file: testFile,
      secret: 'test-secret',
      refreshSecret: 'test-refresh',
    });

    expect(auth.adapter).to.be.instanceOf(FileAdapter);

    // Test registration
    const result = await auth.auth.register({
      email: 'integration@example.com',
      password: 'TestP@ss123',
    });

    expect(result).to.have.property('accessToken');
    expect(result.user).to.have.property('email', 'integration@example.com');

    // Cleanup
    if (fs.existsSync(testFile)) {
      fs.unlinkSync(testFile);
    }
  });
});


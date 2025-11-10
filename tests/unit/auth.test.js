import { describe, it, beforeEach, afterEach } from 'mocha';
import { expect } from 'chai';
import { initializeAuth, getAuth, resetAuth } from '../../index.mjs';

describe('Core Authentication', () => {
  beforeEach(async () => {
    resetAuth();
    await initializeAuth({
      storage: 'memory',
      secret: 'test-secret-key-12345',
      refreshSecret: 'test-refresh-secret-12345',
    });
  });

  afterEach(() => {
    resetAuth();
  });

  describe('User Registration', () => {
    it('should register a user with email', async () => {
      const auth = getAuth();
      const result = await auth.auth.register({
        email: 'test@example.com',
        password: 'SecureP@ss123',
      });

      expect(result.user).to.have.property('email', 'test@example.com');
      expect(result).to.have.property('accessToken');
      expect(result).to.have.property('refreshToken');
      expect(result.accessToken).to.be.a('string');
    });

    it('should prevent duplicate email registration', async () => {
      const auth = getAuth();
      await auth.auth.register({
        email: 'duplicate@example.com',
        password: 'SecureP@ss123',
      });

      try {
        await auth.auth.register({
          email: 'duplicate@example.com',
          password: 'AnotherPass456',
        });
        expect.fail('Should have thrown error');
      } catch (error) {
        expect(error.message).to.include('already exists');
      }
    });
  });

  describe('User Authentication', () => {
    beforeEach(async () => {
      const auth = getAuth();
      await auth.auth.register({
        email: 'login@example.com',
        password: 'LoginP@ss123',
      });
    });

    it('should login with email', async () => {
      const auth = getAuth();
      const result = await auth.auth.loginWithIdentifier('login@example.com', 'LoginP@ss123');

      expect(result.user).to.have.property('email', 'login@example.com');
      expect(result).to.have.property('accessToken');
      expect(result).to.have.property('refreshToken');
    });

    it('should reject invalid credentials', async () => {
      const auth = getAuth();
      try {
        await auth.auth.loginWithIdentifier('login@example.com', 'WrongPassword');
        expect.fail('Should have thrown error');
      } catch (error) {
        expect(error.message).to.include('Invalid credentials');
      }
    });
  });

  describe('Token Management', () => {
    let auth;
    let refreshToken;

    beforeEach(async () => {
      auth = getAuth();
      const result = await auth.auth.register({
        email: 'token@example.com',
        password: 'TokenP@ss123',
      });
      refreshToken = result.refreshToken;
    });

    it('should refresh tokens successfully', async () => {
      const newTokens = await auth.auth.refresh(refreshToken);

      expect(newTokens).to.have.property('accessToken');
      expect(newTokens).to.have.property('refreshToken');
      expect(newTokens.accessToken).to.not.equal(refreshToken);
      expect(newTokens.refreshToken).to.not.equal(refreshToken);
    });

    it('should invalidate old refresh token after rotation', async () => {
      await auth.auth.refresh(refreshToken);

      try {
        await auth.auth.refresh(refreshToken);
        expect.fail('Should have thrown error for reused token');
      } catch (error) {
        expect(error.message).to.include('revoked or not recognized');
      }
    });
  });
});

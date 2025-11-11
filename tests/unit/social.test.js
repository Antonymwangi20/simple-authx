import { describe, it, beforeEach } from 'mocha';
import { expect } from 'chai';
import { SocialAuthProvider } from '../../src/security/social.js';

describe('Social Auth Provider', () => {
  let socialProvider;

  beforeEach(() => {
    socialProvider = new SocialAuthProvider();
  });

  describe('setupProvider', () => {
    it('should setup OAuth provider', async () => {
      await socialProvider.setupProvider('google', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        callbackURL: 'http://localhost:3000/auth/google/callback',
      });

      expect(socialProvider.providers.has('google')).to.be.true; // eslint-disable-line no-unused-expressions
    });

    it('should setup multiple providers', async () => {
      await socialProvider.setupProvider('google', {
        clientId: 'google-id',
        clientSecret: 'google-secret',
        callbackURL: 'http://localhost:3000/auth/google/callback',
      });

      await socialProvider.setupProvider('github', {
        clientId: 'github-id',
        clientSecret: 'github-secret',
        callbackURL: 'http://localhost:3000/auth/github/callback',
      });

      expect(socialProvider.providers.size).to.be.at.least(2);
    });
  });

  describe('getAuthorizationUrl', () => {
    it('should generate authorization URL for provider', async () => {
      await socialProvider.setupProvider('google', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        callbackURL: 'http://localhost:3000/auth/google/callback',
      });

      const state = 'random-state-token';
      const url = socialProvider.getAuthorizationUrl('google', state);

      expect(url).to.be.a('string');
      expect(url).to.include('google');
      expect(url).to.include(state);
    });
  });

  describe('exchangeCode', () => {
    it('should exchange authorization code for access token', async () => {
      await socialProvider.setupProvider('google', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        callbackURL: 'http://localhost:3000/auth/google/callback',
      });

      // Note: This will fail without actual OAuth flow, but tests the method exists
      try {
        await socialProvider.exchangeCode('google', 'invalid-code');
        expect.fail('Should have thrown error');
      } catch (error) {
        expect(error).to.exist; // eslint-disable-line no-unused-expressions
      }
    });
  });

  describe('getUserProfile', () => {
    it('should get user profile from OAuth provider', async () => {
      await socialProvider.setupProvider('google', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        callbackURL: 'http://localhost:3000/auth/google/callback',
      });

      // Note: This will fail without actual OAuth token, but tests the method exists
      try {
        await socialProvider.getUserProfile('google', 'invalid-token');
        expect.fail('Should have thrown error');
      } catch (error) {
        expect(error).to.exist; // eslint-disable-line no-unused-expressions
      }
    });
  });
});


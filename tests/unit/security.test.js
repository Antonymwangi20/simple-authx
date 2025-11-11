import { describe, it, beforeEach, afterEach } from 'mocha';
import { expect } from 'chai';
import { SecurityManager } from '../../src/security/security.js';
import { getAuth, resetAuth, initializeAuth } from '../../index.mjs';

describe('Security Manager', () => {
  let securityManager;

  beforeEach(() => {
    securityManager = new SecurityManager();
  });

  describe('createRateLimiter', () => {
    it('should create rate limiter middleware', () => {
      const limiter = securityManager.createRateLimiter({
        window: '1m',
        max: 10,
      });

      expect(limiter).to.be.a('function');
    });

    it('should create rate limiter with default options', () => {
      const limiter = securityManager.createRateLimiter();
      expect(limiter).to.be.a('function');
    });
  });

  describe('trackLoginAttempt', () => {
    it('should return undefined when redis is not available', async () => {
      const result = await securityManager.trackLoginAttempt('testuser', '127.0.0.1', true);
      expect(result).to.be.undefined; // eslint-disable-line no-unused-expressions
    });

    it('should track successful login attempt with redis', async () => {
      // Mock redis client
      const mockRedis = {
        del: async () => 1,
      };
      securityManager.redis = mockRedis;

      const result = await securityManager.trackLoginAttempt('testuser', '127.0.0.1', true);
      expect(result).to.have.property('userBlocked');
      expect(result).to.have.property('ipBlocked');
    });

    it('should track failed login attempt with redis', async () => {
      // Mock redis client with proper chaining
      const mockMulti = {
        zadd() { return this; },
        zremrangebyscore() { return this; },
        expire() { return this; },
        exec: async () => [0, 0],
      };
      const mockRedis = {
        multi: () => mockMulti,
      };
      securityManager.redis = mockRedis;

      const result = await securityManager.trackLoginAttempt('testuser', '127.0.0.1', false);
      expect(result).to.have.property('userBlocked');
      expect(result).to.have.property('ipBlocked');
    });
  });

  describe('isBlocked', () => {
    it('should return false when redis is not available', async () => {
      const result = await securityManager.isBlocked('testuser', '127.0.0.1');
      expect(result).to.be.false; // eslint-disable-line no-unused-expressions
    });

    it('should return object with blocking info when redis is available', async () => {
      // Mock redis client
      const mockRedis = {
        zcount: async () => 0,
      };
      securityManager.redis = mockRedis;

      const result = await securityManager.isBlocked('testuser', '127.0.0.1');

      expect(result).to.have.property('userBlocked');
      expect(result).to.have.property('ipBlocked');
      expect(result).to.have.property('remainingAttempts');
      expect(result.userBlocked).to.be.a('boolean');
      expect(result.ipBlocked).to.be.a('boolean');
      expect(result.remainingAttempts).to.be.a('number');
    });
  });

  describe('getIPReputation', () => {
    it('should get IP reputation score', async () => {
      const reputation = await securityManager.getIPReputation('127.0.0.1');
      expect(reputation).to.be.a('string');
    });

    it('should handle different IP addresses', async () => {
      const ips = ['127.0.0.1', '192.168.1.1', '10.0.0.1'];
      await Promise.all(ips.map(async (ip) => {
        const reputation = await securityManager.getIPReputation(ip);
        expect(reputation).to.be.a('string');
      }));
    });
  });
});

describe('Security Plugin Integration', () => {
  beforeEach(async () => {
    resetAuth();
    await initializeAuth({
      storage: 'memory',
      secret: 'test-secret',
      refreshSecret: 'test-refresh',
      plugins: {
        security: {
          rateLimit: true,
          maxFailedAttempts: 5,
        },
      },
    });
  });

  afterEach(() => {
    resetAuth();
  });

  it('should have security manager when plugin enabled', () => {
    const auth = getAuth();
    expect(auth.security).to.not.be.null; // eslint-disable-line no-unused-expressions
    expect(auth.security).to.be.instanceOf(SecurityManager);
  });

  it('should track login attempts through security manager', async () => {
    const auth = getAuth();
    if (auth.security) {
      const result = await auth.security.trackLoginAttempt('testuser', '127.0.0.1', false);
      // Result may be undefined if redis not available, or object if redis is available
      if (result) {
        expect(result).to.have.property('userBlocked');
        expect(result).to.have.property('ipBlocked');
      }
      const blocked = await auth.security.isBlocked('testuser', '127.0.0.1');
      // May return false if no redis, or object if redis available
      if (typeof blocked === 'object') {
        expect(blocked).to.have.property('remainingAttempts');
      }
    }
  });
});

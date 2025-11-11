import { describe, it } from 'mocha';
import { expect } from 'chai';
import { hashPassword, verifyPassword, hasherName } from '../../src/utils/hash.js';

describe('Password Hashing Utilities', () => {
  describe('hashPassword', () => {
    it('should hash a password using bcrypt by default', async () => {
      const password = 'TestPassword123';
      const hash = await hashPassword(password);

      expect(hash).to.be.a('string');
      expect(hash).to.not.equal(password);
      expect(hash.length).to.be.greaterThan(20); // bcrypt hashes are long
    });

    it('should produce different hashes for the same password', async () => {
      const password = 'TestPassword123';
      const hash1 = await hashPassword(password);
      const hash2 = await hashPassword(password);

      expect(hash1).to.not.equal(hash2); // bcrypt includes salt
    });

    it('should handle empty password', async () => {
      const hash = await hashPassword('');
      expect(hash).to.be.a('string');
    });

    it('should handle special characters', async () => {
      const password = 'P@ssw0rd!#$%^&*()';
      const hash = await hashPassword(password);
      expect(hash).to.be.a('string');
      expect(hash.length).to.be.greaterThan(20);
    });
  });

  describe('verifyPassword', () => {
    it('should verify correct password against hash', async () => {
      const password = 'TestPassword123';
      const hash = await hashPassword(password);
      const isValid = await verifyPassword(password, hash);

      expect(isValid).to.be.true; // eslint-disable-line no-unused-expressions
    });

    it('should reject incorrect password', async () => {
      const password = 'TestPassword123';
      const wrongPassword = 'WrongPassword456';
      const hash = await hashPassword(password);
      const isValid = await verifyPassword(wrongPassword, hash);

      expect(isValid).to.be.false; // eslint-disable-line no-unused-expressions
    });

    it('should handle empty password verification', async () => {
      const hash = await hashPassword('');
      const isValid = await verifyPassword('', hash);
      expect(isValid).to.be.true; // eslint-disable-line no-unused-expressions
    });

    it('should handle case-sensitive passwords', async () => {
      const password = 'TestPassword123';
      const hash = await hashPassword(password);
      const isValid = await verifyPassword('testpassword123', hash);

      expect(isValid).to.be.false; // eslint-disable-line no-unused-expressions
    });

    it('should handle invalid hash format gracefully', async () => {
      const isValid = await verifyPassword('password', 'invalid-hash-format');
      expect(isValid).to.be.false; // eslint-disable-line no-unused-expressions
    });
  });

  describe('hasherName', () => {
    it('should return the current hasher name', () => {
      const hasher = hasherName();
      expect(hasher).to.be.oneOf(['bcrypt', 'argon2']);
    });

    it('should return a string', () => {
      const hasher = hasherName();
      expect(hasher).to.be.a('string');
    });
  });

  describe('Integration: hash and verify cycle', () => {
    it('should complete full hash-verify cycle successfully', async function () {
      this.timeout(10000); // Increase timeout for multiple bcrypt operations
      const passwords = [
        'SimplePassword123',
        'Complex!P@ssw0rd#2024',
        'a',
        'VeryLongPasswordThatExceedsNormalLengthRequirements123456789',
      ];

      await passwords.reduce(async (promise, password) => {
        await promise;
        const hash = await hashPassword(password);
        const isValid = await verifyPassword(password, hash);
        expect(isValid).to.be.true; // eslint-disable-line no-unused-expressions
      }, Promise.resolve());
    });
  });
});

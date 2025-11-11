import { describe, it, beforeEach } from 'mocha';
import { expect } from 'chai';
import { PasswordManager } from '../../src/security/password.js';

describe('Password Manager', () => {
  let passwordManager;

  beforeEach(() => {
    passwordManager = new PasswordManager({
      minStrength: 2,
      minLength: 8,
    });
  });

  describe('checkStrength', () => {
    it('should check password strength without throwing', () => {
      const result = passwordManager.checkStrength('TestPassword123');

      expect(result).to.have.property('score');
      expect(result).to.have.property('feedback');
      expect(result).to.have.property('crackTime');
      expect(result).to.have.property('crackTimeSeconds');
      expect(result.score).to.be.a('number');
      expect(result.score).to.be.at.least(0).and.at.most(4);
    });

    it('should identify weak passwords', () => {
      const result = passwordManager.checkStrength('123');
      expect(result.score).to.be.below(2);
    });

    it('should identify strong passwords', () => {
      const result = passwordManager.checkStrength('Complex!P@ssw0rd#2024');
      expect(result.score).to.be.at.least(2);
    });

    it('should provide feedback for weak passwords', () => {
      const result = passwordManager.checkStrength('weak');
      expect(result.feedback).to.have.property('warning');
      expect(result.feedback).to.have.property('suggestions');
      expect(result.feedback.suggestions).to.be.an('array');
    });
  });

  describe('validatePassword', () => {
    it('should validate strong password', async () => {
      const result = await passwordManager.validatePassword(
        'StrongP@ssw0rd123',
        'testuser',
        'test@example.com'
      );

      expect(result).to.have.property('score');
      expect(result).to.have.property('feedback');
      expect(result).to.have.property('estimatedCrackTime');
    });

    it('should throw error for weak password when minStrength is set', async () => {
      passwordManager = new PasswordManager({
        minStrength: 3,
        minLength: 8,
      });

      try {
        await passwordManager.validatePassword('weak', 'testuser');
        expect.fail('Should have thrown error');
      } catch (error) {
        expect(error.message).to.include('weak');
      }
    });

    it('should throw error for weak password', async () => {
      passwordManager = new PasswordManager({
        minStrength: 3,
      });

      try {
        await passwordManager.validatePassword('123', 'testuser');
        expect.fail('Should have thrown error');
      } catch (error) {
        expect(error.message).to.be.a('string');
        expect(error.message.length).to.be.greaterThan(0);
      }
    });
  });

  describe('hashPassword', () => {
    it('should hash a password', async function () {
      this.timeout(5000);
      const hash = await passwordManager.hashPassword('TestPassword123');
      expect(hash).to.be.a('string');
      expect(hash).to.not.equal('TestPassword123');
    });

    it('should produce different hashes for same password', async function () {
      this.timeout(5000);
      const password = 'TestPassword123';
      const hash1 = await passwordManager.hashPassword(password);
      const hash2 = await passwordManager.hashPassword(password);

      expect(hash1).to.not.equal(hash2);
    });
  });

  describe('verifyPassword', () => {
    it('should verify correct password', async function () {
      this.timeout(5000);
      const password = 'TestPassword123';
      const hash = await passwordManager.hashPassword(password);
      const isValid = await passwordManager.verifyPassword(password, hash);

      expect(isValid).to.be.true;
    });

    it('should reject incorrect password', async function () {
      this.timeout(10000); // Increase timeout for bcrypt
      const password = 'TestPassword123';
      const hash = await passwordManager.hashPassword(password);
      const isValid = await passwordManager.verifyPassword('WrongPassword', hash);

      expect(isValid).to.be.false;
    });
  });

  describe('Configuration Options', () => {
    it('should work with custom minStrength', () => {
      passwordManager = new PasswordManager({ minStrength: 4 });
      const result = passwordManager.checkStrength('TestPassword123');
      expect(result).to.have.property('score');
    });

    it('should work with custom minLength', () => {
      passwordManager = new PasswordManager({ minLength: 12 });
      const result = passwordManager.checkStrength('TestPassword123');
      expect(result).to.have.property('score');
    });

    it('should work with requireUppercase option', () => {
      passwordManager = new PasswordManager({
        requireUppercase: true,
        minLength: 8,
      });
      const result = passwordManager.checkStrength('testpassword123');
      expect(result).to.have.property('score');
    });
  });
});

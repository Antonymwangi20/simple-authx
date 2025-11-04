import bcrypt from 'bcryptjs';
import argon2 from 'argon2';
import zxcvbn from 'zxcvbn'; // Password strength estimator
import crypto from 'crypto';

export class PasswordManager {
  constructor(config = {}) {
    this.minStrength = config.minStrength || 3; // 0-4 zxcvbn strength score
    this.historyLimit = config.historyLimit || 5; // Remember last 5 passwords
    this.maxAge = config.maxAge || 90 * 24 * 60 * 60 * 1000; // 90 days
    this.resetTokenExpiry = config.resetTokenExpiry || 60 * 60 * 1000; // 1 hour
    this.hashAlgo = config.hashAlgo || 'bcrypt'; // 'bcrypt' or 'argon2'
  }

  /**
   * Check password strength without validation (non-throwing)
   * @param {string} password - Password to check
   * @param {string} username - Optional username for context
   * @param {string} email - Optional email for context
   * @returns {object} Password strength analysis
   */
  checkStrength(password, username, email) {
    // Check password strength using zxcvbn
    const inputs = [username, email].filter(Boolean);
    const result = zxcvbn(password, inputs);
    
    return {
      score: result.score, // 0-4 (0 = weak, 4 = strong)
      feedback: {
        warning: result.feedback.warning || '',
        suggestions: result.feedback.suggestions || []
      },
      crackTime: result.crack_times_display.offline_fast_hashing_1e10_per_second,
      crackTimeSeconds: result.crack_times_seconds.offline_fast_hashing_1e10_per_second
    };
  }

  async validatePassword(password, username, email) {
    // Check password strength using zxcvbn
    const result = zxcvbn(password, [username, email]);
    
    if (result.score < this.minStrength) {
      throw new Error(`Password too weak. ${result.feedback.warning}. Suggestions: ${result.feedback.suggestions.join(', ')}`);
    }

    return {
      score: result.score,
      feedback: result.feedback,
      estimatedCrackTime: result.crack_times_seconds.offline_fast_hashing_1e10_per_second
    };
  }

  async hashPassword(password) {
    if (this.hashAlgo === 'argon2') {
      return argon2.hash(password);
    } else {
      const salt = await bcrypt.genSalt(12);
      return bcrypt.hash(password, salt);
    }
  }

  async verifyPassword(password, hash) {
    if (this.hashAlgo === 'argon2') {
      return argon2.verify(hash, password);
    } else {
      return bcrypt.compare(password, hash);
    }
  }

  generateResetToken() {
    return {
      token: crypto.randomBytes(32).toString('hex'),
      expires: new Date(Date.now() + this.resetTokenExpiry)
    };
  }

  async checkPasswordHistory(password, history) {
    for (const oldHash of history) {
      if (await this.verifyPassword(password, oldHash)) {
        throw new Error('Password was used recently. Please choose a different password.');
      }
    }
  }

  async enforcePasswordPolicy(username, password, userData = {}) {
    // Check common password patterns
    const commonPatterns = [
      username,
      username.split('').reverse().join(''),
      userData.email,
      userData.birthYear,
      'password',
      '12345678'
    ];

    for (const pattern of commonPatterns) {
      if (pattern && password.toLowerCase().includes(pattern.toLowerCase())) {
        throw new Error('Password contains personal information or common patterns');
      }
    }

    // Check for repeated characters
    if (/(.)\1{2,}/.test(password)) {
      throw new Error('Password contains too many repeated characters');
    }

    // Check for sequential characters
    if (/(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)/i.test(password)) {
      throw new Error('Password contains sequential characters');
    }

    return true;
  }

  generateTemporaryPassword() {
    const length = 12;
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    let password = '';
    let hasUpper = false;
    let hasLower = false;
    let hasNumber = false;
    let hasSpecial = false;

    while (password.length < length || !hasUpper || !hasLower || !hasNumber || !hasSpecial) {
      const char = charset[Math.floor(Math.random() * charset.length)];
      password += char;
      
      if (/[A-Z]/.test(char)) hasUpper = true;
      if (/[a-z]/.test(char)) hasLower = true;
      if (/[0-9]/.test(char)) hasNumber = true;
      if (/[^A-Za-z0-9]/.test(char)) hasSpecial = true;
    }

    return password;
  }
}
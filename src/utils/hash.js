import bcrypt from 'bcryptjs';
import argon2 from 'argon2';

const DEFAULT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '10', 10);
const HASHER = (process.env.PASSWORD_HASHER || 'bcrypt').toLowerCase();

export async function hashPassword(password) {
  if (HASHER === 'argon2') {
    return argon2.hash(password);
  }
  // bcrypt
  return bcrypt.hash(password, DEFAULT_ROUNDS);
}

/**
 * Verifies a password against a bcrypt hash
 * @param {string} password - Plain text password to verify
 * @param {string} hash - Bcrypt hash to verify against
 * @returns {Promise<boolean>} True if password matches, false otherwise
 * @example
 * const isValid = await verifyPassword('myPassword123', storedHash);
 */
export async function verifyPassword(password, hash) {
  if (HASHER === 'argon2') {
    try {
      return await argon2.verify(hash, password);
    } catch {
      return false;
    }
  }
  return bcrypt.compare(password, hash);
}

/**
 * Gets the name of the currently configured password hasher
 * @returns {string} 'bcrypt' or 'argon2'
 */
export function hasherName() {
  return HASHER;
}

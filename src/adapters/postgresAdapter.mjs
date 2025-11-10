import { hashPassword, verifyPassword } from '../utils/hash.js';
import crypto from 'crypto';
import pkg from 'pg';
const { Pool } = pkg;

export class PostgresAdapter {
  constructor(config) {
    this.pool = new Pool(config);
  }

  async findUser(identifier) {
    // Try to find by username, email, or phone
    const { rows } = await this.pool.query(
      `SELECT * FROM users 
      WHERE username=$1 OR email=$1 OR phone_number=$1 
      LIMIT 1`,
      [identifier]
    );
    return rows[0] || null;
  }

  async createUser(userData) {
    const { password, ...fields } = userData;
    const hash = await hashPassword(password);

    // Build dynamic INSERT query
    const fieldNames = ['password_hash', ...Object.keys(fields)];
    const fieldValues = [hash, ...Object.values(fields)];
    const placeholders = fieldNames.map((_, i) => `$${i + 1}`).join(', ');

    const { rows } = await this.pool.query(
      `INSERT INTO users (${fieldNames.join(', ')}) 
      VALUES (${placeholders}) 
      RETURNING *`,
      fieldValues
    );

    return rows[0];
  }

  async verifyUser(identifier, password) {
    const user = await this.findUser(identifier);
    if (!user) return null;
    const ok = await verifyPassword(password, user.password_hash);
    return ok ? user : null;
  }

  async storeRefreshToken(userId, token, expiry) {
    // store a SHA-256 hash of the refresh token to avoid storing raw tokens in DB
    const hash = crypto.createHash('sha256').update(token).digest('hex');
    await this.pool.query(
      'INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)',
      [userId, hash, expiry]
    );
  }

  async findRefreshToken(token) {
    const hash = crypto.createHash('sha256').update(token).digest('hex');
    const { rows } = await this.pool.query('SELECT * FROM refresh_tokens WHERE token_hash=$1', [
      hash,
    ]);
    return rows[0] || null;
  }

  async invalidateRefreshToken(token) {
    const hash = crypto.createHash('sha256').update(token).digest('hex');
    await this.pool.query('DELETE FROM refresh_tokens WHERE token_hash=$1', [hash]);
  }

  async invalidateAllRefreshTokens(userId) {
    await this.pool.query('DELETE FROM refresh_tokens WHERE user_id=$1', [userId]);
  }
}

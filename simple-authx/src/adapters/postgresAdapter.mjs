// src/adapters/postgres-adapter.js
import { hashPassword, verifyPassword } from '../utils/hash.js'
import crypto from 'crypto'
import pkg from 'pg'
const { Pool } = pkg

export class PostgresAdapter {
  constructor(config) {
    this.pool = new Pool(config)
  }

  async findUser(username) {
    const { rows } = await this.pool.query('SELECT * FROM users WHERE username=$1', [username])
    return rows[0] || null
  }

  async createUser(username, password) {
    const hash = await hashPassword(password)
    const { rows } = await this.pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING *',
      [username, hash]
    )
    return rows[0]
  }

  async verifyUser(username, password) {
    const user = await this.findUser(username)
    if (!user) return null
    const ok = await verifyPassword(password, user.password_hash)
    return ok ? user : null
  }

  async storeRefreshToken(userId, token, expiry) {
    // store a SHA-256 hash of the refresh token to avoid storing raw tokens in DB
    const hash = crypto.createHash('sha256').update(token).digest('hex')
    await this.pool.query(
      'INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)',
      [userId, hash, expiry]
    )
  }

  async findRefreshToken(token) {
    const hash = crypto.createHash('sha256').update(token).digest('hex')
    const { rows } = await this.pool.query('SELECT * FROM refresh_tokens WHERE token_hash=$1', [hash])
    return rows[0] || null
  }

  async invalidateRefreshToken(token) {
    const hash = crypto.createHash('sha256').update(token).digest('hex')
    await this.pool.query('DELETE FROM refresh_tokens WHERE token_hash=$1', [hash])
  }

  async invalidateAllRefreshTokens(userId) {
    await this.pool.query('DELETE FROM refresh_tokens WHERE user_id=$1', [userId])
  }
}

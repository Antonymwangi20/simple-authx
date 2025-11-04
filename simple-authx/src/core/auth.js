import jwt from 'jsonwebtoken'
import crypto from 'crypto'

export class AuthManager {
  constructor(options = {}) {
    this.secret = options.secret || process.env.JWT_SECRET || 'dev_secret'
    this.refreshSecret = options.refreshSecret || process.env.JWT_REFRESH_SECRET || 'dev_refresh_secret'
    this.accessExpiry = options.accessExpiry || '15m'
    this.refreshExpiry = options.refreshExpiry || '7d'
    this.adapter = options.adapter // e.g., instance of PostgresAdapter

    // Hooks (can be set externally or imported)
    this.hooks = options.hooks || {}
  }

  generateTokens(payload) {
    const accessToken = jwt.sign(payload, this.secret, { expiresIn: this.accessExpiry })
    // add a unique jti to refresh token to ensure rotation produces unique tokens
    const jti = (crypto.randomUUID && crypto.randomUUID()) || crypto.randomBytes(16).toString('hex')
    const refreshPayload = { ...payload, jti }
    const refreshToken = jwt.sign(refreshPayload, this.refreshSecret, { expiresIn: this.refreshExpiry })
    return { accessToken, refreshToken }
  }

  async register(username, password) {
    if (!this.adapter) throw new Error('No database adapter configured')
    const existing = await this.adapter.findUser(username)
    if (existing) throw new Error('Username already exists')

    const user = await this.adapter.createUser(username, password)
    const tokens = this.generateTokens({ userId: user.id })
    const decoded = jwt.decode(tokens.refreshToken)
    await this.adapter.storeRefreshToken(user.id, tokens.refreshToken, new Date(decoded.exp * 1000))

    // run hook
    if (this.hooks.onRegister) await this.hooks.onRegister(user)

    return { user, ...tokens }
  }

  async login(username, password) {
    if (!this.adapter) throw new Error('No database adapter configured')
    const user = await this.adapter.verifyUser(username, password)
    if (!user) throw new Error('Invalid credentials')

    const tokens = this.generateTokens({ userId: user.id })
    const decoded = jwt.decode(tokens.refreshToken)
    await this.adapter.storeRefreshToken(user.id, tokens.refreshToken, new Date(decoded.exp * 1000))

    // run hook
    if (this.hooks.onLogin) await this.hooks.onLogin(user)

    return { user, ...tokens }
  }

  async refresh(oldToken) {
    if (!this.adapter) throw new Error('No database adapter configured')
    // Attempt to find the refresh token in storage (adapters store hashed token)
    const stored = await this.adapter.findRefreshToken(oldToken)

    // If not found, it could be a reuse attack (token already rotated/deleted).
    // We'll still attempt to verify the token to extract the user id and then
    // perform a global invalidation for safety.
    let decoded
    try {
      decoded = jwt.verify(oldToken, this.refreshSecret)
    } catch (err) {
      // token invalid or expired
      if (stored) {
        // stored but verification failed: invalidate stored token
        await this.adapter.invalidateRefreshToken(oldToken)
      }
      throw new Error('Expired or invalid refresh token')
    }

    // If token not found in DB, treat as token reuse and revoke all refresh tokens for user
    if (!stored) {
      try {
        if (this.adapter.invalidateAllRefreshTokens) {
          await this.adapter.invalidateAllRefreshTokens(decoded.userId)
        }
      } catch (e) {
        // log and continue to throw
        if (this.hooks && this.hooks.onError) await this.hooks.onError(e)
      }
      throw new Error('Refresh token revoked or not recognized (possible reuse)')
    }

    // At this point token exists and is valid. Rotate: invalidate old, issue new.
    await this.adapter.invalidateRefreshToken(oldToken)
    const tokens = this.generateTokens({ userId: decoded.userId })
    const newDecoded = jwt.decode(tokens.refreshToken)
    await this.adapter.storeRefreshToken(decoded.userId, tokens.refreshToken, new Date(newDecoded.exp * 1000))
    return tokens
  }

  verifyAccess(token) {
    return jwt.verify(token, this.secret)
  }
}

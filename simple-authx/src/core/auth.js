// src/core/auth.js - Fixed AuthManager with backward compatibility

import jwt from 'jsonwebtoken'
import crypto from 'crypto'

export class AuthManager {
  constructor(options = {}) {
    this.secret = options.secret || process.env.JWT_SECRET || 'dev_secret'
    this.refreshSecret = options.refreshSecret || process.env.JWT_REFRESH_SECRET || 'dev_refresh_secret'
    this.accessExpiry = options.accessExpiry || '15m'
    this.refreshExpiry = options.refreshExpiry || '7d'
    this.adapter = options.adapter
    this.config = options.config || {}

    // Hooks (can be set externally or imported)
    this.hooks = options.hooks || {}
  }

  generateTokens(payload) {
    const accessToken = jwt.sign(payload, this.secret, { expiresIn: this.accessExpiry })
    const jti = (crypto.randomUUID && crypto.randomUUID()) || crypto.randomBytes(16).toString('hex')
    const refreshPayload = { ...payload, jti }
    const refreshToken = jwt.sign(refreshPayload, this.refreshSecret, { expiresIn: this.refreshExpiry })
    return { accessToken, refreshToken }
  }

  /**
   * Register a new user
   * @param {string|object} usernameOrData - Username string (legacy) or userData object (new)
   * @param {string} password - Password (only used in legacy mode)
   * @returns {Promise<{user, accessToken, refreshToken}>}
   */
  async register(usernameOrData, password) {
    if (!this.adapter) throw new Error('No database adapter configured');
    
    let userData;
    
    // Backward compatibility: support both old and new signature
    if (typeof usernameOrData === 'string') {
      // Legacy format: register(username, password)
      console.log('[AuthManager] Using legacy register format (username, password)');
      userData = {
        username: usernameOrData,
        password: password
      };
    } else if (typeof usernameOrData === 'object') {
      // New format: register({ username, password, email, ... })
      console.log('[AuthManager] Using new register format (userData object)');
      userData = usernameOrData;
    } else {
      throw new Error('Invalid registration data format');
    }
    
    // Extract password and other fields
    const { password: pwd, ...userFields } = userData;
    
    if (!pwd) {
      throw new Error('password is required');
    }
    
    console.log('[AuthManager] Registration data:', {
      username: userFields.username,
      email: userFields.email,
      phoneNumber: userFields.phoneNumber,
      hasPassword: !!pwd
    });
    
    // Validate required fields
    const config = this.config?.userFields || { identifiers: ['username'], required: ['username'] };
    
    for (const field of config.required || ['username']) {
      if (!userData[field]) {
        throw new Error(`${field} is required`);
      }
    }
    
    // Check if user already exists (by any identifier)
    for (const identifier of config.identifiers || ['username']) {
      if (userData[identifier]) {
        const existing = await this.adapter.findUser(userData[identifier]);
        if (existing) {
          throw new Error(`User with this ${identifier} already exists`);
        }
      }
    }
    
    // Validate custom fields
    if (config.validate) {
      for (const [field, validator] of Object.entries(config.validate)) {
        if (userData[field] && !validator(userData[field])) {
          throw new Error(`Invalid ${field} format`);
        }
      }
    }
    
    console.log('[AuthManager] Creating user...');
    const user = await this.adapter.createUser(userData);
    console.log('[AuthManager] User created:', user.id);
    
    const tokens = this.generateTokens({ userId: user.id });
    const decoded = jwt.decode(tokens.refreshToken);
    await this.adapter.storeRefreshToken(user.id, tokens.refreshToken, new Date(decoded.exp * 1000));
    
    if (this.hooks.onRegister) await this.hooks.onRegister(user);
    
    return { user, ...tokens };
  }

  /**
   * Login with username (legacy method)
   * @param {string} username - Username
   * @param {string} password - Password
   * @returns {Promise<{user, accessToken, refreshToken}>}
   */
  async login(username, password) {
    console.log('[AuthManager] Using legacy login method');
    return this.loginWithIdentifier(username, password);
  }

  /**
   * Login with any identifier (username, email, or phone)
   * @param {string} identifier - Username, email, or phone number
   * @param {string} password - Password
   * @returns {Promise<{user, accessToken, refreshToken}>}
   */
  async loginWithIdentifier(identifier, password) {
    if (!this.adapter) throw new Error('No database adapter configured');
    
    console.log('[AuthManager] Login attempt for:', identifier);
    
    // Try to find and verify user with the identifier
    const user = await this.adapter.verifyUser(identifier, password);
    
    if (!user) {
      console.log('[AuthManager] Login failed: Invalid credentials');
      throw new Error('Invalid credentials');
    }
    
    console.log('[AuthManager] User verified:', user.id);
    
    const tokens = this.generateTokens({ 
      userId: user.id,
      email: user.email,
      username: user.username,
      phoneNumber: user.phoneNumber
    });
    
    const decoded = jwt.decode(tokens.refreshToken);
    await this.adapter.storeRefreshToken(user.id, tokens.refreshToken, new Date(decoded.exp * 1000));
    
    if (this.hooks.onLogin) await this.hooks.onLogin(user);
    
    console.log('[AuthManager] Login successful');
    
    return { user, ...tokens };
  }

  async refresh(oldToken) {
    if (!this.adapter) throw new Error('No database adapter configured')
    
    console.log('[AuthManager] Refresh token request');
    
    // Attempt to find the refresh token in storage
    const stored = await this.adapter.findRefreshToken(oldToken)

    let decoded
    try {
      decoded = jwt.verify(oldToken, this.refreshSecret)
    } catch (err) {
      console.error('[AuthManager] Token verification failed:', err.message);
      if (stored) {
        await this.adapter.invalidateRefreshToken(oldToken)
      }
      throw new Error('Expired or invalid refresh token')
    }

    // If token not found in DB, treat as token reuse
    if (!stored) {
      console.log('[AuthManager] Token reuse detected, revoking all tokens');
      try {
        if (this.adapter.invalidateAllRefreshTokens) {
          await this.adapter.invalidateAllRefreshTokens(decoded.userId)
        }
      } catch (e) {
        if (this.hooks && this.hooks.onError) await this.hooks.onError(e)
      }
      throw new Error('Refresh token revoked or not recognized (possible reuse)')
    }

    // Rotate token
    console.log('[AuthManager] Rotating refresh token');
    await this.adapter.invalidateRefreshToken(oldToken)
    const tokens = this.generateTokens({ userId: decoded.userId })
    const newDecoded = jwt.decode(tokens.refreshToken)
    await this.adapter.storeRefreshToken(decoded.userId, tokens.refreshToken, new Date(newDecoded.exp * 1000))
    
    console.log('[AuthManager] Token refreshed successfully');
    return tokens
  }

  verifyAccess(token) {
    return jwt.verify(token, this.secret)
  }
}
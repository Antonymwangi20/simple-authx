// redisAdapter.mjs
import { createClient } from 'redis';
import { createHash } from 'crypto';
<<<<<<< HEAD
=======
import { verifyPassword, hashPassword } from '../utils/hash.js'
>>>>>>> f63ac94 (Add working createAuth wrapper with File/Postgres/Mongo/Redis support)

function hashToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

let client = null;

export async function connectRedis(options = {}) {
  if (!client) {
    client = createClient(options);
    client.on('error', (err) => console.error('[AuthX] Redis Error:', err));
    await client.connect();
    console.log('[AuthX] Connected to Redis');
  }
  return client;
}

export function RedisTokenStore(prefix = 'authx:refresh:') {
  if (!client) throw new Error('Redis not connected. Call connectRedis() first.');

  return {
    async get(username) {
      return await client.get(prefix + username);
    },
    async set(username, refreshToken, ttlSeconds = 7 * 24 * 60 * 60) {
      const hashedToken = hashToken(refreshToken);
      await client.set(prefix + username, hashedToken, { EX: ttlSeconds });
      return refreshToken;
    },
    async delete(username) {
      return await client.del(prefix + username);
    },
    async rotate(username, oldToken, newToken, ttlSeconds = 7 * 24 * 60 * 60) {
      const stored = await client.get(prefix + username);
      if (!stored || stored !== hashToken(oldToken)) return false; // reject reused or invalid token
      await this.set(username, newToken, { EX: ttlSeconds });
      return true;
    }
  };
}
<<<<<<< HEAD
=======

// Class adapter compatible with AuthManager. Requires a userStore implementing
// findUser(username), createUser(username, password), verifyUser(username, password)
export class RedisAdapter {
  constructor(userStore, options = {}) {
    if (!client) throw new Error('Redis not connected. Call connectRedis() first.')
    if (!userStore) throw new Error('RedisAdapter requires a userStore')
    this.userStore = userStore
    this.prefix = options.prefix || 'authx:refresh:'
    this.revPrefix = options.revPrefix || 'authx:rt2uid:'
  }

  async findUser(username) {
    return this.userStore.findUser(username)
  }

  async createUser(username, password) {
    // delegate create to userStore, ensure it stores password_hash
    if (this.userStore.createUser) {
      return this.userStore.createUser(username, password)
    }
    // fallback if userStore exposes set API like FileAdapter style
    const hash = await hashPassword(password)
    if (this.userStore.set) {
      const user = { id: Date.now().toString(), username, password_hash: hash }
      await this.userStore.set(username, user)
      return user
    }
    throw new Error('Unsupported userStore implementation')
  }

  async verifyUser(username, password) {
    if (this.userStore.verifyUser) {
      return this.userStore.verifyUser(username, password)
    }
    const user = await this.findUser(username)
    if (!user) return null
    const ok = await verifyPassword(password, user.password_hash)
    return ok ? user : null
  }

  async storeRefreshToken(userId, token, expiry) {
    const hashed = hashToken(token)
    const key = this.prefix + userId
    const ttl = Math.max(1, Math.floor((expiry.getTime() - Date.now()) / 1000))
    await client.set(key, hashed, { EX: ttl })
    await client.set(this.revPrefix + hashed, userId, { EX: ttl })
  }

  async findRefreshToken(token) {
    const hashed = hashToken(token)
    const userId = await client.get(this.revPrefix + hashed)
    if (!userId) return null
    const stored = await client.get(this.prefix + userId)
    if (stored === hashed) return { userId }
    return null
  }

  async invalidateRefreshToken(token) {
    const hashed = hashToken(token)
    const userId = await client.get(this.revPrefix + hashed)
    if (userId) {
      await client.del(this.prefix + userId)
    }
    await client.del(this.revPrefix + hashed)
  }

  async invalidateAllRefreshTokens(userId) {
    await client.del(this.prefix + userId)
  }
}
>>>>>>> f63ac94 (Add working createAuth wrapper with File/Postgres/Mongo/Redis support)

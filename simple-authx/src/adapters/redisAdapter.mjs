// redisAdapter.mjs
import { createClient } from 'redis';
import { createHash } from 'crypto';

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

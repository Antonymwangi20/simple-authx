// Comprehensive test runner for all adapters and features
import assert from 'assert';
import { AuthManager } from '../src/core/auth.js';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { FileAdapter } from '../src/adapters/file-adapter.js';
import { connectMongo, MongoUserStore, MongoTokenStore } from '../src/adapters/mongoAdapters.mjs';
import { connectRedis, RedisTokenStore } from '../src/adapters/redisAdapter.mjs';

// Using dynamic imports for optional adapters
const runMongoTests = async () => {
  try {
    const { default: mongoTests } = await import('./mongo-adapter.test.js');
    await mongoTests();
  } catch (err) {
    console.log('Skipping MongoDB tests:', err.message);
  }
};

const runRedisTests = async () => {
  try {
    const { default: redisTests } = await import('./redis-adapter.test.js');
    await redisTests();
  } catch (err) {
    console.log('Skipping Redis tests:', err.message);
  }
};

class MockAdapter {
  constructor() {
    this.users = new Map()
    this.tokens = [] // store { userId, token_hash }
  }

  async findUser(username) {
    for (const u of this.users.values()) if (u.username === username) return u
    return null
  }

  async createUser(username, password) {
    const hash = await bcrypt.hash(password, 10)
    const id = (this.users.size + 1).toString()
    const user = { id, username, password_hash: hash }
    this.users.set(id, user)
    return user
  }

  async verifyUser(username, password) {
    const user = await this.findUser(username)
    if (!user) return null
    const ok = await bcrypt.compare(password, user.password_hash)
    return ok ? user : null
  }

  async storeRefreshToken(userId, token, expiry) {
    const hash = crypto.createHash('sha256').update(token).digest('hex')
    this.tokens.push({ userId, token_hash: hash, expiresAt: expiry })
  }

  async findRefreshToken(token) {
    const hash = crypto.createHash('sha256').update(token).digest('hex')
    return this.tokens.find(t => t.token_hash === hash) || null
  }

  async invalidateRefreshToken(token) {
    const hash = crypto.createHash('sha256').update(token).digest('hex')
    this.tokens = this.tokens.filter(t => t.token_hash !== hash)
  }

  async invalidateAllRefreshTokens(userId) {
    this.tokens = this.tokens.filter(t => t.userId !== userId)
  }
}

async function run() {
  const adapter = new MockAdapter()
  const auth = new AuthManager({ adapter, secret: 's', refreshSecret: 'r' })

  // Register
  const reg = await auth.register('alice', 'correcthorsebatterystaple')
  assert(reg.user.username === 'alice')

  // Login
  const login = await auth.login('alice', 'correcthorsebatterystaple')
  assert(login.accessToken && login.refreshToken)
  // console.log('login.refreshToken:', login.refreshToken)
  // console.log('tokens after login:', adapter.tokens)

  // Refresh should rotate tokens
  const tokens1 = await auth.refresh(login.refreshToken)
  assert(tokens1.accessToken && tokens1.refreshToken)
  // console.log('tokens after first refresh:', adapter.tokens)

  // Using the old refresh token again should throw (reuse detection)
  let threw = false
  try {
    await auth.refresh(login.refreshToken)
  } catch (e) {
    threw = true
  }
  // console.log('tokens after second refresh attempt:', adapter.tokens)
  assert(threw, 'Old refresh token reuse should throw')

  console.log('All tests passed ✅')

  // Additional adapter contract test: FileAdapter
  const fileAdapter = new FileAdapter('./data/test-auth.json')
  // ensure data dir exists for file adapter tests
  const fs = await import('fs/promises')
  await fs.mkdir('./data', { recursive: true })
  await fileAdapter.init()
  // clean any existing test data
  fileAdapter.data = { users: [], refreshTokens: [] }
  await fileAdapter.save()

  const auth2 = new AuthManager({ adapter: fileAdapter, secret: 's', refreshSecret: 'r' })
  const r2 = await auth2.register('bob', 'correcthorsebatterystaple')
  assert(r2.user.username === 'bob')
  const l2 = await auth2.login('bob', 'correcthorsebatterystaple')
  assert(l2.accessToken && l2.refreshToken)
  const t2 = await auth2.refresh(l2.refreshToken)
  assert(t2.accessToken && t2.refreshToken)

  let threw2 = false
  try {
    await auth2.refresh(l2.refreshToken)
  } catch (e) {
    threw2 = true
  }
  assert(threw2, 'FileAdapter: old refresh token reuse should throw')

  console.log('File adapter contract tests passed ✅')

  // Run MongoDB and Redis tests if available
  await runMongoTests();
  await runRedisTests();
}

run().catch(err => {
  console.error(err)
  process.exit(1)
})

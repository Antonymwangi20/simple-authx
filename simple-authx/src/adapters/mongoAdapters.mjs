// mongoAdapters.mjs
import mongoose from 'mongoose';
import { createHash } from 'crypto';
import { hashPassword, verifyPassword } from '../utils/hash.js'

function hashToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

export async function connectMongo(uri) {
  if (mongoose.connection.readyState === 0) {
    await mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true });
    console.log('[AuthX] Connected to MongoDB');
  }
}

// --- Schemas ---
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
  createdAt: { type: Date, default: Date.now }
});

const tokenSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  refreshToken: String,
  createdAt: { type: Date, default: Date.now, expires: 7 * 24 * 60 * 60 } // 7 days TTL
});

const UserModel = mongoose.model('AuthX_User', userSchema);
const TokenModel = mongoose.model('AuthX_Token', tokenSchema);

// --- Adapters ---
export function MongoUserStore() {
  return {
    async get(username) {
      return UserModel.findOne({ username }).lean();
    },
    async set(username, userData) {
      return UserModel.findOneAndUpdate({ username }, userData, { upsert: true, new: true });
    },
    async delete(username) {
      return UserModel.deleteOne({ username });
    }
  };
}

export function MongoTokenStore() {
  return {
    async get(username) {
      const tokenDoc = await TokenModel.findOne({ username });
      return tokenDoc?.refreshToken || null;
    },
    async set(username, refreshToken) {
      const hashedToken = hashToken(refreshToken);
      await TokenModel.findOneAndUpdate(
        { username },
        { refreshToken: hashedToken, createdAt: new Date() },
        { upsert: true }
      );
      return refreshToken;
    },
    async delete(username) {
      return TokenModel.deleteOne({ username });
    },
    async rotate(username, oldToken, newToken) {
      const tokenDoc = await TokenModel.findOne({ username });
      if (!tokenDoc || tokenDoc.refreshToken !== hashToken(oldToken)) {
        return false; // reject reused or invalid token
      }
      await this.set(username, newToken);
      return true;
    }
  };
}

// Class adapter compatible with AuthManager
export class MongoAdapter {
  constructor() {}

  async findUser(username) {
    const u = await UserModel.findOne({ username }).lean()
    if (!u) return null
    return { id: u._id.toString(), username: u.username, password_hash: u.password }
  }

  async createUser(username, password) {
    const hash = await hashPassword(password)
    const doc = await UserModel.create({ username, password: hash })
    return { id: doc._id.toString(), username: doc.username, password_hash: hash }
  }

  async verifyUser(username, password) {
    const u = await UserModel.findOne({ username })
    if (!u) return null
    const ok = await verifyPassword(password, u.password)
    if (!ok) return null
    return { id: u._id.toString(), username: u.username, password_hash: u.password }
  }

  async storeRefreshToken(userId, token, expiry) {
    const user = await UserModel.findById(userId)
    if (!user) throw new Error('User not found')
    const hashed = hashToken(token)
    await TokenModel.findOneAndUpdate(
      { username: user.username },
      { refreshToken: hashed, createdAt: new Date() },
      { upsert: true }
    )
  }

  async findRefreshToken(token) {
    const hashed = hashToken(token)
    const doc = await TokenModel.findOne({ refreshToken: hashed })
    return doc || null
  }

  async invalidateRefreshToken(token) {
    const hashed = hashToken(token)
    await TokenModel.deleteOne({ refreshToken: hashed })
  }

  async invalidateAllRefreshTokens(userId) {
    const user = await UserModel.findById(userId)
    if (!user) return
    await TokenModel.deleteMany({ username: user.username })
  }
}

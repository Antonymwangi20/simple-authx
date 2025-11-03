// mongoAdapters.mjs
import mongoose from 'mongoose';
import { createHash } from 'crypto';

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

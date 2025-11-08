import mongoose from 'mongoose';
import { createHash } from 'crypto';
import { hashPassword, verifyPassword } from '../utils/hash.js';

function hashToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

export async function connectMongo(uri) {
  if (mongoose.connection.readyState === 0) {
    try {
      await mongoose.connect(uri, {
        serverSelectionTimeoutMS: 5000, // 5 second timeout
        connectTimeoutMS: 10000,
        socketTimeoutMS: 45000,
      });
      console.log('[AuthX] Connected to MongoDB');
    } catch (err) {
      console.error('[AuthX] MongoDB connection failed:', err.message);
      throw new Error(`MongoDB connection failed: ${err.message}`);
    }
  }
}

// --- Schemas ---
const userSchema = new mongoose.Schema({
  email: { type: String, unique: [true, 'Email must be unique'], required: [true, 'Email is required'], index: true, match: [/.+\@.+\..+/, 'Please fill a valid email address'] },
  username: { type: String, unique: [true, 'Username must be unique'], required: [true, 'Username is required'], index: true },
  phoneNumber: { type: String, unique: true, sparse: true },
  password: { type: String, required: [true, 'Password is required'] },
  createdAt: { type: Date, default: Date.now }
}, { collection: 'authx_users' });

const tokenSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'AuthX_User', required: true },
  tokenHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: 7 * 24 * 60 * 60 }
}, { collection: 'authx_tokens' });

const UserModel = mongoose.model('AuthX_User', userSchema);
const TokenModel = mongoose.model('AuthX_Token', tokenSchema);

// Class adapter compatible with AuthManager
export class MongoAdapter {
  constructor() {
    // Check connection on initialization
    if (mongoose.connection.readyState !== 1) {
      console.warn('[MongoAdapter] Warning: MongoDB not connected yet');
    }
  }

  async findUser(username) {
    try {
      const user = await UserModel.findOne({ username }).lean().maxTimeMS(5000);
      if (!user) return null;
      
      return { 
        id: user._id.toString(), 
        username: user.username, 
        password_hash: user.password
      };
    } catch (err) {
      console.error('[MongoAdapter] findUser error:', err.message);
      throw new Error(`Database error: ${err.message}`);
    }
  }

  async createUser(username, password) {
    try {
      // Check if user exists first
      const existing = await UserModel.findOne({ username }).maxTimeMS(5000);
      if (existing) {
        throw new Error('Username already exists');
      }
      
      // Hash password
      const hash = await hashPassword(password);
      
      // Create user
      const doc = await UserModel.create({ 
        username, 
        password: hash 
      });
      
      console.log('[MongoAdapter] User created:', username);
      
      return { 
        id: doc._id.toString(), 
        username: doc.username, 
        password_hash: hash 
      };
    } catch (err) {
      console.error('[MongoAdapter] createUser error:', err.message);
      if (err.code === 11000) {
        throw new Error('Username already exists');
      }
      throw new Error(`Failed to create user: ${err.message}`);
    }
  }

  async verifyUser(username, password) {
    try {
      // Find user with timeout
      const user = await UserModel.findOne({ username }).maxTimeMS(5000);
      
      if (!user) {
        console.log('[MongoAdapter] User not found:', username);
        return null;
      }
      
      // Verify password
      const isValid = await verifyPassword(password, user.password);
      
      if (!isValid) {
        console.log('[MongoAdapter] Invalid password for:', username);
        return null;
      }
      
      console.log('[MongoAdapter] User verified:', username);
      
      return { 
        id: user._id.toString(), 
        username: user.username, 
        password_hash: user.password 
      };
    } catch (err) {
      console.error('[MongoAdapter] verifyUser error:', err.message);
      throw new Error(`Verification failed: ${err.message}`);
    }
  }

  async storeRefreshToken(userId, token, expiry) {
    try {
      const hashed = hashToken(token);
      
      // Remove old tokens for this user
      await TokenModel.deleteMany({ userId }).maxTimeMS(5000);
      
      // Store new token
      await TokenModel.create({
        userId,
        tokenHash: hashed,
        createdAt: new Date()
      });
      
      console.log('[MongoAdapter] Refresh token stored for user:', userId);
    } catch (err) {
      console.error('[MongoAdapter] storeRefreshToken error:', err.message);
      throw new Error(`Failed to store token: ${err.message}`);
    }
  }

  async findRefreshToken(token) {
    try {
      const hashed = hashToken(token);
      
      const doc = await TokenModel.findOne({ tokenHash: hashed })
        .maxTimeMS(5000);
      
      if (!doc) return null;
      
      return { 
        userId: doc.userId.toString()
      };
    } catch (err) {
      console.error('[MongoAdapter] findRefreshToken error:', err.message);
      throw new Error(`Failed to find token: ${err.message}`);
    }
  }

  async invalidateRefreshToken(token) {
    try {
      const hashed = hashToken(token);
      await TokenModel.deleteOne({ tokenHash: hashed }).maxTimeMS(5000);
      console.log('[MongoAdapter] Token invalidated');
    } catch (err) {
      console.error('[MongoAdapter] invalidateRefreshToken error:', err.message);
      // Don't throw on logout
    }
  }

  async invalidateAllRefreshTokens(userId) {
    try {
      await TokenModel.deleteMany({ userId }).maxTimeMS(5000);
      console.log('[MongoAdapter] All tokens invalidated for user:', userId);
    } catch (err) {
      console.error('[MongoAdapter] invalidateAllRefreshTokens error:', err.message);
      // Don't throw on cleanup
    }
  }

  async close() {
    try {
      await mongoose.connection.close();
      console.log('[MongoAdapter] Connection closed');
    } catch (err) {
      console.error('[MongoAdapter] close error:', err.message);
    }
  }
}

// Legacy functions (for backwards compatibility)
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
    async get(userId) {
      const tokenDoc = await TokenModel.findOne({ userId });
      return tokenDoc?.tokenHash || null;
    },
    async set(userId, refreshToken) {
      const hashedToken = hashToken(refreshToken);
      await TokenModel.findOneAndUpdate(
        { userId },
        { tokenHash: hashedToken, createdAt: new Date() },
        { upsert: true }
      );
      return refreshToken;
    },
    async delete(userId) {
      return TokenModel.deleteMany({ userId });
    }
  };
}
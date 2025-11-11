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
const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      unique: true,
      sparse: true,
      index: true,
    },
    username: {
      type: String,
      unique: true,
      sparse: true,
      index: true,
    },
    phoneNumber: {
      type: String,
      unique: true,
      sparse: true,
      index: true,
    },
    password: {
      type: String,
      required: true,
    },
    // Custom fields (flexible schema)
    metadata: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
  },
  {
    timestamps: true,
    collection: 'authx_users',
    strict: false, // Allow additional fields
  }
);

const tokenSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'AuthX_User', required: true },
    tokenHash: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: 7 * 24 * 60 * 60 },
  },
  { collection: 'authx_tokens' }
);

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

  async findUser(identifier) {
    try {
      const user = await UserModel.findOne({
        $or: [{ username: identifier }, { email: identifier }, { phoneNumber: identifier }],
      })
        .lean()
        .maxTimeMS(5000);

      if (!user) return null;

      return {
        id: user._id.toString(),
        username: user.username,
        email: user.email,
        phoneNumber: user.phoneNumber,
        password_hash: user.password,
        ...user.metadata,
      };
    } catch (err) {
      console.error('[MongoAdapter] findUser error:', err.message);
      throw new Error(`Database error: ${err.message}`);
    }
  }

  async createUser(userData) {
    try {
      const { password, ...fields } = userData;

      // Check for existing user by any identifier
      const existing = await UserModel.findOne({
        $or: [
          fields.username ? { username: fields.username } : null,
          fields.email ? { email: fields.email } : null,
          fields.phoneNumber ? { phoneNumber: fields.phoneNumber } : null,
        ].filter(Boolean),
      }).maxTimeMS(5000);

      if (existing) {
        throw new Error('User already exists');
      }

      const hash = await hashPassword(password);

      // Separate known fields from custom fields
      const { username, email, phoneNumber, ...customFields } = fields;

      const doc = await UserModel.create({
        username,
        email,
        phoneNumber,
        password: hash,
        metadata: customFields,
      });

      return {
        id: doc._id.toString(),
        username: doc.username,
        email: doc.email,
        phoneNumber: doc.phoneNumber,
        password_hash: hash,
        ...customFields,
      };
    } catch (err) {
      console.error('[MongoAdapter] createUser error:', err.message);
      if (err.code === 11000) {
        throw new Error('Username, email, or phone number already exists');
      }
      throw new Error(`Failed to create user: ${err.message}`);
    }
  }

  async verifyUser(identifier, password) {
    try {
      console.log('[MongoAdapter] Verifying user:', identifier);

      // Find user with timeout - support all identifiers
      const user = await UserModel.findOne({
        $or: [{ username: identifier }, { email: identifier }, { phoneNumber: identifier }],
      }).maxTimeMS(5000);

      if (!user) {
        console.log('[MongoAdapter] User not found:', identifier);
        return null;
      }

      console.log('[MongoAdapter] User found:', {
        id: user._id.toString(),
        username: user.username,
        email: user.email,
        hasPassword: !!user.password,
      });

      // Verify password
      const isValid = await verifyPassword(password, user.password);

      if (!isValid) {
        console.log('[MongoAdapter] Invalid password for:', identifier);
        return null;
      }

      console.log('[MongoAdapter] User verified successfully');

      return {
        id: user._id.toString(),
        username: user.username,
        email: user.email,
        phoneNumber: user.phoneNumber,
        password_hash: user.password,
      };
    } catch (err) {
      console.error('[MongoAdapter] verifyUser error:', err.message);
      throw new Error(`Verification failed: ${err.message}`);
    }
  }

  async storeRefreshToken(userId, token) {
    try {
      const hashed = hashToken(token);

      // Remove old tokens for this user
      await TokenModel.deleteMany({ userId }).maxTimeMS(5000);

      // Store new token
      await TokenModel.create({
        userId,
        tokenHash: hashed,
        createdAt: new Date(),
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

      const doc = await TokenModel.findOne({ tokenHash: hashed }).maxTimeMS(5000);

      if (!doc) return null;

      return {
        userId: doc.userId.toString(),
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
    },
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
    },
  };
}

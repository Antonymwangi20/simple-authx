import mongoose from 'mongoose';
import { createHash } from 'crypto';
import { hashPassword, verifyPassword } from '../utils/hash.js'

function hashToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

export async function connectMongo(uri) {
  if (mongoose.connection.readyState === 0) {
    await mongoose.connect(uri);
    console.log('[AuthX] Connected to MongoDB');
  }
}

// --- Schemas ---
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,  // This stores the hashed password
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
    const user = await UserModel.findOne({ username }).lean();
    if (!user) return null;
    
    // IMPORTANT: Return consistent format with password_hash field
    return { 
      id: user._id.toString(), 
      username: user.username, 
      password_hash: user.password  // Map 'password' field to 'password_hash'
    };
  }

  async createUser(username, password) {
    // Hash the password before storing
    const hash = await hashPassword(password);
    
    // Check if user already exists
    const existing = await UserModel.findOne({ username });
    if (existing) {
      throw new Error('Username already exists');
    }
    
    // Create new user with hashed password
    const doc = await UserModel.create({ 
      username, 
      password: hash  // Store in 'password' field
    });
    
    return { 
      id: doc._id.toString(), 
      username: doc.username, 
      password_hash: hash 
    };
  }

  async verifyUser(username, password) {
    // Find user
    const user = await UserModel.findOne({ username });
    if (!user) {
      console.log('[MongoAdapter] User not found:', username);
      return null;
    }
    
    // Debug logging (remove in production)
    console.log('[MongoAdapter] Verifying user:', {
      username: user.username,
      hasPassword: !!user.password,
      passwordLength: user.password?.length
    });
    
    // Verify password against stored hash
    const isValid = await verifyPassword(password, user.password);
    
    console.log('[MongoAdapter] Password verification result:', isValid);
    
    if (!isValid) {
      return null;
    }
    
    // Return user with consistent format
    return { 
      id: user._id.toString(), 
      username: user.username, 
      password_hash: user.password 
    };
  }

  async storeRefreshToken(userId, token, expiry) {
    // Find user by ID to get username
    const user = await UserModel.findById(userId);
    if (!user) {
      throw new Error('User not found');
    }
    
    // Hash the refresh token before storing
    const hashed = hashToken(token);
    
    // Store or update the token
    await TokenModel.findOneAndUpdate(
      { username: user.username },
      { 
        refreshToken: hashed, 
        createdAt: new Date() 
      },
      { upsert: true }
    );
  }

  async findRefreshToken(token) {
    // Hash the incoming token to compare
    const hashed = hashToken(token);
    
    // Find matching token
    const doc = await TokenModel.findOne({ refreshToken: hashed });
    
    if (!doc) return null;
    
    // Get user to return userId
    const user = await UserModel.findOne({ username: doc.username });
    if (!user) return null;
    
    return { 
      userId: user._id.toString(),
      username: doc.username
    };
  }

  async invalidateRefreshToken(token) {
    const hashed = hashToken(token);
    await TokenModel.deleteOne({ refreshToken: hashed });
  }

  async invalidateAllRefreshTokens(userId) {
    // Find user to get username
    const user = await UserModel.findById(userId);
    if (!user) return;
    
    // Delete all tokens for this user
    await TokenModel.deleteMany({ username: user.username });
  }

  // Optional: Close connection
  async close() {
    await mongoose.connection.close();
  }
}
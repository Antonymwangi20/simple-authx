import fs from 'fs/promises';
import crypto from 'crypto';
import { hashPassword, verifyPassword } from '../utils/hash.js';

export class FileAdapter {
  constructor(filename = './auth-data.json') {
    this.filename = filename;
    this.data = { users: [], refreshTokens: [] };
  }

  async init() {
    try {
      const content = await fs.readFile(this.filename, 'utf-8');
      this.data = JSON.parse(content);
    } catch {
      await this.save();
    }
  }

  async save() {
    await fs.writeFile(this.filename, JSON.stringify(this.data, null, 2));
  }

  async findUser(identifier) {
    return (
      this.data.users.find(
        (u) => u.username === identifier || u.email === identifier || u.phoneNumber === identifier
      ) || null
    );
  }

  async createUser(userData) {
    const { password, ...fields } = userData;
    const hash = await hashPassword(password);
    const id = Date.now().toString();

    const user = {
      id,
      password_hash: hash,
      ...fields,
      createdAt: new Date().toISOString(),
    };

    this.data.users.push(user);
    await this.save();
    return user;
  }

  async verifyUser(identifier, password) {
    const user = await this.findUser(identifier);
    if (!user) return null;
    const ok = await verifyPassword(password, user.password_hash);
    return ok ? user : null;
  }

  async storeRefreshToken(userId, token, expiry) {
    // store SHA-256 hash of token to avoid saving raw refresh tokens
    const hash = crypto.createHash('sha256').update(token).digest('hex');
    this.data.refreshTokens.push({ userId, token_hash: hash, expiresAt: expiry });
    await this.save();
  }

  async findRefreshToken(token) {
    // compare by SHA-256 hash against stored token_hash entries
    const hash = crypto.createHash('sha256').update(token).digest('hex');
    return this.data.refreshTokens.find((rt) => rt.token_hash === hash) || null;
  }

  async invalidateRefreshToken(token) {
    const hash = crypto.createHash('sha256').update(token).digest('hex');
    this.data.refreshTokens = this.data.refreshTokens.filter((rt) => rt.token_hash !== hash);
    await this.save();
  }

  async invalidateAllRefreshTokens(userId) {
    this.data.refreshTokens = this.data.refreshTokens.filter((rt) => rt.userId !== userId);
    await this.save();
  }
}

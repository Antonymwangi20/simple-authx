// Type definitions for simple-authx v2.0.0
import { Router, RequestHandler } from 'express';

// Main API
export function createAuth(config?: AuthConfig): Promise<AuthInstance>;

// Configuration
export interface AuthConfig {
  storage?: 'memory' | 'file' | 'postgres' | 'mongodb' | 'redis';
  file?: string;
  postgres?: { connectionString: string; ssl?: boolean | object };
  mongodb?: string;
  redis?: { host?: string; port?: number; password?: string; url?: string };
  secret?: string;
  refreshSecret?: string;
  accessExpiry?: string;
  refreshExpiry?: string;
  cookies?: {
    refresh?: boolean;
    name?: string;
    secure?: boolean;
    httpOnly?: boolean;
    sameSite?: 'strict' | 'lax' | 'none';
    domain?: string;
    maxAge?: number;
  };
  csrf?: { enabled?: boolean; cookieName?: string; headerName?: string };
  plugins?: {
    mfa?: { issuer?: string; algorithm?: 'sha1' | 'sha256' | 'sha512' };
    social?: {
      google?: OAuthConfig;
      github?: OAuthConfig;
      facebook?: OAuthConfig;
    };
    sessions?: { redis?: string; maxSessions?: number; slidingExpiry?: boolean };
    security?: { rateLimit?: boolean; maxAttempts?: number; windowMs?: number };
    password?: { minStrength?: number; minLength?: number; requireUppercase?: boolean };
    audit?: { events?: string[]; storage?: 'database' | 'file'; retentionDays?: number };
  };
  hooks?: {
    onRegister?: (user: User) => void | Promise<void>;
    onLogin?: (user: User) => void | Promise<void>;
    onError?: (error: Error) => void | Promise<void>;
  };
  adapter?: Adapter;
}

interface OAuthConfig {
  clientId: string;
  clientSecret: string;
  callbackURL: string;
}

// Auth Instance
export interface AuthInstance {
  routes: Router;
  router: Router;
  protect: RequestHandler;
  auth: AuthManager;
  adapter: Adapter;
  mfa: MFAProvider | null;
  social: SocialAuthProvider | null;
  sessions: SessionManager | null;
  security: SecurityManager | null;
  password: PasswordManager | null;
  audit: AuditLogger | null;
  generateTokens: (payload: TokenPayload) => TokenPair;
  verifyAccess: (token: string) => DecodedToken;
  close: () => Promise<void>;
}

// Core Types
export interface User {
  id: string;
  username: string;
  password_hash?: string;
  [key: string]: any;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

export interface TokenPayload {
  userId: string;
  [key: string]: any;
}

export interface DecodedToken extends TokenPayload {
  iat: number;
  exp: number;
  jti?: string;
}

// Core Classes
export class AuthManager {
  constructor(options: any);
  generateTokens(payload: TokenPayload): TokenPair;
  register(username: string, password: string): Promise<{ user: User } & TokenPair>;
  login(username: string, password: string): Promise<{ user: User } & TokenPair>;
  refresh(refreshToken: string): Promise<TokenPair>;
  verifyAccess(token: string): DecodedToken;
}

// Adapters
export interface Adapter {
  findUser(username: string): Promise<User | null>;
  createUser(username: string, password: string): Promise<User>;
  verifyUser(username: string, password: string): Promise<User | null>;
  storeRefreshToken(userId: string, token: string, expiry: Date): Promise<void>;
  findRefreshToken(token: string): Promise<any>;
  invalidateRefreshToken(token: string): Promise<void>;
  invalidateAllRefreshTokens(userId: string): Promise<void>;
}

export class PostgresAdapter implements Adapter {
  constructor(config: any);
  findUser(username: string): Promise<User | null>;
  createUser(username: string, password: string): Promise<User>;
  verifyUser(username: string, password: string): Promise<User | null>;
  storeRefreshToken(userId: string, token: string, expiry: Date): Promise<void>;
  findRefreshToken(token: string): Promise<any>;
  invalidateRefreshToken(token: string): Promise<void>;
  invalidateAllRefreshTokens(userId: string): Promise<void>;
  close(): Promise<void>;
}

export class FileAdapter implements Adapter {
  constructor(filePath: string);
  findUser(username: string): Promise<User | null>;
  createUser(username: string, password: string): Promise<User>;
  verifyUser(username: string, password: string): Promise<User | null>;
  storeRefreshToken(userId: string, token: string, expiry: Date): Promise<void>;
  findRefreshToken(token: string): Promise<any>;
  invalidateRefreshToken(token: string): Promise<void>;
  invalidateAllRefreshTokens(userId: string): Promise<void>;
}

export class MongoAdapter implements Adapter {
  constructor(connection: any);
  findUser(username: string): Promise<User | null>;
  createUser(username: string, password: string): Promise<User>;
  verifyUser(username: string, password: string): Promise<User | null>;
  storeRefreshToken(userId: string, token: string, expiry: Date): Promise<void>;
  findRefreshToken(token: string): Promise<any>;
  invalidateRefreshToken(token: string): Promise<void>;
  invalidateAllRefreshTokens(userId: string): Promise<void>;
  close(): Promise<void>;
}

export class RedisAdapter implements Adapter {
  constructor(config: any);
  findUser(username: string): Promise<User | null>;
  createUser(username: string, password: string): Promise<User>;
  verifyUser(username: string, password: string): Promise<User | null>;
  storeRefreshToken(userId: string, token: string, expiry: Date): Promise<void>;
  findRefreshToken(token: string): Promise<any>;
  invalidateRefreshToken(token: string): Promise<void>;
  invalidateAllRefreshTokens(userId: string): Promise<void>;
  close(): Promise<void>;
}

// Security Modules
export class MFAProvider {
  generateSecret(): string;
  generateQRCode(secret: string, label: string): Promise<string>;
  verifyToken(secret: string, token: string): boolean;
  generateBackupCodes(count?: number): string[];
}

export class SocialAuthProvider {
  providers: Record<string, any>;
}

export class SessionManager {
  getUserSessions(userId: string): Promise<any[]>;
  revokeSession(sessionId: string): Promise<void>;
  revokeOtherSessions(userId: string, currentSessionId: string): Promise<void>;
}

export class SecurityManager {
  checkRateLimit(identifier: string): Promise<boolean>;
}

export class PasswordManager {
  validatePassword(password: string, username?: string, email?: string): Promise<void>;
  checkStrength(password: string, username?: string, email?: string): {
    score: number;
    feedback: {
      warning: string;
      suggestions: string[];
    };
    crackTime: string;
    crackTimeSeconds: number;
  };
  hashPassword(password: string): Promise<string>;
  verifyPassword(password: string, hash: string): Promise<boolean>;
  generateResetToken(): { token: string; expires: Date };
  checkPasswordHistory(password: string, history: string[]): Promise<void>;
  enforcePasswordPolicy(username: string, password: string, userData?: any): Promise<boolean>;
  generateTemporaryPassword(): string;
}

export class AuditLogger {
  log(event: string, data: any): Promise<void>;
  query(filters: any): Promise<any[]>;
}

// Utilities
export function requireRole(role: string): RequestHandler;
export function requireAnyRole(roles: string[]): RequestHandler;
export function hashPassword(password: string): Promise<string>;
export function verifyPassword(password: string, hash: string): Promise<boolean>;
export const defaultHooks: any;
export function connectMongo(connectionString: string): Promise<any>;
export function connectRedis(config: any): Promise<any>;

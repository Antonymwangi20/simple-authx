// Type definitions for simple-authx v2.0.5+
// Project: https://github.com/Antonymwangi20/simple-authx
// Definitions by: Antony Mwangi <https://github.com/Antonymwangi20>

import { Router, RequestHandler, Request, Response, NextFunction } from 'express';

// ==================== Express Type Augmentation ====================

/**
 * Augment Express Request to include user property set by protect middleware
 */
declare global {
  namespace Express {
    interface Request {
      /**
       * Authenticated user (set by protect middleware)
       * Contains decoded JWT token payload (userId, role, etc.)
       */
      user?: DecodedToken;
    }
  }
}

// ==================== PRIMARY API (Singleton Pattern - RECOMMENDED) ====================

/**
 * Initialize authentication globally (call ONCE in your main server file)
 * This is the RECOMMENDED pattern for most applications
 * 
 * @param config - Authentication configuration
 * @returns Promise resolving to AuthInstance
 * 
 * @example
 * // server.js - Initialize once
 * import { initializeAuth, protect, getAuth } from 'simple-authx';
 * 
 * await initializeAuth({
 *   storage: 'mongodb',
 *   mongodb: process.env.MONGODB_URI,
 *   secret: process.env.JWT_SECRET
 * });
 * 
 * app.use('/auth', getAuth().routes);
 * 
 * // routes/api.js - Use anywhere
 * import { protect } from 'simple-authx';
 * 
 * router.get('/profile', protect, (req, res) => {
 *   res.json({ user: req.user });
 * });
 */
export function initializeAuth(config?: AuthConfig): Promise<AuthInstance>;

/**
 * Get the initialized auth instance
 * @throws Error if initializeAuth() has not been called
 * 
 * @example
 * import { getAuth } from 'simple-authx';
 * 
 * const auth = getAuth();
 * app.use('/auth', auth.routes);
 */
export function getAuth(): AuthInstance;

/**
 * Protection middleware - can be imported and used directly
 * Requires initializeAuth() to be called first
 * 
 * @example
 * import { protect } from 'simple-authx';
 * 
 * router.get('/profile', protect, (req, res) => {
 *   res.json({ user: req.user });
 * });
 */
export const protect: RequestHandler;

/**
 * Check if auth has been initialized
 * @returns True if initializeAuth() has been called
 */
export function isAuthInitialized(): boolean;

/**
 * Reset the auth instance (useful for testing)
 * 
 * @example
 * import { resetAuth, initializeAuth } from 'simple-authx';
 * 
 * beforeEach(async () => {
 *   resetAuth();
 *   await initializeAuth(); // Fresh instance for each test
 * });
 */
export function resetAuth(): void;

// ==================== ALTERNATIVE API (Instance Pattern - Advanced) ====================

/**
 * Create an authentication instance (for advanced use cases)
 * Use this when you need multiple auth instances or more control
 * 
 * @param config - Authentication configuration or file path for file storage
 * @returns Promise resolving to AuthInstance
 * 
 * @example
 * // auth.js - Create and export
 * import { createAuth } from 'simple-authx';
 * 
 * export const auth = await createAuth({
 *   storage: 'mongodb',
 *   mongodb: process.env.MONGODB_URI
 * });
 * 
 * // routes/api.js - Import and use
 * import { auth } from '../auth.js';
 * 
 * router.get('/profile', auth.protect, (req, res) => {
 *   res.json({ user: req.user });
 * });
 */
export function createAuth(config?: AuthConfig | string): Promise<AuthInstance>;

// ==================== Configuration ====================

export interface AuthConfig {
  // Storage Configuration
  /** Storage type to use */
  storage?: 'memory' | 'file' | 'postgres' | 'mongodb' | 'redis';
  
  /** File path for file storage (can also be passed as string to createAuth) */
  file?: string;
  
  /** PostgreSQL configuration */
  postgres?: PostgresConfig;
  
  /** MongoDB connection string */
  mongodb?: string;
  
  /** Redis configuration */
  redis?: RedisConfig;
  
  /** Custom storage adapter */
  adapter?: Adapter;
  
  // User Schema Configuration (NEW in v2.0!)
  /** Configure user fields and identifiers */
  userFields?: UserFieldsConfig;
  
  // JWT Configuration
  /** Secret for access tokens (use strong random string in production) */
  secret?: string;
  
  /** Secret for refresh tokens (use different strong random string) */
  refreshSecret?: string;
  
  /** Access token expiry (default: '15m') */
  accessExpiry?: string;
  
  /** Refresh token expiry (default: '7d') */
  refreshExpiry?: string;
  
  // Legacy compatibility
  /** @deprecated Use accessExpiry instead */
  accessExpiresIn?: string;
  
  /** @deprecated Use refreshExpiry instead */
  refreshExpiresIn?: string;
  
  // Cookie Configuration
  /** Cookie settings for storing refresh tokens */
  cookies?: CookieConfig;
  
  /** CSRF protection configuration */
  csrf?: CSRFConfig;
  
  // Plugin Configuration
  /** Enable optional features via plugins */
  plugins?: PluginConfig;
  
  /** Lifecycle hooks */
  hooks?: HooksConfig;
}

export interface PostgresConfig {
  /** PostgreSQL connection string */
  connectionString: string;
  
  /** SSL configuration */
  ssl?: boolean | {
    rejectUnauthorized?: boolean;
    ca?: string;
    key?: string;
    cert?: string;
  };
  
  /** Maximum number of clients in the pool */
  max?: number;
  
  /** Number of milliseconds to wait before timing out */
  connectionTimeoutMillis?: number;
  
  /** Number of milliseconds a client must sit idle before being disconnected */
  idleTimeoutMillis?: number;
}

export interface RedisConfig {
  /** Redis host */
  host?: string;
  
  /** Redis port */
  port?: number;
  
  /** Redis password */
  password?: string;
  
  /** Redis connection URL (alternative to host/port) */
  url?: string;
  
  /** Redis database number */
  db?: number;
  
  /** Key prefix for namespacing */
  prefix?: string;
}

export interface UserFieldsConfig {
  /**
   * Fields that can be used to identify users during login
   * @default ['username']
   * @example ['email', 'username', 'phoneNumber']
   */
  identifiers?: Array<'email' | 'username' | 'phoneNumber'>;
  
  /**
   * Fields that are required during registration
   * @default ['username']
   * @example ['email', 'username']
   */
  required?: Array<'email' | 'username' | 'phoneNumber' | string>;
  
  /**
   * Fields that must be unique across users
   * @default ['username']
   * @example ['email', 'username', 'phoneNumber']
   */
  unique?: Array<'email' | 'username' | 'phoneNumber' | string>;
  
  /**
   * Custom field validation functions
   * @example
   * {
   *   email: (value) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value),
   *   phoneNumber: (value) => /^\+?[1-9]\d{1,14}$/.test(value)
   * }
   */
  validate?: {
    [field: string]: (value: any) => boolean;
  };
  
  /**
   * Custom fields to add to user schema
   * @example
   * {
   *   firstName: { type: 'string', required: false },
   *   lastName: { type: 'string', required: false },
   *   role: { type: 'string', default: 'user' }
   * }
   */
  custom?: {
    [field: string]: {
      type: 'string' | 'number' | 'boolean' | 'date' | 'object' | 'array';
      required?: boolean;
      default?: any;
      validate?: (value: any) => boolean;
    };
  };
}

export interface CookieConfig {
  /** Store refresh token in httpOnly cookie */
  refresh?: boolean;
  
  /** Cookie name (default: 'refreshToken') */
  name?: string;
  
  /** Use secure cookies (HTTPS only) */
  secure?: boolean;
  
  /** HttpOnly flag (recommended: true) */
  httpOnly?: boolean;
  
  /** SameSite policy */
  sameSite?: 'strict' | 'lax' | 'none';
  
  /** Cookie domain */
  domain?: string;
  
  /** Cookie max age in milliseconds */
  maxAge?: number;
  
  /** Cookie path */
  path?: string;
}

export interface CSRFConfig {
  /** Enable CSRF protection */
  enabled?: boolean;
  
  /** CSRF cookie name (default: 'csrfToken') */
  cookieName?: string;
  
  /** CSRF header name (default: 'x-csrf-token') */
  headerName?: string;
  
  /** Secret for CSRF token generation */
  secret?: string;
}

export interface PluginConfig {
  /** Multi-factor authentication (MFA/2FA) */
  mfa?: MFAConfig;
  
  /** Social authentication (OAuth) */
  social?: SocialAuthConfig;
  
  /** Session management */
  sessions?: SessionConfig;
  
  /** Security features (rate limiting, IP blocking) */
  security?: SecurityConfig;
  
  /** Password strength validation */
  password?: PasswordConfig;
  
  /** Audit logging */
  audit?: AuditConfig;
}

export interface MFAConfig {
  /** Issuer name for TOTP (shown in authenticator apps) */
  issuer?: string;
  
  /** Hash algorithm */
  algorithm?: 'sha1' | 'sha256' | 'sha512';
  
  /** Number of digits in TOTP */
  digits?: number;
  
  /** Time step in seconds */
  step?: number;
  
  /** Number of time windows to check */
  window?: number;
}

export interface SocialAuthConfig {
  /** Google OAuth configuration */
  google?: OAuthProviderConfig;
  
  /** GitHub OAuth configuration */
  github?: OAuthProviderConfig;
  
  /** Facebook OAuth configuration */
  facebook?: OAuthProviderConfig;
  
  /** Twitter OAuth configuration (coming soon) */
  twitter?: OAuthProviderConfig;
}

export interface OAuthProviderConfig {
  /** OAuth client ID */
  clientId: string;
  
  /** OAuth client secret */
  clientSecret: string;
  
  /** Callback URL after authentication */
  callbackURL: string;
  
  /** OAuth scopes */
  scope?: string[];
}

export interface SessionConfig {
  /** Redis connection for session storage */
  redis?: string | RedisConfig;
  
  /** Maximum concurrent sessions per user */
  maxSessions?: number;
  
  /** Extend session expiry on activity */
  slidingExpiry?: boolean;
  
  /** Track user location (IP-based geolocation) */
  trackLocation?: boolean;
  
  /** Track device information */
  trackDevice?: boolean;
}

export interface SecurityConfig {
  /** Redis connection for rate limiting */
  redis?: RedisConfig;
  
  /** Enable rate limiting */
  rateLimit?: boolean;
  
  /** Maximum failed login attempts */
  maxFailedAttempts?: number;
  
  /** Time window for counting attempts */
  attemptWindow?: string;
  
  /** Time window for rate limiting */
  windowMs?: number;
  
  /** Duration to block after max attempts */
  blockDuration?: string;
  
  /** IP addresses to whitelist (bypass rate limits) */
  ipWhitelist?: string[];
}

export interface PasswordConfig {
  /** Minimum password strength (0-4, zxcvbn score) */
  minStrength?: number;
  
  /** Minimum password length */
  minLength?: number;
  
  /** Require at least one uppercase letter */
  requireUppercase?: boolean;
  
  /** Require at least one number */
  requireNumbers?: boolean;
  
  /** Require at least one special character */
  requireSpecialChars?: boolean;
  
  /** Blacklist of common passwords */
  blacklist?: string[];
  
  /** Password hashing algorithm */
  hashAlgo?: 'bcrypt' | 'argon2';
  
  /** Remember last N passwords to prevent reuse */
  historyLimit?: number;
  
  /** Maximum password age in milliseconds */
  maxAge?: number;
}

export interface AuditConfig {
  /** Events to log */
  events?: string[];
  
  /** Storage type for audit logs */
  storage?: 'database' | 'file' | 'console';
  
  /** Log retention in days */
  retentionDays?: number;
  
  /** Include metadata (IP, user agent, etc.) */
  includeMetadata?: boolean;
  
  /** Log level */
  level?: 'debug' | 'info' | 'warn' | 'error';
  
  /** Pino logger options */
  pinoOptions?: any;
}

export interface HooksConfig {
  /** Called after successful user registration */
  onRegister?: (user: User) => void | Promise<void>;
  
  /** Called after successful login */
  onLogin?: (user: User) => void | Promise<void>;
  
  /** Called on authentication errors */
  onError?: (error: Error) => void | Promise<void>;
  
  /** Called before user registration (can modify user data) */
  beforeRegister?: (userData: UserRegistrationData) => UserRegistrationData | Promise<UserRegistrationData>;
  
  /** Called before login (can perform additional checks) */
  beforeLogin?: (identifier: string, password: string) => boolean | Promise<boolean>;
}

// ==================== Auth Instance ====================

export interface AuthInstance {
  /** Express router with all auth routes */
  routes: Router;
  
  /** Alias for routes (backwards compatibility) */
  router: Router;
  
  /** Middleware to protect routes (requires valid access token) */
  protect: RequestHandler;
  
  /** Core authentication manager */
  auth: AuthManager;
  
  /** Storage adapter instance */
  adapter: Adapter;
  
  // Plugins (available if configured)
  /** MFA/2FA provider (null if not configured) */
  mfa: MFAProvider | null;
  
  /** Social authentication provider (null if not configured) */
  social: SocialAuthProvider | null;
  
  /** Session manager (null if not configured) */
  sessions: SessionManager | null;
  
  /** Security manager (null if not configured) */
  security: SecurityManager | null;
  
  /** Password manager (null if not configured) */
  password: PasswordManager | null;
  
  /** Audit logger (null if not configured) */
  audit: AuditLogger | null;
  
  // Utility Methods
  /** Generate access and refresh tokens for a payload */
  generateTokens: (payload: TokenPayload) => TokenPair;
  
  /** Verify and decode an access token */
  verifyAccess: (token: string) => DecodedToken;
  
  /** Close database connections and cleanup */
  close: () => Promise<void>;
}

// ==================== Core Types ====================

export interface User {
  /** Unique user identifier */
  id: string;
  
  /** Username (if configured as identifier) */
  username?: string;
  
  /** Email address (if configured as identifier) */
  email?: string;
  
  /** Phone number (if configured as identifier) */
  phoneNumber?: string;
  
  /** Password hash (never exposed in responses) */
  password_hash?: string;
  
  /** Account creation timestamp */
  createdAt?: Date;
  
  /** Last update timestamp */
  updatedAt?: Date;
  
  /** MFA secret (if MFA enabled) */
  mfaSecret?: string;
  
  /** MFA backup codes */
  backupCodes?: string[];
  
  /** User role for RBAC */
  role?: string;
  
  /** Additional custom fields */
  [key: string]: any;
}

export interface UserRegistrationData {
  /** Username (required if in userFields.required) */
  username?: string;
  
  /** Email (required if in userFields.required) */
  email?: string;
  
  /** Phone number (required if in userFields.required) */
  phoneNumber?: string;
  
  /** Password (always required) */
  password: string;
  
  /** User role (default: 'user') */
  role?: string;
  
  /** Additional custom fields */
  [key: string]: any;
}

export interface TokenPair {
  /** JWT access token (short-lived) */
  accessToken: string;
  
  /** JWT refresh token (long-lived) */
  refreshToken: string;
}

export interface TokenPayload {
  /** User ID */
  userId: string;
  
  /** Username (optional) */
  username?: string;
  
  /** Email (optional) */
  email?: string;
  
  /** Phone number (optional) */
  phoneNumber?: string;
  
  /** User role for RBAC */
  role?: string;
  
  /** Additional claims */
  [key: string]: any;
}

export interface DecodedToken extends TokenPayload {
  /** Issued at (timestamp) */
  iat: number;
  
  /** Expiration time (timestamp) */
  exp: number;
  
  /** JWT ID (for token rotation) */
  jti?: string;
}

export interface LoginResult {
  /** User object (without password_hash) */
  user: Omit<User, 'password_hash'>;
  
  /** JWT access token */
  accessToken: string;
  
  /** JWT refresh token (if not using cookies) */
  refreshToken?: string;
}

// ==================== Core Classes ====================

export class AuthManager {
  constructor(options: AuthManagerOptions);
  
  /**
   * Generate access and refresh tokens
   * @param payload - Token payload (userId, role, etc.)
   * @returns Token pair
   */
  generateTokens(payload: TokenPayload): TokenPair;
  
  /**
   * Register a new user
   * @param userData - User registration data (object or username for backward compat)
   * @param password - Password (only used in legacy format)
   * @returns User and tokens
   */
  register(userData: UserRegistrationData | string, password?: string): Promise<LoginResult>;
  
  /**
   * Login with identifier (email/username/phone)
   * @param identifier - Email, username, or phone number
   * @param password - User password
   * @returns User and tokens
   */
  loginWithIdentifier(identifier: string, password: string): Promise<LoginResult>;
  
  /**
   * Login with username (legacy method, same as loginWithIdentifier)
   * @param username - Username (or email/phone - auto-detected)
   * @param password - User password
   * @returns User and tokens
   */
  login(username: string, password: string): Promise<LoginResult>;
  
  /**
   * Refresh access token using refresh token
   * @param refreshToken - Valid refresh token
   * @returns New token pair
   */
  refresh(refreshToken: string): Promise<TokenPair>;
  
  /**
   * Verify and decode access token
   * @param token - JWT access token
   * @returns Decoded token payload
   */
  verifyAccess(token: string): DecodedToken;
}

export interface AuthManagerOptions {
  adapter: Adapter;
  secret?: string;
  refreshSecret?: string;
  accessExpiry?: string;
  refreshExpiry?: string;
  hooks?: HooksConfig;
  config?: AuthConfig;
}

// ==================== Storage Adapters ====================

export interface Adapter {
  /**
   * Find user by identifier (username, email, or phone)
   * @param identifier - Username, email, or phone number
   * @returns User or null if not found
   */
  findUser(identifier: string): Promise<User | null>;
  
  /**
   * Create a new user
   * @param userData - User registration data
   * @returns Created user
   */
  createUser(userData: UserRegistrationData): Promise<User>;
  
  /**
   * Verify user credentials
   * @param identifier - Username, email, or phone number
   * @param password - User password
   * @returns User if credentials valid, null otherwise
   */
  verifyUser(identifier: string, password: string): Promise<User | null>;
  
  /**
   * Store refresh token
   * @param userId - User ID
   * @param token - Refresh token (will be hashed)
   * @param expiry - Token expiration date
   */
  storeRefreshToken(userId: string, token: string, expiry: Date): Promise<void>;
  
  /**
   * Find refresh token
   * @param token - Refresh token
   * @returns Token data or null if not found
   */
  findRefreshToken(token: string): Promise<{ userId: string } | null>;
  
  /**
   * Invalidate a specific refresh token
   * @param token - Refresh token to invalidate
   */
  invalidateRefreshToken(token: string): Promise<void>;
  
  /**
   * Invalidate all refresh tokens for a user
   * @param userId - User ID
   */
  invalidateAllRefreshTokens(userId: string): Promise<void>;
  
  /**
   * Close database connections (optional)
   */
  close?(): Promise<void>;
}

export class PostgresAdapter implements Adapter {
  constructor(config: PostgresConfig);
  findUser(identifier: string): Promise<User | null>;
  createUser(userData: UserRegistrationData): Promise<User>;
  verifyUser(identifier: string, password: string): Promise<User | null>;
  storeRefreshToken(userId: string, token: string, expiry: Date): Promise<void>;
  findRefreshToken(token: string): Promise<{ userId: string } | null>;
  invalidateRefreshToken(token: string): Promise<void>;
  invalidateAllRefreshTokens(userId: string): Promise<void>;
  close(): Promise<void>;
}

export class FileAdapter implements Adapter {
  constructor(filePath: string);
  init(): Promise<void>;
  findUser(identifier: string): Promise<User | null>;
  createUser(userData: UserRegistrationData): Promise<User>;
  verifyUser(identifier: string, password: string): Promise<User | null>;
  storeRefreshToken(userId: string, token: string, expiry: Date): Promise<void>;
  findRefreshToken(token: string): Promise<{ userId: string } | null>;
  invalidateRefreshToken(token: string): Promise<void>;
  invalidateAllRefreshTokens(userId: string): Promise<void>;
}

export class MongoAdapter implements Adapter {
  constructor();
  findUser(identifier: string): Promise<User | null>;
  createUser(userData: UserRegistrationData): Promise<User>;
  verifyUser(identifier: string, password: string): Promise<User | null>;
  storeRefreshToken(userId: string, token: string, expiry: Date): Promise<void>;
  findRefreshToken(token: string): Promise<{ userId: string } | null>;
  invalidateRefreshToken(token: string): Promise<void>;
  invalidateAllRefreshTokens(userId: string): Promise<void>;
  close(): Promise<void>;
}

export class RedisAdapter implements Adapter {
  constructor(userStore: Adapter, options?: { prefix?: string });
  findUser(identifier: string): Promise<User | null>;
  createUser(userData: UserRegistrationData): Promise<User>;
  verifyUser(identifier: string, password: string): Promise<User | null>;
  storeRefreshToken(userId: string, token: string, expiry: Date): Promise<void>;
  findRefreshToken(token: string): Promise<{ userId: string } | null>;
  invalidateRefreshToken(token: string): Promise<void>;
  invalidateAllRefreshTokens(userId: string): Promise<void>;
  close(): Promise<void>;
}

// ==================== Plugin Classes ====================

export class MFAProvider {
  constructor(config?: MFAConfig);
  
  /**
   * Generate a new TOTP secret
   * @returns Base32-encoded secret
   */
  generateSecret(): string;
  
  /**
   * Generate QR code for authenticator app
   * @param label - User identifier (email/username)
   * @param secret - TOTP secret
   * @returns Data URL of QR code image
   */
  generateQRCode(label: string, secret: string): Promise<string>;
  
  /**
   * Verify TOTP token
   * @param token - 6-digit TOTP code
   * @param secret - User's TOTP secret
   * @returns True if valid
   */
  verifyToken(token: string, secret: string): boolean;
  
  /**
   * Generate backup codes
   * @param count - Number of codes to generate (default: 10)
   * @returns Array of backup codes
   */
  generateBackupCodes(count?: number): string[];
  
  /**
   * Generate recovery key for secret encryption
   * @returns Recovery key
   */
  generateRecoveryKey(): string;
}

export class SocialAuthProvider {
  providers: Map<string, any>;
  
  constructor();
  
  /**
   * Setup OAuth provider
   * @param name - Provider name ('google', 'github', etc.)
   * @param config - OAuth configuration
   */
  setupProvider(name: string, config: OAuthProviderConfig): Promise<void>;
  
  /**
   * Get OAuth authorization URL
   * @param provider - Provider name
   * @param state - CSRF state token
   * @returns Authorization URL
   */
  getAuthorizationUrl(provider: string, state: string): string;
  
  /**
   * Exchange authorization code for access token
   * @param provider - Provider name
   * @param code - Authorization code
   * @returns Token response
   */
  exchangeCode(provider: string, code: string): Promise<{
    access_token: string;
    token_type: string;
    expires_in?: number;
    refresh_token?: string;
  }>;
  
  /**
   * Get user profile from OAuth provider
   * @param provider - Provider name
   * @param accessToken - OAuth access token
   * @returns User profile
   */
  getUserProfile(provider: string, accessToken: string): Promise<any>;
}

export class SessionManager {
  constructor(adapter: Adapter);
  
  /**
   * Create a new session
   * @param userId - User ID
   * @param req - Express request (for device fingerprinting)
   * @returns Session data
   */
  createSession(userId: string, req: Request): Promise<Session>;
  
  /**
   * Update session activity timestamp
   * @param sessionId - Session ID
   */
  updateSession(sessionId: string): Promise<void>;
  
  /**
   * Get all sessions for a user
   * @param userId - User ID
   * @returns Array of sessions
   */
  getSessions(userId: string): Promise<Session[]>;
  
  /**
   * Get sessions for a user (alias)
   * @param userId - User ID
   * @returns Array of sessions
   */
  getUserSessions(userId: string): Promise<Session[]>;
  
  /**
   * Invalidate a specific session
   * @param sessionId - Session ID
   */
  invalidateSession(sessionId: string): Promise<void>;
  
  /**
   * Revoke a specific session (alias)
   * @param sessionId - Session ID
   */
  revokeSession(sessionId: string): Promise<void>;
  
  /**
   * Invalidate all sessions except current
   * @param userId - User ID
   * @param currentSessionId - Session ID to keep
   */
  invalidateAllSessions(userId: string, currentSessionId?: string): Promise<void>;
  
  /**
   * Revoke all sessions except current (alias)
   * @param userId - User ID
   * @param currentSessionId - Session ID to keep
   */
  revokeOtherSessions(userId: string, currentSessionId: string): Promise<void>;
  
  /**
   * Detect suspicious activity in session
   * @param session - Session data
   * @param req - Current request
   * @returns Array of suspicious indicators
   */
  detectSuspiciousActivity(session: Session, req: Request): Promise<string[]>;
}

export interface Session {
  id: string;
  userId: string;
  createdAt: Date;
  lastActive: Date;
  device: {
    type: string;
    browser?: string;
    os?: string;
    ip: string;
    location?: {
      country: string;
      city?: string;
      timezone?: string;
    };
    fingerprint: string;
  };
}

export class SecurityManager {
  constructor(config?: SecurityConfig);
  
  /**
   * Create rate limiter middleware
   * @param options - Rate limit options
   * @returns Express middleware
   */
  createRateLimiter(options?: RateLimitOptions): RequestHandler;
  
  /**
   * Track login attempt
   * @param username - Username
   * @param ip - IP address
   * @param success - Whether login was successful
   */
  trackLoginAttempt(username: string, ip: string, success: boolean): Promise<void>;
  
  /**
   * Check if user or IP is blocked
   * @param username - Username
   * @param ip - IP address
   * @returns Block status
   */
  isBlocked(username: string, ip: string): Promise<{
    userBlocked: boolean;
    ipBlocked: boolean;
    remainingAttempts: number;
  }>;
  
  /**
   * Check rate limit for identifier
   * @param identifier - User/IP identifier
   * @returns True if within limits
   */
  checkRateLimit(identifier: string): Promise<boolean>;
  
  /**
   * Get IP reputation score
   * @param ip - IP address
   * @returns Reputation ('blocked', 'suspicious', 'normal', etc.)
   */
  getIPReputation(ip: string): Promise<string>;
}

export interface RateLimitOptions {
  window?: string;
  max?: number;
  skipSuccessful?: boolean;
  prefix?: string;
}

export class PasswordManager {
  constructor(config?: PasswordConfig);
  
  /**
   * Validate password strength (throws on weak password)
   * @param password - Password to validate
   * @param username - Username for context
   * @param email - Email for context
   */
  validatePassword(password: string, username?: string, email?: string): Promise<{
    score: number;
    feedback: { warning: string; suggestions: string[] };
    estimatedCrackTime: number;
  }>;
  
  /**
   * Check password strength without throwing
   * @param password - Password to check
   * @param username - Username for context
   * @param email - Email for context
   * @returns Password strength analysis
   */
  checkStrength(password: string, username?: string, email?: string): {
    score: number;
    feedback: { warning: string; suggestions: string[] };
    crackTime: string;
    crackTimeSeconds: number;
  };
  
  /**
   * Hash password
   * @param password - Plain text password
   * @returns Hashed password
   */
  hashPassword(password: string): Promise<string>;
  
  /**
   * Verify password against hash
   * @param password - Plain text password
   * @param hash - Password hash
   * @returns True if password matches
   */
  verifyPassword(password: string, hash: string): Promise<boolean>;
} 

export class AuditLogger {
  constructor(config?: AuditConfig);
  
  /**
   * Log an audit event
   * @param event - Event name
   * @param userId - User ID (if applicable)
   * @param metadata - Additional metadata
   */
  logEvent(event: string, userId?: string, metadata?: any): Promise<void>;
}

// ==================== Utility Functions ====================

/**
 * Role-based access control middleware factory
 * @param role - Required role
 * @returns Express middleware that checks if user has the required role
 * 
 * @example
 * import { requireRole } from 'simple-authx';
 * 
 * router.get('/admin', protect, requireRole('admin'), (req, res) => {
 *   res.json({ message: 'Admin only' });
 * });
 */
export function requireRole(role: string): RequestHandler;

/**
 * Multi-role access control middleware factory
 * @param roles - Array of allowed roles
 * @returns Express middleware that checks if user has any of the required roles
 * 
 * @example
 * import { requireAnyRole } from 'simple-authx';
 * 
 * router.get('/moderators', protect, requireAnyRole(['admin', 'moderator']), (req, res) => {
 *   res.json({ message: 'Admin or moderator only' });
 * });
 */
export function requireAnyRole(roles: string[]): RequestHandler;

/**
 * Hash a password using the configured hasher (bcrypt or argon2)
 * @param password - Plain text password
 * @returns Promise resolving to hashed password
 * 
 * @example
 * import { hashPassword } from 'simple-authx';
 * 
 * const hash = await hashPassword('myPassword123');
 */
export function hashPassword(password: string): Promise<string>;

/**
 * Verify a password against a hash
 * @param password - Plain text password
 * @param hash - Password hash to verify against
 * @returns Promise resolving to true if password matches
 * 
 * @example
 * import { verifyPassword } from 'simple-authx';
 * 
 * const isValid = await verifyPassword('myPassword123', storedHash);
 */
export function verifyPassword(password: string, hash: string): Promise<boolean>;

/**
 * Get the name of the currently configured password hasher
 * @returns 'bcrypt' or 'argon2'
 */
export function hasherName(): string;

// ==================== Connection Helpers ====================

/**
 * Connect to MongoDB
 * @param uri - MongoDB connection URI
 * @returns Promise that resolves when connected
 * 
 * @example
 * import { connectMongo } from 'simple-authx';
 * 
 * await connectMongo('mongodb://localhost:27017/myapp');
 */
export function connectMongo(uri: string): Promise<void>;

/**
 * Connect to Redis
 * @param options - Redis connection options
 * @returns Promise resolving to Redis client
 * 
 * @example
 * import { connectRedis } from 'simple-authx';
 * 
 * await connectRedis({ host: 'localhost', port: 6379 });
 */
export function connectRedis(options?: RedisConfig): Promise<any>;

// ==================== Default Hooks ====================

/**
 * Default lifecycle hooks
 * Can be used as a starting point for custom hooks
 * 
 * @example
 * import { defaultHooks, createAuth } from 'simple-authx';
 * 
 * const auth = await createAuth({
 *   hooks: {
 *     ...defaultHooks,
 *     onRegister: async (user) => {
 *       await defaultHooks.onRegister(user);
 *       // Custom logic
 *     }
 *   }
 * });
 */
export const defaultHooks: HooksConfig;

// ==================== Legacy API ====================

/**
 * Legacy AuthX function for backwards compatibility
 * @deprecated Use createAuth() instead for better features and multiple storage adapters
 * @param config - Configuration options
 * @returns Authentication middleware and handlers
 * 
 * @example
 * import AuthX from 'simple-authx';
 * 
 * const auth = AuthX({ secret: 'my-secret' });
 * app.use('/auth', auth.routes);
 */
declare function AuthX(config?: {
  secret?: string;
  refreshSecret?: string;
  accessExpiresIn?: string;
  refreshExpiresIn?: string;
  saltRounds?: number;
  cookieName?: string;
  userStore?: any;
  tokenStore?: any;
}): {
  hashPassword: (password: string) => Promise<string>;
  verifyPassword: (password: string, hash: string) => Promise<boolean>;
  signAccess: (payload: any) => string;
  signRefresh: (payload: any) => string;
  verifyAccess: (token: string) => any;
  verifyRefresh: (token: string) => any;
  protect: RequestHandler;
  registerHandler: (saveUserFn?: any) => RequestHandler;
  loginHandler: (getUserFn?: any) => RequestHandler;
  refreshHandler: RequestHandler;
  logoutHandler: RequestHandler;
  middleware: RequestHandler[];
  router: Router;
  routes: Router;
};

export default AuthX;

// ==================== Exports Summary ====================

/**
 * Main exports from simple-authx:
 * 
 * Primary API:
 * - createAuth(config?) - Create auth instance (recommended)
 * 
 * Core Components:
 * - AuthManager - Core authentication manager
 * - defaultHooks - Default lifecycle hooks
 * - initializeAuth() - Global singleton setup
 * - getAuth() - Get global auth instance
 * - protect - Global protection middleware
 * - isAuthInitialized() - Check if initialized
 * 
 * Storage Adapters:
 * - PostgresAdapter - PostgreSQL storage
 * - FileAdapter - File-based storage
 * - MongoAdapter - MongoDB storage
 * - RedisAdapter - Redis storage
 * - connectMongo() - MongoDB connection helper
 * - connectRedis() - Redis connection helper
 * 
 * Security Modules:
 * - MFAProvider - Multi-factor authentication
 * - SocialAuthProvider - OAuth social login
 * - SessionManager - Session management
 * - SecurityManager - Rate limiting & security
 * - PasswordManager - Password validation
 * - AuditLogger - Audit logging
 * 
 * Utilities:
 * - requireRole() - Role-based access middleware
 * - requireAnyRole() - Multi-role access middleware
 * - hashPassword() - Password hashing
 * - verifyPassword() - Password verification
 * 
 * Legacy:
 * - AuthX() - Legacy default export (deprecated)
 */
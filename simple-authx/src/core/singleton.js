import { createAuth } from './unified-api.js';

let authInstance = null;
let initPromise = null;

/**
 * Get default config from environment variables
 */
function getDefaultConfig() {
  return {
    storage: process.env.AUTH_STORAGE || 'mongodb',
    mongodb: process.env.MONGODB_URI,
    postgres: process.env.DATABASE_URL ? {
      connectionString: process.env.DATABASE_URL
    } : undefined,
    secret: process.env.JWT_SECRET,
    refreshSecret: process.env.JWT_REFRESH_SECRET,
    accessExpiry: process.env.ACCESS_EXPIRY || '15m',
    refreshExpiry: process.env.REFRESH_EXPIRY || '7d',
  };
}

/**
 * Initialize the auth instance (call this once in your main server file)
 * If no config provided, uses environment variables
 */
export async function initializeAuth(config = {}) {
  if (!initPromise) {
    const finalConfig = Object.keys(config).length > 0 
      ? config 
      : getDefaultConfig();
    
    initPromise = createAuth(finalConfig);
    authInstance = await initPromise;
  }
  return authInstance;
}

/**
 * Get the initialized auth instance
 * Throws error if not initialized
 */
export function getAuth() {
  if (!authInstance) {
    throw new Error(
      'Auth not initialized. Call initializeAuth() in your main server file first.'
    );
  }
  return authInstance;
}

/**
 * Protect middleware - can be imported directly
 */
export const protect = async (req, res, next) => {
  const auth = getAuth();
  await auth.protect(req, res, next);
};

/**
 * Check if auth is initialized
 */
export function isAuthInitialized() {
  return authInstance !== null;
}

/**
 * Reset the auth instance (useful for testing)
 */
export function resetAuth() {
  authInstance = null;
  initPromise = null;

}
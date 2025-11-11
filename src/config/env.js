// Optional configuration helper using environment variables
// If you want to use envalid for validation, install it: npm install envalid

export function getConfig() {
  return {
    jwtSecret: process.env.JWT_SECRET || '',
    jwtRefreshSecret: process.env.JWT_REFRESH_SECRET || '',
    accessExpiry: process.env.ACCESS_TOKEN_EXPIRY || process.env.ACCESS_EXPIRES_IN || '15m',
    refreshExpiry: process.env.REFRESH_TOKEN_EXPIRY || process.env.REFRESH_EXPIRES_IN || '7d',
    nodeEnv: process.env.NODE_ENV || 'development',
    databaseUrl: process.env.DATABASE_URL || '',
    pgPort: parseInt(process.env.PGPORT, 10) || 5432,
  };
}

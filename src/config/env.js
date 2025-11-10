import { cleanEnv, str, port, url } from 'envalid';

export function getConfig() {
  const env = cleanEnv(process.env, {
    JWT_SECRET: str(),
    JWT_REFRESH_SECRET: str(),
    DATABASE_URL: url({ default: process.env.DATABASE_URL || '' }),
    PGPORT: port({ default: parseInt(process.env.PGPORT) || 5432 }),
  });

  return {
    jwtSecret: env.JWT_SECRET,
    jwtRefreshSecret: env.JWT_REFRESH_SECRET,
    accessExpiry: process.env.ACCESS_TOKEN_EXPIRY || process.env.ACCESS_EXPIRES_IN || '15m',
    refreshExpiry: process.env.REFRESH_TOKEN_EXPIRY || process.env.REFRESH_EXPIRES_IN || '7d',
    nodeEnv: process.env.NODE_ENV || 'development',
    databaseUrl: env.DATABASE_URL,
  };
}

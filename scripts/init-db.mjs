// Idempotent DB initialization script for simple-authx
// Creates users and refresh_tokens tables (refresh_tokens stores token_hash)

import 'dotenv/config';
import pkg from 'pg';

const { Pool } = pkg;

const pool = new Pool(
  process.env.DATABASE_URL
    ? { connectionString: process.env.DATABASE_URL }
    : {
        host: process.env.PGHOST || 'localhost',
        user: process.env.PGUSER || 'postgres',
        password: process.env.PGPASSWORD || '',
        database: process.env.PGDATABASE || 'auth_demo',
        port: process.env.PGPORT ? Number(process.env.PGPORT) : 5432,
      }
);

async function main() {
  console.log('[init-db] Connecting to Postgres...');
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE,
      email TEXT UNIQUE,
      phone_number TEXT UNIQUE,
      password_hash TEXT NOT NULL,
      first_name TEXT,
      last_name TEXT,
      role TEXT DEFAULT 'user',
      metadata JSONB DEFAULT '{}',
      created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
      updated_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
      
      -- Ensure at least one identifier exists
      CONSTRAINT at_least_one_identifier CHECK (
        username IS NOT NULL OR 
        email IS NOT NULL OR 
        phone_number IS NOT NULL
      )
    )`);

    // Create indexes for faster lookups
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone_number);
      CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
    `);

    console.log('[init-db] Tables ensured.');
  } catch (err) {
    console.error('[init-db] Error:', err.message || err);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

main();

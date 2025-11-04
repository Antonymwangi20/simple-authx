// Idempotent DB initialization script for simple-authx
// Creates users and refresh_tokens tables (refresh_tokens stores token_hash)

import 'dotenv/config'
import pkg from 'pg'
const { Pool } = pkg

const pool = new Pool(process.env.DATABASE_URL ? { connectionString: process.env.DATABASE_URL } : {
  host: process.env.PGHOST || 'localhost',
  user: process.env.PGUSER || 'postgres',
  password: process.env.PGPASSWORD || '',
  database: process.env.PGDATABASE || 'auth_demo',
  port: process.env.PGPORT ? Number(process.env.PGPORT) : 5432,
})

async function main() {
  console.log('[init-db] Connecting to Postgres...')
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
    )`)

    await pool.query(`CREATE TABLE IF NOT EXISTS refresh_tokens (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL,
      expires_at TIMESTAMP WITH TIME ZONE,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
    )`)

    console.log('[init-db] Tables ensured.')
  } catch (err) {
    console.error('[init-db] Error:', err.message || err)
    process.exitCode = 1
  } finally {
    await pool.end()
  }
}

main()

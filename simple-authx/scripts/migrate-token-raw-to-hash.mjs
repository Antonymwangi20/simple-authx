// scripts/migrate-token-raw-to-hash.mjs
// Migrate any existing refresh_tokens.token column to token_hash (SHA-256) and drop the old column.

import 'dotenv/config'
import pkg from 'pg'
import crypto from 'crypto'
const { Pool } = pkg

const pool = new Pool(process.env.DATABASE_URL ? { connectionString: process.env.DATABASE_URL } : {
  host: process.env.PGHOST || 'localhost',
  user: process.env.PGUSER || 'postgres',
  password: process.env.PGPASSWORD || '',
  database: process.env.PGDATABASE || 'auth_demo',
  port: process.env.PGPORT ? Number(process.env.PGPORT) : 5432,
})

async function columnExists(name) {
  const { rows } = await pool.query(
    `SELECT column_name FROM information_schema.columns WHERE table_name='refresh_tokens' AND column_name=$1`,
    [name]
  )
  return rows.length > 0
}

async function main() {
  try {
    const hasToken = await columnExists('token')
    const hasTokenHash = await columnExists('token_hash')

    if (!hasToken) {
      console.log('[migrate] No raw token column found. Nothing to migrate.')
      return
    }

    if (!hasTokenHash) {
      console.log('[migrate] Adding token_hash column...')
      await pool.query(`ALTER TABLE refresh_tokens ADD COLUMN token_hash TEXT`)
    }

    console.log('[migrate] Reading rows with raw tokens...')
    const { rows } = await pool.query('SELECT id, token FROM refresh_tokens WHERE token IS NOT NULL')
    for (const r of rows) {
      const hash = crypto.createHash('sha256').update(r.token).digest('hex')
      await pool.query('UPDATE refresh_tokens SET token_hash=$1 WHERE id=$2', [hash, r.id])
    }

    console.log('[migrate] Dropping raw token column...')
    await pool.query('ALTER TABLE refresh_tokens DROP COLUMN token')

    console.log('[migrate] Migration complete.')
  } catch (err) {
    console.error('[migrate] Error:', err.message || err)
  } finally {
    await pool.end()
  }
}

main()

import bcrypt from 'bcryptjs'
import argon2 from 'argon2'

const DEFAULT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '10')
const HASHER = (process.env.PASSWORD_HASHER || 'bcrypt').toLowerCase()

export async function hashPassword(password) {
  if (HASHER === 'argon2') {
    return argon2.hash(password)
  }
  // bcrypt
  return bcrypt.hash(password, DEFAULT_ROUNDS)
}

export async function verifyPassword(password, hash) {
  if (HASHER === 'argon2') {
    try {
      return await argon2.verify(hash, password)
    } catch {
      return false
    }
  }
  return bcrypt.compare(password, hash)
}

export function hasherName() {
  return HASHER
}

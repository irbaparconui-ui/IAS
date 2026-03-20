
'use strict';

const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt    = require('jsonwebtoken');
const env    = require('./environment');
const { AuthError, RateLimitError, logger } = require('./errorHandler');

// ── Config (all from .env via environment.js) ────────────────
const BCRYPT_ROUNDS   = () => env.num('BCRYPT_ROUNDS', 12);
const JWT_SECRET      = () => env.str('JWT_SECRET');
const JWT_ALGORITHM   = () => env.str('JWT_ALGORITHM', 'HS256');
const JWT_EXPIRY      = () => env.str('JWT_EXPIRY', '1h');
const REFRESH_EXPIRY  = () => env.str('JWT_REFRESH_EXPIRY', '7d');
const MAX_ATTEMPTS    = () => env.num('LOGIN_MAX_ATTEMPTS', 5);
const LOCKOUT_SECS    = () => env.num('LOGIN_LOCKOUT_SECONDS', 900);

// ── In-memory stores (swap for Redis in production) ──────────
const _failedAttempts = new Map();  // { hash → { count, lockedUntil } }
const _blacklist      = new Set();  // revoked jti values

// ============================================================
// PASSWORD MANAGER
// ============================================================

async function hashPassword(plaintext) {
  if (!plaintext) throw new Error('Password must not be empty.');
  return bcrypt.hash(plaintext, BCRYPT_ROUNDS());
}

async function verifyPassword(plaintext, hashed) {
  // bcrypt.compare is timing-safe by design
  try {
    return await bcrypt.compare(plaintext, hashed);
  } catch {
    return false;
  }
}

function passwordNeedsRehash(hashed) {
  const info = bcrypt.getRounds(hashed);
  return info !== BCRYPT_ROUNDS();
}

// ============================================================
// JWT TOKEN MANAGER
// ============================================================

function createAccessToken(subject, extra = {}) {
  return _signToken(subject, JWT_EXPIRY(), 'access', extra);
}

function createRefreshToken(subject) {
  return _signToken(subject, REFRESH_EXPIRY(), 'refresh');
}

function _signToken(subject, expiresIn, type, extra = {}) {
  const jti = crypto.randomBytes(16).toString('hex');
  return jwt.sign(
    { sub: String(subject), type, jti, ...extra },
    JWT_SECRET(),
    { algorithm: JWT_ALGORITHM(), expiresIn }
  );
}

function verifyToken(token, expectedType = 'access') {
  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET(), {
      algorithms: [JWT_ALGORITHM()],
    });
  } catch (err) {
    if (err.name === 'TokenExpiredError') throw new AuthError('Token has expired.');
    throw new AuthError('Token is invalid or malformed.');
  }

  if (payload.type !== expectedType)
    throw new AuthError(`Expected ${expectedType} token.`);

  if (_blacklist.has(payload.jti))
    throw new AuthError('Token has been revoked.');

  return payload;
}

function revokeToken(token) {
  try {
    const payload = jwt.decode(token);
    if (payload?.jti) _blacklist.add(payload.jti);
  } catch { /* already invalid */ }
}

// ============================================================
// CSRF PROTECTION
// ============================================================

function generateCsrfToken() {
  return crypto.randomBytes(32).toString('hex');
}

function validateCsrf(cookieToken, headerToken) {
  if (!cookieToken || !headerToken) return false;
  // timing-safe comparison
  try {
    return crypto.timingSafeEqual(
      Buffer.from(cookieToken),
      Buffer.from(headerToken)
    );
  } catch {
    return false;
  }
}

// ============================================================
// BRUTE-FORCE GUARD
// ============================================================

function _identifierKey(identifier) {
  // Store as hash — never plain text
  return crypto.createHash('sha256').update(identifier.toLowerCase()).digest('hex');
}

function isLockedOut(identifier) {
  const rec = _failedAttempts.get(_identifierKey(identifier));
  if (!rec) return false;
  if (rec.count < MAX_ATTEMPTS()) return false;
  if (Date.now() >= rec.lockedUntil) {
    _failedAttempts.delete(_identifierKey(identifier));
    return false;
  }
  return true;
}

function recordFailure(identifier) {
  const key = _identifierKey(identifier);
  const rec = _failedAttempts.get(key) || { count: 0, lockedUntil: 0 };
  rec.count += 1;
  rec.lockedUntil = Date.now() + LOCKOUT_SECS() * 1000;
  _failedAttempts.set(key, rec);

  logger.warning('Failed login attempt', {
    id_hash:  key.slice(0, 12) + '…',
    attempts: rec.count,
  });
  return rec.count;
}

function clearFailures(identifier) {
  _failedAttempts.delete(_identifierKey(identifier));
}

function lockoutRemaining(identifier) {
  const rec = _failedAttempts.get(_identifierKey(identifier));
  if (!rec || Date.now() >= rec.lockedUntil) return 0;
  return Math.ceil((rec.lockedUntil - Date.now()) / 1000);
}

// ============================================================
// FULL LOGIN FLOW
// ============================================================

async function login(identifier, plaintext, storedHash) {
  if (isLockedOut(identifier)) {
    const secs = lockoutRemaining(identifier);
    throw new RateLimitError(
      `Account locked. Try again in ${secs} seconds.`,
      { lockout_remaining: secs }
    );
  }

  // Always run bcrypt even if user not found — prevents timing-based enumeration
  const ok = await verifyPassword(plaintext, storedHash || '$2b$12$invalidhashpadding000000000000000000000000000000000000');

  if (!ok || !storedHash) {
    recordFailure(identifier);
    throw new AuthError('Invalid credentials.');      // Generic — no hint which field
  }

  clearFailures(identifier);
  logger.info('Successful login', {
    id_hash: _identifierKey(identifier).slice(0, 12) + '…',
  });

  return {
    access_token:  createAccessToken(identifier),
    refresh_token: createRefreshToken(identifier),
    token_type:    'Bearer',
  };
}

// ============================================================
// EXPRESS MIDDLEWARE
// ============================================================

function requireAuth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token) return next(new AuthError('Bearer token is required.'));

  try {
    req.user = verifyToken(token, 'access');
    next();
  } catch (err) {
    next(err);
  }
}

function optionalAuth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (token) {
    try { req.user = verifyToken(token, 'access'); } catch { /* anonymous ok */ }
  }
  next();
}

module.exports = {
  hashPassword, verifyPassword, passwordNeedsRehash,
  createAccessToken, createRefreshToken, verifyToken, revokeToken,
  generateCsrfToken, validateCsrf,
  isLockedOut, recordFailure, clearFailures, lockoutRemaining,
  login,
  requireAuth, optionalAuth,
};

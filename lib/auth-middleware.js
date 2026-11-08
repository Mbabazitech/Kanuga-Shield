'use strict';

// lib/auth-middleware.js – JWT authentication for Kanuga Shield API
// ---------------------------------------------------------------
// Provides token generation, verification, and Express middleware.
// Uses HS256 symmetric signing with a secret from the environment.
// ---------------------------------------------------------------

const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/**
 * Resolve the JWT signing secret.  If JWT_SECRET is not set in the
 * environment a random key is generated (suitable for single-process
 * dev mode only).
 */
function _resolveSecret() {
  if (process.env.JWT_SECRET) {
    return process.env.JWT_SECRET;
  }
  const generated = crypto.randomBytes(48).toString('hex');
  console.warn(
    '[auth] WARNING: JWT_SECRET not set – generated an ephemeral secret. ' +
    'Tokens will not survive restarts. Set JWT_SECRET in .env for production.'
  );
  return generated;
}

const JWT_SECRET = _resolveSecret();
const TOKEN_EXPIRY = process.env.JWT_EXPIRY || '24h';

// Admin credentials loaded from environment (simple built-in auth)
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || null;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || null;

// When true, all API routes are wide-open (useful during development)
const AUTH_DISABLED =
  !ADMIN_EMAIL || !ADMIN_PASSWORD ||
  process.env.AUTH_ENABLED === 'false';

if (AUTH_DISABLED) {
  console.warn(
    '[auth] WARNING: Authentication is DISABLED. Set ADMIN_EMAIL, ' +
    'ADMIN_PASSWORD, and JWT_SECRET in .env to enforce API security.'
  );
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generate a signed JWT for the given payload.
 *
 * @param {Object} payload – claims to embed (e.g. { email, role })
 * @returns {string} Signed JWT string.
 */
function generateToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
}

/**
 * Verify and decode a JWT.
 *
 * @param {string} token – JWT to verify.
 * @returns {Object} Decoded payload.
 * @throws {jwt.JsonWebTokenError|jwt.TokenExpiredError}
 */
function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

/**
 * Validate admin login credentials.
 *
 * @param {string} email
 * @param {string} password
 * @returns {{ valid: boolean, email?: string }}
 */
function validateCredentials(email, password) {
  if (AUTH_DISABLED) {
    return { valid: false };
  }
  if (email === ADMIN_EMAIL && password === ADMIN_PASSWORD) {
    return { valid: true, email };
  }
  return { valid: false };
}

/**
 * Express middleware that verifies the Authorization header contains
 * a valid Bearer token.
 *
 * When AUTH_DISABLED is true the middleware is a pass-through so the
 * platform can still be used during local development without
 * configuring credentials.
 */
function authMiddleware(req, res, next) {
  // Skip auth when it is explicitly disabled
  if (AUTH_DISABLED) {
    return next();
  }

  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or malformed Authorization header' });
  }

  const token = authHeader.slice(7); // strip "Bearer "

  try {
    const decoded = verifyToken(token);
    req.user = decoded; // attach decoded claims for downstream handlers
    return next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
module.exports = {
  generateToken,
  verifyToken,
  validateCredentials,
  authMiddleware,
  AUTH_DISABLED,
};

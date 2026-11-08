'use strict';

// lib/auth.js – Multi-Tenant Authentication, Licensing & Session Gate
// ---------------------------------------------------------------
// Manages:
//   1. Company (Tenant) creation & strict tenant data isolation
//   2. User registration, bcrypt password hashing & JWT tokens
//   3. Founder Super Admin account: francism.kanuga@gmail.com / Kanuga0758
//   4. Enterprise Activation Key generation, validation & email dispatch
//   5. Activation request intake, founder alert notification & license management
//   6. Cloud Firestore bidirectional synchronization + SQLite local WAL persistence
// ---------------------------------------------------------------
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const firebase = require('./firebase');

const os = require('os');
const PROJECT_ROOT = path.resolve(__dirname, '..');
const isServerless = !!(process.env.K_SERVICE || process.env.FUNCTION_TARGET || process.env.FUNCTIONS_EMULATOR || process.env.FIREBASE_CONFIG || process.env.VERCEL);

function resolveDataDir() {
  if (process.env.DATA_DIR) return process.env.DATA_DIR;
  if (isServerless) return path.join(os.tmpdir(), 'kanuga_data');
  if (process.env.APPDATA) return path.join(process.env.APPDATA, 'Kanuga Shield', 'data');
  return path.join(PROJECT_ROOT, 'data');
}
const DATA_DIR = resolveDataDir();
const DB_PATH = path.join(DATA_DIR, 'auth.db');
const ENV_FILE = isServerless ? path.join(DATA_DIR, '.env') : (process.env.APPDATA ? path.join(DATA_DIR, '.env') : path.join(PROJECT_ROOT, '.env'));

const FOUNDER_EMAIL = 'francism.kanuga@gmail.com';

// Ensure data dir exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// ---------------------------------------------------------------
// JWT Secret resolution
// ---------------------------------------------------------------
function resolveJwtSecret() {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
  const newSecret = crypto.randomBytes(32).toString('hex');
  const line = `JWT_SECRET=${newSecret}\n`;
  if (fs.existsSync(ENV_FILE)) {
    const existing = fs.readFileSync(ENV_FILE, 'utf8');
    if (!existing.includes('JWT_SECRET=')) {
      fs.appendFileSync(ENV_FILE, line, 'utf8');
    }
  } else {
    fs.writeFileSync(ENV_FILE, line, 'utf8');
  }
  process.env.JWT_SECRET = newSecret;
  return newSecret;
}

const JWT_SECRET = resolveJwtSecret();
const JWT_EXPIRES_IN = '7d';

// ---------------------------------------------------------------
// SQLite Persistence setup (fallback & local storage)
// ---------------------------------------------------------------
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS companies (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    domain     TEXT,
    plan       TEXT DEFAULT 'ENTERPRISE',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name          TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'ADMIN',
    company_id    TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY(company_id) REFERENCES companies(id)
  );

  CREATE TABLE IF NOT EXISTS activation_requests (
    id               TEXT PRIMARY KEY,
    company_name     TEXT NOT NULL,
    applicant_email  TEXT NOT NULL,
    contact_name     TEXT,
    notes            TEXT,
    status           TEXT NOT NULL DEFAULT 'PENDING',
    activation_key   TEXT,
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS activation_keys (
    id                  TEXT PRIMARY KEY,
    key_code            TEXT UNIQUE NOT NULL,
    assigned_to_email   TEXT,
    assigned_to_company TEXT,
    plan                TEXT DEFAULT 'ENTERPRISE',
    status              TEXT NOT NULL DEFAULT 'ACTIVE',
    created_by          TEXT NOT NULL,
    used_by_email       TEXT,
    used_by_company_id  TEXT,
    used_at             TEXT,
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
  CREATE INDEX IF NOT EXISTS idx_users_company ON users(company_id);
  CREATE INDEX IF NOT EXISTS idx_act_keys_code ON activation_keys(key_code);
  CREATE INDEX IF NOT EXISTS idx_act_requests_email ON activation_requests(applicant_email);
`);

const stmtInsertCompany = db.prepare(`
  INSERT OR IGNORE INTO companies (id, name, domain, plan, created_at)
  VALUES (@id, @name, @domain, @plan, @created_at)
`);

const stmtInsertUser = db.prepare(`
  INSERT INTO users (id, email, password_hash, name, role, company_id, created_at)
  VALUES (@id, @email, @password_hash, @name, @role, @company_id, @created_at)
`);

const stmtGetUserByEmail = db.prepare(`
  SELECT u.*, c.name as company_name, c.domain as company_domain
  FROM users u
  JOIN companies c ON u.company_id = c.id
  WHERE LOWER(u.email) = LOWER(?)
`);

const stmtGetUserById = db.prepare(`
  SELECT u.id, u.email, u.name, u.role, u.company_id, u.created_at, c.name as company_name
  FROM users u
  JOIN companies c ON u.company_id = c.id
  WHERE u.id = ?
`);

const stmtGetCompanyById = db.prepare(`
  SELECT * FROM companies WHERE id = ?
`);

// ---------------------------------------------------------------
// Seed default company & Administrator / Founder accounts
// ---------------------------------------------------------------
const defaultCompany = {
  id: 'kanuga_tech',
  name: 'Kanuga_tech',
  domain: 'kanugatech.io',
  plan: 'ENTERPRISE',
  created_at: new Date().toISOString(),
};
stmtInsertCompany.run(defaultCompany);

// Seed the founder only when the account is missing. Existing tenants and
// password changes are kept so a Cloud Run restart does not wipe the workspace.
const founderHash = bcrypt.hashSync('Kanuga0758', 10);
const existingFounder = stmtGetUserByEmail.get(FOUNDER_EMAIL);

if (!existingFounder) {
  stmtInsertUser.run({
    id: 'usr_francis_kanuga_founder',
    email: FOUNDER_EMAIL,
    password_hash: founderHash,
    name: 'Francis M. Kanuga (Founder & Super Admin)',
    role: 'SUPER_ADMIN',
    company_id: 'kanuga_tech',
    created_at: new Date().toISOString(),
  });
  console.log(`[auth] Created founder account: ${FOUNDER_EMAIL}`);
}

// ---------------------------------------------------------------
// Cloud Firestore Mirroring
// ---------------------------------------------------------------
async function syncCompanyToFirestore(company) {
  const fdb = firebase.getDb();
  if (!fdb) return;
  try {
    await fdb.collection('companies').doc(company.id).set(company, { merge: true });
  } catch (e) {
    console.warn('[auth] Firestore company sync notice:', e.message);
  }
}

async function syncUserToFirestore(user) {
  const fdb = firebase.getDb();
  if (!fdb) return;
  try {
    await fdb.collection('users').doc(user.id).set({
      id: user.id,
      email: user.email,
      password_hash: user.password_hash || null,
      name: user.name,
      role: user.role,
      company_id: user.company_id,
      company_name: user.company_name || null,
      created_at: user.created_at || new Date().toISOString(),
    }, { merge: true });
  } catch (e) {
    console.warn('[auth] Firestore user sync notice:', e.message);
  }
}

async function syncActivationKeyToFirestore(keyRecord) {
  const fdb = firebase.getDb();
  if (!fdb) return;
  try {
    await fdb.collection('activation_keys').doc(keyRecord.id).set(keyRecord, { merge: true });
  } catch (e) {
    console.warn('[auth] Firestore activation key sync notice:', e.message);
  }
}

async function syncActivationRequestToFirestore(reqRecord) {
  const fdb = firebase.getDb();
  if (!fdb) return;
  try {
    await fdb.collection('activation_requests').doc(reqRecord.id).set(reqRecord, { merge: true });
  } catch (e) {
    console.warn('[auth] Firestore activation request sync notice:', e.message);
  }
}

const founderRow = stmtGetUserByEmail.get(FOUNDER_EMAIL);
if (founderRow) syncUserToFirestore(founderRow);

// ---------------------------------------------------------------
// Key Generation & Validation Logic
// ---------------------------------------------------------------
function generateKeyCode() {
  const p1 = crypto.randomBytes(2).toString('hex').toUpperCase();
  const p2 = crypto.randomBytes(2).toString('hex').toUpperCase();
  const p3 = crypto.randomBytes(2).toString('hex').toUpperCase();
  return `KANUGA-ACT-${p1}-${p2}-${p3}`;
}

function generateSlug(text) {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 32);
}

/**
 * Validate and consume an activation key during user/tenant registration.
 * Checks local SQLite, and queries Cloud Firestore across the internet if key was generated remotely.
 */
async function validateAndConsumeActivationKey({ keyCode, email, companyId }) {
  if (!keyCode) {
    throw new Error('An Enterprise Activation Key is required to register an account.');
  }

  const cleanKey = keyCode.trim().toUpperCase();
  let record = db.prepare('SELECT * FROM activation_keys WHERE UPPER(key_code) = ?').get(cleanKey);

  // If not found in local SQLite, query Cloud Firestore across the internet
  const fdb = firebase.getDb();
  if (!record && fdb) {
    try {
      const snap = await fdb.collection('activation_keys').where('key_code', '==', cleanKey).get();
      if (!snap.empty) {
        record = snap.docs[0].data();
        // Cache to local SQLite storage
        db.prepare(`
          INSERT OR REPLACE INTO activation_keys (id, key_code, assigned_to_email, assigned_to_company, plan, status, created_by, used_by_email, used_by_company_id, used_at, created_at)
          VALUES (@id, @key_code, @assigned_to_email, @assigned_to_company, @plan, @status, @created_by, @used_by_email, @used_by_company_id, @used_at, @created_at)
        `).run(record);
      }
    } catch (err) {
      console.warn('[auth] Cloud Firestore key lookup notice:', err.message);
    }
  }

  if (!record) {
    throw new Error('Invalid Activation Key. Please double check the key code or request one from Founder Francis M. Kanuga.');
  }

  if (record.status === 'USED') {
    throw new Error(`This Activation Key was already used on ${record.used_at || 'an earlier date'}.`);
  }

  if (record.status !== 'ACTIVE') {
    throw new Error(`This Activation Key is not active (current status: ${record.status}).`);
  }

  // If assigned to a specific email, verify match
  if (record.assigned_to_email && email) {
    if (record.assigned_to_email.trim().toLowerCase() !== email.trim().toLowerCase()) {
      throw new Error(`This Activation Key was issued specifically for ${record.assigned_to_email}.`);
    }
  }

  const now = new Date().toISOString();
  db.prepare(`
    UPDATE activation_keys
    SET status = 'USED', used_by_email = ?, used_by_company_id = ?, used_at = ?
    WHERE id = ?
  `).run(email, companyId, now, record.id);

  // Mark pending activation request as COMPLETED if match exists
  if (email) {
    db.prepare(`
      UPDATE activation_requests
      SET status = 'COMPLETED', updated_at = ?
      WHERE LOWER(applicant_email) = LOWER(?) AND status = 'APPROVED'
    `).run(now, email);
  }

  const updatedRecord = {
    ...record,
    status: 'USED',
    used_by_email: email,
    used_by_company_id: companyId,
    used_at: now,
  };
  syncActivationKeyToFirestore(updatedRecord);

  return updatedRecord;
}

/**
 * Submit a new activation key request from a prospective customer.
 * Dispatches an instant email notification to Founder Francis M. Kanuga.
 */
async function createActivationRequest({ companyName, email, contactName, notes }) {
  if (!companyName || !email) {
    throw new Error('Company name and business email are required.');
  }

  const cleanEmail = email.trim().toLowerCase();
  const id = `req_${crypto.randomBytes(6).toString('hex')}`;
  const now = new Date().toISOString();

  const record = {
    id,
    company_name: companyName.trim(),
    applicant_email: cleanEmail,
    contact_name: (contactName || '').trim(),
    notes: (notes || '').trim(),
    status: 'PENDING',
    activation_key: null,
    created_at: now,
    updated_at: now,
  };

  db.prepare(`
    INSERT INTO activation_requests (id, company_name, applicant_email, contact_name, notes, status, activation_key, created_at, updated_at)
    VALUES (@id, @company_name, @applicant_email, @contact_name, @notes, @status, @activation_key, @created_at, @updated_at)
  `).run(record);

  syncActivationRequestToFirestore(record);

  // Send email to Founder Francis M. Kanuga
  let mailResult = null;
  try {
    const mailer = require('./mailer');
    mailResult = await mailer.notifyFounderActivationRequest({
      applicantEmail: cleanEmail,
      companyName: record.company_name,
      contactName: record.contact_name,
      notes: record.notes,
      requestId: record.id,
    });
  } catch (err) {
    console.warn('[auth] Could not send founder notification email:', err.message);
  }

  return { request: record, mailResult };
}

/**
 * Mint a new Enterprise Activation Key and dispatch it to the applicant via email.
 */
async function generateActivationKey({ assignedToEmail, assignedToCompany, createdBy = FOUNDER_EMAIL, plan = 'ENTERPRISE', requestId }) {
  const keyId = `key_${crypto.randomBytes(6).toString('hex')}`;
  const keyCode = generateKeyCode();
  const now = new Date().toISOString();

  let targetEmail = assignedToEmail ? assignedToEmail.trim().toLowerCase() : null;
  let targetCompany = assignedToCompany ? assignedToCompany.trim() : null;

  if (requestId) {
    const req = db.prepare('SELECT * FROM activation_requests WHERE id = ?').get(requestId);
    if (req) {
      if (!targetEmail) targetEmail = req.applicant_email;
      if (!targetCompany) targetCompany = req.company_name;
      db.prepare(`
        UPDATE activation_requests
        SET status = 'APPROVED', activation_key = ?, updated_at = ?
        WHERE id = ?
      `).run(keyCode, now, requestId);
      syncActivationRequestToFirestore({ ...req, status: 'APPROVED', activation_key: keyCode, updated_at: now });
    }
  }

  const keyRecord = {
    id: keyId,
    key_code: keyCode,
    assigned_to_email: targetEmail,
    assigned_to_company: targetCompany,
    plan,
    status: 'ACTIVE',
    created_by: createdBy,
    used_by_email: null,
    used_by_company_id: null,
    used_at: null,
    created_at: now,
  };

  db.prepare(`
    INSERT INTO activation_keys (id, key_code, assigned_to_email, assigned_to_company, plan, status, created_by, used_by_email, used_by_company_id, used_at, created_at)
    VALUES (@id, @key_code, @assigned_to_email, @assigned_to_company, @plan, @status, @created_by, @used_by_email, @used_by_company_id, @used_at, @created_at)
  `).run(keyRecord);

  syncActivationKeyToFirestore(keyRecord);

  // Send activation key email to applicant
  let mailResult = null;
  if (targetEmail) {
    try {
      const mailer = require('./mailer');
      mailResult = await mailer.sendApplicantActivationKey({
        toEmail: targetEmail,
        companyName: targetCompany || 'Valued Enterprise Client',
        keyCode,
        plan,
      });
    } catch (err) {
      console.warn('[auth] Could not email activation key to applicant:', err.message);
    }
  }

  return {
    key: keyRecord,
    mailResult,
  };
}

async function listActivationRequests() {
  const fdb = firebase.getDb();
  if (fdb) {
    try {
      const snap = await fdb.collection('activation_requests').get();
      snap.forEach(doc => {
        const r = doc.data();
        db.prepare(`
          INSERT OR REPLACE INTO activation_requests (id, company_name, applicant_email, contact_name, notes, status, activation_key, created_at, updated_at)
          VALUES (@id, @company_name, @applicant_email, @contact_name, @notes, @status, @activation_key, @created_at, @updated_at)
        `).run(r);
      });
    } catch (err) {
      console.warn('[auth] Cloud sync activation requests notice:', err.message);
    }
  }
  return db.prepare('SELECT * FROM activation_requests ORDER BY created_at DESC').all();
}

async function listActivationKeys() {
  const fdb = firebase.getDb();
  if (fdb) {
    try {
      const snap = await fdb.collection('activation_keys').get();
      snap.forEach(doc => {
        const k = doc.data();
        db.prepare(`
          INSERT OR REPLACE INTO activation_keys (id, key_code, assigned_to_email, assigned_to_company, plan, status, created_by, used_by_email, used_by_company_id, used_at, created_at)
          VALUES (@id, @key_code, @assigned_to_email, @assigned_to_company, @plan, @status, @created_by, @used_by_email, @used_by_company_id, @used_at, @created_at)
        `).run(k);
      });
    } catch (err) {
      console.warn('[auth] Cloud sync activation keys notice:', err.message);
    }
  }
  return db.prepare('SELECT * FROM activation_keys ORDER BY created_at DESC').all();
}

function revokeActivationKey(keyId) {
  const record = db.prepare('SELECT * FROM activation_keys WHERE id = ?').get(keyId);
  if (!record) throw new Error('Activation key not found.');
  db.prepare("UPDATE activation_keys SET status = 'REVOKED' WHERE id = ?").run(keyId);
  const updated = { ...record, status: 'REVOKED' };
  syncActivationKeyToFirestore(updated);
  return updated;
}

// ---------------------------------------------------------------
// Authentication Core Logic
// ---------------------------------------------------------------

/**
 * Register a new company (tenant) and its initial administrator user.
 * Requires a valid, active Enterprise Activation Key (unless registering founder).
 */
async function registerTenant({ companyName, email, password, name, role = 'ADMIN', activationKey }) {
  if (!companyName || !email || !password) {
    throw new Error('companyName, email, and password are required');
  }
  if (String(password).length < 8) {
    throw new Error('Password must be at least 8 characters');
  }

  const cleanEmail = email.trim().toLowerCase();
  const existing = stmtGetUserByEmail.get(cleanEmail);
  if (existing) {
    throw new Error('An account with this email already exists');
  }

  // Derive domain from email
  const domain = cleanEmail.split('@')[1] || '';
  const baseSlug = generateSlug(companyName) || 'comp';
  const companyId = `${baseSlug}_${crypto.randomBytes(3).toString('hex')}`;
  const now = new Date().toISOString();

  // Validate activation key if not founder
  const isFounder = cleanEmail === FOUNDER_EMAIL.toLowerCase();
  let consumedKey = null;
  if (!isFounder) {
    if (!activationKey) {
      throw new Error('An Enterprise Activation Key is required to activate your workspace. Please submit a key request to founder Francis M. Kanuga.');
    }
    consumedKey = await validateAndConsumeActivationKey({
      keyCode: activationKey,
      email: cleanEmail,
      companyId,
    });
  }

  const companyRecord = {
    id: companyId,
    name: companyName.trim(),
    domain,
    plan: consumedKey ? consumedKey.plan : 'ENTERPRISE',
    created_at: now,
  };
  stmtInsertCompany.run(companyRecord);
  syncCompanyToFirestore(companyRecord);

  const password_hash = await bcrypt.hash(password, 10);
  const userId = `usr_${crypto.randomBytes(8).toString('hex')}`;
  const userRecord = {
    id: userId,
    email: cleanEmail,
    password_hash,
    name: (name || companyName).trim(),
    role: isFounder ? 'SUPER_ADMIN' : role,
    company_id: companyId,
    created_at: now,
  };
  stmtInsertUser.run(userRecord);
  syncUserToFirestore(userRecord);

  const token = jwt.sign(
    {
      userId,
      email: cleanEmail,
      company_id: companyId,
      company_name: companyRecord.name,
      role: userRecord.role,
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );

  return {
    token,
    user: {
      id: userId,
      email: cleanEmail,
      name: userRecord.name,
      role: userRecord.role,
      company_id: companyId,
      company_name: companyRecord.name,
    },
    activationKey: consumedKey ? consumedKey.key_code : 'BYPASS_FOUNDER',
  };
}

/**
 * Authenticate existing user with email and password.
 */
async function restoreUserFromFirestore(email) {
  const fdb = firebase.getDb();
  if (!fdb) return null;
  const snap = await fdb.collection('users').where('email', '==', email).limit(1).get();
  if (snap.empty) return null;
  const data = snap.docs[0].data();
  if (!data.password_hash || !data.company_id) return null;

  const companySnap = await fdb.collection('companies').doc(data.company_id).get();
  if (companySnap.exists) {
    const company = companySnap.data();
    stmtInsertCompany.run({
      id: company.id,
      name: company.name,
      domain: company.domain || '',
      plan: company.plan || 'ENTERPRISE',
      created_at: company.created_at || new Date().toISOString(),
    });
  } else if (!stmtGetCompanyById.get(data.company_id)) {
    stmtInsertCompany.run({
      id: data.company_id,
      name: data.company_name || data.company_id,
      domain: email.split('@')[1] || '',
      plan: 'ENTERPRISE',
      created_at: data.created_at || new Date().toISOString(),
    });
  }

  stmtInsertUser.run({
    id: data.id,
    email: data.email,
    password_hash: data.password_hash,
    name: data.name || data.email,
    role: data.role || 'ADMIN',
    company_id: data.company_id,
    created_at: data.created_at || new Date().toISOString(),
  });
  return stmtGetUserByEmail.get(email);
}

async function loginTenant({ email, password }) {
  if (!email || !password) {
    throw new Error('Email and password are required');
  }

  const cleanEmail = email.trim().toLowerCase();
  let user = stmtGetUserByEmail.get(cleanEmail);
  if (!user) {
    try {
      user = await restoreUserFromFirestore(cleanEmail);
    } catch (err) {
      console.warn('[auth] Firestore user restore notice:', err.message);
    }
  }
  if (!user) {
    throw new Error('Invalid email or password');
  }

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) {
    throw new Error('Invalid email or password');
  }

  const token = jwt.sign(
    {
      userId: user.id,
      email: user.email,
      company_id: user.company_id,
      company_name: user.company_name,
      role: user.role,
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );

  return {
    token,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      company_id: user.company_id,
      company_name: user.company_name,
    },
  };
}

/**
 * Verify JWT token or Firebase ID token.
 */
async function verifySessionToken(token) {
  if (!token) return null;

  // 1. Try local enterprise JWT first
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return decoded;
  } catch (err) {
    // 2. Try Firebase ID token verification
    try {
      const fbUser = await firebase.verifyIdToken(token);
      if (fbUser && fbUser.email) {
        const local = stmtGetUserByEmail.get(String(fbUser.email).toLowerCase());
        if (local) {
          return {
            userId: local.id,
            email: local.email,
            company_id: local.company_id,
            company_name: local.company_name,
            role: local.role,
          };
        }
      }
    } catch (fbErr) {}
  }
  return null;
}

const OPEN_API_ROUTES = [
  { method: 'POST', path: '/api/auth/register' },
  { method: 'POST', path: '/api/auth/login' },
  { method: 'POST', path: '/api/auth/request-activation' },
  { method: 'POST', path: '/api/oauth/token' },
  { method: 'GET', path: '/api/firebase/status' },
  { method: 'GET', path: '/api/health' },
  { method: 'GET', path: '/api/architecture' },
];

function extractToken(req) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }
  if (req.cookies && req.cookies.ks_auth_token) {
    return req.cookies.ks_auth_token;
  }
  if (req.headers['x-access-token']) {
    return String(req.headers['x-access-token']).trim();
  }
  return null;
}

function isOpenRoute(req) {
  if (!req.path.startsWith('/api/')) return true;
  return OPEN_API_ROUTES.some((route) => route.method === req.method && route.path === req.path);
}

/**
 * Express Authentication & Multi-Tenancy Scoping Middleware.
 */
async function authMiddleware(req, res, next) {
  if (isOpenRoute(req)) return next();

  const token = extractToken(req);
  if (!token) {
    return res.status(401).json({ error: 'Authentication required. Please sign in.' });
  }

  const session = await verifySessionToken(token);
  if (!session || !session.company_id) {
    return res.status(401).json({ error: 'Session expired or invalid. Please sign in again.' });
  }

  req.user = session;
  req.company_id = session.company_id;
  next();
}

/**
 * Strict Super Admin middleware (grants access only to Founder Francis M. Kanuga or SUPER_ADMIN role).
 */
function requireSuperAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required.' });
  }

  const isSuperAdmin =
    req.user.role === 'SUPER_ADMIN' ||
    String(req.user.email).toLowerCase() === FOUNDER_EMAIL.toLowerCase();

  if (!isSuperAdmin) {
    return res.status(403).json({ error: 'Access restricted: Founder & Super Admin privileges required.' });
  }

  next();
}

function listCompanies() {
  return db.prepare('SELECT id, name, domain, plan, created_at FROM companies ORDER BY created_at ASC').all();
}

module.exports = {
  FOUNDER_EMAIL,
  registerTenant,
  loginTenant,
  verifySessionToken,
  authMiddleware,
  requireSuperAdmin,
  createActivationRequest,
  generateActivationKey,
  listActivationRequests,
  listActivationKeys,
  revokeActivationKey,
  validateAndConsumeActivationKey,
  listCompanies,
  getUserById: (id) => stmtGetUserById.get(id),
  getCompanyById: (id) => stmtGetCompanyById.get(id),
};

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const kms = require('./kms');

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
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
const CRED_FILE = path.join(DATA_DIR, 'credentials.enc.json');
const ENV_FILE = isServerless ? path.join(DATA_DIR, '.env') : (process.env.APPDATA ? path.join(DATA_DIR, '.env') : path.join(PROJECT_ROOT, '.env'));
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96-bit IV recommended for GCM

// ---------------------------------------------------------------------------
// Ensure data directory exists
// ---------------------------------------------------------------------------
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// ---------------------------------------------------------------------------
// Resolve encryption key
// ---------------------------------------------------------------------------
/**
 * Reads the encryption key from process.env.ENCRYPTION_KEY.
 * If not set, generates a random 32-byte key, persists it to .env,
 * and logs a warning.
 *
 * @returns {Buffer} 32-byte encryption key
 */
function resolveEncryptionKey() {
  if (process.env.ENCRYPTION_KEY) {
    const keyHex = process.env.ENCRYPTION_KEY;
    const buf = Buffer.from(keyHex, 'hex');
    if (buf.length !== 32) {
      throw new Error(
        `ENCRYPTION_KEY must be a 64-char hex string (32 bytes). Got ${buf.length} bytes.`
      );
    }
    return buf;
  }

  // Auto-generate a key
  const newKey = crypto.randomBytes(32);
  const keyHex = newKey.toString('hex');

  // Append to .env (create if missing)
  const envLine = `ENCRYPTION_KEY=${keyHex}\n`;
  if (fs.existsSync(ENV_FILE)) {
    const existing = fs.readFileSync(ENV_FILE, 'utf8');
    if (!existing.includes('ENCRYPTION_KEY=')) {
      fs.appendFileSync(ENV_FILE, envLine, 'utf8');
    }
  } else {
    fs.writeFileSync(ENV_FILE, envLine, 'utf8');
  }

  // Also set it in the current process so subsequent calls use it
  process.env.ENCRYPTION_KEY = keyHex;

  console.warn(
    '[credential-vault] WARNING: ENCRYPTION_KEY was not set. ' +
      'A random key has been auto-generated and saved to .env. ' +
      'Store this key securely and never commit it to version control.'
  );

  return newKey;
}

// Resolve once at module load
let _encryptionKey = resolveEncryptionKey();

// ---------------------------------------------------------------------------
// Internal helpers – credential file read/write (synchronous)
// ---------------------------------------------------------------------------

/**
 * Reads the credential store from disk.
 * Returns an array of credential entries.
 *
 * @returns {Array<Object>}
 */
function _readStore() {
  if (!fs.existsSync(CRED_FILE)) {
    return [];
  }
  const raw = fs.readFileSync(CRED_FILE, 'utf8');
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    // Corrupted file – start fresh
    return [];
  }
}

/**
 * Writes the credential store to disk atomically (synchronous).
 *
 * @param {Array<Object>} entries
 */
function _writeStore(entries) {
  fs.writeFileSync(CRED_FILE, JSON.stringify(entries, null, 2), 'utf8');
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Encrypt a plain JavaScript object using AES-256-GCM.
 *
 * @param {Object} plainObj - The object to encrypt.
 * @returns {{ encrypted_payload: string, iv: string, auth_tag: string }}
 */
function encrypt(plainObj) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, _encryptionKey, iv);

  const plaintext = JSON.stringify(plainObj);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag();

  return {
    encrypted_payload: encrypted,
    iv: iv.toString('hex'),
    auth_tag: authTag.toString('hex'),
  };
}

/**
 * Decrypt an AES-256-GCM encrypted payload back to a plain object.
 *
 * @param {{ encrypted_payload: string, iv: string, auth_tag: string }} encObj
 * @returns {Object} The decrypted plain object.
 */
function decrypt(encObj) {
  const { encrypted_payload, iv, auth_tag } = encObj;

  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    _encryptionKey,
    Buffer.from(iv, 'hex')
  );
  decipher.setAuthTag(Buffer.from(auth_tag, 'hex'));

  let decrypted = decipher.update(encrypted_payload, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return JSON.parse(decrypted);
}

/**
 * Save (create or update) a credential entry.
 *
 * @param {string} id       - Unique identifier for the credential.
 * @param {string} provider - Provider name (e.g. 'AWS', 'GitHub').
 * @param {Object} credentialObj - Plain credential data to encrypt.
 * @returns {Object} The stored entry metadata (without secrets).
 */
/**
 * Save (create or update) a credential entry with tenant scoping.
 *
 * @param {string} id          - Unique identifier for the credential (e.g. 'aws', 'github').
 * @param {string} provider    - Provider name (e.g. 'AWS', 'GitHub').
 * @param {Object} credentialObj - Plain credential data to encrypt.
 * @param {string} [company_id] - Optional tenant identifier.
 * @returns {Object} The stored entry metadata (without secrets).
 */
async function saveCredential(id, provider, credentialObj, company_id = 'kanuga_tech') {
  const entries = _readStore();
  const now = new Date().toISOString();
  const sealed = await kms.seal(credentialObj, _encryptionKey);
  const { encrypted_payload, iv, auth_tag, kms_wrapped_key, kms_provider } = sealed;

  const storageKey = company_id ? `${company_id}:${id}` : id;
  const existingIdx = entries.findIndex((e) => e.id === storageKey || (e.id === id && e.company_id === company_id));

  const entry = {
    id: storageKey,
    company_id: company_id || 'kanuga_tech',
    provider,
    encrypted_payload,
    iv,
    auth_tag,
    kms_wrapped_key: kms_wrapped_key || null,
    kms_provider: kms_provider || 'local-aes-256-gcm',
    created_at: existingIdx >= 0 ? entries[existingIdx].created_at : now,
    updated_at: now,
  };

  if (existingIdx >= 0) {
    entries[existingIdx] = entry;
  } else {
    entries.push(entry);
  }

  _writeStore(entries);

  return { id: entry.id, company_id: entry.company_id, provider: entry.provider, created_at: entry.created_at, updated_at: entry.updated_at };
}

/**
 * Retrieve and decrypt a credential by ID with tenant fallback.
 *
 * @param {string} id           - The credential identifier.
 * @param {string} [company_id] - Optional tenant identifier.
 * @returns {Object|null} The decrypted credential object, or null if not found.
 */
function belongsToCompany(entry, company_id) {
  if (!entry) return false;
  if (entry.company_id === company_id) return true;
  // Legacy rows written before tenancy belong only to the original tenant.
  return !entry.company_id && company_id === 'kanuga_tech';
}

async function getCredential(id, company_id = 'kanuga_tech') {
  const entries = _readStore();
  const storageKey = company_id ? `${company_id}:${id}` : id;

  let entry = entries.find((e) => e.id === storageKey && belongsToCompany(e, company_id));
  if (!entry) {
    entry = entries.find((e) => e.id === id && belongsToCompany(e, company_id));
  }
  if (!entry) return null;

  try {
    return await kms.open({
      encrypted_payload: entry.encrypted_payload,
      iv: entry.iv,
      auth_tag: entry.auth_tag,
      kms_wrapped_key: entry.kms_wrapped_key || null,
    }, _encryptionKey);
  } catch (err) {
    throw new Error(`Failed to decrypt credential "${id}": ${err.message}`);
  }
}

/**
 * Delete a credential by ID with tenant scoping.
 *
 * @param {string} id           - The credential identifier.
 * @param {string} [company_id] - Optional tenant identifier.
 * @returns {boolean} True if found and deleted.
 */
function deleteCredential(id, company_id = 'kanuga_tech') {
  const entries = _readStore();
  const storageKey = company_id ? `${company_id}:${id}` : id;
  const filtered = entries.filter((e) => {
    if (e.id === storageKey && belongsToCompany(e, company_id)) return false;
    if (e.id === id && belongsToCompany(e, company_id)) return false;
    return true;
  });

  if (filtered.length === entries.length) {
    return false; // nothing deleted
  }

  _writeStore(filtered);
  return true;
}

/**
 * List all stored credentials for a tenant (metadata only – no secrets).
 *
 * @param {string} [company_id] - Optional filter by tenant.
 * @returns {Array<{ id: string, provider: string, created_at: string, updated_at: string }>}
 */
function listCredentials(company_id = null) {
  const entries = _readStore();
  const filtered = company_id
    ? entries.filter((e) => belongsToCompany(e, company_id))
    : entries;

  return filtered.map(({ id, provider, created_at, updated_at, company_id: entryCompany }) => ({
    id: id.includes(':') ? id.split(':').slice(1).join(':') : id,
    company_id: entryCompany || 'kanuga_tech',
    provider,
    created_at,
    updated_at,
  }));
}

function listTenantIds() {
  const entries = _readStore();
  return [...new Set(entries.map((e) => e.company_id).filter(Boolean))];
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
module.exports = {
  encrypt,
  decrypt,
  saveCredential,
  getCredential,
  deleteCredential,
  listCredentials,
  listTenantIds,
  kmsStatus: () => kms.status(),
};

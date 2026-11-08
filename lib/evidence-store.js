'use strict';

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const firebase = require('./firebase');

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
const DB_PATH = path.join(DATA_DIR, 'evidence_vault.db');

// ---------------------------------------------------------------------------
// Ensure data directory exists
// ---------------------------------------------------------------------------
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// ---------------------------------------------------------------------------
// Database initialisation
// ---------------------------------------------------------------------------
const db = new Database(DB_PATH);

// Enable WAL mode for better concurrent read performance
db.pragma('journal_mode = WAL');

// Create the evidence_vault table if it doesn't already exist
db.exec(`
  CREATE TABLE IF NOT EXISTS evidence_vault (
    id                 TEXT PRIMARY KEY,
    company_id         TEXT DEFAULT 'kanuga_tech',
    integration_source TEXT NOT NULL,
    control_code       TEXT NOT NULL,
    control_title      TEXT,
    status             TEXT NOT NULL CHECK(status IN ('PASS','FAIL','ERROR')),
    sha256_hash        TEXT NOT NULL,
    raw_json_payload   TEXT NOT NULL,
    scan_run_id        TEXT,
    created_at         TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// Graceful schema migration for existing SQLite files before creating index
try {
  db.exec(`ALTER TABLE evidence_vault ADD COLUMN company_id TEXT DEFAULT 'kanuga_tech'`);
} catch (e) {
  // Column already exists
}

// Create indexes and control_results table
db.exec(`
  CREATE INDEX IF NOT EXISTS idx_ev_company ON evidence_vault(company_id);
  CREATE INDEX IF NOT EXISTS idx_ev_control ON evidence_vault(control_code);
  CREATE INDEX IF NOT EXISTS idx_ev_source  ON evidence_vault(integration_source);
  CREATE INDEX IF NOT EXISTS idx_ev_status  ON evidence_vault(status);
  CREATE INDEX IF NOT EXISTS idx_ev_created ON evidence_vault(created_at);

  CREATE TABLE IF NOT EXISTS control_results (
    company_id         TEXT NOT NULL,
    control_code       TEXT NOT NULL,
    control_title      TEXT,
    integration_source TEXT,
    status             TEXT NOT NULL,
    raw_json_payload   TEXT,
    scan_run_id        TEXT,
    updated_at         TEXT NOT NULL,
    PRIMARY KEY (company_id, control_code)
  );
`);

// ---------------------------------------------------------------------------
// Prepared statements (cached for performance)
// ---------------------------------------------------------------------------
const stmtInsert = db.prepare(`
  INSERT INTO evidence_vault
    (id, company_id, integration_source, control_code, control_title, status, sha256_hash, raw_json_payload, scan_run_id, created_at)
  VALUES
    (@id, @company_id, @integration_source, @control_code, @control_title, @status, @sha256_hash, @raw_json_payload, @scan_run_id, @created_at)
`);

const stmtGetById = db.prepare(`
  SELECT * FROM evidence_vault WHERE id = ?
`);

const stmtDeleteOlderThan = db.prepare(`
  DELETE FROM evidence_vault WHERE created_at < datetime('now', '-' || ? || ' days')
`);

const stmtStats = db.prepare(`
  SELECT
    COUNT(*)                                           AS total,
    SUM(CASE WHEN status = 'PASS'  THEN 1 ELSE 0 END) AS pass_count,
    SUM(CASE WHEN status = 'FAIL'  THEN 1 ELSE 0 END) AS fail_count,
    SUM(CASE WHEN status = 'ERROR' THEN 1 ELSE 0 END) AS error_count,
    MAX(created_at)                                    AS latest_scan_at
  FROM evidence_vault
`);

const stmtDistinctSources = db.prepare(`
  SELECT DISTINCT integration_source FROM evidence_vault ORDER BY integration_source
`);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Insert a new evidence record into the vault.
 *
 * @param {Object} params
 * @param {string} params.integration_source - Source system (e.g. 'AWS', 'GitHub').
 * @param {string} params.control_code       - SOC 2 control code (e.g. 'CC6.1').
 * @param {string} [params.control_title]    - Human-readable control title.
 * @param {'PASS'|'FAIL'|'ERROR'} params.status - Check result status.
 * @param {*}      params.raw_json_payload   - Raw evidence payload (will be JSON-stringified).
 * @param {string} [params.scan_run_id]      - Optional scan run identifier.
 * @returns {Object} The full inserted row.
 */
function insertEvidence({
  company_id = 'kanuga_tech',
  integration_source,
  control_code,
  control_title = null,
  status,
  raw_json_payload,
  scan_run_id = null,
}) {
  const id = crypto.randomUUID();
  const created_at = new Date().toISOString();

  // Serialise the payload if it isn't already a string
  const payloadStr =
    typeof raw_json_payload === 'string'
      ? raw_json_payload
      : JSON.stringify(raw_json_payload);

  const sha256_hash = crypto
    .createHash('sha256')
    .update(payloadStr)
    .digest('hex');

  const row = {
    id,
    company_id,
    integration_source,
    control_code,
    control_title,
    status,
    sha256_hash,
    raw_json_payload: payloadStr,
    scan_run_id,
    created_at,
  };

  const allowed = ['PASS', 'FAIL', 'ERROR'];
  if (!allowed.includes(row.status)) row.status = 'ERROR';

  stmtInsert.run(row);

  // Sync to Cloud Firestore if Firebase is active
  firebase.saveEvidenceToFirestore(row).catch((e) => {
    console.warn('[evidence-store] Background cloud sync note:', e.message);
  });

  return row;
}

/**
 * Query evidence records with optional filters.
 *
 * @param {Object}  [opts]
 * @param {number}  [opts.limit=100]            - Max rows to return.
 * @param {number}  [opts.offset=0]             - Offset for pagination.
 * @param {string}  [opts.company_id]           - Filter by tenant company ID.
 * @param {string}  [opts.control_code]         - Filter by control code.
 * @param {string}  [opts.integration_source]   - Filter by source.
 * @param {string}  [opts.status]               - Filter by status.
 * @returns {Array<Object>}
 */
function getEvidence({
  limit = 100,
  offset = 0,
  company_id,
  control_code,
  integration_source,
  status,
} = {}) {
  const conditions = [];
  const params = { limit, offset };

  if (company_id) {
    conditions.push('company_id = @company_id');
    params.company_id = company_id;
  }
  if (control_code) {
    conditions.push('control_code = @control_code');
    params.control_code = control_code;
  }
  if (integration_source) {
    conditions.push('integration_source = @integration_source');
    params.integration_source = integration_source;
  }
  if (status) {
    conditions.push('status = @status');
    params.status = status;
  }

  const whereClause =
    conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  const sql = `
    SELECT * FROM evidence_vault
    ${whereClause}
    ORDER BY created_at DESC
    LIMIT @limit OFFSET @offset
  `;

  params.limit = limit;
  params.offset = offset;

  return db.prepare(sql).all(params);
}

/**
 * Retrieve a single evidence record by ID.
 *
 * @param {string} id
 * @returns {Object|null}
 */
function getEvidenceById(id, company_id) {
  const row = stmtGetById.get(id) || null;
  if (!row) return null;
  if (company_id && row.company_id !== company_id) return null;
  return row;
}

/**
 * Get aggregate statistics about stored evidence.
 *
 * @returns {{ total: number, pass_count: number, fail_count: number, error_count: number, sources: string[], latest_scan_at: string|null }}
 */
function getEvidenceStats(company_id) {
  const where = company_id ? 'WHERE company_id = ?' : '';
  const args = company_id ? [company_id] : [];
  const row = db.prepare(`
    SELECT
      COUNT(*)                                           AS total,
      SUM(CASE WHEN status = 'PASS'  THEN 1 ELSE 0 END) AS pass_count,
      SUM(CASE WHEN status = 'FAIL'  THEN 1 ELSE 0 END) AS fail_count,
      SUM(CASE WHEN status = 'ERROR' THEN 1 ELSE 0 END) AS error_count,
      MAX(created_at)                                    AS latest_scan_at
    FROM evidence_vault
    ${where}
  `).get(...args);
  const sources = db.prepare(`
    SELECT DISTINCT integration_source FROM evidence_vault ${where} ORDER BY integration_source
  `).all(...args).map((r) => r.integration_source);

  return {
    total: row.total,
    pass_count: row.pass_count || 0,
    fail_count: row.fail_count || 0,
    error_count: row.error_count || 0,
    sources,
    latest_scan_at: row.latest_scan_at || null,
    company_id: company_id || null,
  };
}

function upsertControlResult({
  company_id = 'kanuga_tech',
  control_code,
  control_title = null,
  integration_source = null,
  status,
  raw_json_payload = null,
  scan_run_id = null,
}) {
  const payloadStr =
    raw_json_payload == null
      ? null
      : typeof raw_json_payload === 'string'
        ? raw_json_payload
        : JSON.stringify(raw_json_payload);

  db.prepare(`
    INSERT INTO control_results
      (company_id, control_code, control_title, integration_source, status, raw_json_payload, scan_run_id, updated_at)
    VALUES
      (@company_id, @control_code, @control_title, @integration_source, @status, @raw_json_payload, @scan_run_id, @updated_at)
    ON CONFLICT(company_id, control_code) DO UPDATE SET
      control_title = excluded.control_title,
      integration_source = excluded.integration_source,
      status = excluded.status,
      raw_json_payload = excluded.raw_json_payload,
      scan_run_id = excluded.scan_run_id,
      updated_at = excluded.updated_at
  `).run({
    company_id,
    control_code,
    control_title,
    integration_source,
    status,
    raw_json_payload: payloadStr,
    scan_run_id,
    updated_at: new Date().toISOString(),
  });

  firebase.saveControlResultToFirestore({
    company_id,
    control_code,
    control_title,
    integration_source,
    status,
    raw_json_payload: payloadStr,
    scan_run_id,
    updated_at: new Date().toISOString(),
  }).catch((err) => {
    console.warn('[evidence-store] Control result cloud sync note:', err.message);
  });
}

function getControlResults(company_id) {
  return db.prepare(`
    SELECT company_id, control_code, control_title, integration_source, status, raw_json_payload, scan_run_id, updated_at
    FROM control_results
    WHERE company_id = ?
    ORDER BY control_code ASC
  `).all(company_id);
}

/**
 * Delete evidence records older than a given number of days.
 *
 * @param {number} days - Records older than this many days will be deleted.
 * @returns {number} The number of rows deleted.
 */
function deleteEvidenceOlderThan(days) {
  if (typeof days !== 'number' || days <= 0) {
    throw new Error('days must be a positive number');
  }
  const result = stmtDeleteOlderThan.run(days);
  return result.changes;
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
module.exports = {
  insertEvidence,
  getEvidence,
  getEvidenceById,
  getEvidenceStats,
  upsertControlResult,
  getControlResults,
  deleteEvidenceOlderThan,
};

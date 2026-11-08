'use strict';

// lib/firebase.js – Firebase Integration Layer for Kanuga Shield
// ---------------------------------------------------------------
// Manages:
//   1. Cloud Firestore for multi-tenant data, evidence ledger, & control states
//   2. Firebase Auth token verification for protected enterprise API routes
//   3. Firebase Cloud Storage for evidence bundles and auditor artifacts
//   4. Automatic graceful fallback to local SQLite if service account is pending
// ---------------------------------------------------------------
const fs = require('fs');
const path = require('path');
const admin = require('firebase-admin');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const SERVICE_ACCOUNT_FILE = path.join(PROJECT_ROOT, 'firebase-service-account.json');

let isInitialized = false;
let firebaseApp = null;
let firestoreDb = null;
let firebaseAuth = null;
let firebaseStorage = null;
let activeProjectId = null;

function initFirebase() {
  if (isInitialized) return { isConfigured: true, db: firestoreDb, auth: firebaseAuth, storage: firebaseStorage };

  try {
    let credential = null;

    // 1. Look for service account key file in project root
    let targetKeyFile = null;
    if (fs.existsSync(SERVICE_ACCOUNT_FILE)) {
      targetKeyFile = SERVICE_ACCOUNT_FILE;
    } else {
      const candidateFiles = fs.readdirSync(PROJECT_ROOT).filter(f =>
        f.endsWith('.json') &&
        (f.includes('firebase-adminsdk') || f.includes('serviceAccount') || f.includes('service-account'))
      );
      if (candidateFiles.length > 0) {
        targetKeyFile = path.join(PROJECT_ROOT, candidateFiles[0]);
      }
    }

    if (targetKeyFile && fs.existsSync(targetKeyFile)) {
      const fileContent = fs.readFileSync(targetKeyFile, 'utf8');
      const parsed = JSON.parse(fileContent);
      credential = admin.credential.cert(parsed);
      activeProjectId = parsed.project_id;
      console.log(`[firebase] Loaded service account credential from: ${path.basename(targetKeyFile)}`);
    }
    // Cloud Run / Cloud Functions provide Application Default Credentials.
    else if (process.env.K_SERVICE || process.env.FUNCTION_TARGET || process.env.FUNCTION_NAME || process.env.GOOGLE_CLOUD_PROJECT) {
      credential = admin.credential.applicationDefault();
      activeProjectId = process.env.GOOGLE_CLOUD_PROJECT || process.env.GCLOUD_PROJECT || process.env.FIREBASE_PROJECT_ID || 'kanugashield';
      console.log(`[firebase] Using Application Default Credentials (Project: ${activeProjectId})`);
    }
    // 2. Check for inline JSON environment variable
    else if (process.env.FIREBASE_SERVICE_ACCOUNT_KEY) {
      const parsed = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY);
      credential = admin.credential.cert(parsed);
      activeProjectId = parsed.project_id;
    }
    // 3. Check for standard Google Application Credentials
    else if (process.env.GOOGLE_APPLICATION_CREDENTIALS && fs.existsSync(process.env.GOOGLE_APPLICATION_CREDENTIALS)) {
      credential = admin.credential.applicationDefault();
      activeProjectId = process.env.FIREBASE_PROJECT_ID || 'kanuga-shield-cloud';
    }
    // 4. Check for individual env vars
    else if (process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY) {
      credential = admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
      });
      activeProjectId = process.env.FIREBASE_PROJECT_ID;
    }

    if (credential) {
      firebaseApp = admin.initializeApp({
        credential,
        projectId: activeProjectId || undefined,
        storageBucket: process.env.FIREBASE_STORAGE_BUCKET || `${activeProjectId}.appspot.com`,
      });
      firestoreDb = firebaseApp.firestore();
      firebaseAuth = firebaseApp.auth();
      firebaseStorage = firebaseApp.storage();
      isInitialized = true;
      console.log(`[firebase] Connected to Google Cloud Firestore & Firebase Auth (Project: ${activeProjectId})`);
      return { isConfigured: true, db: firestoreDb, auth: firebaseAuth, storage: firebaseStorage };
    }
  } catch (err) {
    console.warn(`[firebase] Initialization notice: ${err.message}. Operating in Local-Hybrid mode.`);
  }

  return { isConfigured: false, db: null, auth: null, storage: null };
}

// Initialise on load
initFirebase();

/**
 * Returns current Firebase status for UI and diagnostic health checks.
 */
function getFirebaseStatus() {
  return {
    configured: isInitialized,
    projectId: activeProjectId,
    mode: isInitialized ? 'CLOUD_FIRESTORE' : 'LOCAL_HYBRID',
    storageBucket: isInitialized ? (process.env.FIREBASE_STORAGE_BUCKET || `${activeProjectId}.appspot.com`) : null,
    instruction: isInitialized
      ? 'Firebase Cloud Firestore and Auth are active.'
      : 'To link your live Firebase cloud, place your `firebase-service-account.json` into the project root directory or set FIREBASE_SERVICE_ACCOUNT_KEY in .env.',
  };
}

/**
 * Persists an evaluation record to Firestore under the 'evidence_vault' collection.
 */
async function saveEvidenceToFirestore(record) {
  if (!isInitialized || !firestoreDb) return false;
  try {
    const docRef = firestoreDb.collection('evidence_vault').doc(record.id);
    await docRef.set({
      id: record.id,
      company_id: record.company_id || 'kanuga_tech_default',
      integration_source: record.integration_source,
      control_code: record.control_code,
      control_title: record.control_title || '',
      status: record.status,
      sha256_hash: record.sha256_hash,
      raw_json_payload: typeof record.raw_json_payload === 'string'
        ? record.raw_json_payload
        : JSON.stringify(record.raw_json_payload),
      scan_run_id: record.scan_run_id || '',
      created_at: record.created_at || new Date().toISOString(),
      synced_to_cloud_at: new Date().toISOString(),
    });
    return true;
  } catch (err) {
    console.error('[firebase] Error saving evidence to Firestore:', err.message);
    return false;
  }
}

/**
 * Queries evidence records from Firestore with optional filtering.
 */
async function getEvidenceFromFirestore({ limit = 50, company_id, control_code, integration_source, status } = {}) {
  if (!isInitialized || !firestoreDb) return null;
  try {
    let query = firestoreDb.collection('evidence_vault');
    if (company_id) query = query.where('company_id', '==', company_id);

    const snapshot = await query.limit(Math.max(limit, 50) * 4).get();
    let results = [];
    snapshot.forEach((doc) => results.push(doc.data()));

    if (control_code) results = results.filter((row) => row.control_code === control_code);
    if (integration_source) results = results.filter((row) => row.integration_source === integration_source);
    if (status) results = results.filter((row) => row.status === status);

    results.sort((a, b) => String(b.created_at || '').localeCompare(String(a.created_at || '')));
    return results.slice(0, limit);
  } catch (err) {
    console.error('[firebase] Error querying evidence from Firestore:', err.message);
    return null;
  }
}

/**
 * Verifies a Firebase ID token from client requests (for authentication middleware).
 */
async function verifyIdToken(token) {
  if (!isInitialized || !firebaseAuth) {
    return null;
  }

  try {
    const decoded = await firebaseAuth.verifyIdToken(token);
    return decoded;
  } catch (err) {
    console.error('[firebase] ID token verification failed:', err.message);
    return null;
  }
}

async function saveControlResultToFirestore(row) {
  if (!isInitialized || !firestoreDb || !row) return false;
  try {
    const id = `${row.company_id || 'kanuga_tech'}_${row.control_code}`;
    await firestoreDb.collection('control_results').doc(id).set({
      ...row,
      raw_json_payload: typeof row.raw_json_payload === 'string'
        ? row.raw_json_payload
        : JSON.stringify(row.raw_json_payload || null),
      updated_at: row.updated_at || new Date().toISOString(),
    }, { merge: true });
    return true;
  } catch (err) {
    console.error('[firebase] Error saving control result:', err.message);
    return false;
  }
}

async function getControlResultsFromFirestore(companyId) {
  if (!isInitialized || !firestoreDb || !companyId) return null;
  try {
    const snap = await firestoreDb.collection('control_results').where('company_id', '==', companyId).get();
    const rows = [];
    snap.forEach((doc) => rows.push(doc.data()));
    rows.sort((a, b) => String(a.control_code).localeCompare(String(b.control_code)));
    return rows;
  } catch (err) {
    console.error('[firebase] Error reading control results:', err.message);
    return null;
  }
}

module.exports = {
  initFirebase,
  getFirebaseStatus,
  saveEvidenceToFirestore,
  getEvidenceFromFirestore,
  saveControlResultToFirestore,
  getControlResultsFromFirestore,
  verifyIdToken,
  getApp: () => firebaseApp,
  getDb: () => firestoreDb,
  getAuth: () => firebaseAuth,
  getStorage: () => firebaseStorage,
};

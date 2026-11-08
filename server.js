'use strict';

// server.js – Express API for Kanuga Shield integration & control evaluation
// ---------------------------------------------------------------
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const tls = require('tls');
const path = require('path');
const cookieParser = require('cookie-parser');

// AWS SDK v3 clients
const { STSClient, AssumeRoleCommand } = require('@aws-sdk/client-sts');

// Helper to dynamically load ESM Octokit in CommonJS
let _Octokit = null;
async function getOctokitClass() {
  if (!_Octokit) {
    const mod = await import('@octokit/rest');
    _Octokit = mod.Octokit;
  }
  return _Octokit;
}

// Kanuga Shield lib modules
const credentialVault = require('./lib/credential-vault');
const evidenceStore = require('./lib/evidence-store');
const awsScanner = require('./lib/aws-scanner');
const githubScanner = require('./lib/github-scanner');
const oktaScanner = require('./lib/okta-scanner');
const gcpScanner = require('./lib/gcp-scanner');
const firebase = require('./lib/firebase');
const auth = require('./lib/auth');
const scanEngine = require('./lib/scan-engine');
const jobQueue = require('./lib/job-queue');
const workerRuntime = require('./lib/worker-runtime');
const complianceRules = require('./lib/compliance-rules');
const kms = require('./lib/kms');

// ---------------------------------------------------------------
// Express app setup
// ---------------------------------------------------------------
const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(auth.authMiddleware);

// Serve static front-end assets from ./public
app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------
// AUTHENTICATION & MULTI-TENANCY ROUTES (/api/auth)
// ---------------------------------------------------------------

/**
 * POST /api/auth/register
 * Body: { companyName, email, password, name?, activationKey }
 */
app.post('/api/auth/register', async (req, res, next) => {
  try {
    const { companyName, email, password, name, activationKey } = req.body;
    const result = await auth.registerTenant({ companyName, email, password, name, activationKey });
    setSessionCookie(res, result.token);
    return res.status(201).json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/**
 * POST /api/auth/request-activation
 * Public endpoint: Prospective applicant submits company details to request a key.
 * Dispatches an automated notification email to founder Francis M. Kanuga (francism.kanuga@gmail.com).
 */
app.post('/api/auth/request-activation', async (req, res, next) => {
  try {
    const { companyName, email, contactName, notes } = req.body;
    const result = await auth.createActivationRequest({ companyName, email, contactName, notes });
    return res.status(201).json({
      ok: true,
      request: result.request,
      message: 'Activation request received. Founder Francis M. Kanuga has been notified and will email your key upon verification.',
      mailStatus: result.mailResult ? result.mailResult.status : 'QUEUED',
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/**
 * POST /api/auth/login
 * Body: { email, password }
 */
app.post('/api/auth/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const result = await auth.loginTenant({ email, password });
    setSessionCookie(res, result.token);
    return res.json(result);
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

/**
 * GET /api/auth/me
 * Returns currently authenticated user and active company profile.
 */
app.get('/api/auth/me', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthenticated' });
  }
  const company = auth.getCompanyById(req.company_id);
  const isSuperAdmin = req.user.role === 'SUPER_ADMIN' || req.user.email.toLowerCase() === auth.FOUNDER_EMAIL.toLowerCase();

  return res.json({
    user: {
      ...req.user,
      isSuperAdmin,
    },
    company: company || { id: req.company_id, name: req.user.company_name || 'Kanuga_tech' },
  });
});

/**
 * POST /api/auth/logout
 * Clears the session cookie.
 */
app.post('/api/auth/logout', (_req, res) => {
  res.clearCookie('ks_auth_token', { path: '/' });
  return res.json({ status: 'LOGGED_OUT' });
});

// ---------------------------------------------------------------
// FOUNDER & SUPER ADMIN LICENSING / ACTIVATION MANAGEMENT ROUTES
// ---------------------------------------------------------------

/**
 * GET /api/admin/activation-requests
 * Restricted to Founder & Super Admin.
 */
app.get('/api/admin/activation-requests', auth.requireSuperAdmin, async (req, res) => {
  const requests = await auth.listActivationRequests();
  return res.json({ requests });
});

/**
 * GET /api/admin/activation-keys
 * Restricted to Founder & Super Admin.
 */
app.get('/api/admin/activation-keys', auth.requireSuperAdmin, async (req, res) => {
  const keys = await auth.listActivationKeys();
  return res.json({ keys });
});

/**
 * POST /api/admin/activation-keys/generate
 * Restricted to Founder & Super Admin. Mints a key and emails it to the applicant.
 * Body: { requestId?, assignedToEmail?, assignedToCompany?, plan? }
 */
app.post('/api/admin/activation-keys/generate', auth.requireSuperAdmin, async (req, res) => {
  try {
    const { requestId, assignedToEmail, assignedToCompany, plan } = req.body;
    const result = await auth.generateActivationKey({
      requestId,
      assignedToEmail,
      assignedToCompany,
      createdBy: req.user.email,
      plan: plan || 'ENTERPRISE',
    });
    return res.status(201).json({
      ok: true,
      key: result.key,
      mailResult: result.mailResult,
      message: `Activation key ${result.key.key_code} successfully generated and emailed.`,
    });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

/**
 * POST /api/admin/activation-keys/:id/revoke
 * Restricted to Founder & Super Admin. Revokes an active key.
 */
app.post('/api/admin/activation-keys/:id/revoke', auth.requireSuperAdmin, (req, res) => {
  try {
    const revoked = auth.revokeActivationKey(req.params.id);
    return res.json({ ok: true, key: revoked });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

/**
 * GET /api/admin/mail-outbox
 * Restricted to Founder & Super Admin. Lists dispatched email history.
 */
app.get('/api/admin/mail-outbox', auth.requireSuperAdmin, (req, res) => {
  const mailer = require('./lib/mailer');
  return res.json({ outbox: mailer.getOutbox() });
});

// ---------------------------------------------------------------
// Utility – session cookie and UUID
// ---------------------------------------------------------------
function setSessionCookie(res, token) {
  res.cookie('ks_auth_token', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 3600 * 1000,
    path: '/',
  });
}

function uuidv4() {
  return crypto.randomUUID();
}

// ---------------------------------------------------------------
// POST /api/integrations/aws/connect
// Body: { roleArn, externalId, region? }
// ---------------------------------------------------------------
app.post('/api/integrations/aws/connect', async (req, res, next) => {
  try {
    const { roleArn, externalId, region } = req.body;
    const companyId = req.company_id;

    if (!roleArn || !externalId) {
      return res.status(400).json({ error: 'roleArn and externalId are required' });
    }

    const effectiveRegion = region || 'us-east-1';

    // Assume the role via STS
    const sts = new STSClient({ region: effectiveRegion });
    const cmd = new AssumeRoleCommand({
      RoleArn: roleArn,
      RoleSessionName: 'KanugaShieldSession',
      ExternalId: externalId,
      DurationSeconds: 3600,
    });
    const resp = await sts.send(cmd);
    const cred = resp.Credentials;

    // Persist credentials securely scoped to the tenant
    await credentialVault.saveCredential('aws', 'AWS', {
      accessKeyId: cred.AccessKeyId,
      secretAccessKey: cred.SecretAccessKey,
      sessionToken: cred.SessionToken,
      roleArn,
      externalId,
      region: effectiveRegion,
    }, companyId);

    return res.json({ status: 'CONNECTED', provider: 'AWS', company_id: companyId });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------
// POST /api/integrations/github/connect
// Body: { token, org? }
// ---------------------------------------------------------------
app.post('/api/integrations/github/connect', async (req, res, next) => {
  try {
    const { token, org } = req.body;
    const companyId = req.company_id;

    if (!token) {
      return res.status(400).json({ error: 'GitHub token is required' });
    }

    const Octokit = await getOctokitClass();
    const octokit = new Octokit({ auth: token });
    const { data: user } = await octokit.request('GET /user');

    await credentialVault.saveCredential('github', 'GitHub', {
      token,
      org: org || user.login,
    }, companyId);

    return res.json({ status: 'CONNECTED', provider: 'GitHub', login: user.login, company_id: companyId });
  } catch (err) {
    if (err.status === 401) {
      return res.status(401).json({ error: 'Invalid GitHub token' });
    }
    next(err);
  }
});

// ---------------------------------------------------------------
// POST /api/integrations/okta/connect
// Body: { orgUrl, apiToken }
// ---------------------------------------------------------------
app.post('/api/integrations/okta/connect', async (req, res, next) => {
  try {
    const { orgUrl, apiToken } = req.body;
    const companyId = req.company_id;
    if (!apiToken) {
      return res.status(400).json({ error: 'Okta apiToken is required' });
    }

    const domain = orgUrl || 'kanuga.okta.com';
    await credentialVault.saveCredential('okta', 'Okta', {
      orgUrl: domain,
      apiToken,
    }, companyId);

    return res.json({ status: 'CONNECTED', provider: 'Okta', domain, company_id: companyId });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------
// POST /api/integrations/gcp/connect
// Body: { projectId, clientEmail?, privateKey?, accessToken? }
// ---------------------------------------------------------------
app.post('/api/integrations/gcp/connect', async (req, res, next) => {
  try {
    const { projectId, clientEmail, privateKey, accessToken } = req.body;
    const companyId = req.company_id;
    if (!projectId) {
      return res.status(400).json({ error: 'GCP projectId is required' });
    }

    await credentialVault.saveCredential('gcp', 'Google Cloud', {
      projectId,
      clientEmail,
      privateKey,
      accessToken,
    }, companyId);

    return res.json({ status: 'CONNECTED', provider: 'Google Cloud', projectId, company_id: companyId });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------
// DELETE /api/integrations/:id
// Removes the credential with tenant scoping.
// ---------------------------------------------------------------
app.delete('/api/integrations/:id', async (req, res, next) => {
  try {
    const { id } = req.params;
    const companyId = req.company_id;
    await credentialVault.deleteCredential(id, companyId);
    return res.json({ status: 'DISCONNECTED', id, company_id: companyId });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------
// GET /api/integrations
// Lists stored credentials for the active tenant.
// ---------------------------------------------------------------
app.get('/api/integrations', async (req, res, next) => {
  try {
    const companyId = req.company_id;
    const list = await credentialVault.listCredentials(companyId);
    return res.json(list);
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------
// GET /api/controls/evaluate
// Runs live security checks against all connected integrations,
// stores every result as tamper-evident evidence, and returns a
// summary to the caller.
// ---------------------------------------------------------------
app.get('/api/controls/evaluate', async (req, res, next) => {
  try {
    const companyId = req.company_id;
    const [awsCreds, githubCreds, oktaCreds, gcpCreds] = await Promise.all([
      credentialVault.getCredential('aws', companyId),
      credentialVault.getCredential('github', companyId),
      credentialVault.getCredential('okta', companyId),
      credentialVault.getCredential('gcp', companyId),
    ]);

    if (!awsCreds && !githubCreds && !oktaCreds && !gcpCreds) {
      return res.status(400).json({ error: 'No integrations connected' });
    }

    const scanPromises = [];

    if (awsCreds) {
      scanPromises.push(
        awsScanner.runAllAwsChecks(awsCreds, awsCreds.region || 'us-east-1')
      );
    }
    if (githubCreds) {
      scanPromises.push(
        githubScanner.runAllGithubChecks({ token: githubCreds.token, org: githubCreds.org })
      );
    }
    if (oktaCreds) {
      scanPromises.push(
        oktaScanner.runAllOktaChecks(oktaCreds)
      );
    }
    if (gcpCreds) {
      scanPromises.push(
        gcpScanner.runAllGcpChecks(gcpCreds)
      );
    }

    // Run all scanner modules in parallel then flatten into a single array
    const scanResults = (await Promise.all(scanPromises)).flat();

    // Shared scan_run_id ties every evidence row from this evaluation together
    const scanRunId = uuidv4();

    // Persist each result as evidence
    await Promise.all(
      scanResults.map((r) =>
        evidenceStore.insertEvidence({
          company_id: companyId,
          integration_source: r.integration_source,
          control_code: r.control_code,
          control_title: r.control_title,
          status: r.status,
          raw_json_payload: r.raw_evidence,
          scan_run_id: scanRunId,
        })
      )
    );

    for (const r of scanResults) {
      if (!r.control_code || !['PASS', 'FAIL', 'ERROR'].includes(r.status)) continue;
      evidenceStore.upsertControlResult({
        company_id: companyId,
        control_code: r.control_code,
        control_title: r.control_title,
        integration_source: r.integration_source,
        status: r.status,
        raw_json_payload: r.raw_evidence,
        scan_run_id: scanRunId,
      });
    }

    return res.json({
      evaluatedAt: new Date().toISOString(),
      scan_run_id: scanRunId,
      company_id: companyId,
      results: scanResults,
    });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------
// GET /api/controls
// Latest control results recorded for the signed-in company.
// ---------------------------------------------------------------
app.get('/api/controls', (req, res, next) => {
  try {
    return res.json(evidenceStore.getControlResults(req.company_id));
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------
// GET /api/evidence/vault
// Query params: limit, offset, control_code, integration_source,
//               status
// Returns matching evidence rows plus aggregate stats.
// ---------------------------------------------------------------
app.get('/api/evidence/vault', async (req, res, next) => {
  try {
    const companyId = req.company_id;
    const { limit, offset, control_code, integration_source, status } = req.query;

    // Check Cloud Firestore first when active
    const firestoreRecords = await firebase.getEvidenceFromFirestore({
      limit: limit ? parseInt(limit, 10) : 50,
      company_id: companyId,
      control_code,
      integration_source,
      status,
    });

    if (firestoreRecords && firestoreRecords.length > 0) {
      const stats = await evidenceStore.getEvidenceStats(companyId);
      return res.json({
        evidence: firestoreRecords,
        stats: {
          ...stats,
          total: firestoreRecords.length,
          storage_mode: 'CLOUD_FIRESTORE',
          cloud_project: 'kanugashield',
          company_id: companyId,
        },
      });
    }

    const [evidence, stats] = await Promise.all([
      evidenceStore.getEvidence({
        limit: limit ? parseInt(limit, 10) : undefined,
        offset: offset ? parseInt(offset, 10) : undefined,
        company_id: companyId,
        control_code,
        integration_source,
        status,
      }),
      evidenceStore.getEvidenceStats(companyId),
    ]);

    return res.json({ evidence, stats });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------
// GET /api/evidence/vault/:id
// Returns a single evidence row by its primary key.
// ---------------------------------------------------------------
app.get('/api/evidence/vault/:id', async (req, res, next) => {
  try {
    const row = await evidenceStore.getEvidenceById(req.params.id, req.company_id);
    if (!row) {
      return res.status(404).json({ error: 'Evidence not found' });
    }
    return res.json(row);
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------
// GET /api/evidence/stats
// Returns aggregate statistics about the evidence store.
// ---------------------------------------------------------------
app.get('/api/evidence/stats', async (req, res, next) => {
  try {
    const stats = await evidenceStore.getEvidenceStats(req.company_id);
    return res.json(stats);
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------
// GET /api/scan/live
// Performs a real TLS handshake against a target host and returns
// certificate details – useful for ad-hoc security reconnaissance.
// Query params: host (required), port (default 443)
// ---------------------------------------------------------------
app.get('/api/scan/live', async (req, res, next) => {
  try {
    const { host, port } = req.query;

    if (!host) {
      return res.status(400).json({ error: 'host query parameter is required' });
    }

    const targetPort = parseInt(port, 10) || 443;

    const certInfo = await new Promise((resolve, reject) => {
      const socket = tls.connect(targetPort, host, { servername: host }, () => {
        const cert = socket.getPeerCertificate();
        socket.end();

        if (!cert || !cert.subject) {
          return reject(new Error('No certificate returned'));
        }

        resolve({
          subject: cert.subject,
          issuer: cert.issuer,
          valid_from: cert.valid_from,
          valid_to: cert.valid_to,
          serialNumber: cert.serialNumber,
          fingerprint256: cert.fingerprint256,
        });
      });

      socket.setTimeout(10000, () => {
        socket.destroy();
        reject(new Error('TLS connection timed out'));
      });

      socket.on('error', reject);
    });

    return res.json({
      host,
      port: targetPort,
      scannedAt: new Date().toISOString(),
      certificate: certInfo,
    });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------
// POST /api/auditor-link
// Generates a shareable read-only link for an external auditor.
// Body: { auditorEmail, expiresInHours? }
// ---------------------------------------------------------------
app.post('/api/auditor-link', async (req, res, next) => {
  try {
    const { auditorEmail, expiresInHours } = req.body;

    if (!auditorEmail) {
      return res.status(400).json({ error: 'auditorEmail is required' });
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(
      Date.now() + (expiresInHours || 72) * 60 * 60 * 1000
    ).toISOString();

    // In a production system this token would be persisted and validated
    // on a dedicated /auditor-view route.
    return res.json({
      auditorEmail,
      company_id: req.company_id,
      token,
      expiresAt,
      link: `${req.protocol}://${req.get('host')}/auditor-view?token=${token}`,
    });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------
// GET /api/firebase/status
// Returns the status of the Firebase Cloud integration (Firestore,
// Auth, and Storage) or local hybrid fallback information.
// ---------------------------------------------------------------
app.get('/api/firebase/status', (_req, res) => {
  const status = firebase.getFirebaseStatus();
  return res.json(status);
});

// ---------------------------------------------------------------
// Global error-handling middleware
// ---------------------------------------------------------------
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err);
  const statusCode = err.statusCode || err.status || 500;
  res.status(statusCode).json({
    error: err.message || 'Internal server error',
  });
});

// ---------------------------------------------------------------
// Start the server (standalone) or export for Cloud Functions
// ---------------------------------------------------------------
const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Kanuga Shield API listening on port ${PORT}`);
  });
}

// Export for Firebase Cloud Functions (v2)
let api;
try {
  const { onRequest } = require('firebase-functions/v2/https');
  api = onRequest({ cors: true, region: 'us-central1' }, app);
} catch (e) {
  // Graceful fallback if firebase-functions is not present
}

module.exports = app;
if (api) {
  module.exports.api = api;
}

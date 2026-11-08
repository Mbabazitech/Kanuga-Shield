'use strict';

// cron-worker.js – Kanuga Shield background scanner
// ---------------------------------------------------------------
// Runs security checks on a cron schedule against all connected
// integrations and persists the results as evidence.
// ---------------------------------------------------------------
require('dotenv').config();

const cron = require('node-cron');
const crypto = require('crypto');

// Kanuga Shield lib modules
const auth = require('./lib/auth');
const credentialVault = require('./lib/credential-vault');
const evidenceStore = require('./lib/evidence-store');
const awsScanner = require('./lib/aws-scanner');
const githubScanner = require('./lib/github-scanner');
const oktaScanner = require('./lib/okta-scanner');
const gcpScanner = require('./lib/gcp-scanner');

// ---------------------------------------------------------------
// Utility – generate a UUID v4
// ---------------------------------------------------------------
function uuidv4() {
  return crypto.randomUUID();
}

// ---------------------------------------------------------------
// Core scan job – loads credentials, runs every scanner that has
// valid credentials, and persists all results to the evidence store.
// ---------------------------------------------------------------
async function runScanJob(companyId) {
  const startedAt = new Date();
  console.log(`[cron-worker] Scan started for ${companyId} at ${startedAt.toISOString()}`);

  try {
    const [awsCreds, githubCreds, oktaCreds, gcpCreds] = await Promise.all([
      credentialVault.getCredential('aws', companyId),
      credentialVault.getCredential('github', companyId),
      credentialVault.getCredential('okta', companyId),
      credentialVault.getCredential('gcp', companyId),
    ]);

    if (!awsCreds && !githubCreds && !oktaCreds && !gcpCreds) {
      console.log(`[cron-worker] No integrations connected for ${companyId} – skipping scan.`);
      return;
    }

    const scanPromises = [];

    if (awsCreds) {
      console.log('[cron-worker] Running AWS checks…');
      scanPromises.push(
        awsScanner.runAllAwsChecks(awsCreds, awsCreds.region || 'us-east-1')
      );
    }

    if (githubCreds) {
      console.log('[cron-worker] Running GitHub checks…');
      scanPromises.push(
        githubScanner.runAllGithubChecks({ token: githubCreds.token, org: githubCreds.org })
      );
    }

    if (oktaCreds) {
      console.log('[cron-worker] Running Okta checks…');
      scanPromises.push(
        oktaScanner.runAllOktaChecks(oktaCreds)
      );
    }

    if (gcpCreds) {
      console.log('[cron-worker] Running Google Cloud checks…');
      scanPromises.push(
        gcpScanner.runAllGcpChecks(gcpCreds)
      );
    }

    // Run all scanner modules in parallel then flatten results
    const scanResults = (await Promise.all(scanPromises)).flat();

    // Shared scan_run_id ties every evidence row from this run together
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

    // Summary statistics
    const passCount = scanResults.filter((r) => r.status === 'PASS').length;
    const failCount = scanResults.filter((r) => r.status === 'FAIL').length;

    console.log(
      `[cron-worker] Cron scan complete for ${companyId}: ${scanResults.length} checks evaluated, ${passCount} PASS, ${failCount} FAIL (scan_run_id: ${scanRunId})`
    );
  } catch (err) {
    console.error('[cron-worker] Scan job failed:', err);
  }
}

async function runAllTenantScans() {
  const fromAuth = auth.listCompanies().map((company) => company.id);
  const fromVault = credentialVault.listTenantIds();
  const companyIds = [...new Set([...fromAuth, ...fromVault])];
  for (const companyId of companyIds) {
    await runScanJob(companyId);
  }
}

// ---------------------------------------------------------------
// Schedule: run every hour at the top of the hour
// ---------------------------------------------------------------
const task = cron.schedule('0 * * * *', () => {
  runAllTenantScans();
}, {
  scheduled: true,
});

console.log('[cron-worker] Scheduled hourly scan (0 * * * *)');

// Run once immediately on startup so results are available right away
runAllTenantScans();

// ---------------------------------------------------------------
// Graceful shutdown handling
// ---------------------------------------------------------------
function shutdown(signal) {
  console.log(`[cron-worker] Received ${signal} – shutting down gracefully…`);
  task.stop();
  console.log('[cron-worker] Cron task stopped. Exiting.');
  process.exit(0);
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

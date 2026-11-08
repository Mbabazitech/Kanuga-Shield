'use strict';

// Runs the control engine for one company and writes SHA-256 evidence.

const crypto = require('crypto');
const auth = require('./auth');
const credentialVault = require('./credential-vault');
const evidenceStore = require('./evidence-store');
const awsScanner = require('./aws-scanner');
const githubScanner = require('./github-scanner');
const oktaScanner = require('./okta-scanner');
const gcpScanner = require('./gcp-scanner');
const { annotateResult } = require('./compliance-rules');

async function runCompanyScan(companyId) {
  const [awsCreds, githubCreds, oktaCreds, gcpCreds] = await Promise.all([
    credentialVault.getCredential('aws', companyId),
    credentialVault.getCredential('github', companyId),
    credentialVault.getCredential('okta', companyId),
    credentialVault.getCredential('gcp', companyId),
  ]);

  if (!awsCreds && !githubCreds && !oktaCreds && !gcpCreds) {
    return {
      evaluatedAt: new Date().toISOString(),
      company_id: companyId,
      results: [],
      skipped: true,
      reason: 'No integrations connected',
    };
  }

  const scanPromises = [];
  if (awsCreds) {
    scanPromises.push(awsScanner.runAllAwsChecks(awsCreds, awsCreds.region || 'us-east-1'));
  }
  if (githubCreds) {
    scanPromises.push(githubScanner.runAllGithubChecks({ token: githubCreds.token, org: githubCreds.org }));
  }
  if (oktaCreds) {
    scanPromises.push(oktaScanner.runAllOktaChecks(oktaCreds));
  }
  if (gcpCreds) {
    scanPromises.push(gcpScanner.runAllGcpChecks(gcpCreds));
  }

  const scanResults = (await Promise.all(scanPromises)).flat().map(annotateResult);
  const scanRunId = crypto.randomUUID();

  await Promise.all(scanResults.map((result) => evidenceStore.insertEvidence({
    company_id: companyId,
    integration_source: result.integration_source,
    control_code: result.control_code,
    control_title: result.control_title,
    status: result.status,
    raw_json_payload: result.raw_evidence,
    scan_run_id: scanRunId,
  })));

  for (const result of scanResults) {
    if (!result.control_code) continue;
    evidenceStore.upsertControlResult({
      company_id: companyId,
      control_code: result.control_code,
      control_title: result.control_title,
      integration_source: result.integration_source,
      status: result.status,
      raw_json_payload: result.raw_evidence,
      scan_run_id: scanRunId,
    });
  }

  const passCount = scanResults.filter((result) => result.status === 'PASS').length;
  const failCount = scanResults.filter((result) => result.status === 'FAIL').length;

  return {
    evaluatedAt: new Date().toISOString(),
    scan_run_id: scanRunId,
    company_id: companyId,
    passCount,
    failCount,
    results: scanResults,
  };
}

function listCompanyIds() {
  const fromAuth = auth.listCompanies().map((company) => company.id);
  const fromVault = credentialVault.listTenantIds();
  return [...new Set([...fromAuth, ...fromVault])];
}

module.exports = {
  runCompanyScan,
  listCompanyIds,
};

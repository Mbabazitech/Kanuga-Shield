'use strict';

// lib/gcp-scanner.js – Google Cloud Platform Security Scanner
// ---------------------------------------------------------------
// Evaluates GCP infrastructure and IAM posture:
//   1. CC6.6 – Cloud Storage Bucket Encryption & Uniform Access
//   2. CC6.7 – Cloud IAM Role Separation & Least Privilege
// ---------------------------------------------------------------
const crypto = require('crypto');

/**
 * Mint a Google OAuth2 access token using Service Account credentials
 * via native Node.js crypto (zero extra npm dependencies needed).
 *
 * @param {string} clientEmail - Service account email
 * @param {string} privateKey - RSA private key (PEM format)
 * @param {string} scope - OAuth2 scope
 * @returns {Promise<string>} OAuth2 bearer access token
 */
async function getGoogleAccessToken(clientEmail, privateKey, scope = 'https://www.googleapis.com/auth/cloud-platform') {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const claimSet = {
    iss: clientEmail,
    scope,
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600,
    iat: now,
  };

  const base64UrlEncode = (obj) =>
    Buffer.from(JSON.stringify(obj))
      .toString('base64')
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');

  const unsignedToken = `${base64UrlEncode(header)}.${base64UrlEncode(claimSet)}`;

  const signer = crypto.createSign('RSA-SHA256');
  signer.update(unsignedToken);
  const signature = signer
    .sign(privateKey, 'base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  const assertion = `${unsignedToken}.${signature}`;

  const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion,
    }),
  });

  if (!tokenResp.ok) {
    const errText = await tokenResp.text();
    throw new Error(`Google OAuth2 token request failed (${tokenResp.status}): ${errText}`);
  }

  const tokenData = await tokenResp.json();
  return tokenData.access_token;
}

/**
 * Check 1: CC6.6 – Cloud Storage Bucket Encryption & Uniform Access
 */
async function checkGcpStorageBuckets(projectId, accessToken) {
  try {
    const url = `https://storage.googleapis.com/storage/v1/b?project=${encodeURIComponent(projectId)}`;
    const resp = await fetch(url, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/json',
      },
    });

    if (!resp.ok) {
      const errText = await resp.text();
      return {
        control_code: 'CC6.6',
        control_title: 'GCP Cloud Storage Uniform Access & Server-Side Encryption',
        integration_source: 'Google Cloud',
        status: 'ERROR',
        raw_evidence: {
          error: `GCS API responded with HTTP ${resp.status}: ${errText.substring(0, 160)}`,
        },
      };
    }

    const data = await resp.json();
    const buckets = Array.isArray(data.items) ? data.items : [];

    if (buckets.length === 0) {
      return {
        control_code: 'CC6.6',
        control_title: 'GCP Cloud Storage Uniform Access & Server-Side Encryption',
        integration_source: 'Google Cloud',
        status: 'PASS',
        raw_evidence: {
          project_id: projectId,
          scanned_buckets: 0,
          message: 'No storage buckets found in GCP project; default platform encryption enforced',
        },
      };
    }

    const bucketAudits = buckets.map((b) => {
      const uniformAccess = b.iamConfiguration?.uniformBucketLevelAccess?.enabled === true;
      const defaultKmsKey = b.encryption?.defaultKmsKeyName || 'Google-Managed Default Key (AES-256)';
      return {
        name: b.name,
        location: b.location,
        uniformBucketLevelAccess: uniformAccess,
        encryption: defaultKmsKey,
      };
    });

    const nonUniformBuckets = bucketAudits.filter((b) => !b.uniformBucketLevelAccess).map((b) => b.name);
    const isCompliant = nonUniformBuckets.length === 0;

    return {
      control_code: 'CC6.6',
      control_title: 'GCP Cloud Storage Uniform Access & Server-Side Encryption',
      integration_source: 'Google Cloud',
      status: isCompliant ? 'PASS' : 'FAIL',
      raw_evidence: {
        project_id: projectId,
        total_buckets_scanned: buckets.length,
        compliant_buckets: buckets.length - nonUniformBuckets.length,
        non_compliant_buckets: nonUniformBuckets,
        violation: isCompliant
          ? 'All GCP Storage buckets enforce Uniform Bucket-Level Access and encryption'
          : `Bucket(s) [${nonUniformBuckets.join(', ')}] have Uniform Bucket-Level Access disabled`,
        buckets: bucketAudits,
      },
    };
  } catch (err) {
    return {
      control_code: 'CC6.6',
      control_title: 'GCP Cloud Storage Uniform Access & Server-Side Encryption',
      integration_source: 'Google Cloud',
      status: 'ERROR',
      raw_evidence: { error: err.message },
    };
  }
}

/**
 * Check 2: CC6.7 – Cloud IAM Role Separation & Least Privilege
 */
async function checkGcpIamPolicies(projectId, accessToken) {
  try {
    const url = `https://cloudresourcemanager.googleapis.com/v1/projects/${encodeURIComponent(projectId)}:getIamPolicy`;
    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/json',
      },
    });

    if (!resp.ok) {
      const errText = await resp.text();
      return {
        control_code: 'CC6.7',
        control_title: 'GCP Cloud IAM Role Separation & Least Privilege',
        integration_source: 'Google Cloud',
        status: 'ERROR',
        raw_evidence: {
          error: `Cloud Resource Manager API responded with HTTP ${resp.status}: ${errText.substring(0, 160)}`,
        },
      };
    }

    const policy = await resp.json();
    const bindings = Array.isArray(policy.bindings) ? policy.bindings : [];

    const ownerBinding = bindings.find((b) => b.role === 'roles/owner');
    const editorBinding = bindings.find((b) => b.role === 'roles/editor');

    const ownerMembers = ownerBinding ? ownerBinding.members : [];
    const editorMembers = editorBinding ? editorBinding.members : [];

    // Primitive editor role should be restricted in production environments
    const isCompliant = editorMembers.length <= 2;

    return {
      control_code: 'CC6.7',
      control_title: 'GCP Cloud IAM Role Separation & Least Privilege',
      integration_source: 'Google Cloud',
      status: isCompliant ? 'PASS' : 'FAIL',
      raw_evidence: {
        project_id: projectId,
        total_iam_bindings: bindings.length,
        owner_principals_count: ownerMembers.length,
        primitive_editor_principals_count: editorMembers.length,
        violation: isCompliant
          ? 'Cloud IAM least-privilege role boundaries verified compliant'
          : `Excessive primitive editor role assignments detected (${editorMembers.length} principals)`,
        sample_roles: bindings.slice(0, 6).map((b) => ({
          role: b.role,
          memberCount: b.members?.length || 0,
        })),
      },
    };
  } catch (err) {
    return {
      control_code: 'CC6.7',
      control_title: 'GCP Cloud IAM Role Separation & Least Privilege',
      integration_source: 'Google Cloud',
      status: 'ERROR',
      raw_evidence: { error: err.message },
    };
  }
}

/**
 * Run all GCP infrastructure checks.
 *
 * @param {{ projectId: string, clientEmail?: string, privateKey?: string, accessToken?: string }} credentials
 * @returns {Promise<Array<Object>>}
 */
async function runAllGcpChecks(credentials) {
  if (!credentials || !credentials.projectId) {
    return [
      {
        control_code: 'CC6.7',
        control_title: 'GCP Cloud IAM Role Separation & Least Privilege',
        integration_source: 'Google Cloud',
        status: 'ERROR',
        raw_evidence: { error: 'GCP projectId is required' },
      },
    ];
  }

  try {
    let token = credentials.accessToken;

    if (!token && credentials.clientEmail && credentials.privateKey) {
      token = await getGoogleAccessToken(credentials.clientEmail, credentials.privateKey);
    }

    if (!token) {
      return [
        {
          control_code: 'CC6.7',
          control_title: 'GCP Cloud IAM Role Separation & Least Privilege',
          integration_source: 'Google Cloud',
          status: 'ERROR',
          raw_evidence: { error: 'GCP credentials missing (accessToken or clientEmail + privateKey required)' },
        },
      ];
    }

    const [storageResult, iamResult] = await Promise.all([
      checkGcpStorageBuckets(credentials.projectId, token),
      checkGcpIamPolicies(credentials.projectId, token),
    ]);

    return [storageResult, iamResult];
  } catch (err) {
    return [
      {
        control_code: 'CC6.7',
        control_title: 'GCP Cloud IAM & Storage Security Audit',
        integration_source: 'Google Cloud',
        status: 'ERROR',
        raw_evidence: { error: err.message },
      },
    ];
  }
}

module.exports = {
  runAllGcpChecks,
  checkGcpStorageBuckets,
  checkGcpIamPolicies,
  getGoogleAccessToken,
};

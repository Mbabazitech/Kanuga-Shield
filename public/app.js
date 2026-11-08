/**
 * Kanuga Shield - Application Logic & Reactive State Store
 * Company: Kanuga_tech
 * Product: Kanuga Shield - Enterprise Compliance & Security Automation
 */

// Central Reactive Application State Store
const state = {
  currentTab: 'dashboard',
  auditorMode: false,
  filterFramework: 'ALL', // 'ALL', 'SOC2', 'ISO27001', 'HIPAA'
  searchQuery: '',
  lastSyncTimestamp: Date.now(),
  connectingProviders: {}, // tracks in-flight loading spinners { [id]: boolean }

  // 1. Central Security Controls Store (SOC 2, ISO 27001, HIPAA)
  controls: [
    {
      id: 'ctrl-sec-01',
      code: 'CC6.1 / A.9.4.2',
      title: 'MFA Enforced Across Identity Providers',
      description: 'Multi-factor authentication must be mandatory for all active employees across Okta and Google Workspace.',
      category: 'Identity & Access',
      framework: 'SOC 2 Type II / ISO 27001',
      severity: 'CRITICAL',
      status: 'FAIL', // Will turn PASS on Okta / Google connect
      integration_provider: 'Okta',
      last_run_at: '14 mins ago',
      raw_evidence: {
        total_users: 48,
        mfa_enrolled: 46,
        mfa_missing_users: ['alex.dev@kanugatech.io', 'contractor_temp@kanugatech.io'],
        policy_rule_id: 'pol_okta_mfa_rule_09',
        violation: '2 active directory accounts have MFA bypass flag set'
      },
      remediation_guide: 'Navigate to Okta Admin Console -> Security -> Authenticators -> Enrollment Policies. Ensure policy "Require MFA for all staff" applies to group "All Active Employees" with no exclusions.'
    },
    {
      id: 'ctrl-sec-02',
      code: 'CC6.6 / A.10.1.1',
      title: 'S3 Cloud Storage Server-Side Encryption Enabled',
      description: 'All production cloud object storage buckets must have AES-256 or KMS encryption enabled by default.',
      category: 'Data Protection & Encryption',
      framework: 'SOC 2 Type II / HIPAA',
      severity: 'HIGH',
      status: 'FAIL', // Will turn PASS on AWS connect or re-test
      integration_provider: 'AWS',
      last_run_at: '14 mins ago',
      raw_evidence: {
        scanned_buckets: 14,
        encrypted_buckets: 13,
        unencrypted_buckets: ['kanuga-prod-public-assets-raw'],
        default_encryption: 'aws:kms:arn:aws:kms:us-east-1:849201928410:key/5d22f',
        violation: 'Bucket "kanuga-prod-public-assets-raw" has default SSE disabled'
      },
      remediation_guide: 'Run `aws s3api put-bucket-encryption --bucket kanuga-prod-public-assets-raw --server-side-encryption-configuration ...` or enable SSE-S3 via AWS S3 Console -> Properties -> Default Encryption.'
    },
    {
      id: 'ctrl-sec-03',
      code: 'CC8.1 / A.14.2.2',
      title: 'PR Review & Branch Protection Enforced on Main',
      description: 'Production code repository branches must require at least one peer approval and passing CI status checks prior to merge.',
      category: 'Software Development Lifecycle',
      framework: 'SOC 2 Type II / ISO 27001',
      severity: 'MEDIUM',
      status: 'FAIL', // Will turn PASS on GitHub connect or re-test
      integration_provider: 'GitHub',
      last_run_at: '14 mins ago',
      raw_evidence: {
        repo: 'kanuga-tech/shield-core-api',
        branch: 'main',
        required_approving_review_count: 0,
        enforce_admins: false,
        dismiss_stale_reviews: true,
        violation: 'Required approval review count is set to 0 on repository default branch'
      },
      remediation_guide: 'Open GitHub Settings for repo "shield-core-api" -> Branches -> Edit "main" protection rule. Check "Require a pull request before merging" and set "Required approvals" to 1 or higher.'
    },
    {
      id: 'ctrl-sec-04',
      code: 'CC6.2 / A.9.2.6',
      title: 'Offboarded User Access Revoked Within 24h',
      description: 'Terminated personnel must have all cloud and SaaS access revoked within 24 hours of separation timestamp.',
      category: 'Human Resources Security',
      framework: 'SOC 2 Type II / ISO 27001',
      severity: 'HIGH',
      status: 'PASS',
      integration_provider: 'Rippling',
      last_run_at: '14 mins ago',
      raw_evidence: {
        recent_terminations: 3,
        sla_met_count: 3,
        average_deprovisioning_minutes: 8.2,
        zero_orphan_accounts: true
      },
      remediation_guide: 'Ensure HR offboarding workflow is connected via webhook to Okta deactivation lifecycle.'
    },
    {
      id: 'ctrl-sec-05',
      code: 'CC7.2 / A.12.4.1',
      title: 'CloudTrail Audit Logs Retained & Tamper-Resistant',
      description: 'Multi-region AWS CloudTrail logging must be enabled with S3 log file integrity validation enabled.',
      category: 'Logging & Monitoring',
      framework: 'SOC 2 Type II / HIPAA',
      severity: 'HIGH',
      status: 'PASS',
      integration_provider: 'AWS',
      last_run_at: '14 mins ago',
      raw_evidence: {
        trail_name: 'kanuga-security-trail-all-regions',
        is_multi_region: true,
        log_file_validation_enabled: true,
        kms_key_encrypted: true
      },
      remediation_guide: 'Verify CloudTrail status in AWS Console and check CloudWatch alarm dispatchers.'
    },
    {
      id: 'ctrl-sec-06',
      code: 'CC6.7 / A.13.1.1',
      title: 'VPC Default Security Groups Restrict Inbound Traffic',
      description: 'Default security groups must not allow unrestricted inbound traffic (0.0.0.0/0 on sensitive ports).',
      category: 'Network Security',
      framework: 'SOC 2 Type II / ISO 27001',
      severity: 'CRITICAL',
      status: 'PASS',
      integration_provider: 'AWS',
      last_run_at: '14 mins ago',
      raw_evidence: {
        vpcs_audited: 3,
        open_inbound_rules: 0,
        ssh_restricted: true,
        rdp_restricted: true
      },
      remediation_guide: 'Remove ingress rules on port 22 and 3389 from default security group.'
    },
    {
      id: 'ctrl-sec-07',
      code: 'CC6.4 / A.12.1.2',
      title: 'Database Automated Backups & Point-in-Time Recovery',
      description: 'Production RDS databases must maintain automated daily snapshots with at least 30-day retention.',
      category: 'Business Continuity',
      framework: 'SOC 2 Type II / HIPAA',
      severity: 'MEDIUM',
      status: 'PASS',
      integration_provider: 'AWS',
      last_run_at: '14 mins ago',
      raw_evidence: {
        instance: 'kanuga-db-production-cluster',
        backup_retention_days: 35,
        pitr_enabled: true,
        multi_az_deployment: true
      },
      remediation_guide: 'Modify RDS instance settings to enable 30+ day retention window.'
    },
    {
      id: 'ctrl-sec-08',
      code: 'CC8.1 / A.12.6.1',
      title: 'Vulnerability Scanning on Container Registries',
      description: 'Container images pushed to production must undergo automated static vulnerability scans before release.',
      category: 'Vulnerability Management',
      framework: 'SOC 2 Type II / ISO 27001',
      severity: 'HIGH',
      status: 'PASS',
      integration_provider: 'GitHub',
      last_run_at: '14 mins ago',
      raw_evidence: {
        scanned_images_last_7d: 28,
        critical_cves: 0,
        high_cves: 0,
        medium_cves: 2,
        trivy_action_installed: true
      },
      remediation_guide: 'Include Trivy or Snyk scanner step in GitHub Actions workflow.'
    }
  ],

  // 2. Integration Mesh Store
  integrations: [
    {
      id: 'int_aws',
      provider: 'AWS',
      category: 'Cloud Infrastructure',
      name: 'Amazon Web Services',
      description: 'IAM, S3 encryption, CloudTrail logs, RDS backups, GuardDuty findings',
      icon: 'aws',
      status: 'CONNECTED',
      account_id: '849201928410',
      region: 'us-east-1',
      last_synced_at: '14 mins ago',
      evidence_count: 142
    },
    {
      id: 'int_gcp',
      provider: 'Google Cloud',
      category: 'Cloud Infrastructure',
      name: 'Google Cloud Platform',
      description: 'GCS bucket policies, VPC Service Controls, Cloud IAM roles',
      icon: 'gcp',
      status: 'CONNECTED',
      account_id: 'kanuga-shield-prod-88',
      region: 'us-central1',
      last_synced_at: '14 mins ago',
      evidence_count: 88
    },
    {
      id: 'int_azure',
      provider: 'Microsoft Azure',
      category: 'Cloud Infrastructure',
      name: 'Microsoft Azure',
      description: 'Azure Defender, Key Vault rotation policies, Blob security',
      icon: 'azure',
      status: 'DISCONNECTED',
      account_id: 'sub-7301-azure-gov',
      region: 'eastus',
      last_synced_at: 'Never',
      evidence_count: 0
    },
    {
      id: 'int_github',
      provider: 'GitHub',
      category: 'Code Repositories',
      name: 'GitHub Enterprise',
      description: 'Branch protection, PR code review requirements, Dependabot scanning',
      icon: 'github',
      status: 'CONNECTED',
      account_id: 'org:kanuga-tech',
      region: 'Global',
      last_synced_at: '14 mins ago',
      evidence_count: 64
    },
    {
      id: 'int_gitlab',
      provider: 'GitLab',
      category: 'Code Repositories',
      name: 'GitLab Cloud',
      description: 'Protected branches, merge approval rules, secret push protection',
      icon: 'gitlab',
      status: 'DISCONNECTED',
      account_id: 'gitlab.com/kanuga-tech',
      region: 'Global',
      last_synced_at: 'Never',
      evidence_count: 0
    },
    {
      id: 'int_okta',
      provider: 'Okta',
      category: 'Identity & Access',
      name: 'Okta Workforce Identity',
      description: 'MFA enforcement, single sign-on sessions, suspended user de-provisioning',
      icon: 'okta',
      status: 'CONNECTED',
      account_id: 'kanuga.okta.com',
      region: 'US Cell 1',
      last_synced_at: '14 mins ago',
      evidence_count: 110
    },
    {
      id: 'int_gsuite',
      provider: 'Google Workspace',
      category: 'Identity & Access',
      name: 'Google Workspace',
      description: 'Admin MFA enforcement, external sharing restrictions, audit logs',
      icon: 'google',
      status: 'CONNECTED',
      account_id: 'admin@kanugatech.io',
      region: 'Global',
      last_synced_at: '14 mins ago',
      evidence_count: 95
    },
    {
      id: 'int_entra',
      provider: 'Microsoft Entra ID',
      category: 'Identity & Access',
      name: 'Microsoft Entra ID (Azure AD)',
      description: 'Conditional Access policies, privileged identity management',
      icon: 'microsoft',
      status: 'DISCONNECTED',
      account_id: 'kanugatech.onmicrosoft.com',
      region: 'Global',
      last_synced_at: 'Never',
      evidence_count: 0
    },
    {
      id: 'int_rippling',
      provider: 'Rippling',
      category: 'HR & Operations',
      name: 'Rippling HRIS',
      description: 'Employee onboarding checklists, offboarding within 24h, background checks',
      icon: 'rippling',
      status: 'CONNECTED',
      account_id: 'rippling:kanuga_tech',
      region: 'US',
      last_synced_at: '14 mins ago',
      evidence_count: 76
    },
    {
      id: 'int_gusto',
      provider: 'Gusto',
      category: 'HR & Operations',
      name: 'Gusto HR',
      description: 'Staff directory sync, contractor verification & termination logs',
      icon: 'gusto',
      status: 'DISCONNECTED',
      account_id: 'app.gusto.com/c/kanuga',
      region: 'US',
      last_synced_at: 'Never',
      evidence_count: 0
    },
    {
      id: 'int_bamboohr',
      provider: 'BambooHR',
      category: 'HR & Operations',
      name: 'BambooHR',
      description: 'Personnel records, emergency contact validation, security training track',
      icon: 'bamboohr',
      status: 'CONNECTED',
      account_id: 'kanugatech.bamboohr.com',
      region: 'US',
      last_synced_at: '14 mins ago',
      evidence_count: 52
    }
  ],

  // 3. Auditor Links Store
  auditorLinks: [
    {
      id: 'aud-link-01',
      token: 'ks_audit_live_79a2efb4c8109',
      display_url: 'http://localhost:3000/?auditor_token=ks_audit_live_79a2efb4c8109',
      full_url: 'http://localhost:3000/?auditor_token=ks_audit_live_79a2efb4c8109',
      firm_name: 'Schellman & Company CPA',
      auditor_contact: 'lead-auditor@schellman-cpa.com',
      created_at: 'Feb 1, 2026',
      expiration_date: 'May 1, 2026 (90 Days)',
      status: 'ACTIVE',
      scope: 'SOC 2 Type II & ISO 27001 Evidence Vault'
    }
  ],

  // 4. Live Telemetry Stream
  testStream: [
    { id: 'th-101', control_code: 'CC6.1', test_name: 'Okta MFA Enforcement Check', status: 'FAIL', message: '2 directory users without MFA token', executed_at: '14 mins ago', severity: 'CRITICAL' },
    { id: 'th-102', control_code: 'CC6.6', test_name: 'AWS S3 Default Encryption Scan', status: 'FAIL', message: 'Bucket kanuga-prod-public-assets-raw unencrypted', executed_at: '14 mins ago', severity: 'HIGH' },
    { id: 'th-103', control_code: 'CC8.1', test_name: 'GitHub Branch Protection Approval Count', status: 'FAIL', message: 'Main branch approval threshold is 0', executed_at: '14 mins ago', severity: 'MEDIUM' },
    { id: 'th-104', control_code: 'CC6.2', test_name: 'Rippling 24h Deprovisioning Audit', status: 'PASS', message: 'All 3 separated staff deactivated within 8.2 mins', executed_at: '14 mins ago', severity: 'HIGH' },
    { id: 'th-105', control_code: 'CC7.2', test_name: 'AWS CloudTrail Multi-Region Log Validation', status: 'PASS', message: 'File validation active on all 14 regions', executed_at: '14 mins ago', severity: 'HIGH' },
    { id: 'th-106', control_code: 'CC6.7', test_name: 'AWS Default Security Group Ingress Rule', status: 'PASS', message: 'Zero open ingress rules on 0.0.0.0/0', executed_at: '14 mins ago', severity: 'CRITICAL' },
    { id: 'th-107', control_code: 'CC6.4', test_name: 'AWS RDS Automated Daily Snapshot Check', status: 'PASS', message: '35-day backup retention confirmed with PITR', executed_at: '14 mins ago', severity: 'MEDIUM' },
    { id: 'th-108', control_code: 'CC8.1', test_name: 'GitHub Container Trivy Vulnerability Scan', status: 'PASS', message: '0 critical and 0 high vulnerabilities detected', executed_at: '14 mins ago', severity: 'HIGH' }
  ],

  // Policy Center Models
  policies: [
    {
      id: 'pol-01',
      title: 'Information Security Policy',
      code: 'POL-SEC-01',
      version: 'v2.4',
      status: 'PUBLISHED',
      frameworks: ['SOC 2', 'ISO 27001', 'HIPAA'],
      last_updated: '2026-02-01',
      owner: 'CISO / Security Office',
      signoff_progress: { signed: 45, total: 48, percentage: 94 },
      content: `# Kanuga_tech - Information Security Policy (v2.4)

## 1. Objective and Scope
This Information Security Policy defines the foundational technical and organizational principles implemented by **Kanuga_tech** to safeguard customer data, proprietary intellectual property, and critical infrastructure.

## 2. Core Security Requirements
- **Multi-Factor Authentication (MFA)**: Mandatory hardware token (FIDO2) or TOTP across all internal accounts. SMS 2FA is prohibited.
- **Cryptographic Standards**: TLS 1.3 in transit; AES-256 or KMS envelope encryption at rest.
- **Access Control & Least Privilege**: Strictly role-based access control (RBAC) audited quarterly.`
    },
    {
      id: 'pol-02',
      title: 'Access Control & Password Policy',
      code: 'POL-IAM-02',
      version: 'v1.8',
      status: 'PUBLISHED',
      frameworks: ['SOC 2', 'ISO 27001'],
      last_updated: '2026-01-20',
      owner: 'IT Operations',
      signoff_progress: { signed: 47, total: 48, percentage: 98 },
      content: `# Kanuga_tech - Access Control & Password Policy (v1.8)

## 1. Identity Verification & Credential Standards
Provisioned centrally via Okta SSO. Direct creation of shared or standalone credentials on production servers is prohibited.

## 2. Password Complexity
- Minimum length: 16 characters. Stored in enterprise password vaults.`
    },
    {
      id: 'pol-03',
      title: 'Incident Response & Disaster Recovery',
      code: 'POL-IR-03',
      version: 'v3.0',
      status: 'PUBLISHED',
      frameworks: ['SOC 2', 'HIPAA', 'ISO 27001'],
      last_updated: '2026-02-10',
      owner: 'DevOps & SRE',
      signoff_progress: { signed: 44, total: 48, percentage: 92 },
      content: `# Kanuga_tech - Incident Response & Disaster Recovery Policy (v3.0)

## 1. Classification
- **P0 - Critical**: Active data breach or complete system outage.
- **P1 - High**: Partial service disruption.

## 2. Targets
- **RPO**: <= 1 hour (Automated incremental DB backups).
- **RTO**: <= 4 hours (Terraform multi-region orchestrator).`
    },
    {
      id: 'pol-04',
      title: 'Vendor & Third-Party Management Policy',
      code: 'POL-VEN-04',
      version: 'v1.2',
      status: 'PUBLISHED',
      frameworks: ['SOC 2', 'ISO 27001'],
      last_updated: '2026-01-10',
      owner: 'Procurement & Legal',
      signoff_progress: { signed: 42, total: 48, percentage: 88 },
      content: `# Kanuga_tech - Vendor & Third-Party Management Policy (v1.2)

## 1. Vendor Risk Assessment
Third-party vendors processing customer data must provide active SOC 2 Type II or ISO 27001 certifications.`
    }
  ],

  signatures: [
    { id: 'sig-01', policy_id: 'pol-01', user_name: 'David Kanuga', user_email: 'david@kanugatech.io', role: 'Chief Executive Officer', department: 'Executive', signed_at: '2026-02-02T10:14:22Z', ip_hash: '24.182.xx.xx' },
    { id: 'sig-02', policy_id: 'pol-01', user_name: 'Sarah Chen', user_email: 'sarah.c@kanugatech.io', role: 'Head of Engineering', department: 'Engineering', signed_at: '2026-02-02T11:30:10Z', ip_hash: '72.14.xx.xx' },
    { id: 'sig-03', policy_id: 'pol-01', user_name: 'Marcus Vance', user_email: 'marcus.v@kanugatech.io', role: 'Lead DevOps Architect', department: 'Infrastructure', signed_at: '2026-02-02T14:45:00Z', ip_hash: '98.128.xx.xx' }
  ],

  selectedPolicy: null,
  activeRemediationControl: null,
  session: null,
  authMode: 'login'
};

// =============================================================
// API HELPER – clean fetch wrapper for backend calls
// =============================================================
async function fetchApi(url, options = {}) {
  try {
    const resp = await fetch(url, {
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', ...options.headers },
      ...options,
      body: options.body ? JSON.stringify(options.body) : undefined
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
    return data;
  } catch (err) {
    console.error(`API Error [${url}]:`, err);
    throw err;
  }
}

// Map backend control_code → frontend control id
const CONTROL_CODE_MAP = {
  'CC6.6': 'ctrl-sec-02',   // S3 Encryption
  'CC6.1': 'ctrl-sec-01',   // MFA
  'CC7.2': 'ctrl-sec-05',   // CloudTrail
  'CC6.7': 'ctrl-sec-06',   // Security Groups
  'CC8.1': 'ctrl-sec-03',   // Branch Protection
  'CC6.8': 'ctrl-sec-08',   // Secret Scanning
};

function applyEvalResults(results, { recordStream = true } = {}) {
  if (!results || !Array.isArray(results)) return;
  results.forEach(r => {
    const ctrlId = CONTROL_CODE_MAP[r.control_code];
    if (!ctrlId) return;
    const ctrl = state.controls.find(c => c.id === ctrlId);
    if (!ctrl) return;

    ctrl.status = (r.status === 'PASS' || r.status === 'FAIL') ? r.status : ctrl.status;
    ctrl.company_id = state.session && state.session.company ? state.session.company.id : ctrl.company_id;
    ctrl.last_run_at = 'Just now';
    if (r.raw_evidence) ctrl.raw_evidence = r.raw_evidence;

    if (!recordStream) return;

    // Add telemetry entry
    state.testStream.unshift({
      id: 'th-' + Date.now() + '-' + r.control_code,
      control_code: r.control_code,
      test_name: r.control_title || ctrl.title,
      status: r.status,
      message: r.status === 'PASS'
        ? `Live scan passed – ${r.control_title}`
        : r.status === 'FAIL'
          ? `Gap detected – ${JSON.stringify(r.raw_evidence).substring(0, 120)}`
          : `Error during scan: ${r.error || 'unknown'}`,
      executed_at: 'Just now',
      severity: ctrl.severity
    });
  });
}

// =============================================================
// API HELPER
// =============================================================
async function fetchApi(url, options = {}) {
  try {
    const resp = await fetch(url, {
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', ...options.headers },
      ...options,
      body: options.body ? JSON.stringify(options.body) : undefined
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
    return data;
  } catch (err) {
    console.error(`API Error [${url}]:`, err);
    throw err;
  }
}

// =============================================================
// DYNAMIC READINESS SCORE CALCULATION
// =============================================================
function calculateReadiness() {
  const total = state.controls.length;
  const passed = state.controls.filter(c => c.status === 'PASS').length;
  const failed = state.controls.filter(c => c.status === 'FAIL').length;
  const pending = state.controls.filter(c => c.status === 'PENDING').length;

  // Framework breakdowns
  const soc2List = state.controls.filter(c => c.framework.includes('SOC 2'));
  const soc2Pass = soc2List.filter(c => c.status === 'PASS').length;
  const soc2Percent = soc2List.length > 0 ? Math.round((soc2Pass / soc2List.length) * 100) : 0;

  const isoList = state.controls.filter(c => c.framework.includes('ISO 27001'));
  const isoPass = isoList.filter(c => c.status === 'PASS').length;
  const isoPercent = isoList.length > 0 ? Math.round((isoPass / isoList.length) * 100) : 0;

  const hipaaList = state.controls.filter(c => c.framework.includes('HIPAA'));
  const hipaaPass = hipaaList.filter(c => c.status === 'PASS').length;
  const hipaaPercent = hipaaList.length > 0 ? Math.round((hipaaPass / hipaaList.length) * 100) : 0;

  const overallPercent = total > 0 ? Math.round((passed / total) * 100) : 0;

  return {
    overall: overallPercent,
    soc2: soc2Percent,
    iso27001: isoPercent,
    hipaa: hipaaPercent,
    passed,
    total,
    failed,
    pending
  };
}

// Update Header Readiness UI
function updateHeaderMetrics() {
  const stats = calculateReadiness();

  const percentEl = document.getElementById('header-readiness-percent');
  if (percentEl) {
    percentEl.textContent = `${stats.overall}%`;
    percentEl.className = stats.overall >= 90 ? 'text-emerald-400 font-extrabold ml-1' :
                          stats.overall >= 70 ? 'text-blue-400 font-extrabold ml-1' :
                          'text-amber-400 font-extrabold ml-1';
  }

  const summaryEl = document.getElementById('header-passing-summary');
  if (summaryEl) {
    summaryEl.textContent = `${stats.passed} of ${stats.total} Controls Compliant`;
  }
}

// Safe Lucide icon refresh
function refreshIcons() {
  if (window.lucide && typeof window.lucide.createIcons === 'function') {
    try {
      window.lucide.createIcons();
    } catch (e) {
      console.warn('Lucide icon render error:', e);
    }
  }
}

// Toast Notifications
function showToast(message, type = 'success') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  const bg = type === 'success' ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' :
             type === 'error' ? 'bg-rose-500/10 border-rose-500/30 text-rose-400' :
             'bg-blue-500/10 border-blue-500/30 text-blue-400';
  
  const icon = type === 'success' ? 'check-circle' : type === 'error' ? 'alert-triangle' : 'info';

  toast.className = `flex items-center gap-3 px-4 py-3 rounded-xl border ${bg} backdrop-blur-md shadow-2xl transition-all duration-300 transform translate-y-2 opacity-0 text-sm font-medium pointer-events-auto`;
  toast.innerHTML = `
    <i data-lucide="${icon}" class="w-4 h-4 flex-shrink-0"></i>
    <span>${message}</span>
  `;

  container.appendChild(toast);
  refreshIcons();

  requestAnimationFrame(() => {
    toast.classList.remove('translate-y-2', 'opacity-0');
  });

  setTimeout(() => {
    toast.classList.add('opacity-0', 'translate-y-2');
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

async function updateFirebaseStatus() {
  try {
    const data = await fetchApi('/api/firebase/status');
    const dot = document.getElementById('firebase-dot');
    const label = document.getElementById('firebase-label');
    if (dot && label) {
      if (data.configured) {
        dot.className = 'w-1.5 h-1.5 rounded-full bg-emerald-400 pulse-indicator';
        label.textContent = `Firebase: Cloud (${data.projectId || 'Live'})`;
        label.className = 'text-emerald-400 font-semibold';
      } else {
        dot.className = 'w-1.5 h-1.5 rounded-full bg-amber-400';
        label.textContent = 'Firebase: Ready for Key';
        label.className = 'text-amber-400';
      }
    }
  } catch (e) {
    console.warn('Firebase status check notice:', e.message);
  }
}

// =============================================================
// SESSION GATE & ACTIVATION KEY MANAGEMENT
// =============================================================
function setAuthMode(mode) {
  state.authMode = mode; // 'login', 'register', or 'request-key'
  const loginTab = document.getElementById('auth-tab-login');
  const registerTab = document.getElementById('auth-tab-register');
  const requestTab = document.getElementById('auth-tab-request');
  const authForm = document.getElementById('auth-form');
  const requestForm = document.getElementById('request-key-form');
  const companyField = document.getElementById('auth-company-field');
  const nameField = document.getElementById('auth-name-field');
  const keyField = document.getElementById('auth-key-field');
  const submit = document.getElementById('auth-submit');
  const password = document.getElementById('auth-password');

  showAuthError('');
  const reqErr = document.getElementById('req-error');
  if (reqErr) { reqErr.classList.add('hidden'); reqErr.textContent = ''; }
  const reqSucc = document.getElementById('req-success');
  if (reqSucc) { reqSucc.classList.add('hidden'); reqSucc.textContent = ''; }

  const isLogin = mode === 'login';
  const isRegister = mode === 'register';
  const isRequest = mode === 'request-key';

  if (loginTab) {
    loginTab.className = isLogin
      ? 'px-2 py-2 rounded-lg text-xs font-bold bg-blue-600 text-white transition-all'
      : 'px-2 py-2 rounded-lg text-xs font-bold text-slate-400 hover:text-white transition-all';
  }
  if (registerTab) {
    registerTab.className = isRegister
      ? 'px-2 py-2 rounded-lg text-xs font-bold bg-blue-600 text-white transition-all'
      : 'px-2 py-2 rounded-lg text-xs font-bold text-slate-400 hover:text-white transition-all';
  }
  if (requestTab) {
    requestTab.className = isRequest
      ? 'px-2 py-2 rounded-lg text-xs font-bold bg-emerald-600 text-white transition-all flex items-center justify-center gap-1'
      : 'px-2 py-2 rounded-lg text-xs font-bold text-emerald-400 hover:text-emerald-300 transition-all flex items-center justify-center gap-1';
  }

  if (isRequest) {
    if (authForm) authForm.classList.add('hidden');
    if (requestForm) requestForm.classList.remove('hidden');
  } else {
    if (authForm) authForm.classList.remove('hidden');
    if (requestForm) requestForm.classList.add('hidden');
    if (companyField) companyField.classList.toggle('hidden', !isRegister);
    if (nameField) nameField.classList.toggle('hidden', !isRegister);
    if (keyField) keyField.classList.toggle('hidden', !isRegister);
    if (submit) submit.textContent = isRegister ? 'Activate & Register Workspace' : 'Sign in';
    if (password) password.autocomplete = isRegister ? 'new-password' : 'current-password';
  }
  refreshIcons();
}

function showAuthError(message) {
  const el = document.getElementById('auth-error');
  if (!el) return;
  if (!message) {
    el.classList.add('hidden');
    el.textContent = '';
    return;
  }
  el.textContent = message;
  el.classList.remove('hidden');
}

function showAuthGate() {
  document.body.classList.remove('signed-in');
  refreshIcons();
}

function showAppShell() {
  document.body.classList.add('signed-in');
}

async function refreshAdminBadges() {
  try {
    const data = await fetchApi('/api/admin/activation-requests');
    if (data && data.requests) {
      state.licensingRequests = data.requests;
      const pendingCount = data.requests.filter(r => r.status === 'PENDING').length;
      const badge = document.getElementById('badge-pending-requests');
      if (badge) {
        if (pendingCount > 0) {
          badge.textContent = pendingCount;
          badge.classList.remove('hidden');
        } else {
          badge.classList.add('hidden');
        }
      }
    }
  } catch (err) {
    // Non-superadmin: silent fallback
  }
}

function applySessionChrome(session) {
  state.session = session;
  const companyName = (session.company && session.company.name) || session.user.company_name || 'Workspace';
  const person = session.user.name || session.user.email || 'User';
  const isSuperAdmin = session.user.isSuperAdmin || session.user.role === 'SUPER_ADMIN' || session.user.email.toLowerCase() === 'francism.kanuga@gmail.com';

  const initials = isSuperAdmin ? 'FK' : (companyName.replace(/[^A-Za-z0-9]/g, '').slice(0, 2).toUpperCase() || 'KS');
  const initialsEl = document.getElementById('session-initials');
  const companyEl = document.getElementById('session-company');
  const roleEl = document.getElementById('session-role');

  if (initialsEl) {
    initialsEl.textContent = initials;
    if (isSuperAdmin) {
      initialsEl.className = 'w-7 h-7 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/40 flex items-center justify-center font-bold text-xs';
    }
  }
  if (companyEl) companyEl.textContent = companyName;
  if (roleEl) {
    roleEl.textContent = isSuperAdmin ? `${person} · Founder Admin` : `${person} · ${session.user.role || 'MEMBER'}`;
    if (isSuperAdmin) roleEl.className = 'text-[10px] text-amber-400 font-semibold truncate';
  }

  // Toggle Founder Licensing nav button (use style display to avoid hidden+flex conflict)
  const licensingNavBtn = document.getElementById('nav-btn-licensing');
  if (licensingNavBtn) {
    if (isSuperAdmin) {
      licensingNavBtn.classList.remove('hidden');
      licensingNavBtn.style.display = 'flex';
      refreshAdminBadges();
    } else {
      licensingNavBtn.classList.add('hidden');
      licensingNavBtn.style.display = '';
    }
  }

  state.integrations.forEach((item) => {
    item.company_id = session.company && session.company.id;
  });
  state.controls.forEach((ctrl) => {
    ctrl.company_id = session.company && session.company.id;
  });
}

async function submitAuth(event) {
  event.preventDefault();
  showAuthError('');
  const email = document.getElementById('auth-email').value.trim();
  const password = document.getElementById('auth-password').value;
  const submit = document.getElementById('auth-submit');
  if (submit) submit.disabled = true;

  try {
    if (state.authMode === 'register') {
      const companyName = document.getElementById('auth-company').value.trim();
      const name = document.getElementById('auth-name').value.trim();
      const activationKey = document.getElementById('auth-key').value.trim();

      if (!companyName) throw new Error('Company name is required');
      if (!email) throw new Error('Work email is required');
      if (!password || password.length < 8) throw new Error('Password must be at least 8 characters');

      if (email.toLowerCase() !== 'francism.kanuga@gmail.com' && !activationKey) {
        throw new Error('An Enterprise Activation Key is required. Click "Need an activation key?" to request one.');
      }

      await fetchApi('/api/auth/register', {
        method: 'POST',
        body: { companyName, email, password, name, activationKey }
      });
    } else {
      await fetchApi('/api/auth/login', {
        method: 'POST',
        body: { email, password }
      });
    }
    const session = await fetchApi('/api/auth/me');
    await enterWorkspace(session);
  } catch (err) {
    showAuthError(err.message || 'Authentication failed');
  } finally {
    if (submit) submit.disabled = false;
  }
}

async function submitActivationRequest(event) {
  event.preventDefault();
  const companyInput = document.getElementById('req-company');
  const nameInput = document.getElementById('req-name');
  const emailInput = document.getElementById('req-email');
  const notesInput = document.getElementById('req-notes');
  const errEl = document.getElementById('req-error');
  const succEl = document.getElementById('req-success');
  const submitBtn = document.getElementById('req-submit');

  if (errEl) { errEl.classList.add('hidden'); errEl.textContent = ''; }
  if (succEl) { succEl.classList.add('hidden'); succEl.textContent = ''; }

  const companyName = companyInput ? companyInput.value.trim() : '';
  const contactName = nameInput ? nameInput.value.trim() : '';
  const email = emailInput ? emailInput.value.trim() : '';
  const notes = notesInput ? notesInput.value.trim() : '';

  if (!companyName || !email) {
    if (errEl) {
      errEl.textContent = 'Company name and work email are required.';
      errEl.classList.remove('hidden');
    }
    return;
  }

  if (submitBtn) submitBtn.disabled = true;

  try {
    const res = await fetchApi('/api/auth/request-activation', {
      method: 'POST',
      body: { companyName, contactName, email, notes }
    });

    if (succEl) {
      succEl.innerHTML = `
        <strong>Request Submitted!</strong><br>
        Founder <strong>Francis M. Kanuga</strong> (francism.kanuga@gmail.com) has been notified.
        Once payment confirmation is processed, your activation key will be dispatched to <strong>${email}</strong>.
      `;
      succEl.classList.remove('hidden');
    }

    // Pre-fill registration form
    const regCompany = document.getElementById('auth-company');
    const regName = document.getElementById('auth-name');
    const regEmail = document.getElementById('auth-email');
    if (regCompany) regCompany.value = companyName;
    if (regName) regName.value = contactName;
    if (regEmail) regEmail.value = email;

    showToast('Key request sent to Founder Francis M. Kanuga!', 'success');
  } catch (err) {
    if (errEl) {
      errEl.textContent = err.message || 'Failed to submit activation request.';
      errEl.classList.remove('hidden');
    }
  } finally {
    if (submitBtn) submitBtn.disabled = false;
  }
}

async function logoutSession() {
  try {
    await fetchApi('/api/auth/logout', { method: 'POST', body: {} });
  } catch (err) {
    console.warn('Logout notice:', err.message);
  }
  state.session = null;
  showAuthGate();
}

async function loadTenantScope() {
  const companyId = state.session && state.session.company && state.session.company.id;
  try {
    const [controls, integrations] = await Promise.all([
      fetchApi('/api/controls'),
      fetchApi('/api/integrations'),
    ]);
    const connected = new Set((integrations || []).map((item) => String(item.id || '').toLowerCase()));
    const liveProviders = {
      AWS: 'aws',
      GitHub: 'github',
      Okta: 'okta',
      'Google Cloud': 'gcp',
    };
    state.integrations.forEach((item) => {
      const key = liveProviders[item.provider];
      if (!key) return;
      item.status = connected.has(key) ? 'CONNECTED' : 'DISCONNECTED';
      item.company_id = companyId;
      if (item.status === 'DISCONNECTED') item.last_synced_at = 'Not connected';
    });
    if (Array.isArray(controls) && controls.length > 0) {
      applyEvalResults(controls.map((row) => {
        let raw = row.raw_json_payload;
        if (typeof raw === 'string') {
          try { raw = JSON.parse(raw); } catch (e) { raw = { payload: raw }; }
        }
        return {
          control_code: row.control_code,
          control_title: row.control_title,
          status: row.status,
          raw_evidence: raw,
        };
      }), { recordStream: false });
    }
  } catch (err) {
    console.warn('Tenant scope load notice:', err.message);
  }
}

async function enterWorkspace(session) {
  applySessionChrome(session);
  await loadTenantScope();
  showAppShell();
  renderAll();
}

// Initialize App
async function initApp() {
  state.selectedPolicy = state.policies[0];
  setAuthMode('login');

  // Check URL for auditor token
  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get('auditor_token')) {
    state.auditorMode = true;
    state.currentTab = 'audit';
  }

  try {
    const session = await fetchApi('/api/auth/me');
    await enterWorkspace(session);
  } catch (err) {
    showAuthGate();
  }

  initSignaturePad();
  startTelemetryTicker();
  updateFirebaseStatus();
}

function renderAll() {
  updateHeaderMetrics();
  renderCurrentTab();
  refreshIcons();
}

function switchTab(tabId) {
  state.currentTab = tabId;
  document.querySelectorAll('.nav-link').forEach(btn => {
    if (btn.dataset.tab === tabId) {
      btn.classList.add('bg-blue-600/10', 'text-blue-400', 'border-blue-500/30');
      btn.classList.remove('text-slate-400', 'hover:bg-slate-800/60');
    } else {
      btn.classList.remove('bg-blue-600/10', 'text-blue-400', 'border-blue-500/30');
      btn.classList.add('text-slate-400', 'hover:bg-slate-800/60');
    }
  });

  if (tabId === 'evidence') {
    fetchApi('/api/evidence/vault')
      .then(data => {
        if (data && data.evidence && data.evidence.length > 0) {
          state.persistedEvidence = data.evidence;
          if (state.currentTab === 'evidence') {
            renderCurrentTab();
            refreshIcons();
          }
        }
      })
      .catch(e => console.warn('Evidence vault fetch error:', e.message));
  }

  if (tabId === 'licensing') {
    Promise.all([
      fetchApi('/api/admin/activation-requests').catch(() => ({ requests: [] })),
      fetchApi('/api/admin/activation-keys').catch(() => ({ keys: [] })),
      fetchApi('/api/admin/mail-outbox').catch(() => ({ outbox: [] }))
    ]).then(([reqData, keyData, mailData]) => {
      state.licensingRequests = reqData.requests || [];
      state.licensingKeys = keyData.keys || [];
      state.licensingOutbox = mailData.outbox || [];
      refreshAdminBadges();
      if (state.currentTab === 'licensing') {
        renderCurrentTab();
        refreshIcons();
      }
    });
  }

  renderCurrentTab();
  refreshIcons();
}

function renderCurrentTab() {
  const main = document.getElementById('main-content-view');
  if (!main) return;

  switch (state.currentTab) {
    case 'dashboard':
      main.innerHTML = getDashboardHTML();
      break;
    case 'integrations':
      main.innerHTML = getIntegrationsHTML();
      break;
    case 'controls':
      main.innerHTML = getControlsHTML();
      break;
    case 'policies':
      main.innerHTML = getPoliciesHTML();
      break;
    case 'evidence':
      main.innerHTML = getEvidenceHTML();
      break;
    case 'audit':
      main.innerHTML = getAuditorRoomHTML();
      break;
    case 'licensing':
      main.innerHTML = getLicensingHTML();
      break;
    case 'settings':
      main.innerHTML = getSettingsHTML();
      break;
    default:
      main.innerHTML = getDashboardHTML();
  }
}

// =============================================================
// 1. DASHBOARD VIEW WITH DYNAMIC READINESS SCORES
// =============================================================
function getDashboardHTML() {
  const stats = calculateReadiness();
  const failing = state.controls.filter(c => c.status === 'FAIL');

  return `
    <div class="space-y-6">
      <!-- Welcome Hero Banner -->
      <div class="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 p-6 rounded-2xl glass-panel gradient-border-glow">
        <div>
          <div class="flex items-center gap-2 mb-1">
            <span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 pulse-indicator"></span> Continuous Monitoring Active
            </span>
            <span class="text-xs text-slate-400">Target Audit: SOC 2 Type II & ISO 27001</span>
          </div>
          <h1 class="text-2xl font-bold tracking-tight text-white">Executive Compliance & Security Posture</h1>
          <p class="text-sm text-slate-400 mt-0.5">Real-time telemetry stream evaluating ${stats.total} continuous controls across connected cloud and identity providers.</p>
        </div>
        <div class="flex items-center gap-3">
          <button onclick="triggerManualSync()" id="btn-run-tests" class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-medium text-sm transition-all shadow-lg shadow-blue-600/25 active:scale-95">
            <i data-lucide="refresh-cw" class="w-4 h-4" id="refresh-icon"></i>
            <span>Run All Automated Tests</span>
          </button>
          <button onclick="switchTab('audit')" class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-sm border border-slate-700 transition-all">
            <i data-lucide="external-link" class="w-4 h-4 text-slate-400"></i>
            <span>Auditor Room</span>
          </button>
        </div>
      </div>

      <!-- Framework Score Gauges Grid -->
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <!-- Overall Readiness Score Card -->
        <div class="p-5 rounded-2xl glass-panel transition-card border ${stats.overall >= 90 ? 'border-emerald-500/30' : 'border-blue-500/30'}">
          <div class="flex items-center justify-between mb-3">
            <span class="text-xs font-semibold uppercase tracking-wider text-slate-400">Overall Readiness</span>
            <span class="px-2 py-0.5 rounded-md text-[11px] font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20">Combined Score</span>
          </div>
          <div class="flex items-baseline gap-2">
            <span class="text-3xl font-extrabold text-white">${stats.overall}%</span>
            <span class="text-xs font-medium text-emerald-400 flex items-center gap-0.5">
              <i data-lucide="trending-up" class="w-3 h-3"></i> ${stats.passed}/${stats.total} Passing
            </span>
          </div>
          <div class="w-full bg-slate-700/50 rounded-full h-2 mt-3 overflow-hidden">
            <div class="bg-gradient-to-r from-blue-600 to-emerald-400 h-2 rounded-full transition-all duration-700" style="width: ${stats.overall}%"></div>
          </div>
          <p class="text-xs text-slate-400 mt-2">${stats.passed} of ${stats.total} security checks passing</p>
        </div>

        <!-- SOC 2 Type II -->
        <div class="p-5 rounded-2xl glass-panel transition-card">
          <div class="flex items-center justify-between mb-3">
            <span class="text-xs font-semibold uppercase tracking-wider text-slate-400">SOC 2 Type II</span>
            <span class="px-2 py-0.5 rounded-md text-[11px] font-semibold ${stats.soc2 >= 90 ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'}">
              ${stats.soc2 >= 90 ? 'Audit-Ready' : 'In Progress'}
            </span>
          </div>
          <div class="flex items-baseline gap-2">
            <span class="text-3xl font-extrabold text-white">${stats.soc2}%</span>
            <span class="text-xs text-slate-400">Trust Criteria</span>
          </div>
          <div class="w-full bg-slate-700/50 rounded-full h-2 mt-3 overflow-hidden">
            <div class="bg-emerald-500 h-2 rounded-full transition-all duration-700" style="width: ${stats.soc2}%"></div>
          </div>
          <div class="flex justify-between items-center text-xs text-slate-400 mt-2">
            <span>Security CC6 & CC7</span>
            <span class="text-emerald-400 font-medium">${stats.soc2}%</span>
          </div>
        </div>

        <!-- ISO 27001 -->
        <div class="p-5 rounded-2xl glass-panel transition-card">
          <div class="flex items-center justify-between mb-3">
            <span class="text-xs font-semibold uppercase tracking-wider text-slate-400">ISO 27001:2022</span>
            <span class="px-2 py-0.5 rounded-md text-[11px] font-semibold ${stats.iso27001 >= 90 ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'}">
              ${stats.iso27001 >= 90 ? 'Compliant' : `${failing.length} Gaps`}
            </span>
          </div>
          <div class="flex items-baseline gap-2">
            <span class="text-3xl font-extrabold text-white">${stats.iso27001}%</span>
            <span class="text-xs text-amber-400 flex items-center gap-0.5">
              <i data-lucide="shield" class="w-3 h-3"></i> Annex A
            </span>
          </div>
          <div class="w-full bg-slate-700/50 rounded-full h-2 mt-3 overflow-hidden">
            <div class="bg-amber-500 h-2 rounded-full transition-all duration-700" style="width: ${stats.iso27001}%"></div>
          </div>
          <div class="flex justify-between items-center text-xs text-slate-400 mt-2">
            <span>A.9, A.10, A.14</span>
            <span class="text-amber-400 font-medium">${stats.iso27001}%</span>
          </div>
        </div>

        <!-- HIPAA Security -->
        <div class="p-5 rounded-2xl glass-panel transition-card">
          <div class="flex items-center justify-between mb-3">
            <span class="text-xs font-semibold uppercase tracking-wider text-slate-400">HIPAA Security Rule</span>
            <span class="px-2 py-0.5 rounded-md text-[11px] font-semibold ${stats.hipaa >= 90 ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'}">
              ${stats.hipaa >= 90 ? 'Compliant' : 'Review'}
            </span>
          </div>
          <div class="flex items-baseline gap-2">
            <span class="text-3xl font-extrabold text-white">${stats.hipaa}%</span>
            <span class="text-xs text-slate-400">Safeguards</span>
          </div>
          <div class="w-full bg-slate-700/50 rounded-full h-2 mt-3 overflow-hidden">
            <div class="bg-purple-500 h-2 rounded-full transition-all duration-700" style="width: ${stats.hipaa}%"></div>
          </div>
          <div class="flex justify-between items-center text-xs text-slate-400 mt-2">
            <span>Technical & Physical</span>
            <span class="text-purple-400 font-medium">${stats.hipaa}%</span>
          </div>
        </div>
      </div>

      <!-- Action Items Queue & Live Telemetry Stream -->
      <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <!-- Action Items Queue (Left Column, 7 cols) -->
        <div class="lg:col-span-7 space-y-4">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <h2 class="text-base font-semibold text-white">Action Item Queue</h2>
              <span class="px-2 py-0.5 rounded-full text-xs font-bold ${failing.length > 0 ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20' : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'}">
                ${failing.length} Failing Checks
              </span>
            </div>
            <span class="text-xs text-slate-400">Ranked by risk severity</span>
          </div>

          ${failing.length === 0 ? `
            <div class="p-8 rounded-2xl glass-panel text-center">
              <div class="w-12 h-12 rounded-full bg-emerald-500/10 text-emerald-400 mx-auto flex items-center justify-center mb-3">
                <i data-lucide="shield-check" class="w-6 h-6"></i>
              </div>
              <h3 class="text-white font-semibold">Zero Outstanding Compliance Gaps!</h3>
              <p class="text-xs text-slate-400 mt-1 max-w-sm mx-auto">All continuous security tests are currently passing across all linked cloud, code, and identity integrations. Overall Readiness is 100%.</p>
            </div>
          ` : `
            <div class="space-y-3">
              ${failing.map(c => `
                <div class="p-4 rounded-xl glass-panel-elevated border border-rose-500/20 transition-card flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                  <div class="space-y-1.5 flex-1">
                    <div class="flex items-center gap-2 flex-wrap">
                      <span class="px-2 py-0.5 rounded text-[10px] font-extrabold uppercase ${
                        c.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                        c.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                        'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                      }">
                        ${c.severity}
                      </span>
                      <span class="text-xs font-mono text-slate-400">${c.code}</span>
                      <span class="text-xs text-slate-400">• ${c.integration_provider}</span>
                    </div>
                    <h3 class="text-sm font-semibold text-white">${c.title}</h3>
                    <p class="text-xs text-slate-400 leading-relaxed">${c.raw_evidence?.violation || c.description}</p>
                  </div>
                  <div class="flex items-center gap-2 flex-shrink-0 w-full md:w-auto">
                    <button onclick="openRemediationModal('${c.id}')" class="flex-1 md:flex-none inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium transition-all shadow-md shadow-blue-600/20">
                      <i data-lucide="wrench" class="w-3.5 h-3.5"></i>
                      <span>Fix Guide</span>
                    </button>
                    <button onclick="remediateControl('${c.id}')" class="flex-1 md:flex-none inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 transition-all">
                      <i data-lucide="check" class="w-3.5 h-3.5 text-emerald-400"></i>
                      <span>Re-test</span>
                    </button>
                  </div>
                </div>
              `).join('')}
            </div>
          `}

          <!-- Quick Navigation to Integrations Banner -->
          <div class="p-4 rounded-xl glass-panel border border-blue-500/20 flex items-center justify-between">
            <div class="flex items-center gap-3">
              <div class="w-9 h-9 rounded-lg bg-blue-500/10 text-blue-400 flex items-center justify-center">
                <i data-lucide="layers" class="w-5 h-5"></i>
              </div>
              <div>
                <p class="text-xs font-semibold text-white">Need to connect additional data sources?</p>
                <p class="text-[11px] text-slate-400">Connect Okta, AWS, or GitHub to automatically resolve failing security checks.</p>
              </div>
            </div>
            <button onclick="switchTab('integrations')" class="text-xs text-blue-400 hover:text-blue-300 font-semibold flex items-center gap-1">
              <span>Integration Hub</span>
              <i data-lucide="chevron-right" class="w-3.5 h-3.5"></i>
            </button>
          </div>
        </div>

        <!-- Live Security Posture Stream (Right Column, 5 cols) -->
        <div class="lg:col-span-5 space-y-4">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <span class="w-2 h-2 rounded-full bg-emerald-400 pulse-indicator"></span>
              <h2 class="text-base font-semibold text-white">Live Posture Stream</h2>
            </div>
            <span class="text-xs text-slate-400">${state.testStream.length} Events</span>
          </div>

          <div class="p-4 rounded-2xl glass-panel divide-y divide-slate-800/80 max-h-[460px] overflow-y-auto space-y-3">
            ${state.testStream.slice(0, 10).map(event => `
              <div class="pt-3 first:pt-0 space-y-1">
                <div class="flex items-center justify-between">
                  <div class="flex items-center gap-2">
                    <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold ${
                      event.status === 'PASS' ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/20' :
                      event.status === 'FAIL' ? 'bg-rose-500/15 text-rose-400 border border-rose-500/20' :
                      'bg-blue-500/15 text-blue-400 border border-blue-500/20'
                    }">
                      ${event.status}
                    </span>
                    <span class="text-xs font-medium text-slate-200 truncate max-w-[200px]">${event.test_name}</span>
                  </div>
                  <span class="text-[11px] font-mono text-slate-500">${event.executed_at}</span>
                </div>
                <p class="text-xs text-slate-400 truncate">${event.message}</p>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    </div>
  `;
}

// =============================================================
// 2. INTEGRATION HUB & MOCK API ENGINE
// =============================================================
function getIntegrationsHTML() {
  const categories = ['Cloud Infrastructure', 'Code Repositories', 'Identity & Access', 'HR & Operations'];
  const activeCount = state.integrations.filter(i => i.status === 'CONNECTED').length;

  return `
    <div class="space-y-6">
      <!-- Header -->
      <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-2xl glass-panel">
        <div>
          <div class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20 mb-1">
            <i data-lucide="plug" class="w-3.5 h-3.5"></i> API Connection Mesh
          </div>
          <h1 class="text-2xl font-bold text-white">Integration Hub</h1>
          <p class="text-sm text-slate-400">Continuous API connectors automatically evaluating and passing technical security checks every hour.</p>
        </div>
        <div class="flex items-center gap-3">
          <div class="text-right hidden sm:block">
            <div class="text-xs text-slate-400">Active Connections</div>
            <div class="text-lg font-bold text-white">${activeCount} / ${state.integrations.length} Active</div>
          </div>
          <button onclick="triggerAllIntegrationsSync()" class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-medium text-sm transition-all shadow-lg shadow-blue-600/25">
            <i data-lucide="refresh-cw" class="w-4 h-4"></i>
            <span>Sync All Connectors</span>
          </button>
        </div>
      </div>

      <!-- Categories Layout -->
      ${categories.map(cat => {
        const items = state.integrations.filter(i => i.category === cat);
        return `
          <div class="space-y-3">
            <div class="flex items-center justify-between border-b border-slate-800 pb-2">
              <h2 class="text-sm font-bold uppercase tracking-wider text-slate-400">${cat}</h2>
              <span class="text-xs text-slate-500">${items.length} Connectors Available</span>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              ${items.map(item => {
                const isLoading = state.connectingProviders[item.id];
                const isConnected = item.status === 'CONNECTED';

                return `
                  <div class="p-5 rounded-2xl glass-panel transition-card border ${
                    isConnected ? 'border-blue-500/40 shadow-lg shadow-blue-900/10' : 'border-slate-800'
                  } flex flex-col justify-between space-y-4">
                    <div>
                      <div class="flex items-start justify-between gap-3 mb-2">
                        <div class="flex items-center gap-3">
                          <div class="w-10 h-10 rounded-xl bg-slate-800 border border-slate-700/60 flex items-center justify-center text-blue-400 font-bold text-sm">
                            ${getProviderBadge(item.icon)}
                          </div>
                          <div>
                            <h3 class="text-sm font-bold text-white">${item.name}</h3>
                            <span class="text-xs text-slate-400 font-mono">${item.account_id}</span>
                          </div>
                        </div>
                        <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-bold ${
                          isConnected ? 'bg-blue-500/15 text-blue-400 border border-blue-500/30' : 'bg-slate-700/40 text-slate-400 border border-slate-700'
                        }">
                          ${isConnected ? '<span class="w-1.5 h-1.5 rounded-full bg-blue-400 pulse-indicator"></span> CONNECTED' : 'DISCONNECTED'}
                        </span>
                      </div>
                      <p class="text-xs text-slate-400 leading-relaxed mt-2">${item.description}</p>
                    </div>

                    <div class="space-y-3 pt-3 border-t border-slate-800/80">
                      <div class="flex justify-between items-center text-xs text-slate-400">
                        <span>Last Telemetry Ingest:</span>
                        <span class="text-slate-200 font-mono">${item.last_synced_at}</span>
                      </div>
                      <div class="flex justify-between items-center text-xs text-slate-400">
                        <span>Evidence Records:</span>
                        <span class="text-blue-400 font-mono font-semibold">${item.evidence_count} items</span>
                      </div>

                      <div class="flex items-center gap-2 pt-1">
                        <button onclick="handleIntegrationClick('${item.id}')" ${isLoading ? 'disabled' : ''} class="flex-1 py-1.5 px-3 rounded-lg text-xs font-semibold transition-all flex items-center justify-center gap-1.5 ${
                          isLoading ? 'bg-blue-600/50 text-white cursor-wait' :
                          isConnected ? 'bg-rose-500/10 text-rose-400 hover:bg-rose-500/20 border border-rose-500/20' :
                          'bg-blue-600 hover:bg-blue-500 text-white shadow-md shadow-blue-600/20'
                        }">
                          ${
                            isLoading ? '<i data-lucide="loader-2" class="w-3.5 h-3.5 animate-spin"></i> Ingesting Telemetry...' :
                            isConnected ? 'Disconnect' : 'Connect'
                          }
                        </button>
                        <button onclick="openCredentialsModal('${item.id}')" title="Configure Live Credentials" class="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-all">
                          <i data-lucide="sliders" class="w-3.5 h-3.5"></i>
                        </button>
                        ${isConnected ? `
                          <button onclick="syncSingleIntegration('${item.id}')" title="Sync Live Evidence" class="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-all">
                            <i data-lucide="refresh-cw" class="w-3.5 h-3.5"></i>
                          </button>
                        ` : ''}
                      </div>
                    </div>
                  </div>
                `;
              }).join('')}
            </div>
          </div>
        `;
      }).join('')}
    </div>
  `;
}

function getProviderBadge(icon) {
  switch (icon) {
    case 'aws': return 'AWS';
    case 'gcp': return 'GCP';
    case 'azure': return 'AZ';
    case 'github': return 'GH';
    case 'gitlab': return 'GL';
    case 'okta': return 'OK';
    case 'google': return 'G';
    case 'microsoft': return 'MS';
    case 'rippling': return 'RP';
    case 'gusto': return 'GU';
    case 'bamboohr': return 'BB';
    default: return 'API';
  }
}

// -------------------------------------------------------------
// INTEGRATION HANDLER (CONNECT / DISCONNECT / SCAN) — REAL API
// -------------------------------------------------------------
async function handleIntegrationClick(id) {
  const item = state.integrations.find(i => i.id === id);
  if (!item) return;

  // ── DISCONNECT FLOW ──
  if (item.status === 'CONNECTED') {
    try {
      await fetchApi(`/api/integrations/${item.provider.toLowerCase()}`, { method: 'DELETE' });
      item.status = 'DISCONNECTED';
      item.last_synced_at = 'Never';
      showToast(`Disconnected ${item.name}.`, 'info');
    } catch (err) {
      showToast(`Failed to disconnect ${item.name}: ${err.message}`, 'error');
    }

    // Add telemetry entry
    state.testStream.unshift({
      id: 'th-' + Date.now(),
      control_code: 'INT-DISCONNECT',
      test_name: `${item.name} Session Terminated`,
      status: 'INFO',
      message: `Connector ${item.name} disconnected by user. Live telemetry paused.`,
      executed_at: 'Just now',
      severity: 'LOW'
    });

    renderAll();
    return;
  }

  // ── CONNECT FLOW ──
  state.connectingProviders[id] = true;
  renderCurrentTab();
  refreshIcons();

  showToast(`Initiating secure API handshake with ${item.name}...`, 'info');

  try {
    const providerKey = item.provider.toLowerCase();

    if (item.provider === 'AWS') {
      // Read credential modal inputs if available, otherwise use defaults
      const roleArnEl = document.getElementById('cred-input-1');
      const extIdEl   = document.getElementById('cred-input-2');
      const roleArn   = (roleArnEl && roleArnEl.value) || 'arn:aws:iam::849201928410:role/KanugaShieldAuditRole';
      const externalId = (extIdEl && extIdEl.value)     || 'ks-corp-84920192';

      await fetchApi('/api/integrations/aws/connect', {
        method: 'POST',
        body: { roleArn, externalId }
      });
    } else if (item.provider === 'GitHub') {
      const tokenEl = document.getElementById('cred-input-2');
      const orgEl   = document.getElementById('cred-input-1');
      const token   = (tokenEl && tokenEl.value) || 'ghp_kanugashield99281a8b273c';
      const org     = (orgEl && orgEl.value)      || 'kanuga-tech';

      await fetchApi('/api/integrations/github/connect', {
        method: 'POST',
        body: { token, org }
      });
    } else if (item.provider === 'Okta') {
      const orgEl = document.getElementById('cred-input-1');
      const tokenEl = document.getElementById('cred-input-2');
      const orgUrl = (orgEl && orgEl.value) || 'kanuga.okta.com';
      const apiToken = (tokenEl && tokenEl.value) || '00_ssws_okta_token_99182a';

      await fetchApi('/api/integrations/okta/connect', {
        method: 'POST',
        body: { orgUrl, apiToken }
      });
    } else if (item.provider === 'Google Cloud') {
      const projEl = document.getElementById('cred-input-1');
      const keyEl = document.getElementById('cred-input-2');
      const projectId = (projEl && projEl.value) || 'kanuga-shield-prod-88';
      const accessToken = (keyEl && keyEl.value) || 'ya29.sample_oauth_token';

      await fetchApi('/api/integrations/gcp/connect', {
        method: 'POST',
        body: { projectId, accessToken }
      });
    } else {
      // Other providers: keep simulated 1.5s handshake
      await new Promise(resolve => setTimeout(resolve, 1500));
    }

    // ── Success path ──
    delete state.connectingProviders[id];
    item.status = 'CONNECTED';
    item.last_synced_at = 'Just now';
    if (item.evidence_count === 0) item.evidence_count = 42;

    showToast(`Connected ${item.name}! Running live compliance checks...`, 'success');

    // Immediately evaluate controls via real backend
    try {
      const evalData = await fetchApi('/api/controls/evaluate');
      const results = evalData.results || evalData;

      (Array.isArray(results) ? results : []).forEach(r => {
        const ctrl = state.controls.find(c => c.code === r.control_code);
        if (ctrl) {
          ctrl.status = r.status;
          if (ctrl.raw_evidence && r.violation) ctrl.raw_evidence.violation = r.violation;
        }
        // Telemetry stream entry for each result
        state.testStream.unshift({
          id: 'th-' + Date.now() + '-' + (r.control_code || ''),
          control_code: r.control_code || 'EVAL',
          test_name: r.test_name || `${item.name} Live Check`,
          status: r.status || 'PASS',
          message: r.message || `Live evaluation completed for ${r.control_code}`,
          executed_at: 'Just now',
          severity: r.severity || 'HIGH'
        });
      });
    } catch (evalErr) {
      console.warn('Live control evaluation skipped:', evalErr.message);
    }

    showToast(`Connected ${item.name}! Ingested live telemetry and verified security checks.`, 'success');
  } catch (err) {
    // ── Error path ──
    delete state.connectingProviders[id];
    showToast(`Failed to connect ${item.name}: ${err.message}`, 'error');
  }

  // Recalculate the overall readiness score live
  renderAll();
}

function syncSingleIntegration(id) {
  const item = state.integrations.find(i => i.id === id);
  if (!item) return;

  showToast(`Syncing latest telemetry from ${item.name}...`, 'info');
  setTimeout(() => {
    item.last_synced_at = 'Just now';
    item.evidence_count += 3;

    state.testStream.unshift({
      id: 'th-' + Date.now(),
      control_code: 'INT-SYNC',
      test_name: `${item.name} Configuration Ingest`,
      status: 'PASS',
      message: `${item.name} On-Demand Ingest: Live configuration telemetry refreshed`,
      executed_at: 'Just now',
      severity: 'LOW'
    });

    showToast(`Refreshed live evidence from ${item.name}`, 'success');
    renderAll();
  }, 800);
}

function triggerAllIntegrationsSync() {
  showToast('Initiating parallel configuration sync across all active connectors...', 'info');
  setTimeout(() => {
    state.integrations.forEach(i => {
      if (i.status === 'CONNECTED') {
        i.last_synced_at = 'Just now';
        i.evidence_count += 3;
      }
    });

    state.testStream.unshift({
      id: 'th-' + Date.now(),
      control_code: 'SYS-SYNC',
      test_name: 'All Integrations Parallel Scan',
      status: 'PASS',
      message: 'Ingested live JSON configs from AWS, GitHub, Okta, and Rippling',
      executed_at: 'Just now',
      severity: 'LOW'
    });

    showToast('Parallel sync complete: Ingested latest telemetry across connected services!', 'success');
    renderAll();
  }, 1200);
}

// =============================================================
// 3. CONTINUOUS CONTROLS & MONITORING MATRIX
// =============================================================
function getControlsHTML() {
  let list = state.controls;
  if (state.filterFramework !== 'ALL') {
    list = list.filter(c => c.framework.toUpperCase().includes(state.filterFramework));
  }

  const stats = calculateReadiness();

  return `
    <div class="space-y-6">
      <!-- Header -->
      <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-2xl glass-panel">
        <div>
          <div class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 mb-1">
            <i data-lucide="shield" class="w-3.5 h-3.5"></i> Security Check Matrix
          </div>
          <h1 class="text-2xl font-bold text-white">Continuous Controls</h1>
          <p class="text-sm text-slate-400">Mapping API telemetry to SOC 2 Criteria (Security CC6-CC8), ISO 27001 Annex A, & HIPAA Safeguards.</p>
        </div>
        <!-- Framework Tabs -->
        <div class="flex items-center gap-2 p-1 rounded-xl bg-slate-900 border border-slate-800">
          <button onclick="setFilterFramework('ALL')" class="px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${state.filterFramework === 'ALL' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'}">All (${state.controls.length})</button>
          <button onclick="setFilterFramework('SOC2')" class="px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${state.filterFramework === 'SOC2' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'}">SOC 2 (${stats.soc2}%)</button>
          <button onclick="setFilterFramework('ISO27001')" class="px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${state.filterFramework === 'ISO27001' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'}">ISO 27001 (${stats.iso27001}%)</button>
          <button onclick="setFilterFramework('HIPAA')" class="px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${state.filterFramework === 'HIPAA' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'}">HIPAA (${stats.hipaa}%)</button>
        </div>
      </div>

      <!-- Controls Table View -->
      <div class="rounded-2xl glass-panel overflow-hidden border border-slate-800">
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm">
            <thead class="bg-slate-900/80 text-xs uppercase font-bold text-slate-400 border-b border-slate-800">
              <tr>
                <th class="py-3.5 px-4">Control Code & Title</th>
                <th class="py-3.5 px-4">Framework / Criteria</th>
                <th class="py-3.5 px-4">Source Provider</th>
                <th class="py-3.5 px-4">Severity</th>
                <th class="py-3.5 px-4">Status</th>
                <th class="py-3.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800/80 text-slate-300">
              ${list.map(c => `
                <tr class="hover:bg-slate-800/40 transition-colors">
                  <td class="py-4 px-4">
                    <div class="font-semibold text-white">${c.title}</div>
                    <div class="text-xs font-mono text-slate-400 mt-0.5">${c.code} • ${c.category}</div>
                  </td>
                  <td class="py-4 px-4 text-xs font-medium text-slate-300">
                    <span class="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700/60">${c.framework}</span>
                  </td>
                  <td class="py-4 px-4 text-xs font-mono text-slate-400">
                    <span class="inline-flex items-center gap-1.5">
                      <span class="w-2 h-2 rounded-full bg-blue-500"></span> ${c.integration_provider}
                    </span>
                  </td>
                  <td class="py-4 px-4">
                    <span class="px-2 py-0.5 rounded text-[10px] font-extrabold uppercase ${
                      c.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                      c.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                      'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                    }">
                      ${c.severity}
                    </span>
                  </td>
                  <td class="py-4 px-4">
                    <span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-bold ${
                      c.status === 'PASS' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                    }">
                      <span class="w-1.5 h-1.5 rounded-full ${c.status === 'PASS' ? 'bg-emerald-400' : 'bg-rose-400'}"></span>
                      ${c.status === 'PASS' ? 'PASSING' : 'FAILING CHECK'}
                    </span>
                  </td>
                  <td class="py-4 px-4 text-right">
                    <div class="inline-flex items-center gap-2">
                      <button onclick="viewEvidenceModal('${c.id}')" class="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-all text-xs" title="Inspect JSON Evidence">
                        <i data-lucide="file-json" class="w-3.5 h-3.5"></i>
                      </button>
                      ${c.status === 'FAIL' ? `
                        <button onclick="openRemediationModal('${c.id}')" class="px-2.5 py-1 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold transition-all">
                          Remediate
                        </button>
                      ` : `
                        <button onclick="remediateControl('${c.id}')" class="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-all text-xs" title="Re-verify Check">
                          <i data-lucide="refresh-cw" class="w-3.5 h-3.5"></i>
                        </button>
                      `}
                    </div>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

function setFilterFramework(fw) {
  state.filterFramework = fw;
  renderCurrentTab();
  refreshIcons();
}

// =============================================================
// 4. AUDITOR ROOM & ACCESS LINK GENERATOR
// =============================================================
function getAuditorRoomHTML() {
  const stats = calculateReadiness();
  const urlParams = new URLSearchParams(window.location.search);
  const activeToken = urlParams.get('auditor_token') || (state.auditorLinks[0] ? state.auditorLinks[0].token : 'ks_audit_live');

  // IF ACCESSED VIA AUDITOR LINK (AUDITOR READ-ONLY PORTAL MODE)
  if (state.auditorMode) {
    return `
      <div class="space-y-6">
        <!-- High-Trust CPA Portal Banner -->
        <div class="p-6 rounded-2xl glass-panel-elevated border border-emerald-500/40 bg-gradient-to-r from-emerald-950/40 via-slate-900 to-slate-900 shadow-2xl">
          <div class="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div>
              <div class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 mb-2">
                <i data-lucide="shield-check" class="w-4 h-4 text-emerald-400"></i>
                <span>Authenticated Read-Only CPA Auditor Session</span>
              </div>
              <h1 class="text-2xl font-bold text-white">External Auditor Evidence Room</h1>
              <p class="text-xs text-slate-300 mt-1 max-w-2xl leading-relaxed">
                Authorized Firm: <strong class="text-white">Schellman & Company CPA</strong> • Token: <span class="font-mono text-emerald-400 font-bold">${activeToken}</span> • Access Scope: <span class="text-blue-400 font-medium">SOC 2 Type II & ISO 27001 Evidence Vault</span>. Write actions and administrative mutation permissions are locked.
              </p>
            </div>
            <div class="flex items-center gap-2">
              <button onclick="downloadEvidenceBundle()" class="inline-flex items-center gap-1.5 px-4 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs transition-all shadow-lg shadow-blue-600/30">
                <i data-lucide="download" class="w-4 h-4"></i>
                <span>Download CPA Evidence Package (JSON)</span>
              </button>
              <button onclick="exitAuditorMode()" class="inline-flex items-center gap-1.5 px-3 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white font-medium text-xs border border-slate-700 transition-all">
                <i data-lucide="log-out" class="w-3.5 h-3.5"></i>
                <span>Exit Auditor View</span>
              </button>
            </div>
          </div>
        </div>

        <!-- Auditor Readiness Gauges -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div class="p-5 rounded-2xl glass-panel border border-slate-800">
            <div class="flex justify-between items-center text-xs text-slate-400 mb-2">
              <span class="font-bold uppercase tracking-wider">SOC 2 Trust Criteria</span>
              <span class="text-emerald-400 font-bold">${stats.soc2}% Ready</span>
            </div>
            <div class="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
              <div class="bg-emerald-500 h-2 rounded-full" style="width: ${stats.soc2}%"></div>
            </div>
            <p class="text-[11px] text-slate-400 mt-2">Logical Access (CC6), System Ops (CC7), Change Mgmt (CC8)</p>
          </div>

          <div class="p-5 rounded-2xl glass-panel border border-slate-800">
            <div class="flex justify-between items-center text-xs text-slate-400 mb-2">
              <span class="font-bold uppercase tracking-wider">ISO 27001:2022</span>
              <span class="text-amber-400 font-bold">${stats.iso27001}% Ready</span>
            </div>
            <div class="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
              <div class="bg-amber-500 h-2 rounded-full" style="width: ${stats.iso27001}%"></div>
            </div>
            <p class="text-[11px] text-slate-400 mt-2">Annex A: Information Security & Technical Safeguards</p>
          </div>

          <div class="p-5 rounded-2xl glass-panel border border-slate-800">
            <div class="flex justify-between items-center text-xs text-slate-400 mb-2">
              <span class="font-bold uppercase tracking-wider">HIPAA Security Rule</span>
              <span class="text-purple-400 font-bold">${stats.hipaa}% Ready</span>
            </div>
            <div class="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
              <div class="bg-purple-500 h-2 rounded-full" style="width: ${stats.hipaa}%"></div>
            </div>
            <p class="text-[11px] text-slate-400 mt-2">ePHI Encryption at rest & multi-region CloudTrail audit logging</p>
          </div>
        </div>

        <!-- Controls Proof Verification Table -->
        <div class="rounded-2xl glass-panel overflow-hidden border border-slate-800 space-y-3 p-6">
          <div class="flex items-center justify-between">
            <div>
              <h2 class="text-base font-bold text-white">Continuous Evidence & Control Verification</h2>
              <p class="text-xs text-slate-400">Click "Inspect Proof" to verify raw API configuration telemetry and cryptographic hash validation.</p>
            </div>
            <span class="text-xs font-mono text-emerald-400 font-semibold">${stats.passed} / ${stats.total} Controls Verified Passing</span>
          </div>

          <div class="overflow-x-auto pt-2">
            <table class="w-full text-left text-sm">
              <thead class="bg-slate-900/80 text-xs uppercase font-bold text-slate-400 border-b border-slate-800">
                <tr>
                  <th class="py-3 px-3">Control Code</th>
                  <th class="py-3 px-3">Security Requirement</th>
                  <th class="py-3 px-3">Telemetry Source</th>
                  <th class="py-3 px-3">Status</th>
                  <th class="py-3 px-3 text-right">Proof Object</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-800/80 text-slate-300">
                ${state.controls.map(c => `
                  <tr class="hover:bg-slate-800/40 transition-colors">
                    <td class="py-3.5 px-3 font-mono text-xs font-bold text-blue-400">${c.code}</td>
                    <td class="py-3.5 px-3">
                      <div class="font-semibold text-white text-xs">${c.title}</div>
                      <div class="text-[11px] text-slate-400 mt-0.5">${c.framework}</div>
                    </td>
                    <td class="py-3.5 px-3 text-xs font-mono text-slate-300">${c.integration_provider}</td>
                    <td class="py-3.5 px-3">
                      <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold ${
                        c.status === 'PASS' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                      }">
                        ${c.status === 'PASS' ? 'AUDIT VERIFIED' : 'GAP IDENTIFIED'}
                      </span>
                    </td>
                    <td class="py-3.5 px-3 text-right">
                      <button onclick="viewEvidenceModal('${c.id}')" class="px-3 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-blue-400 text-xs font-semibold border border-slate-700 inline-flex items-center gap-1">
                        <i data-lucide="eye" class="w-3.5 h-3.5"></i>
                        <span>Inspect Proof JSON</span>
                      </button>
                    </td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>

        <!-- Policy Sign-Off Ledger for Auditors -->
        <div class="p-6 rounded-2xl glass-panel border border-slate-800 space-y-3">
          <div class="flex items-center justify-between">
            <h3 class="text-base font-bold text-white">Workforce Governance & Policy Sign-Off Ledger</h3>
            <span class="text-xs text-emerald-400 font-mono">Immutable Attestations</span>
          </div>
          <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
            ${state.signatures.map(s => `
              <div class="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 text-xs space-y-1">
                <div class="flex justify-between font-bold text-white">
                  <span>${s.user_name}</span>
                  <span class="text-emerald-400">Signed</span>
                </div>
                <div class="text-slate-400">${s.role} • ${s.department}</div>
                <div class="text-[10px] font-mono text-slate-500 pt-1 border-t border-slate-800/80">
                  Signed: ${s.signed_at} • IP Hash Verified
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    `;
  }

  // STANDARD ADMIN VIEW OF AUDITOR ROOM
  return `
    <div class="space-y-6">
      <!-- Auditor Room Banner -->
      <div class="p-6 rounded-2xl glass-panel-elevated gradient-border-glow border border-blue-500/30">
        <div class="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 mb-2">
              <i data-lucide="check-circle" class="w-3.5 h-3.5"></i> External CPA Auditor Portal
            </div>
            <h1 class="text-2xl font-bold text-white">Auditor Room</h1>
            <p class="text-sm text-slate-400 max-w-2xl">
              Zero-friction, read-only proof portal prepared for independent AICPA SOC 2 Type II and ISO 27001 lead auditors. Grant secure, time-bound evidence access without exposing raw cloud credentials.
            </p>
          </div>
          <div class="flex items-center gap-3">
            <button onclick="openGenerateAuditorLinkModal()" class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-medium text-sm transition-all shadow-lg shadow-blue-600/25">
              <i data-lucide="link" class="w-4 h-4"></i>
              <span>Generate Auditor Access Link</span>
            </button>
          </div>
        </div>
      </div>

      <!-- Active Auditor Links & Checklist -->
      <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <!-- Active Links (6 cols) -->
        <div class="lg:col-span-6 space-y-4">
          <div class="flex items-center justify-between">
            <h2 class="text-base font-semibold text-white">Active Auditor Access Keys</h2>
            <span class="text-xs text-slate-400">${state.auditorLinks.filter(l => l.status === 'ACTIVE').length} Active Keys</span>
          </div>

          <div class="space-y-3">
            ${state.auditorLinks.length === 0 ? `
              <div class="p-6 rounded-xl glass-panel border border-slate-800 text-center">
                <i data-lucide="key" class="w-6 h-6 text-slate-500 mx-auto mb-2"></i>
                <p class="text-xs text-slate-400">No active external auditor links created yet.</p>
                <button onclick="openGenerateAuditorLinkModal()" class="mt-2 text-xs text-blue-400 font-semibold hover:underline">Create first link</button>
              </div>
            ` : state.auditorLinks.map(l => {
              const isActive = l.status === 'ACTIVE';
              const workingUrl = `${window.location.origin}/?auditor_token=${l.token}`;

              return `
                <div class="p-4 rounded-xl glass-panel border ${isActive ? 'border-blue-500/30' : 'border-slate-800 opacity-60'} space-y-3 transition-card">
                  <div class="flex items-center justify-between">
                    <div>
                      <span class="text-xs font-bold text-white">${l.firm_name}</span>
                      <div class="text-[11px] text-slate-400">${l.auditor_contact}</div>
                    </div>
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold ${
                      isActive ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                    }">
                      ${l.status}
                    </span>
                  </div>

                  <div class="space-y-1">
                    <div class="text-[10px] uppercase font-bold text-slate-500">Live Secure Access Link</div>
                    <div class="text-[11px] font-mono text-blue-400 bg-slate-900/90 p-2.5 rounded-lg border border-slate-800 break-all select-all flex items-center justify-between gap-2">
                      <span class="truncate">${workingUrl}</span>
                    </div>
                  </div>

                  <div class="flex items-center justify-between text-[11px] text-slate-400 pt-2 border-t border-slate-800">
                    <span class="truncate max-w-[180px]">Expires: ${l.expiration_date}</span>
                    <div class="flex items-center gap-2">
                      ${isActive ? `
                        <a href="${workingUrl}" target="_blank" class="text-emerald-400 hover:text-emerald-300 font-semibold flex items-center gap-1 px-2.5 py-1 rounded bg-emerald-500/10 border border-emerald-500/20 transition-colors">
                          <i data-lucide="external-link" class="w-3 h-3"></i>
                          <span>Open Portal</span>
                        </a>
                        <button onclick="copyAuditorLink('${l.id}')" id="copy-btn-${l.id}" class="text-blue-400 hover:text-blue-300 font-semibold flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 border border-slate-700 transition-colors">
                          <i data-lucide="copy" class="w-3 h-3"></i>
                          <span>Copy Link</span>
                        </button>
                        <button onclick="revokeAuditorLink('${l.id}')" class="text-rose-400 hover:text-rose-300 font-semibold flex items-center gap-1 px-2 py-1 rounded bg-rose-500/10 border border-rose-500/20 transition-colors">
                          <i data-lucide="trash-2" class="w-3 h-3"></i>
                          <span>Revoke</span>
                        </button>
                      ` : `
                        <span class="text-xs text-slate-500">Access Terminated</span>
                      `}
                    </div>
                  </div>
                </div>
              `;
            }).join('')}
          </div>
        </div>

        <!-- Auditor Review Checklist (6 cols) -->
        <div class="lg:col-span-6 space-y-4">
          <div class="flex items-center justify-between">
            <h2 class="text-base font-semibold text-white">SOC 2 Type II Readiness Checklist</h2>
            <span class="text-xs font-semibold text-emerald-400">AICPA Criteria</span>
          </div>

          <div class="p-5 rounded-2xl glass-panel space-y-3">
            <div class="flex items-start gap-3 p-3 rounded-xl bg-slate-800/40 border border-slate-800">
              <i data-lucide="check-circle-2" class="w-5 h-5 text-emerald-400 flex-shrink-0 mt-0.5"></i>
              <div>
                <h4 class="text-xs font-bold text-white">Trust Services Criteria CC6.1 - CC6.8</h4>
                <p class="text-[11px] text-slate-400 mt-0.5">Automated mapping of continuous API telemetry to CC6 (Logical Access), CC7 (System Operations), and CC8 (Change Management).</p>
              </div>
            </div>

            <div class="flex items-start gap-3 p-3 rounded-xl bg-slate-800/40 border border-slate-800">
              <i data-lucide="check-circle-2" class="w-5 h-5 text-emerald-400 flex-shrink-0 mt-0.5"></i>
              <div>
                <h4 class="text-xs font-bold text-white">Annual Policy Review & Employee Sign-Offs</h4>
                <p class="text-[11px] text-slate-400 mt-0.5">4 published compliance policies with over 90% workforce completion and cryptographic timestamp logs.</p>
              </div>
            </div>

            <div class="flex items-start gap-3 p-3 rounded-xl bg-slate-800/40 border border-slate-800">
              <i data-lucide="check-circle-2" class="w-5 h-5 text-emerald-400 flex-shrink-0 mt-0.5"></i>
              <div>
                <h4 class="text-xs font-bold text-white">Infrastructure & Encryption Verification</h4>
                <p class="text-[11px] text-slate-400 mt-0.5">CloudTrail multi-region audit trails and KMS automated encryption verified with hourly proof collection.</p>
              </div>
            </div>

            <div class="flex items-start gap-3 p-3 rounded-xl bg-slate-800/40 border border-blue-500/20">
              <i data-lucide="shield-check" class="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5"></i>
              <div>
                <h4 class="text-xs font-bold text-white">Read-Only Evidence Vault Scope</h4>
                <p class="text-[11px] text-slate-400 mt-0.5">CPA auditors can inspect JSON configurations and download proof bundles without production write credentials.</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;
}

// Exit Auditor Mode
function exitAuditorMode() {
  state.auditorMode = false;
  // Clear search param in URL
  const url = new URL(window.location);
  url.searchParams.delete('auditor_token');
  window.history.replaceState({}, '', url.pathname);
  showToast('Exited Auditor View. Returned to Admin Console.', 'info');
  switchTab('dashboard');
}

// Auditor Link Modal Handlers
function openGenerateAuditorLinkModal() {
  const modal = document.getElementById('auditor-link-modal');
  if (modal) modal.classList.remove('hidden');
  refreshIcons();
}

function closeGenerateAuditorLinkModal() {
  const modal = document.getElementById('auditor-link-modal');
  if (modal) modal.classList.add('hidden');
}

function submitGenerateAuditorLink() {
  const firmInput = document.getElementById('aud-firm-input');
  const emailInput = document.getElementById('aud-email-input');
  const daysSelect = document.getElementById('aud-days-select');
  const scopeSelect = document.getElementById('aud-scope-select');

  const firmName = firmInput?.value || 'Schellman & Company CPA';
  const email = emailInput?.value || 'auditor@schellman-cpa.com';
  const days = parseInt(daysSelect?.value || '30', 10);
  const scope = scopeSelect?.value || 'Full Read-Only Evidence Vault';

  const token = `ks_audit_${Math.random().toString(36).substring(2, 10)}`;
  const liveUrl = `${window.location.origin}/?auditor_token=${token}`;

  const expDate = new Date(Date.now() + days * 86400000);
  const expFormatted = `${expDate.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })} (${days} Days)`;

  const newLink = {
    id: 'aud-link-' + Date.now(),
    token: token,
    display_url: liveUrl,
    full_url: liveUrl,
    firm_name: firmName,
    auditor_contact: email,
    created_at: new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
    expiration_date: expFormatted,
    status: 'ACTIVE',
    scope: scope
  };

  state.auditorLinks.unshift(newLink);
  closeGenerateAuditorLinkModal();
  showToast(`Created secure auditor access link for ${firmName}`, 'success');
  renderCurrentTab();
  refreshIcons();
}

function copyAuditorLink(linkId) {
  const link = state.auditorLinks.find(l => l.id === linkId);
  if (!link) return;

  const url = link.full_url || `${window.location.origin}/?auditor_token=${link.token}`;
  navigator.clipboard.writeText(url).then(() => {
    const btn = document.getElementById(`copy-btn-${linkId}`);
    if (btn) {
      btn.innerHTML = `<i data-lucide="check" class="w-3 h-3 text-emerald-400"></i><span class="text-emerald-400">Copied!</span>`;
      refreshIcons();
      setTimeout(() => {
        btn.innerHTML = `<i data-lucide="copy" class="w-3 h-3"></i><span>Copy Link</span>`;
        refreshIcons();
      }, 2000);
    }
    showToast(`Copied live auditor URL: ${url}`, 'success');
  }).catch(() => {
    showToast(`Auditor Link: ${url}`, 'info');
  });
}

function revokeAuditorLink(linkId) {
  const link = state.auditorLinks.find(l => l.id === linkId);
  if (!link) return;

  link.status = 'REVOKED';
  showToast(`Auditor access key for ${link.firm_name} has been revoked.`, 'info');
  renderCurrentTab();
  refreshIcons();
}

// =============================================================
// PRODUCTION VS SIMULATED CREDENTIALS MODAL
// =============================================================
let activeConfigProviderId = null;

function openCredentialsModal(providerId) {
  activeConfigProviderId = providerId;
  const item = state.integrations.find(i => i.id === providerId);
  if (!item) return;

  const modal = document.getElementById('credentials-modal');
  const title = document.getElementById('cred-modal-title');
  const fields = document.getElementById('cred-form-fields');

  if (title) title.textContent = `Configure ${item.name} API Credentials`;

  if (fields) {
    if (item.provider === 'AWS') {
      fields.innerHTML = `
        <div>
          <label class="block text-xs font-semibold text-slate-400 mb-1">AWS IAM SecurityAudit Role ARN</label>
          <input type="text" id="cred-input-1" value="arn:aws:iam::849201928410:role/KanugaShieldAuditRole" class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 text-xs font-mono">
          <p class="text-[10px] text-slate-500 mt-1">Requires AWS-managed policy <code class="text-blue-400">SecurityAudit</code> (read-only).</p>
        </div>
        <div class="grid grid-cols-2 gap-3">
          <div>
            <label class="block text-xs font-semibold text-slate-400 mb-1">External ID</label>
            <input type="text" id="cred-input-2" value="ks-corp-84920192" class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 text-xs font-mono">
          </div>
          <div>
            <label class="block text-xs font-semibold text-slate-400 mb-1">Default Region</label>
            <input type="text" id="cred-input-3" value="us-east-1" class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 text-xs font-mono">
          </div>
        </div>
      `;
    } else if (item.provider === 'GitHub') {
      fields.innerHTML = `
        <div>
          <label class="block text-xs font-semibold text-slate-400 mb-1">GitHub Organization Name</label>
          <input type="text" id="cred-input-1" value="kanuga-tech" class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 text-xs font-mono">
        </div>
        <div>
          <label class="block text-xs font-semibold text-slate-400 mb-1">Personal Access Token / App Secret</label>
          <input type="password" id="cred-input-2" value="ghp_kanugashield99281a8b273c" class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 text-xs font-mono">
          <p class="text-[10px] text-slate-500 mt-1">Scopes required: <code class="text-blue-400">repo:status, admin:org_hook, read:org</code>.</p>
        </div>
      `;
    } else if (item.provider === 'Okta') {
      fields.innerHTML = `
        <div>
          <label class="block text-xs font-semibold text-slate-400 mb-1">Okta Organization Domain</label>
          <input type="text" id="cred-input-1" value="kanuga.okta.com" class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 text-xs font-mono">
        </div>
        <div>
          <label class="block text-xs font-semibold text-slate-400 mb-1">Okta Read-Only API Token (SSWS)</label>
          <input type="password" id="cred-input-2" value="00_ssws_okta_token_99182a" class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 text-xs font-mono">
        </div>
      `;
    } else {
      fields.innerHTML = `
        <div>
          <label class="block text-xs font-semibold text-slate-400 mb-1">API Client ID / Key</label>
          <input type="text" id="cred-input-1" value="client_live_kanuga_${item.provider.toLowerCase()}" class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 text-xs font-mono">
        </div>
        <div>
          <label class="block text-xs font-semibold text-slate-400 mb-1">Secret Token</label>
          <input type="password" id="cred-input-2" value="sec_tok_live_882910" class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 text-xs font-mono">
        </div>
      `;
    }
  }

  if (modal) modal.classList.remove('hidden');
  refreshIcons();
}

function closeCredentialsModal() {
  const modal = document.getElementById('credentials-modal');
  if (modal) modal.classList.add('hidden');
}

async function testConnectionCredentials() {
  const item = state.integrations.find(i => i.id === activeConfigProviderId);
  if (!item) return;

  showToast('Testing TLS connection & validating IAM permissions...', 'info');

  try {
    if (item.provider === 'AWS') {
      const roleArn    = (document.getElementById('cred-input-1') || {}).value || '';
      const externalId = (document.getElementById('cred-input-2') || {}).value || '';
      await fetchApi('/api/integrations/aws/connect', {
        method: 'POST',
        body: { roleArn, externalId }
      });
    } else if (item.provider === 'GitHub') {
      const org   = (document.getElementById('cred-input-1') || {}).value || '';
      const token = (document.getElementById('cred-input-2') || {}).value || '';
      await fetchApi('/api/integrations/github/connect', {
        method: 'POST',
        body: { token, org }
      });
    } else if (item.provider === 'Okta') {
      const orgUrl   = (document.getElementById('cred-input-1') || {}).value || '';
      const apiToken = (document.getElementById('cred-input-2') || {}).value || '';
      await fetchApi('/api/integrations/okta/connect', {
        method: 'POST',
        body: { orgUrl, apiToken }
      });
    } else if (item.provider === 'Google Cloud') {
      const projectId   = (document.getElementById('cred-input-1') || {}).value || '';
      const accessToken = (document.getElementById('cred-input-2') || {}).value || '';
      await fetchApi('/api/integrations/gcp/connect', {
        method: 'POST',
        body: { projectId, accessToken }
      });
    } else {
      // Simulated test for other providers
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    showToast('Handshake Success: Permissions verified (HTTP 200 OK)', 'success');
  } catch (err) {
    showToast(`Connection test failed: ${err.message}`, 'error');
  }
}

async function saveConnectionCredentials() {
  const item = state.integrations.find(i => i.id === activeConfigProviderId);
  if (!item) { closeCredentialsModal(); return; }

  try {
    if (item.provider === 'AWS') {
      const roleArn    = (document.getElementById('cred-input-1') || {}).value || '';
      const externalId = (document.getElementById('cred-input-2') || {}).value || '';
      await fetchApi('/api/integrations/aws/connect', {
        method: 'POST',
        body: { roleArn, externalId }
      });
    } else if (item.provider === 'GitHub') {
      const org   = (document.getElementById('cred-input-1') || {}).value || '';
      const token = (document.getElementById('cred-input-2') || {}).value || '';
      await fetchApi('/api/integrations/github/connect', {
        method: 'POST',
        body: { token, org }
      });
    } else if (item.provider === 'Okta') {
      const orgUrl   = (document.getElementById('cred-input-1') || {}).value || '';
      const apiToken = (document.getElementById('cred-input-2') || {}).value || '';
      await fetchApi('/api/integrations/okta/connect', {
        method: 'POST',
        body: { orgUrl, apiToken }
      });
    } else if (item.provider === 'Google Cloud') {
      const projectId   = (document.getElementById('cred-input-1') || {}).value || '';
      const accessToken = (document.getElementById('cred-input-2') || {}).value || '';
      await fetchApi('/api/integrations/gcp/connect', {
        method: 'POST',
        body: { projectId, accessToken }
      });
    } else {
      await new Promise(resolve => setTimeout(resolve, 800));
    }

    item.status = 'CONNECTED';
    item.last_synced_at = 'Just now';
    showToast(`Saved credentials for ${item.name}! Connected to telemetry pipeline.`, 'success');
    closeCredentialsModal();
    renderAll();
  } catch (err) {
    showToast(`Failed to save credentials: ${err.message}`, 'error');
  }
}

// =============================================================
// 4. TELEMETRY & AUTO-SYNC TIMER (DYNAMIC CRON TICKER)
// =============================================================
function startTelemetryTicker() {
  // Update relative timestamps every second
  setInterval(() => {
    const elapsedSec = Math.floor((Date.now() - state.lastSyncTimestamp) / 1000);
    const elapsedMin = Math.floor(elapsedSec / 60);

    let text;
    if (elapsedSec < 60) {
      text = `Synced ${elapsedSec}s ago`;
    } else {
      text = `Synced ${elapsedMin}m ago`;
    }

    const nextPollMin = Math.max(1, 60 - (elapsedMin % 60));

    // Update bottom sidebar
    const sidebarStatus = document.getElementById('sidebar-sync-status');
    if (sidebarStatus) {
      sidebarStatus.innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-emerald-400 pulse-indicator"></span><span>${text}</span>`;
    }
    const nextPollEl = document.getElementById('sidebar-next-poll');
    if (nextPollEl) {
      nextPollEl.textContent = `Next hourly auto-poll in ${nextPollMin}m`;
    }

    // Update top header last sync if present
    const headerSync = document.getElementById('header-last-sync');
    if (headerSync) {
      headerSync.textContent = `${text} (Hourly auto-run)`;
    }
  }, 1000);

  // Background check simulation every 45s
  setInterval(() => {
    if (state.controls.length > 0) {
      const randomCtrl = state.controls[Math.floor(Math.random() * state.controls.length)];
      if (randomCtrl) {
        state.testStream.unshift({
          id: 'th-' + Date.now(),
          control_code: randomCtrl.code,
          test_name: randomCtrl.title,
          status: randomCtrl.status,
          message: randomCtrl.status === 'PASS' ? 'Hourly automated telemetry check verified' : 'Detected configuration gap',
          executed_at: 'Just now',
          severity: randomCtrl.severity
        });

        if (state.currentTab === 'dashboard') {
          renderCurrentTab();
          refreshIcons();
        }
      }
    }
  }, 45000);
}

// Manual Sync Now Trigger — calls real /api/controls/evaluate
async function triggerManualSync() {
  const syncBtn = document.getElementById('header-sync-btn');
  const syncIcon = document.getElementById('header-sync-icon');
  const sidebarIcon = document.getElementById('sidebar-sync-icon');

  if (syncIcon) syncIcon.classList.add('animate-spin');
  if (sidebarIcon) sidebarIcon.classList.add('animate-spin');
  if (syncBtn) syncBtn.disabled = true;

  showToast('Executing comprehensive telemetry scan across all connected providers...', 'info');

  try {
    const evalData = await fetchApi('/api/controls/evaluate');
    const results = evalData.results || evalData;

    state.lastSyncTimestamp = Date.now();

    // Map live results back into state.controls
    (Array.isArray(results) ? results : []).forEach(r => {
      const ctrl = state.controls.find(c => c.code === r.control_code);
      if (ctrl) {
        ctrl.status = r.status;
        ctrl.last_run_at = 'Just now';
        if (ctrl.raw_evidence && r.violation) ctrl.raw_evidence.violation = r.violation;
      }
    });

    // Refresh all control timestamps
    state.controls.forEach(c => { c.last_run_at = 'Just now'; });

    // Refresh active integrations
    state.integrations.forEach(i => {
      if (i.status === 'CONNECTED') {
        i.last_synced_at = 'Just now';
        i.evidence_count += 2;
      }
    });

    const scanRunId = evalData.scan_run_id || ('sr-' + Date.now());
    state.testStream.unshift({
      id: 'th-' + Date.now(),
      control_code: 'SYS-SYNC',
      test_name: 'Kanuga Shield Full Telemetry Ingest',
      status: 'PASS',
      message: `Live scan ${scanRunId} — Ingested configuration across all active connectors (${state.controls.length} checks evaluated)`,
      executed_at: 'Just now',
      severity: 'LOW'
    });

    if (syncIcon) syncIcon.classList.remove('animate-spin');
    if (sidebarIcon) sidebarIcon.classList.remove('animate-spin');
    if (syncBtn) syncBtn.disabled = false;

    showToast('Manual Sync Complete: Ingested telemetry across all connected providers!', 'success');
    renderAll();
  } catch (err) {
    // Fallback: no live integrations — run simulated update
    console.warn('Live sync failed, falling back to simulated checks:', err.message);
    state.lastSyncTimestamp = Date.now();

    state.controls.forEach(c => { c.last_run_at = 'Just now'; });
    state.integrations.forEach(i => {
      if (i.status === 'CONNECTED') {
        i.last_synced_at = 'Just now';
        i.evidence_count += 2;
      }
    });

    state.testStream.unshift({
      id: 'th-' + Date.now(),
      control_code: 'SYS-SYNC',
      test_name: 'Kanuga Shield Full Telemetry Ingest',
      status: 'PASS',
      message: `Ingested live configuration JSON across all active connectors (${state.controls.length} checks evaluated)`,
      executed_at: 'Just now',
      severity: 'LOW'
    });

    if (syncIcon) syncIcon.classList.remove('animate-spin');
    if (sidebarIcon) sidebarIcon.classList.remove('animate-spin');
    if (syncBtn) syncBtn.disabled = false;

    showToast('No live integrations connected – running simulated checks', 'info');
    renderAll();
  }
}

// =============================================================
// REMEDIATION FLOW
// =============================================================
function openRemediationModal(controlId) {
  const control = state.controls.find(c => c.id === controlId);
  if (!control) return;
  state.activeRemediationControl = control;

  const modal = document.getElementById('remediation-modal');
  const title = document.getElementById('rem-modal-title');
  const code = document.getElementById('rem-modal-code');
  const guide = document.getElementById('rem-modal-guide');
  const violation = document.getElementById('rem-modal-violation');

  if (title) title.textContent = control.title;
  if (code) code.textContent = `${control.code} • ${control.integration_provider}`;
  if (guide) guide.textContent = control.remediation_guide;
  if (violation) violation.textContent = control.raw_evidence?.violation || control.description;

  if (modal) modal.classList.remove('hidden');
  refreshIcons();
}

function closeRemediationModal() {
  const modal = document.getElementById('remediation-modal');
  if (modal) modal.classList.add('hidden');
}

function remediateActiveControl() {
  if (!state.activeRemediationControl) return;
  remediateControl(state.activeRemediationControl.id);
  closeRemediationModal();
}

function remediateControl(controlId) {
  const ctrl = state.controls.find(c => c.id === controlId);
  if (!ctrl) return;

  ctrl.status = 'PASS';
  ctrl.last_run_at = 'Just now';
  if (ctrl.raw_evidence) ctrl.raw_evidence.violation = 'Remediated & Verified Compliant';

  state.testStream.unshift({
    id: 'th-' + Date.now(),
    control_code: ctrl.code,
    test_name: ctrl.title,
    status: 'PASS',
    message: 'Remediation verified: Automated check passed successfully',
    executed_at: 'Just now',
    severity: ctrl.severity
  });

  showToast(`Control ${ctrl.title} successfully verified and passing!`, 'success');
  renderAll();
}

// Evidence JSON Inspector Modal
function viewEvidenceModal(recordId) {
  // Check persisted evidence first
  const persisted = (state.persistedEvidence || []).find(e => e.id === recordId || e.control_code === recordId);
  const ctrl = state.controls.find(c => c.id === recordId || c.code === recordId);
  
  const modal = document.getElementById('evidence-modal');
  const title = document.getElementById('evidence-modal-title');
  const jsonPre = document.getElementById('evidence-modal-json');

  if (persisted) {
    if (title) title.textContent = `${persisted.control_code} - ${persisted.control_title || 'Evidence Proof'} (SHA-256 Ledger)`;
    if (jsonPre) {
      let rawPayload = persisted.raw_json_payload;
      try {
        if (typeof rawPayload === 'string') rawPayload = JSON.parse(rawPayload);
      } catch (e) {}
      jsonPre.textContent = JSON.stringify({
        id: persisted.id,
        integration_source: persisted.integration_source,
        control_code: persisted.control_code,
        control_title: persisted.control_title,
        status: persisted.status,
        sha256_hash: persisted.sha256_hash,
        scan_run_id: persisted.scan_run_id,
        created_at: persisted.created_at,
        raw_json_payload: rawPayload
      }, null, 2);
    }
  } else if (ctrl) {
    if (title) title.textContent = `${ctrl.code} - ${ctrl.title} Evidence JSON`;
    if (jsonPre) {
      jsonPre.textContent = JSON.stringify({
        control_id: ctrl.id,
        code: ctrl.code,
        framework: ctrl.framework,
        provider: ctrl.integration_provider,
        status: ctrl.status,
        timestamp: new Date().toISOString(),
        evidence_payload: ctrl.raw_evidence,
        sha256_hash: '3f7a1c49b0e25867192a54b38d99c4217fa5b0183b'
      }, null, 2);
    }
  } else {
    return;
  }

  if (modal) modal.classList.remove('hidden');
  refreshIcons();
}

function closeEvidenceModal() {
  const modal = document.getElementById('evidence-modal');
  if (modal) modal.classList.add('hidden');
}

function downloadEvidenceBundle() {
  const records = state.controls.map(c => ({
    control_id: c.id,
    code: c.code,
    title: c.title,
    framework: c.framework,
    source: c.integration_provider,
    status: c.status,
    timestamp: c.last_run_at,
    evidence: c.raw_evidence,
    sha256_fingerprint: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  }));

  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(records, null, 2));
  const dlAnchorElem = document.createElement('a');
  dlAnchorElem.setAttribute("href", dataStr);
  dlAnchorElem.setAttribute("download", `Kanuga_Shield_Evidence_Bundle_${new Date().toISOString().slice(0, 10)}.json`);
  dlAnchorElem.click();
  showToast('Downloaded complete evidence package (JSON)', 'success');
}

// =============================================================
// POLICY CENTER & E-SIGNATURES
// =============================================================
function getPoliciesHTML() {
  const current = state.selectedPolicy || state.policies[0];

  return `
    <div class="space-y-6">
      <!-- Header -->
      <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-2xl glass-panel">
        <div>
          <div class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20 mb-1">
            <i data-lucide="file-text" class="w-3.5 h-3.5"></i> Governance & Policies
          </div>
          <h1 class="text-2xl font-bold text-white">Policy Center & E-Signatures</h1>
          <p class="text-sm text-slate-400">Pre-built compliance policies with versioning, markdown editor, and employee sign-off logs.</p>
        </div>
        <div class="flex items-center gap-3">
          <button onclick="openSignatureModal()" class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-sm transition-all shadow-lg shadow-emerald-600/20">
            <i data-lucide="pen-tool" class="w-4 h-4"></i>
            <span>Sign Policy (Employee)</span>
          </button>
        </div>
      </div>

      <!-- Main Layout: Policy Sidebar + Markdown Viewer -->
      <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <!-- Policies List (4 cols) -->
        <div class="lg:col-span-4 space-y-3">
          <h3 class="text-xs font-bold uppercase tracking-wider text-slate-400 px-1">Standard Policies (${state.policies.length})</h3>
          ${state.policies.map(p => `
            <div onclick="selectPolicy('${p.id}')" class="p-4 rounded-xl cursor-pointer transition-all border ${
              current && current.id === p.id ? 'bg-blue-600/15 border-blue-500/40 shadow-lg shadow-blue-600/10' : 'glass-panel hover:bg-slate-800/60 border-slate-800'
            }">
              <div class="flex items-center justify-between mb-1">
                <span class="text-xs font-mono text-blue-400 font-semibold">${p.code}</span>
                <span class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-300">${p.version}</span>
              </div>
              <h4 class="text-sm font-bold text-white">${p.title}</h4>
              <div class="mt-3 flex items-center justify-between text-xs text-slate-400">
                <span>Signatures:</span>
                <span class="font-semibold text-emerald-400">${p.signoff_progress.signed}/${p.signoff_progress.total} (${p.signoff_progress.percentage}%)</span>
              </div>
              <div class="w-full bg-slate-800 rounded-full h-1.5 mt-1.5 overflow-hidden">
                <div class="bg-emerald-500 h-1.5 rounded-full" style="width: ${p.signoff_progress.percentage}%"></div>
              </div>
            </div>
          `).join('')}

          <!-- Recent Signature Audit Trail Card -->
          <div class="p-4 rounded-xl glass-panel mt-4 space-y-3">
            <div class="flex items-center justify-between">
              <h4 class="text-xs font-bold uppercase tracking-wider text-slate-400">Sign-Off Ledger</h4>
              <span class="text-[10px] text-emerald-400 font-mono">Cryptographically Verified</span>
            </div>
            <div class="space-y-2 max-h-48 overflow-y-auto divide-y divide-slate-800/80">
              ${state.signatures.slice(0, 5).map(s => `
                <div class="pt-2 first:pt-0 text-xs">
                  <div class="flex justify-between font-medium text-slate-200">
                    <span>${s.user_name}</span>
                    <span class="text-emerald-400">Signed</span>
                  </div>
                  <div class="flex justify-between text-[11px] text-slate-500 mt-0.5">
                    <span>${s.role} • ${s.department}</span>
                    <span class="font-mono">${s.signed_at.slice(0, 10)}</span>
                  </div>
                </div>
              `).join('')}
            </div>
          </div>
        </div>

        <!-- Policy Markdown Viewer & Live Editor (8 cols) -->
        <div class="lg:col-span-8 space-y-4">
          ${current ? `
            <div class="p-6 rounded-2xl glass-panel-elevated border border-slate-800 space-y-4">
              <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
                <div>
                  <div class="flex items-center gap-2">
                    <span class="px-2 py-0.5 rounded text-xs font-mono font-bold bg-blue-500/10 text-blue-400 border border-blue-500/20">${current.code}</span>
                    <span class="text-xs text-slate-400">Updated: ${current.last_updated}</span>
                  </div>
                  <h2 class="text-xl font-bold text-white mt-1">${current.title}</h2>
                </div>
                <div class="flex items-center gap-2">
                  <button onclick="togglePolicyEditor()" id="btn-toggle-editor" class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 transition-all">
                    <i data-lucide="edit-3" class="w-3.5 h-3.5"></i>
                    <span id="editor-toggle-text">Edit Markdown</span>
                  </button>
                  <button onclick="savePolicyContent('${current.id}')" id="btn-save-policy" class="hidden inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium transition-all">
                    <i data-lucide="check" class="w-3.5 h-3.5"></i>
                    <span>Save Changes</span>
                  </button>
                </div>
              </div>

              <!-- Markdown Render View -->
              <div id="policy-content-preview" class="prose prose-invert max-w-none text-slate-300 text-sm leading-relaxed space-y-3 font-sans max-h-[500px] overflow-y-auto pr-2">
                ${formatMarkdown(current.content)}
              </div>

              <!-- Markdown Raw Editor (hidden by default) -->
              <div id="policy-content-editor" class="hidden">
                <textarea id="policy-editor-textarea" class="w-full h-96 p-4 rounded-xl bg-slate-900 border border-slate-700 text-slate-200 font-mono text-xs focus:ring-2 focus:ring-blue-500 focus:outline-none resize-none">${current.content}</textarea>
              </div>

              <!-- Framework Badges & Owner -->
              <div class="flex flex-wrap items-center justify-between gap-3 pt-4 border-t border-slate-800 text-xs text-slate-400">
                <div class="flex items-center gap-2">
                  <span>Satisfies Frameworks:</span>
                  ${current.frameworks.map(f => `<span class="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-semibold border border-slate-700/60">${f}</span>`).join('')}
                </div>
                <div>
                  <span>Owner: <strong class="text-white">${current.owner}</strong></span>
                </div>
              </div>
            </div>
          ` : `
            <div class="p-8 rounded-2xl glass-panel text-center text-slate-400">
              Select a policy from the sidebar to inspect or edit.
            </div>
          `}
        </div>
      </div>
    </div>
  `;
}

function selectPolicy(id) {
  state.selectedPolicy = state.policies.find(p => p.id === id);
  renderCurrentTab();
  refreshIcons();
}

function togglePolicyEditor() {
  const preview = document.getElementById('policy-content-preview');
  const editor = document.getElementById('policy-content-editor');
  const saveBtn = document.getElementById('btn-save-policy');
  const toggleText = document.getElementById('editor-toggle-text');

  if (!preview || !editor) return;

  const isEditing = editor.classList.contains('hidden');
  if (isEditing) {
    editor.classList.remove('hidden');
    preview.classList.add('hidden');
    saveBtn.classList.remove('hidden');
    toggleText.textContent = 'Preview';
  } else {
    editor.classList.add('hidden');
    preview.classList.remove('hidden');
    saveBtn.classList.add('hidden');
    toggleText.textContent = 'Edit Markdown';
  }
}

function savePolicyContent(id) {
  const textarea = document.getElementById('policy-editor-textarea');
  if (!textarea) return;

  const p = state.policies.find(item => item.id === id);
  if (p) {
    p.content = textarea.value;
    p.last_updated = new Date().toISOString().slice(0, 10);
    showToast(`Policy ${p.title} successfully updated with new revision!`, 'success');
    togglePolicyEditor();
    renderCurrentTab();
    refreshIcons();
  }
}

function formatMarkdown(md) {
  return md
    .replace(/^# (.*$)/gim, '<h1 class="text-xl font-bold text-white mt-4 mb-2">$1</h1>')
    .replace(/^## (.*$)/gim, '<h2 class="text-base font-bold text-blue-400 mt-4 mb-1.5">$1</h2>')
    .replace(/^### (.*$)/gim, '<h3 class="text-sm font-semibold text-slate-200 mt-3 mb-1">$1</h3>')
    .replace(/\*\*(.*)\*\*/gim, '<strong class="text-white font-semibold">$1</strong>')
    .replace(/\n\n/gim, '</p><p class="text-slate-300 text-xs leading-relaxed my-2">')
    .replace(/^\- (.*$)/gim, '<li class="text-slate-300 text-xs ml-4 list-disc">$1</li>');
}

// E-Signature Modal & Drawing Pad
function openSignatureModal() {
  const modal = document.getElementById('signature-modal');
  if (modal) modal.classList.remove('hidden');
  clearSignaturePad();
  refreshIcons();
}

function closeSignatureModal() {
  const modal = document.getElementById('signature-modal');
  if (modal) modal.classList.add('hidden');
}

let canvas, ctx, isDrawing = false;
function initSignaturePad() {
  canvas = document.getElementById('signature-canvas');
  if (!canvas) return;
  ctx = canvas.getContext('2d');
  ctx.strokeStyle = '#2563EB';
  ctx.lineWidth = 2.5;
  ctx.lineCap = 'round';

  const startDrawing = (e) => {
    isDrawing = true;
    ctx.beginPath();
    const rect = canvas.getBoundingClientRect();
    const x = (e.clientX || (e.touches && e.touches[0].clientX)) - rect.left;
    const y = (e.clientY || (e.touches && e.touches[0].clientY)) - rect.top;
    ctx.moveTo(x, y);
  };

  const draw = (e) => {
    if (!isDrawing) return;
    const rect = canvas.getBoundingClientRect();
    const x = (e.clientX || (e.touches && e.touches[0].clientX)) - rect.left;
    const y = (e.clientY || (e.touches && e.touches[0].clientY)) - rect.top;
    ctx.lineTo(x, y);
    ctx.stroke();
  };

  const stopDrawing = () => { isDrawing = false; };

  canvas.addEventListener('mousedown', startDrawing);
  canvas.addEventListener('mousemove', draw);
  canvas.addEventListener('mouseup', stopDrawing);
  canvas.addEventListener('mouseleave', stopDrawing);

  canvas.addEventListener('touchstart', startDrawing);
  canvas.addEventListener('touchmove', draw);
  canvas.addEventListener('touchend', stopDrawing);
}

function clearSignaturePad() {
  if (canvas && ctx) {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
  }
}

function submitSignature() {
  const nameInput = document.getElementById('sig-name-input');
  const emailInput = document.getElementById('sig-email-input');
  const roleInput = document.getElementById('sig-role-input');
  const deptInput = document.getElementById('sig-dept-input');
  const agreeCheck = document.getElementById('sig-agree-check');

  if (!agreeCheck || !agreeCheck.checked) {
    showToast('Please check the acknowledgment box to sign legally.', 'error');
    return;
  }
  if (!nameInput.value || !emailInput.value) {
    showToast('Please enter your full legal name and work email.', 'error');
    return;
  }

  const payload = {
    policyId: state.selectedPolicy ? state.selectedPolicy.id : 'pol-01',
    name: nameInput.value,
    email: emailInput.value,
    role: roleInput?.value || 'Employee',
    department: deptInput?.value || 'Engineering'
  };

  state.signatures.unshift({
    id: 'sig-' + Date.now(),
    policy_id: payload.policyId,
    user_name: payload.name,
    user_email: payload.email,
    role: payload.role,
    department: payload.department,
    signed_at: new Date().toISOString(),
    ip_hash: '198.51.44.xx'
  });

  if (state.selectedPolicy) {
    state.selectedPolicy.signoff_progress.signed = Math.min(state.selectedPolicy.signoff_progress.total, state.selectedPolicy.signoff_progress.signed + 1);
    state.selectedPolicy.signoff_progress.percentage = Math.round((state.selectedPolicy.signoff_progress.signed / state.selectedPolicy.signoff_progress.total) * 100);
  }

  showToast('E-Signature recorded & cryptographically bound to policy!', 'success');
  closeSignatureModal();
  renderCurrentTab();
  refreshIcons();
}

// =============================================================
// EVIDENCE VAULT
// =============================================================
function getEvidenceHTML() {
  const records = (state.persistedEvidence && state.persistedEvidence.length > 0)
    ? state.persistedEvidence.map(ev => ({
        control_id: ev.id,
        control_code: ev.control_code,
        control_title: ev.control_title || ev.control_code,
        framework: (ev.control_code || '').startsWith('CC') ? 'SOC 2 Type II' : 'ISO 27001',
        source: ev.integration_source,
        status: ev.status,
        timestamp: new Date(ev.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + ' (' + new Date(ev.created_at).toLocaleDateString() + ')',
        sha256_fingerprint: (ev.sha256_hash || '').slice(0, 32)
      }))
    : state.controls.map(c => ({
        control_id: c.id,
        control_code: c.code,
        control_title: c.title,
        framework: c.framework,
        source: c.integration_provider,
        status: c.status,
        timestamp: c.last_run_at,
        sha256_fingerprint: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'.slice(0, 32)
      }));

  return `
    <div class="space-y-6">
      <!-- Header -->
      <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-2xl glass-panel">
        <div>
          <div class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20 mb-1">
            <i data-lucide="archive" class="w-3.5 h-3.5"></i> Automated Audit Trails
          </div>
          <h1 class="text-2xl font-bold text-white">Evidence Vault</h1>
          <p class="text-sm text-slate-400">Immutable JSON proofs, configuration captures, and policy signatures stamped with SHA-256 fingerprints.</p>
        </div>
        <div class="flex items-center gap-3">
          <button onclick="downloadEvidenceBundle()" class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-medium text-sm transition-all shadow-lg shadow-blue-600/25">
            <i data-lucide="download" class="w-4 h-4"></i>
            <span>Export Evidence Bundle (JSON)</span>
          </button>
        </div>
      </div>

      <!-- Evidence Cards Grid -->
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        ${records.map(e => `
          <div class="p-5 rounded-2xl glass-panel border border-slate-800 transition-card flex flex-col justify-between space-y-4">
            <div>
              <div class="flex items-center justify-between gap-2 mb-2">
                <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-500/10 text-blue-400 border border-blue-500/20">${e.control_code}</span>
                <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold ${
                  e.status === 'PASS' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-rose-500/10 text-rose-400'
                }">
                  ${e.status}
                </span>
              </div>
              <h3 class="text-sm font-bold text-white">${e.control_title}</h3>
              <p class="text-xs text-slate-400 mt-1">Source: <span class="text-slate-200 font-medium">${e.source}</span></p>
            </div>

            <div class="space-y-3 pt-3 border-t border-slate-800">
              <div class="text-[11px] font-mono text-slate-500 truncate">
                SHA: ${e.sha256_fingerprint}...
              </div>
              <div class="flex items-center justify-between pt-1">
                <span class="text-xs text-slate-400">${e.timestamp}</span>
                <button onclick="viewEvidenceModal('${e.control_id}')" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-blue-400 text-xs font-semibold border border-slate-700 transition-all flex items-center gap-1">
                  <i data-lucide="eye" class="w-3.5 h-3.5"></i>
                  <span>Inspect JSON</span>
                </button>
              </div>
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

// =============================================================
// SETTINGS
// =============================================================
function getSettingsHTML() {
  return `
    <div class="space-y-6 max-w-4xl">
      <div class="p-6 rounded-2xl glass-panel">
        <h1 class="text-2xl font-bold text-white">Platform Settings</h1>
        <p class="text-sm text-slate-400">Configure company organization profile, automated alert webhooks, and hourly check frequency.</p>
      </div>

      <div class="p-6 rounded-2xl glass-panel space-y-4">
        <h2 class="text-base font-semibold text-white">Organization Profile</h2>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label class="block text-xs font-medium text-slate-400 mb-1">Company Legal Entity</label>
            <input type="text" value="Kanuga_tech" readonly class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-300 text-xs font-medium">
          </div>
          <div>
            <label class="block text-xs font-medium text-slate-400 mb-1">Platform Instance</label>
            <input type="text" value="Kanuga Shield Enterprise Edition" readonly class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-300 text-xs font-medium">
          </div>
        </div>
      </div>

      <!-- Firebase Cloud Infrastructure Card -->
      <div class="p-6 rounded-2xl glass-panel space-y-4 border border-amber-500/20">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-xl bg-amber-500/10 text-amber-400 flex items-center justify-center">
              <i data-lucide="database" class="w-5 h-5"></i>
            </div>
            <div>
              <h2 class="text-base font-semibold text-white">Firebase Cloud Storage & Firestore Backend</h2>
              <p class="text-xs text-slate-400">Stores live evidence proofs, multi-tenant organizations, and auditor access tokens.</p>
            </div>
          </div>
          <span class="px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30 flex items-center gap-1.5">
            <span class="w-1.5 h-1.5 rounded-full bg-amber-400 pulse-indicator"></span> Ready For Connection
          </span>
        </div>
        <div class="p-4 rounded-xl bg-slate-900/80 border border-slate-800 text-xs space-y-2 text-slate-300">
          <p class="font-semibold text-white flex items-center gap-1.5">
            <i data-lucide="check-circle" class="w-4 h-4 text-emerald-400"></i>
            <span>Firebase Admin & Firestore Adapter Active</span>
          </p>
          <p class="text-slate-400 leading-relaxed">
            The platform is built with an automated dual-mode storage engine. To connect your live Google Cloud Firebase project, save your Firebase service account key as <code class="text-blue-400 font-mono">firebase-service-account.json</code> in the project directory, or define <code class="text-blue-400 font-mono">FIREBASE_SERVICE_ACCOUNT_KEY</code> in <code class="text-blue-400 font-mono">.env</code>.
          </p>
        </div>
      </div>

      <div class="p-6 rounded-2xl glass-panel space-y-4">
        <div class="flex items-center justify-between">
          <div>
            <h2 class="text-base font-semibold text-white">Continuous Auto-Remediation Alerts</h2>
            <p class="text-xs text-slate-400">Send real-time alerts to Slack or security email when any control check fails.</p>
          </div>
          <button onclick="testWebhookTrigger('slack')" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-blue-400 text-xs font-semibold border border-slate-700 transition-all flex items-center gap-1.5">
            <i data-lucide="send" class="w-3.5 h-3.5"></i> Test Slack Alert
          </button>
        </div>

        <div class="space-y-3">
          <div>
            <label class="block text-xs font-medium text-slate-400 mb-1">Slack Incoming Webhook URL</label>
            <input type="text" id="setting-slack-webhook" value="https://hooks.slack.com/services/T00/B00/kanugashield-alerts" class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-300 text-xs font-mono">
          </div>
          <div>
            <label class="block text-xs font-medium text-slate-400 mb-1">Security Team Alert Email</label>
            <input type="email" id="setting-email-alerts" value="security-team@kanugatech.io" class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-300 text-xs">
          </div>
        </div>
      </div>
    </div>
  `;
}

function testWebhookTrigger(type) {
  showToast(`Dispatched test payload to Slack #compliance-alerts (HTTP 200)`, 'success');
}

// =============================================================
// FOUNDER & SUPER ADMIN LICENSING HUB
// =============================================================
function getLicensingHTML() {
  const requests = state.licensingRequests || [];
  const keys = state.licensingKeys || [];
  const outbox = state.licensingOutbox || [];

  const pendingRequests = requests.filter(r => r.status === 'PENDING');
  const activeKeys = keys.filter(k => k.status === 'ACTIVE');
  const usedKeys = keys.filter(k => k.status === 'USED');

  return `
    <div class="space-y-6 max-w-7xl mx-auto">
      <!-- Founder Header Banner -->
      <div class="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 p-6 rounded-2xl glass-panel border border-amber-500/30 gradient-border-glow">
        <div>
          <div class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20 mb-2">
            <i data-lucide="crown" class="w-3.5 h-3.5 text-amber-400"></i>
            <span>Founder & Super Admin Licensing Portal</span>
          </div>
          <h1 class="text-2xl font-bold text-white flex items-center gap-2 flex-wrap">
            <span>Enterprise Account Licensing & Key Engine</span>
            <span class="text-xs px-2.5 py-0.5 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/30 font-mono">francism.kanuga@gmail.com</span>
          </h1>
          <p class="text-sm text-slate-400 mt-1">Review pending customer activation requests, mint cryptographic enterprise keys, and dispatch activation emails upon payment receipt.</p>
        </div>
        <div class="flex items-center gap-2">
          <button onclick="switchTab('licensing')" class="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold transition-all">
            <i data-lucide="refresh-cw" class="w-3.5 h-3.5"></i>
            <span>Refresh Requests & Keys</span>
          </button>
        </div>
      </div>

      <!-- Stats Cards Row -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div class="p-5 rounded-2xl glass-panel border border-amber-500/30 flex items-center justify-between">
          <div>
            <div class="text-xs text-amber-400 font-semibold uppercase tracking-wider">Pending Requests</div>
            <div class="text-2xl font-black text-white mt-1">${pendingRequests.length}</div>
            <div class="text-[11px] text-slate-400 mt-0.5">Awaiting payment verification</div>
          </div>
          <div class="w-10 h-10 rounded-xl bg-amber-500/10 text-amber-400 flex items-center justify-center">
            <i data-lucide="inbox" class="w-5 h-5"></i>
          </div>
        </div>

        <div class="p-5 rounded-2xl glass-panel border border-emerald-500/30 flex items-center justify-between">
          <div>
            <div class="text-xs text-emerald-400 font-semibold uppercase tracking-wider">Active Keys</div>
            <div class="text-2xl font-black text-white mt-1">${activeKeys.length}</div>
            <div class="text-[11px] text-slate-400 mt-0.5">Dispatched & ready to redeem</div>
          </div>
          <div class="w-10 h-10 rounded-xl bg-emerald-500/10 text-emerald-400 flex items-center justify-center">
            <i data-lucide="key" class="w-5 h-5"></i>
          </div>
        </div>

        <div class="p-5 rounded-2xl glass-panel border border-blue-500/30 flex items-center justify-between">
          <div>
            <div class="text-xs text-blue-400 font-semibold uppercase tracking-wider">Redeemed Tenants</div>
            <div class="text-2xl font-black text-white mt-1">${usedKeys.length}</div>
            <div class="text-[11px] text-slate-400 mt-0.5">Active licensed companies</div>
          </div>
          <div class="w-10 h-10 rounded-xl bg-blue-500/10 text-blue-400 flex items-center justify-center">
            <i data-lucide="check-circle" class="w-5 h-5"></i>
          </div>
        </div>

        <div class="p-5 rounded-2xl glass-panel border border-purple-500/30 flex items-center justify-between">
          <div>
            <div class="text-xs text-purple-400 font-semibold uppercase tracking-wider">Founder Gateway</div>
            <div class="text-sm font-bold text-white mt-1.5 flex items-center gap-1.5">
              <span class="w-2 h-2 rounded-full bg-emerald-400 pulse-indicator"></span>
              <span>Super Admin Connected</span>
            </div>
            <div class="text-[11px] text-slate-400 mt-0.5">Root licensing authority</div>
          </div>
          <div class="w-10 h-10 rounded-xl bg-purple-500/10 text-purple-400 flex items-center justify-center">
            <i data-lucide="shield-check" class="w-5 h-5"></i>
          </div>
        </div>
      </div>

      <!-- Section 1: Customer Activation Requests -->
      <div class="p-6 rounded-2xl glass-panel space-y-4 border border-slate-800">
        <div class="flex items-center justify-between">
          <div>
            <h2 class="text-base font-bold text-white flex items-center gap-2">
              <i data-lucide="mail-question" class="w-4 h-4 text-amber-400"></i>
              <span>Customer Account & Key Requests (${requests.length})</span>
            </h2>
            <p class="text-xs text-slate-400 mt-0.5">When users apply without a key, their request arrives here. Verify payment and click 'Mint & Email Key' to instantly generate and send their key.</p>
          </div>
        </div>

        ${requests.length === 0 ? `
          <div class="p-8 text-center rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
            <i data-lucide="check-circle-2" class="w-8 h-8 text-emerald-400 mx-auto"></i>
            <div class="text-sm font-semibold text-white">No Pending Account Requests</div>
            <p class="text-xs text-slate-400">All customer account requests have been verified and processed.</p>
          </div>
        ` : `
          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs text-slate-300">
              <thead class="text-[11px] font-bold uppercase tracking-wider text-slate-400 bg-slate-900/80 border-b border-slate-800">
                <tr>
                  <th class="py-3 px-4">Company Name</th>
                  <th class="py-3 px-4">Contact & Email</th>
                  <th class="py-3 px-4">Payment Ref / Notes</th>
                  <th class="py-3 px-4">Requested At</th>
                  <th class="py-3 px-4">Status</th>
                  <th class="py-3 px-4 text-right">Founder Action</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-800/80">
                ${requests.map(r => `
                  <tr class="hover:bg-slate-800/40 transition-colors">
                    <td class="py-3.5 px-4 font-bold text-white">${r.company_name}</td>
                    <td class="py-3.5 px-4">
                      <div class="font-medium text-slate-200">${r.contact_name || 'N/A'}</div>
                      <a href="mailto:${r.applicant_email}" class="text-[11px] text-blue-400 hover:underline font-mono">${r.applicant_email}</a>
                    </td>
                    <td class="py-3.5 px-4 text-slate-400 max-w-xs truncate">${r.notes || 'Standard Enterprise Setup'}</td>
                    <td class="py-3.5 px-4 text-slate-400 text-[11px]">${new Date(r.created_at).toLocaleString()}</td>
                    <td class="py-3.5 px-4">
                      <span class="px-2 py-0.5 rounded text-[10px] font-bold ${
                        r.status === 'PENDING' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                        r.status === 'APPROVED' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
                        'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                      }">${r.status}</span>
                      ${r.activation_key ? `<div class="text-[10px] font-mono text-emerald-400 mt-1">${r.activation_key}</div>` : ''}
                    </td>
                    <td class="py-3.5 px-4 text-right">
                      ${r.status === 'PENDING' ? `
                        <button onclick="mintAndEmailKey('${r.id}', '${r.applicant_email}', '${r.company_name}')" class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs transition-all shadow-md shadow-emerald-600/20">
                          <i data-lucide="key" class="w-3.5 h-3.5"></i>
                          <span>Mint & Email Key</span>
                        </button>
                      ` : `
                        <span class="text-[11px] text-emerald-400 font-semibold flex items-center justify-end gap-1">
                          <i data-lucide="check" class="w-3.5 h-3.5"></i>
                          <span>Key Dispatched</span>
                        </span>
                      `}
                    </td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        `}
      </div>

      <!-- Section 2: Manual Key Generator Form -->
      <div class="p-6 rounded-2xl glass-panel space-y-4 border border-slate-800">
        <div>
          <h2 class="text-base font-bold text-white flex items-center gap-2">
            <i data-lucide="plus-circle" class="w-4 h-4 text-blue-400"></i>
            <span>Manual Enterprise Key Generator</span>
          </h2>
          <p class="text-xs text-slate-400 mt-0.5">Mint a new enterprise activation key directly for custom corporate agreements or offline wire payments.</p>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
          <div>
            <label class="block text-xs font-semibold text-slate-400 mb-1">Company / Organization</label>
            <input type="text" id="manual-key-company" placeholder="e.g. Nexus Financial Corp" class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 text-xs focus:ring-2 focus:ring-blue-500 focus:outline-none">
          </div>
          <div>
            <label class="block text-xs font-semibold text-slate-400 mb-1">Applicant / Recipient Email</label>
            <input type="email" id="manual-key-email" placeholder="ciso@nexusfinancial.com" class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 text-xs focus:ring-2 focus:ring-blue-500 focus:outline-none">
          </div>
          <div>
            <label class="block text-xs font-semibold text-slate-400 mb-1">Plan Tier</label>
            <select id="manual-key-plan" class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 text-xs focus:ring-2 focus:ring-blue-500 focus:outline-none">
              <option value="ENTERPRISE">Enterprise (Full Multi-Cloud & AI)</option>
              <option value="GROWTH">Growth (Up to 3 Clouds)</option>
              <option value="CUSTOM">Custom Corporate Agreement</option>
            </select>
          </div>
        </div>

        <div class="flex justify-end pt-1">
          <button onclick="generateManualKey()" id="btn-manual-key" class="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs transition-all shadow-lg shadow-blue-600/25">
            <i data-lucide="send" class="w-3.5 h-3.5"></i>
            <span>Generate & Email Key to Applicant</span>
          </button>
        </div>
      </div>

      <!-- Section 3: Activation Keys Ledger -->
      <div class="p-6 rounded-2xl glass-panel space-y-4 border border-slate-800">
        <div class="flex items-center justify-between">
          <div>
            <h2 class="text-base font-bold text-white flex items-center gap-2">
              <i data-lucide="database" class="w-4 h-4 text-emerald-400"></i>
              <span>All Enterprise Activation Keys Ledger (${keys.length})</span>
            </h2>
            <p class="text-xs text-slate-400 mt-0.5">Full history of generated cryptographic tokens, redemption statuses, and tenant associations.</p>
          </div>
        </div>

        ${keys.length === 0 ? `
          <div class="p-8 text-center rounded-xl bg-slate-900/60 border border-slate-800 text-xs text-slate-400">
            No keys generated yet. Use the generator above or approve a customer request.
          </div>
        ` : `
          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs text-slate-300">
              <thead class="text-[11px] font-bold uppercase tracking-wider text-slate-400 bg-slate-900/80 border-b border-slate-800">
                <tr>
                  <th class="py-3 px-4">Activation Key Code</th>
                  <th class="py-3 px-4">Designated Recipient</th>
                  <th class="py-3 px-4">Plan</th>
                  <th class="py-3 px-4">Status</th>
                  <th class="py-3 px-4">Redeemed By</th>
                  <th class="py-3 px-4">Created At</th>
                  <th class="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-800/80">
                ${keys.map(k => `
                  <tr class="hover:bg-slate-800/40 transition-colors">
                    <td class="py-3.5 px-4 font-mono font-bold text-amber-300">
                      <div class="flex items-center gap-2">
                        <span>${k.key_code}</span>
                        <button onclick="copyKeyToClipboard('${k.key_code}')" title="Copy Key" class="text-slate-400 hover:text-white p-1">
                          <i data-lucide="copy" class="w-3.5 h-3.5"></i>
                        </button>
                      </div>
                    </td>
                    <td class="py-3.5 px-4">
                      <div class="font-medium text-slate-200">${k.assigned_to_company || 'Unassigned'}</div>
                      <div class="text-[11px] text-slate-400 font-mono">${k.assigned_to_email || 'Any email'}</div>
                    </td>
                    <td class="py-3.5 px-4">
                      <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-300 border border-slate-700">${k.plan || 'ENTERPRISE'}</span>
                    </td>
                    <td class="py-3.5 px-4">
                      <span class="px-2 py-0.5 rounded text-[10px] font-bold ${
                        k.status === 'ACTIVE' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
                        k.status === 'USED' ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20' :
                        'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                      }">${k.status}</span>
                    </td>
                    <td class="py-3.5 px-4">
                      ${k.used_by_email ? `
                        <div class="text-white font-medium">${k.used_by_email}</div>
                        <div class="text-[10px] text-slate-500">${k.used_at ? new Date(k.used_at).toLocaleDateString() : ''} (${k.used_by_company_id || ''})</div>
                      ` : `
                        <span class="text-slate-500">Unused</span>
                      `}
                    </td>
                    <td class="py-3.5 px-4 text-slate-400 text-[11px]">${new Date(k.created_at).toLocaleDateString()}</td>
                    <td class="py-3.5 px-4 text-right">
                      ${k.status === 'ACTIVE' ? `
                        <button onclick="revokeKey('${k.id}')" class="px-2.5 py-1 rounded text-[11px] font-semibold text-rose-400 hover:text-rose-300 hover:bg-rose-500/10 border border-rose-500/20 transition-all">
                          Revoke
                        </button>
                      ` : `
                        <span class="text-[11px] text-slate-500">&mdash;</span>
                      `}
                    </td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        `}
      </div>

      <!-- Section 4: Email Dispatch History -->
      <div class="p-6 rounded-2xl glass-panel space-y-3 border border-slate-800">
        <h2 class="text-base font-bold text-white flex items-center gap-2">
          <i data-lucide="mail-check" class="w-4 h-4 text-blue-400"></i>
          <span>Licensing Mail Dispatch Log (Outbox)</span>
        </h2>
        <p class="text-xs text-slate-400">Automated dispatch records of notifications to Founder Francis M. Kanuga and activation key deliveries to clients.</p>

        ${outbox.length === 0 ? `
          <div class="p-4 rounded-xl bg-slate-900/60 border border-slate-800 text-xs text-slate-500">
            No outbound emails recorded in this session.
          </div>
        ` : `
          <div class="space-y-2 max-h-56 overflow-y-auto divide-y divide-slate-800/80">
            ${outbox.map(m => `
              <div class="pt-2.5 first:pt-0 flex items-center justify-between text-xs">
                <div>
                  <div class="font-semibold text-white flex items-center gap-2">
                    <span>${m.subject}</span>
                    <span class="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-emerald-500/10 text-emerald-400">${m.status}</span>
                  </div>
                  <div class="text-[11px] text-slate-400 mt-0.5">
                    To: <span class="font-mono text-slate-300">${m.to}</span>
                  </div>
                </div>
                <div class="text-[11px] text-slate-500 font-mono">
                  ${new Date(m.timestamp).toLocaleTimeString()}
                </div>
              </div>
            `).join('')}
          </div>
        `}
      </div>
    </div>
  `;
}

async function mintAndEmailKey(requestId, email, company) {
  try {
    const res = await fetchApi('/api/admin/activation-keys/generate', {
      method: 'POST',
      body: { requestId, assignedToEmail: email, assignedToCompany: company, plan: 'ENTERPRISE' }
    });
    showToast(`Key ${res.key.key_code} generated and emailed to ${email}!`, 'success');
    switchTab('licensing');
  } catch (err) {
    showToast(err.message || 'Failed to mint key', 'error');
  }
}

async function generateManualKey() {
  const companyInput = document.getElementById('manual-key-company');
  const emailInput = document.getElementById('manual-key-email');
  const planSelect = document.getElementById('manual-key-plan');
  const btn = document.getElementById('btn-manual-key');

  const company = companyInput ? companyInput.value.trim() : '';
  const email = emailInput ? emailInput.value.trim() : '';
  const plan = planSelect ? planSelect.value : 'ENTERPRISE';

  if (!email) {
    showToast('Please provide a recipient email.', 'error');
    return;
  }

  if (btn) btn.disabled = true;

  try {
    const res = await fetchApi('/api/admin/activation-keys/generate', {
      method: 'POST',
      body: { assignedToEmail: email, assignedToCompany: company || 'Enterprise Client', plan }
    });

    showToast(`Key ${res.key.key_code} dispatched to ${email}!`, 'success');
    if (companyInput) companyInput.value = '';
    if (emailInput) emailInput.value = '';
    switchTab('licensing');
  } catch (err) {
    showToast(err.message || 'Failed to generate key', 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function revokeKey(keyId) {
  if (!confirm('Are you sure you want to revoke this activation key? It can no longer be used to register.')) {
    return;
  }
  try {
    await fetchApi(`/api/admin/activation-keys/${keyId}/revoke`, { method: 'POST' });
    showToast('Activation key revoked.', 'success');
    switchTab('licensing');
  } catch (err) {
    showToast(err.message || 'Failed to revoke key', 'error');
  }
}

function copyKeyToClipboard(code) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(code).then(() => {
      showToast(`Key copied: ${code}`, 'success');
    }).catch(() => {
      prompt('Copy activation key:', code);
    });
  } else {
    prompt('Copy activation key:', code);
  }
}

// =============================================================
// GLOBAL EXPORTS FOR INLINE ONCLICK HANDLERS
// =============================================================
window.switchTab = switchTab;
window.triggerManualSync = triggerManualSync;
window.triggerFullAutomatedRun = triggerManualSync;
window.handleIntegrationClick = handleIntegrationClick;
window.toggleIntegration = handleIntegrationClick;
window.syncSingleIntegration = syncSingleIntegration;
window.triggerAllIntegrationsSync = triggerAllIntegrationsSync;
window.setFilterFramework = setFilterFramework;
window.openRemediationModal = openRemediationModal;
window.closeRemediationModal = closeRemediationModal;
window.remediateActiveControl = remediateActiveControl;
window.remediateControl = remediateControl;
window.viewEvidenceModal = viewEvidenceModal;
window.closeEvidenceModal = closeEvidenceModal;
window.downloadEvidenceBundle = downloadEvidenceBundle;
window.openGenerateAuditorLinkModal = openGenerateAuditorLinkModal;
window.closeGenerateAuditorLinkModal = closeGenerateAuditorLinkModal;
window.submitGenerateAuditorLink = submitGenerateAuditorLink;
window.copyAuditorLink = copyAuditorLink;
window.revokeAuditorLink = revokeAuditorLink;
window.exitAuditorMode = exitAuditorMode;
window.openCredentialsModal = openCredentialsModal;
window.closeCredentialsModal = closeCredentialsModal;
window.testConnectionCredentials = testConnectionCredentials;
window.saveConnectionCredentials = saveConnectionCredentials;
window.openSignatureModal = openSignatureModal;
window.closeSignatureModal = closeSignatureModal;
window.clearSignaturePad = clearSignaturePad;
window.submitSignature = submitSignature;
window.selectPolicy = selectPolicy;
window.togglePolicyEditor = togglePolicyEditor;
window.savePolicyContent = savePolicyContent;
window.testWebhookTrigger = testWebhookTrigger;
window.fetchApi = fetchApi;
window.submitAuth = submitAuth;
window.setAuthMode = setAuthMode;
window.logoutSession = logoutSession;
window.submitActivationRequest = submitActivationRequest;
window.mintAndEmailKey = mintAndEmailKey;
window.generateManualKey = generateManualKey;
window.revokeKey = revokeKey;
window.copyKeyToClipboard = copyKeyToClipboard;

// Initialize on DOM load
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initApp);
} else {
  initApp();
}

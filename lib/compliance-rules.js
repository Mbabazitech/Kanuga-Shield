'use strict';

// Control engine catalog. Scanners emit a control_code; this module
// attaches the compliance rule the result is judged against.

const RULES = [
  {
    control_code: 'CC6.1',
    title: 'MFA enforced for workforce identities',
    frameworks: ['SOC 2 CC6.1', 'ISO 27001 A.9.4.2'],
    severity: 'CRITICAL',
    sources: ['Okta'],
  },
  {
    control_code: 'CC6.2',
    title: 'Offboarded access revoked within 24 hours',
    frameworks: ['SOC 2 CC6.2', 'ISO 27001 A.9.2.6'],
    severity: 'HIGH',
    sources: ['Okta'],
  },
  {
    control_code: 'CC6.6',
    title: 'Object storage encrypted at rest',
    frameworks: ['SOC 2 CC6.6', 'ISO 27001 A.10.1.1', 'HIPAA'],
    severity: 'HIGH',
    sources: ['AWS', 'Google Cloud'],
  },
  {
    control_code: 'CC6.7',
    title: 'Least-privilege network and IAM boundaries',
    frameworks: ['SOC 2 CC6.7', 'ISO 27001 A.13.1.1'],
    severity: 'CRITICAL',
    sources: ['AWS', 'Google Cloud'],
  },
  {
    control_code: 'CC6.8',
    title: 'Secret scanning and dependency alerts enabled',
    frameworks: ['SOC 2 CC6.8', 'ISO 27001 A.12.6.1'],
    severity: 'HIGH',
    sources: ['GitHub'],
  },
  {
    control_code: 'CC7.2',
    title: 'Audit logs retained and tamper-evident',
    frameworks: ['SOC 2 CC7.2', 'ISO 27001 A.12.4.1', 'HIPAA'],
    severity: 'HIGH',
    sources: ['AWS'],
  },
  {
    control_code: 'CC8.1',
    title: 'Main branch requires pull request review',
    frameworks: ['SOC 2 CC8.1', 'ISO 27001 A.14.2.2'],
    severity: 'MEDIUM',
    sources: ['GitHub'],
  },
];

function getRule(controlCode) {
  return RULES.find((rule) => rule.control_code === controlCode) || null;
}

function listRules() {
  return RULES.map((rule) => ({ ...rule }));
}

function annotateResult(result) {
  const rule = getRule(result.control_code);
  const status = ['PASS', 'FAIL', 'ERROR'].includes(result.status) ? result.status : 'ERROR';
  return {
    ...result,
    status,
    control_title: result.control_title || (rule && rule.title) || result.control_code,
    severity: result.severity || (rule && rule.severity) || 'MEDIUM',
    frameworks: (rule && rule.frameworks) || [],
  };
}

module.exports = {
  RULES,
  getRule,
  listRules,
  annotateResult,
};

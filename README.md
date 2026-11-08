# 🛡️ Kanuga Shield — Enterprise Compliance & Security Automation

**Built by Kanuga_tech**  
*An affordable, streamlined alternative to Vanta & Drata designed for early-stage B2B software companies, health-tech startups, and agencies.*

---

## 🚀 Key Highlights & Architectural Specs

### 1. Unified Executive Dashboard
- **Continuous Readiness Scoring**: Real-time readiness gauge for **SOC 2 Type II**, **ISO 27001:2022**, and **HIPAA Security Rule**.
- **Live Security Posture Stream**: Chronological event telemetry capturing passing & failing tests across all connected cloud, repository, and identity providers.
- **Action Item Queue**: Risk-ranked failing checks (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) with step-by-step remediation guides and instant re-testing.

### 2. Integration Engine (API Connections Hub)
- **Cloud Infrastructure**: AWS, Google Cloud Platform, Microsoft Azure
- **Code Repositories**: GitHub Enterprise, GitLab Cloud
- **Identity & Access Management**: Okta Workforce, Google Workspace, Microsoft Entra ID
- **HRIS & Operations**: Rippling, Gusto, BambooHR
- Built-in simulation engine with hourly telemetry polling and on-demand manual synchronization.

### 3. Continuous Controls & Security Check Matrix
- Direct mapping of technical evidence to **SOC 2 Trust Services Criteria** (`CC6.1`, `CC6.6`, `CC7.2`, `CC8.1`) and **ISO 27001 Annex A** controls (`A.9.4.2`, `A.10.1.1`, `A.14.2.2`).
- Real-time automated test runner verifying MFA enforcement, S3 bucket encryption, PR code reviews, offboarding access revocation within 24 hours, and multi-region CloudTrail audit logging.

### 4. Policy Management & Cryptographic E-Signatures
- Pre-loaded, standard policy templates:
  - *Information Security Policy (v2.4)*
  - *Access Control & Password Policy (v1.8)*
  - *Incident Response & Disaster Recovery (v3.0)*
  - *Vendor & Third-Party Management Policy (v1.2)*
- Integrated markdown viewer and live revision editor.
- Interactive HTML5 canvas e-signature drawing workflow with legal attestation checkboxes and timestamped audit logs.

### 5. Evidence Collector & External Auditor Room
- Timestamped JSON logs with SHA-256 integrity fingerprints.
- Dedicated read-only CPA Auditor View portal with time-bound secure token generation (7d / 30d / 90d) and one-click JSON export.

---

## 💻 Quick Start & Running the Platform

Kanuga Shield requires **Node.js (v18+)** and has **zero external npm dependencies** required to run!

```bash
# Start the server
node server.js
```

Then open your browser at:
👉 **`http://localhost:3000`**

Or simply open `public/index.html` directly in your browser.

---

## 📡 API Endpoints

- `GET /api/status` — Get executive readiness score, statistics, and test stream
- `GET /api/controls` — List all continuous controls and test status
- `POST /api/controls/remediate` — Verify and remediate a failing check
- `POST /api/controls/run-all` — Execute full automated security test suite
- `GET /api/integrations` — List all 11 API connectors and sync status
- `POST /api/integrations/toggle` — Connect / disconnect an integration
- `POST /api/integrations/sync` — Trigger immediate evidence sync
- `GET /api/policies` — List policies, versions, and signature records
- `POST /api/policies/sign` — Submit employee e-signature attestation
- `GET /api/evidence` — Ingest evidence logs from vault
- `POST /api/auditor-link` — Generate secure read-only token for CPA auditors
- `POST /api/webhook/test` — Simulate Slack/Email alert dispatch

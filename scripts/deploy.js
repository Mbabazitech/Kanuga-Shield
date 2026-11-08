#!/usr/bin/env node
/**
 * scripts/deploy.js
 * Kanuga Shield – Official Firebase Deployment Runner
 * 
 * Usage: node scripts/deploy.js
 * 
 * Deploys:
 *  1. Express API backend -> Firebase Cloud Functions v2 ('api' endpoint)
 *  2. Web frontend -> Firebase Hosting (kanugashield.web.app / kanugashield.firebaseapp.com)
 *  3. Verifies Firestore live database connectivity
 */

'use strict';
const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const PROJECT_ID = 'kanugashield';
const ROOT = path.resolve(__dirname, '..');

function run(cmd, opts = {}) {
  console.log(`\n> ${cmd}`);
  return execSync(cmd, { stdio: 'inherit', cwd: ROOT, ...opts });
}

function runCapture(cmd) {
  try {
    return execSync(cmd, { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] }).toString().trim();
  } catch (err) {
    return null;
  }
}

async function main() {
  console.log('╔═════════════════════════════════════════════════════════════════╗');
  console.log('║        Kanuga Shield – Firebase Production Deployment           ║');
  console.log('║      Project: kanugashield | Region: us-central1 (default)      ║');
  console.log('╚═════════════════════════════════════════════════════════════════╝\n');

  // Step 1: Verify Firestore connectivity
  console.log('[1/4] Verifying Google Cloud Firestore & Firebase Auth...');
  const fb = require('../lib/firebase');
  const status = fb.getFirebaseStatus();
  if (status.configured) {
    console.log(`  ✅ Connected to Cloud Firestore (Project: ${status.projectId})`);
  } else {
    console.warn('  ⚠️ Operating in Local-Hybrid mode.');
  }

  // Step 2: Verify Single-Account Policy
  console.log('\n[2/4] Verifying Single Founder Admin Policy...');
  try {
    const Database = require('better-sqlite3');
    const authDbPath = path.join(ROOT, 'data', 'auth.db');
    if (fs.existsSync(authDbPath)) {
      const db = new Database(authDbPath);
      const users = db.prepare('SELECT email, role FROM users').all();
      console.log(`  Found ${users.length} user account(s):`);
      users.forEach(u => console.log(`    - ${u.email} [${u.role}]`));
      if (users.length === 1 && users[0].email.toLowerCase() === 'francism.kanuga@gmail.com') {
        console.log('  ✅ Single Founder Admin policy verified: francism.kanuga@gmail.com');
      } else {
        console.warn('  ⚠️ Multiple accounts found! Run node scripts/cleanup-db.js to purge non-founder accounts.');
      }
      db.close();
    }
  } catch (e) {
    console.log('  Note:', e.message);
  }

  // Step 3: Check Firebase CLI Authentication
  console.log('\n[3/4] Checking Firebase CLI Authentication...');
  const accountsOutput = runCapture('npx firebase-tools login:list');
  const isLoggedIn = accountsOutput && !accountsOutput.includes('No authorized accounts');

  if (isLoggedIn) {
    console.log('  ✅ Firebase CLI user is authenticated:');
    console.log(accountsOutput.split('\n').map(l => '    ' + l).join('\n'));
  } else {
    console.log('  ℹ️  No active CLI user session found.');
    console.log('  Firebase CLI requires an active login session or deploy token.');
  }

  // Step 4: Run Deployment
  console.log('\n[4/4] Deploying to Firebase (Hosting + Functions)...');
  try {
    run(`npx firebase-tools deploy --project ${PROJECT_ID}`);
    console.log('\n═════════════════════════════════════════════════════════════════');
    console.log('  🎉 DEPLOYMENT SUCCESSFUL!');
    console.log(`  Frontend: https://${PROJECT_ID}.web.app`);
    console.log(`  Alternative URL: https://${PROJECT_ID}.firebaseapp.com`);
    console.log(`  API Base URL: https://${PROJECT_ID}.web.app/api`);
    console.log('  Founder Login: francism.kanuga@gmail.com / Kanuga0758');
    console.log('═════════════════════════════════════════════════════════════════\n');
  } catch (err) {
    console.error('\n❌ Deployment command stopped.');
    console.error('\nTo complete deployment to Firebase:');
    console.error('1. Open your terminal and run:');
    console.error('   npx firebase-tools login');
    console.error('2. Log in with your Google account (francism.kanuga@gmail.com).');
    console.error('3. Then re-run:');
    console.error('   node scripts/deploy.js');
    console.error('   (or: npx firebase-tools deploy --project kanugashield)\n');
    process.exit(1);
  }
}

main().catch(err => {
  console.error('Unexpected error:', err);
  process.exit(1);
});

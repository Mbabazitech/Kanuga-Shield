'use strict';
// scripts/cleanup-db.js
// One-time script: purge all non-founder user accounts from local SQLite
// Run: node scripts/cleanup-db.js

const path = require('path');
const Database = require('better-sqlite3');

const DB_PATH = path.join(__dirname, '..', 'data', 'auth.db');
const FOUNDER_EMAIL = 'francism.kanuga@gmail.com';

const db = new Database(DB_PATH);

// 1. Purge non-founder users
const del = db.prepare("DELETE FROM users WHERE LOWER(email) != LOWER(?)").run(FOUNDER_EMAIL);
console.log(`[cleanup] Deleted ${del.changes} non-founder user account(s)`);

// 2. Clean up associated companies (keep kanuga_tech)
const delCompanies = db.prepare("DELETE FROM companies WHERE id != 'kanuga_tech'").run();
console.log(`[cleanup] Deleted ${delCompanies.changes} non-default company record(s)`);

// 3. Clear all activation_requests and activation_keys (fresh start)
const delReqs = db.prepare("DELETE FROM activation_requests").run();
const delKeys = db.prepare("DELETE FROM activation_keys").run();
console.log(`[cleanup] Cleared ${delReqs.changes} activation request(s) and ${delKeys.changes} key(s)`);

// 4. Verify
const remaining = db.prepare("SELECT email, role, name FROM users").all();
console.log('\n[cleanup] Remaining user accounts:');
remaining.forEach(u => console.log(`  - ${u.email}  [${u.role}]  ${u.name}`));

console.log('\n✅ Database clean — only the Founder account remains.');
db.close();

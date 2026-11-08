'use strict';

// Queue between the API and the background worker.
// Redis + BullMQ when REDIS_URL or REDIS_HOST is set.
// Otherwise Cloud Firestore (Firebase) or a local file queue.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SCAN_QUEUE_NAME = 'kanuga-shield-scans';
const DATA_DIR = path.join(__dirname, '..', 'data');
const JOBS_FILE = path.join(DATA_DIR, 'job-queue.json');

const REDIS_CONFIG = process.env.REDIS_URL
  ? { url: process.env.REDIS_URL, maxRetriesPerRequest: null }
  : {
      host: process.env.REDIS_HOST || '127.0.0.1',
      port: parseInt(process.env.REDIS_PORT, 10) || 6379,
      password: process.env.REDIS_PASSWORD || undefined,
      maxRetriesPerRequest: null,
    };

let scanQueue = null;
let mode = 'local';

function redisEnabled() {
  return Boolean(process.env.REDIS_URL || process.env.REDIS_HOST);
}

function initBull() {
  if (!redisEnabled()) return;
  try {
    const { Queue } = require('bullmq');
    scanQueue = new Queue(SCAN_QUEUE_NAME, {
      connection: REDIS_CONFIG,
      defaultJobOptions: {
        attempts: 3,
        backoff: { type: 'exponential', delay: 5000 },
        removeOnComplete: { age: 24 * 3600 },
        removeOnFail: { age: 7 * 24 * 3600 },
      },
    });
    mode = 'bullmq';
    console.log(`[job-queue] BullMQ queue "${SCAN_QUEUE_NAME}" using Redis`);
  } catch (err) {
    console.warn(`[job-queue] BullMQ unavailable (${err.message}). Using the Firebase/local queue.`);
  }
}

initBull();

function resolveMode() {
  if (mode === 'bullmq') return 'bullmq';
  try {
    const firebase = require('./firebase');
    if (firebase.getDb()) return 'firestore';
  } catch (err) {
    // Firebase module failed to load; keep the file queue.
  }
  return 'local';
}

function readJobs() {
  try {
    if (!fs.existsSync(JOBS_FILE)) return [];
    const parsed = JSON.parse(fs.readFileSync(JOBS_FILE, 'utf8'));
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    return [];
  }
}

function writeJobs(jobs) {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(JOBS_FILE, JSON.stringify(jobs, null, 2));
}

function publicJob(job) {
  if (!job) return null;
  return {
    id: job.id,
    name: job.name,
    status: job.status,
    data: job.data,
    result: job.result || null,
    error: job.error || null,
    createdAt: job.createdAt,
    finishedAt: job.finishedAt || null,
  };
}

async function addScanJob(data = {}) {
  const activeMode = resolveMode();
  mode = activeMode;
  const payload = { ...data, requestedAt: new Date().toISOString() };

  if (activeMode === 'bullmq' && scanQueue) {
    const job = await scanQueue.add(data.source === 'cron' ? 'scan:hourly' : 'scan:all', payload);
    return { id: job.id, name: job.name, status: 'queued', data: payload };
  }

  const job = {
    id: `job_${crypto.randomBytes(8).toString('hex')}`,
    name: data.source === 'cron' ? 'scan:hourly' : 'scan:all',
    status: 'waiting',
    data: payload,
    result: null,
    error: null,
    createdAt: new Date().toISOString(),
    finishedAt: null,
  };

  if (activeMode === 'firestore') {
    const firebase = require('./firebase');
    await firebase.getDb().collection('job_queue').doc(job.id).set(job);
    return publicJob(job);
  }

  const jobs = readJobs();
  jobs.push(job);
  writeJobs(jobs);
  return publicJob(job);
}

async function getJob(jobId) {
  const activeMode = resolveMode();
  if (activeMode === 'bullmq' && scanQueue) {
    const { Job } = require('bullmq');
    const job = await Job.fromId(scanQueue, jobId);
    if (!job) return null;
    const state = await job.getState();
    return {
      id: job.id,
      name: job.name,
      status: state,
      data: job.data,
      result: job.returnvalue || null,
      error: job.failedReason || null,
    };
  }
  if (activeMode === 'firestore') {
    const firebase = require('./firebase');
    const snap = await firebase.getDb().collection('job_queue').doc(jobId).get();
    return snap.exists ? publicJob(snap.data()) : null;
  }
  return publicJob(readJobs().find((job) => job.id === jobId) || null);
}

async function takeNextJob() {
  const activeMode = resolveMode();
  if (activeMode === 'bullmq') return null;

  if (activeMode === 'firestore') {
    const firebase = require('./firebase');
    const db = firebase.getDb();
    const snap = await db.collection('job_queue').where('status', '==', 'waiting').limit(1).get();
    if (snap.empty) return null;
    const doc = snap.docs[0];
    const claimed = await db.runTransaction(async (tx) => {
      const fresh = await tx.get(doc.ref);
      if (!fresh.exists || fresh.data().status !== 'waiting') return null;
      tx.update(doc.ref, { status: 'active' });
      return { ...fresh.data(), status: 'active' };
    });
    return claimed;
  }

  const jobs = readJobs();
  const next = jobs.find((job) => job.status === 'waiting');
  if (!next) return null;
  next.status = 'active';
  writeJobs(jobs);
  return next;
}

async function completeJob(jobId, result) {
  return updateJob(jobId, { status: 'completed', result, finishedAt: new Date().toISOString(), error: null });
}

async function failJob(jobId, err) {
  return updateJob(jobId, {
    status: 'failed',
    error: err && err.message ? err.message : String(err),
    finishedAt: new Date().toISOString(),
  });
}

async function updateJob(jobId, patch) {
  const activeMode = resolveMode();
  if (activeMode === 'firestore') {
    const firebase = require('./firebase');
    const ref = firebase.getDb().collection('job_queue').doc(jobId);
    await ref.set(patch, { merge: true });
    const snap = await ref.get();
    return publicJob(snap.data());
  }
  const jobs = readJobs();
  const job = jobs.find((item) => item.id === jobId);
  if (!job) return null;
  Object.assign(job, patch);
  writeJobs(jobs);
  return publicJob(job);
}

async function closeQueue() {
  if (scanQueue) await scanQueue.close();
}

module.exports = {
  scanQueue,
  get mode() { return resolveMode(); },
  get queueAvailable() { return true; },
  addScanJob,
  getJob,
  takeNextJob,
  completeJob,
  failJob,
  closeQueue,
  SCAN_QUEUE_NAME,
  REDIS_CONFIG,
};

'use strict';

// Background worker. Consumes queue jobs and calls the provider scanners:
// AWS SDK (IAM / S3 / CloudTrail), GitHub REST + GraphQL, Okta, GCP IAM.

const cron = require('node-cron');
const queue = require('./job-queue');
const scanEngine = require('./scan-engine');

let started = false;
let ticking = false;

async function handleJob(job) {
  const companyId = job.data && job.data.companyId;
  if (!companyId) {
    return { skipped: true, reason: 'companyId missing' };
  }
  if (job.name === 'scan:hourly' || job.data.source === 'cron') {
    const summaries = [];
    for (const id of scanEngine.listCompanyIds()) {
      summaries.push(await scanEngine.runCompanyScan(id));
    }
    return { companies: summaries.length, summaries };
  }
  return scanEngine.runCompanyScan(companyId);
}

async function drainOnce() {
  if (ticking) return null;
  ticking = true;
  try {
    if (queue.mode === 'bullmq') return null;
    const job = await queue.takeNextJob();
    if (!job) return null;
    try {
      const result = await handleJob(job);
      await queue.completeJob(job.id, result);
      console.log(`[worker] ${job.id} completed for ${job.data && job.data.companyId}`);
      return result;
    } catch (err) {
      await queue.failJob(job.id, err);
      console.error(`[worker] ${job.id} failed:`, err.message);
      return null;
    }
  } finally {
    ticking = false;
  }
}

async function enqueueHourly() {
  const companies = scanEngine.listCompanyIds();
  for (const companyId of companies) {
    await queue.addScanJob({ companyId, source: 'cron' });
  }
  console.log(`[worker] Queued hourly scans for ${companies.length} companies (${queue.mode})`);
}

function startEmbeddedWorker() {
  if (started) return;
  started = true;

  if (queue.mode === 'bullmq' && queue.scanQueue) {
    const { Worker } = require('bullmq');
    const worker = new Worker(
      queue.SCAN_QUEUE_NAME,
      async (job) => handleJob(job),
      { connection: queue.REDIS_CONFIG, concurrency: 2 }
    );
    worker.on('failed', (job, err) => {
      console.error('[worker] BullMQ job failed:', err.message, job && job.id);
    });
    console.log('[worker] BullMQ consumer attached');
  } else {
    setInterval(() => {
      drainOnce().catch((err) => console.error('[worker] drain error:', err.message));
    }, 2000);
    console.log(`[worker] Polling ${queue.mode} queue`);
  }

  cron.schedule('0 * * * *', () => {
    enqueueHourly().catch((err) => console.error('[worker] hourly enqueue failed:', err.message));
  });
  console.log('[worker] Hourly enqueue scheduled (0 * * * *)');
}

module.exports = {
  handleJob,
  drainOnce,
  enqueueHourly,
  startEmbeddedWorker,
};

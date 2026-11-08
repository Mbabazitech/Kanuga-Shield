'use strict';

// Key management for credential sealing.
// Local AES-256-GCM is always available. When KMS_KEY_RESOURCE is set
// (projects/.../locations/.../keyRings/.../cryptoKeys/...), the data key
// is wrapped with Google Cloud KMS before it is stored.

const crypto = require('crypto');
const firebase = require('./firebase');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;

function status() {
  const keyResource = process.env.KMS_KEY_RESOURCE || null;
  return {
    provider: keyResource ? 'gcp-cloud-kms' : 'local-aes-256-gcm',
    algorithm: 'AES-256-GCM',
    keyResource,
    oauth: 'oauth2-bearer',
  };
}

async function accessToken() {
  const app = firebase.getApp && firebase.getApp();
  if (!app || !app.options || !app.options.credential) return null;
  const token = await app.options.credential.getAccessToken();
  return token && token.access_token ? token.access_token : null;
}

async function kmsRequest(action, body) {
  const keyResource = process.env.KMS_KEY_RESOURCE;
  if (!keyResource) return null;
  const token = await accessToken();
  if (!token) {
    throw new Error('Cloud KMS is configured but Firebase/GCP credentials are not available');
  }
  const resp = await fetch(`https://cloudkms.googleapis.com/v1/${keyResource}:${action}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Cloud KMS ${action} failed (${resp.status}): ${text.slice(0, 180)}`);
  }
  return resp.json();
}

async function wrapDataKey(dataKey) {
  if (!process.env.KMS_KEY_RESOURCE) return null;
  const result = await kmsRequest('encrypt', {
    plaintext: dataKey.toString('base64'),
  });
  return result.ciphertext;
}

async function unwrapDataKey(wrapped) {
  const result = await kmsRequest('decrypt', { ciphertext: wrapped });
  return Buffer.from(result.plaintext, 'base64');
}

/**
 * Seal a JSON value. Returns fields the credential vault can persist.
 * @param {object} plainObj
 * @param {Buffer} localKey 32-byte key used when Cloud KMS is not configured
 */
async function seal(plainObj, localKey) {
  const dataKey = process.env.KMS_KEY_RESOURCE ? crypto.randomBytes(32) : localKey;
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, dataKey, iv);
  let encrypted = cipher.update(JSON.stringify(plainObj), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const wrapped = await wrapDataKey(dataKey);
  return {
    encrypted_payload: encrypted,
    iv: iv.toString('hex'),
    auth_tag: cipher.getAuthTag().toString('hex'),
    kms_wrapped_key: wrapped,
    kms_provider: wrapped ? 'gcp-cloud-kms' : 'local-aes-256-gcm',
  };
}

async function open(encObj, localKey) {
  const dataKey = encObj.kms_wrapped_key
    ? await unwrapDataKey(encObj.kms_wrapped_key)
    : localKey;
  const decipher = crypto.createDecipheriv(ALGORITHM, dataKey, Buffer.from(encObj.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(encObj.auth_tag, 'hex'));
  let decrypted = decipher.update(encObj.encrypted_payload, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return JSON.parse(decrypted);
}

function sha256(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  return crypto.createHash('sha256').update(text).digest('hex');
}

module.exports = {
  status,
  seal,
  open,
  sha256,
};

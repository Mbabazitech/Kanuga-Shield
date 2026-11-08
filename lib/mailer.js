'use strict';

// lib/mailer.js – Enterprise Notification & Licensing Dispatch Service
// ---------------------------------------------------------------
// Handles email delivery for:
//   1. Alerts to Founder Francis M. Kanuga (francism.kanuga@gmail.com)
//      when an applicant creates/requests an account and needs an activation key.
//   2. Dispatch of special activation keys to approved paying applicants.
// Supports real SMTP (via .env) and graceful fallback logging/outbox.
// ---------------------------------------------------------------

const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');

const FOUNDER_EMAIL = 'francism.kanuga@gmail.com';
const OUTBOX_LOG_PATH = path.join(__dirname, '..', 'data', 'mail_outbox.log');

// In-memory record of recent emails for dashboard inspection
const emailOutbox = [];

function getTransporter() {
  const host = process.env.SMTP_HOST;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (host && user && pass) {
    return nodemailer.createTransport({
      host: host,
      port: parseInt(process.env.SMTP_PORT || '587', 10),
      secure: process.env.SMTP_SECURE === 'true' || process.env.SMTP_PORT === '465',
      auth: {
        user: user,
        pass: pass,
      },
    });
  }

  // Fallback test transporter (prints and records)
  return nodemailer.createTransport({
    jsonTransport: true,
  });
}

function recordEmail(emailRecord) {
  emailOutbox.unshift(emailRecord);
  if (emailOutbox.length > 100) emailOutbox.pop();

  try {
    const logLine = `[${new Date().toISOString()}] TO: ${emailRecord.to} | SUBJECT: ${emailRecord.subject}\n`;
    fs.appendFileSync(OUTBOX_LOG_PATH, logLine, 'utf8');
  } catch (err) {
    // Ignore logging write error
  }
}

/**
 * Send an email notification. Handles real SMTP or fallback.
 */
async function sendMail({ to, subject, html, text }) {
  const transporter = getTransporter();
  const from = process.env.SMTP_FROM || '"Kanuga Shield Platform" <notifications@kanugashield.io>';

  const mailOptions = {
    from,
    to,
    subject,
    text,
    html,
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    const result = {
      to,
      subject,
      timestamp: new Date().toISOString(),
      messageId: info.messageId || `sim_${Date.now()}`,
      status: 'SENT',
    };
    recordEmail(result);
    console.log(`[mailer] Email successfully dispatched to ${to}: "${subject}"`);
    return result;
  } catch (error) {
    console.error(`[mailer] Failed to send email to ${to}:`, error.message);
    const failRecord = {
      to,
      subject,
      timestamp: new Date().toISOString(),
      status: 'FAILED',
      error: error.message,
    };
    recordEmail(failRecord);
    return failRecord;
  }
}

/**
 * 1. Notify Founder Francis M. Kanuga when a prospective customer requests an activation key.
 */
async function notifyFounderActivationRequest({ applicantEmail, companyName, contactName, notes, requestId }) {
  const subject = `[Kanuga Shield Alert] New Account Key Requested: ${companyName}`;
  const now = new Date().toUTCString();

  const html = `
<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #f3f4f6; margin: 0; padding: 24px; }
    .card { background-color: #111827; border: 1px solid #1f2937; border-radius: 12px; max-width: 600px; margin: 0 auto; overflow: hidden; }
    .header { background: linear-gradient(135deg, #059669 0%, #10b981 100%); padding: 24px; text-align: left; }
    .header h1 { margin: 0; font-size: 20px; color: #ffffff; letter-spacing: 0.5px; }
    .header p { margin: 4px 0 0 0; color: #d1fae5; font-size: 13px; }
    .content { padding: 24px; }
    .badge { display: inline-block; background-color: #f59e0b; color: #111827; font-weight: bold; font-size: 12px; padding: 4px 10px; border-radius: 9999px; text-transform: uppercase; margin-bottom: 16px; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    td { padding: 10px 12px; border-bottom: 1px solid #1f2937; font-size: 14px; }
    td.label { color: #9ca3af; width: 35%; }
    td.value { color: #f9fafb; font-weight: 500; }
    .action-box { background-color: #1f2937; border-left: 4px solid #10b981; padding: 16px; border-radius: 6px; margin-top: 20px; font-size: 14px; line-height: 1.5; color: #d1d5db; }
    .btn { display: inline-block; background-color: #10b981; color: #ffffff; text-decoration: none; font-weight: 600; padding: 12px 24px; border-radius: 8px; margin-top: 16px; }
    .footer { text-align: center; padding: 16px; font-size: 12px; color: #6b7280; border-top: 1px solid #1f2937; }
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <h1>KANUGA SHIELD</h1>
      <p>Founder Security & Licensing Notification</p>
    </div>
    <div class="content">
      <span class="badge">Payment / Key Request</span>
      <p style="font-size: 15px; margin: 0 0 16px 0; color: #e5e7eb;">
        Hello <strong>Francis M. Kanuga</strong>, a new applicant has requested access to Kanuga Shield and requires an Enterprise Activation Key.
      </p>

      <table>
        <tr>
          <td class="label">Company Name</td>
          <td class="value">${companyName}</td>
        </tr>
        <tr>
          <td class="label">Contact Person</td>
          <td class="value">${contactName || 'Not specified'}</td>
        </tr>
        <tr>
          <td class="label">Applicant Email</td>
          <td class="value"><a href="mailto:${applicantEmail}" style="color: #34d399; text-decoration: none;">${applicantEmail}</a></td>
        </tr>
        <tr>
          <td class="label">Request ID</td>
          <td class="value"><code>${requestId || 'REQ-NEW'}</code></td>
        </tr>
        <tr>
          <td class="label">Requested At</td>
          <td class="value">${now}</td>
        </tr>
        <tr>
          <td class="label">Notes / Details</td>
          <td class="value">${notes || 'Standard Enterprise Setup'}</td>
        </tr>
      </table>

      <div class="action-box">
        <strong>Next Step:</strong> Once payment confirmation is received, log into your Kanuga Shield Founder account (<code>${FOUNDER_EMAIL}</code>) to mint and send their special activation key directly from the Licensing Center.
      </div>
    </div>
    <div class="footer">
      Kanuga Shield Automated Licensing Engine &bull; Kanuga_tech
    </div>
  </div>
</body>
</html>
`;

  const text = `
KANUGA SHIELD - NEW ACCOUNT ACTIVATION REQUEST
---------------------------------------------
Hello Francis M. Kanuga,

A new customer has applied for Kanuga Shield access:
Company: ${companyName}
Contact: ${contactName || 'N/A'}
Email: ${applicantEmail}
Request ID: ${requestId || 'N/A'}
Date: ${now}
Notes: ${notes || 'None'}

Please verify payment receipt and log in as Founder (francism.kanuga@gmail.com) to generate their key.
`;

  return sendMail({
    to: FOUNDER_EMAIL,
    subject,
    html,
    text,
  });
}

/**
 * 2. Send the newly generated Activation Key to the paying applicant.
 */
async function sendApplicantActivationKey({ toEmail, companyName, contactName, keyCode, plan = 'ENTERPRISE' }) {
  const subject = `Your Kanuga Shield Enterprise Activation Key: ${keyCode}`;

  const html = `
<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #f3f4f6; margin: 0; padding: 24px; }
    .card { background-color: #111827; border: 1px solid #1f2937; border-radius: 12px; max-width: 600px; margin: 0 auto; overflow: hidden; }
    .header { background: linear-gradient(135deg, #059669 0%, #10b981 100%); padding: 28px; text-align: left; }
    .header h1 { margin: 0; font-size: 22px; color: #ffffff; letter-spacing: 0.5px; }
    .header p { margin: 6px 0 0 0; color: #d1fae5; font-size: 13px; }
    .content { padding: 28px; }
    .key-box { background-color: #0d1527; border: 2px dashed #10b981; border-radius: 10px; padding: 20px; text-align: center; margin: 24px 0; }
    .key-title { font-size: 12px; text-transform: uppercase; letter-spacing: 1.5px; color: #9ca3af; margin-bottom: 8px; }
    .key-code { font-family: 'Courier New', Courier, monospace; font-size: 22px; font-weight: bold; color: #34d399; letter-spacing: 2px; }
    .instructions { background-color: #1f2937; border-radius: 8px; padding: 16px 20px; margin: 20px 0; }
    .instructions ol { margin: 8px 0 0 0; padding-left: 20px; color: #d1d5db; font-size: 14px; line-height: 1.6; }
    .founder-sig { margin-top: 24px; border-top: 1px solid #1f2937; padding-top: 16px; font-size: 13px; color: #9ca3af; }
    .founder-sig strong { color: #f3f4f6; }
    .footer { text-align: center; padding: 16px; font-size: 12px; color: #6b7280; border-top: 1px solid #1f2937; }
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <h1>KANUGA SHIELD</h1>
      <p>Continuous Compliance & Cloud Security Automation</p>
    </div>
    <div class="content">
      <h2 style="margin-top: 0; font-size: 18px; color: #ffffff;">Welcome to Kanuga Shield!</h2>
      <p style="font-size: 14px; line-height: 1.6; color: #d1d5db;">
        Dear <strong>${contactName || companyName}</strong>,<br><br>
        Thank you for subscribing to Kanuga Shield. Founder <strong>Francis M. Kanuga</strong> has confirmed your account and generated your official <strong>${plan}</strong> Activation Key.
      </p>

      <div class="key-box">
        <div class="key-title">Official Enterprise Activation Key</div>
        <div class="key-code">${keyCode}</div>
      </div>

      <div class="instructions">
        <strong style="color: #f9fafb; font-size: 14px;">How to activate your workspace:</strong>
        <ol>
          <li>Open the Kanuga Shield portal.</li>
          <li>Choose <strong>"Register New Company"</strong>.</li>
          <li>Enter your company name (<strong>${companyName}</strong>), your email (<strong>${toEmail}</strong>), and chosen password.</li>
          <li>Paste the <strong>Activation Key</strong> above into the Activation Key field.</li>
          <li>Click <strong>Complete Registration</strong> to immediately access your cloud compliance engines.</li>
        </ol>
      </div>

      <div class="founder-sig">
        Warm regards,<br>
        <strong>Francis M. Kanuga</strong><br>
        Founder & Chief Executive &bull; Kanuga_tech<br>
        <span style="color: #6b7280;">Email: francism.kanuga@gmail.com</span>
      </div>
    </div>
    <div class="footer">
      &copy; ${new Date().getFullYear()} Kanuga_tech &bull; Kanuga Shield Platform
    </div>
  </div>
</body>
</html>
`;

  const text = `
WELCOME TO KANUGA SHIELD
-----------------------
Dear ${contactName || companyName},

Your payment has been verified and your Enterprise Activation Key is ready:

ACTIVATION KEY: ${keyCode}
TIER: ${plan}
ASSIGNED TO: ${toEmail} (${companyName})

Instructions to Activate:
1. Open Kanuga Shield portal.
2. Select 'Register New Company'.
3. Enter your details and paste the Activation Key.
4. Complete registration to unlock your unified multi-cloud compliance workspace.

Best regards,
Francis M. Kanuga
Founder & Chief Executive, Kanuga_tech
`;

  return sendMail({
    to: toEmail,
    subject,
    html,
    text,
  });
}

module.exports = {
  FOUNDER_EMAIL,
  notifyFounderActivationRequest,
  sendApplicantActivationKey,
  sendMail,
  getOutbox: () => [...emailOutbox],
};

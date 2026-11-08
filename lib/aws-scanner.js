'use strict';

const {
  S3Client,
  ListBucketsCommand,
  GetBucketEncryptionCommand,
} = require('@aws-sdk/client-s3');

const {
  IAMClient,
  ListUsersCommand,
  ListMFADevicesCommand,
} = require('@aws-sdk/client-iam');

const {
  CloudTrailClient,
  DescribeTrailsCommand,
  GetTrailStatusCommand,
} = require('@aws-sdk/client-cloudtrail');

const {
  EC2Client,
  DescribeSecurityGroupsCommand,
} = require('@aws-sdk/client-ec2');

// ---------------------------------------------------------------------------
// Helper – build AWS client config from credentials
// ---------------------------------------------------------------------------

/**
 * Build the common configuration object for AWS SDK v3 clients.
 *
 * @param {{ accessKeyId: string, secretAccessKey: string, sessionToken?: string }} credentials
 * @param {string} region
 * @returns {Object}
 */
function _clientConfig(credentials, region) {
  return {
    region,
    credentials: {
      accessKeyId: credentials.accessKeyId,
      secretAccessKey: credentials.secretAccessKey,
      ...(credentials.sessionToken && {
        sessionToken: credentials.sessionToken,
      }),
    },
  };
}

// ---------------------------------------------------------------------------
// Check 1: CC6.6 – S3 Server-Side Encryption
// ---------------------------------------------------------------------------

/**
 * Verify that every S3 bucket has default server-side encryption enabled.
 *
 * @param {Object} credentials - AWS credentials.
 * @param {string} region
 * @returns {Promise<Object>} Check result.
 */
async function checkS3Encryption(credentials, region) {
  try {
    const s3 = new S3Client(_clientConfig(credentials, region));

    const { Buckets = [] } = await s3.send(new ListBucketsCommand({}));

    const details = [];
    const unencryptedBuckets = [];

    for (const bucket of Buckets) {
      try {
        const enc = await s3.send(
          new GetBucketEncryptionCommand({ Bucket: bucket.Name })
        );
        const rules =
          enc.ServerSideEncryptionConfiguration?.Rules || [];
        details.push({
          bucket: bucket.Name,
          encrypted: true,
          rules: rules.map((r) => r.ApplyServerSideEncryptionByDefault),
        });
      } catch (encErr) {
        // ServerSideEncryptionConfigurationNotFoundError means no encryption
        if (
          encErr.name ===
            'ServerSideEncryptionConfigurationNotFoundError' ||
          encErr.Code ===
            'ServerSideEncryptionConfigurationNotFoundError'
        ) {
          unencryptedBuckets.push(bucket.Name);
          details.push({ bucket: bucket.Name, encrypted: false });
        } else {
          // Unexpected error for this bucket – treat as unencrypted
          unencryptedBuckets.push(bucket.Name);
          details.push({
            bucket: bucket.Name,
            encrypted: false,
            error: encErr.message,
          });
        }
      }
    }

    const status = unencryptedBuckets.length === 0 ? 'PASS' : 'FAIL';

    return {
      control_code: 'CC6.6',
      control_title: 'S3 Cloud Storage Server-Side Encryption Enabled',
      integration_source: 'AWS',
      status,
      raw_evidence: {
        scanned_buckets: Buckets.length,
        encrypted_buckets: Buckets.length - unencryptedBuckets.length,
        unencrypted_buckets: unencryptedBuckets,
        details,
      },
    };
  } catch (err) {
    return {
      control_code: 'CC6.6',
      control_title: 'S3 Cloud Storage Server-Side Encryption Enabled',
      integration_source: 'AWS',
      status: 'ERROR',
      raw_evidence: { error: err.message },
    };
  }
}

// ---------------------------------------------------------------------------
// Check 2: CC6.1 – IAM MFA Enforcement
// ---------------------------------------------------------------------------

/**
 * Verify that all IAM users with console access have MFA enabled.
 *
 * @param {Object} credentials - AWS credentials.
 * @param {string} region
 * @returns {Promise<Object>} Check result.
 */
async function checkIamMfa(credentials, region) {
  try {
    const iam = new IAMClient(_clientConfig(credentials, region));

    const { Users = [] } = await iam.send(new ListUsersCommand({}));

    let mfaEnabledCount = 0;
    const mfaMissingUsers = [];

    for (const user of Users) {
      const { MFADevices = [] } = await iam.send(
        new ListMFADevicesCommand({ UserName: user.UserName })
      );

      if (MFADevices.length > 0) {
        mfaEnabledCount++;
      } else {
        // Users with a PasswordLastUsed date are considered to have console access
        if (user.PasswordLastUsed || user.CreateDate) {
          mfaMissingUsers.push(user.UserName);
        }
      }
    }

    const status = mfaMissingUsers.length === 0 ? 'PASS' : 'FAIL';

    return {
      control_code: 'CC6.1',
      control_title: 'MFA Enforced on IAM Users',
      integration_source: 'AWS',
      status,
      raw_evidence: {
        total_users: Users.length,
        mfa_enabled_count: mfaEnabledCount,
        mfa_missing_users: mfaMissingUsers,
      },
    };
  } catch (err) {
    return {
      control_code: 'CC6.1',
      control_title: 'MFA Enforced on IAM Users',
      integration_source: 'AWS',
      status: 'ERROR',
      raw_evidence: { error: err.message },
    };
  }
}

// ---------------------------------------------------------------------------
// Check 3: CC7.2 – CloudTrail Multi-Region Logging
// ---------------------------------------------------------------------------

/**
 * Verify that CloudTrail is enabled with multi-region logging and
 * log file validation.
 *
 * @param {Object} credentials - AWS credentials.
 * @param {string} region
 * @returns {Promise<Object>} Check result.
 */
async function checkCloudTrail(credentials, region) {
  try {
    const ct = new CloudTrailClient(_clientConfig(credentials, region));

    const { trailList = [] } = await ct.send(
      new DescribeTrailsCommand({})
    );

    const trails = [];
    let compliantTrails = 0;
    let nonCompliantTrails = 0;

    for (const trail of trailList) {
      let isLogging = false;

      try {
        const trailStatus = await ct.send(
          new GetTrailStatusCommand({ Name: trail.TrailARN })
        );
        isLogging = trailStatus.IsLogging === true;
      } catch {
        // If we can't determine logging status, treat as non-compliant
        isLogging = false;
      }

      const compliant =
        trail.IsMultiRegionTrail === true &&
        isLogging &&
        trail.LogFileValidationEnabled === true;

      if (compliant) {
        compliantTrails++;
      } else {
        nonCompliantTrails++;
      }

      trails.push({
        name: trail.Name,
        arn: trail.TrailARN,
        is_multi_region: trail.IsMultiRegionTrail,
        is_logging: isLogging,
        log_file_validation: trail.LogFileValidationEnabled,
        compliant,
      });
    }

    // PASS only if at least one compliant trail exists and none are non-compliant
    const status =
      compliantTrails > 0 && nonCompliantTrails === 0 ? 'PASS' : 'FAIL';

    return {
      control_code: 'CC7.2',
      control_title: 'CloudTrail Enabled & Multi-Region Logging',
      integration_source: 'AWS',
      status,
      raw_evidence: {
        trails,
        compliant_trails: compliantTrails,
        non_compliant_trails: nonCompliantTrails,
      },
    };
  } catch (err) {
    return {
      control_code: 'CC7.2',
      control_title: 'CloudTrail Enabled & Multi-Region Logging',
      integration_source: 'AWS',
      status: 'ERROR',
      raw_evidence: { error: err.message },
    };
  }
}

// ---------------------------------------------------------------------------
// Check 4: CC6.7 – Default Security Group Lockdown
// ---------------------------------------------------------------------------

/**
 * Verify that default VPC security groups do not allow inbound traffic
 * from 0.0.0.0/0 or ::/0.
 *
 * @param {Object} credentials - AWS credentials.
 * @param {string} region
 * @returns {Promise<Object>} Check result.
 */
async function checkDefaultSecurityGroups(credentials, region) {
  try {
    const ec2 = new EC2Client(_clientConfig(credentials, region));

    const { SecurityGroups = [] } = await ec2.send(
      new DescribeSecurityGroupsCommand({
        Filters: [{ Name: 'group-name', Values: ['default'] }],
      })
    );

    const openSgs = [];

    for (const sg of SecurityGroups) {
      const hasOpenRule = (sg.IpPermissions || []).some((perm) => {
        const openIpv4 = (perm.IpRanges || []).some(
          (r) => r.CidrIp === '0.0.0.0/0'
        );
        const openIpv6 = (perm.Ipv6Ranges || []).some(
          (r) => r.CidrIpv6 === '::/0'
        );
        return openIpv4 || openIpv6;
      });

      if (hasOpenRule) {
        openSgs.push(sg.GroupId);
      }
    }

    const status = openSgs.length === 0 ? 'PASS' : 'FAIL';

    return {
      control_code: 'CC6.7',
      control_title: 'Default Security Groups Restrict Inbound Traffic',
      integration_source: 'AWS',
      status,
      raw_evidence: {
        default_sgs_checked: SecurityGroups.length,
        open_sgs: openSgs,
      },
    };
  } catch (err) {
    return {
      control_code: 'CC6.7',
      control_title: 'Default Security Groups Restrict Inbound Traffic',
      integration_source: 'AWS',
      status: 'ERROR',
      raw_evidence: { error: err.message },
    };
  }
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/**
 * Run all AWS security checks and return an array of check results.
 *
 * @param {{ accessKeyId: string, secretAccessKey: string, sessionToken?: string }} credentials
 * @param {string} [region='us-east-1']
 * @returns {Promise<Array<Object>>} Array of check result objects.
 */
async function runAllAwsChecks(credentials, region = 'us-east-1') {
  const results = await Promise.all([
    checkS3Encryption(credentials, region),
    checkIamMfa(credentials, region),
    checkCloudTrail(credentials, region),
    checkDefaultSecurityGroups(credentials, region),
  ]);

  return results;
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
module.exports = {
  runAllAwsChecks,
};

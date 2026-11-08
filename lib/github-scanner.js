'use strict';

// Helper to dynamically load ESM Octokit in CommonJS
let _Octokit = null;
async function getOctokitClass() {
  if (!_Octokit) {
    const mod = await import('@octokit/rest');
    _Octokit = mod.Octokit;
  }
  return _Octokit;
}

// ---------------------------------------------------------------------------
// Helper – fetch all org repos (with user fallback)
// ---------------------------------------------------------------------------

/**
 * Fetch repositories for the given org. Falls back to authenticated user's
 * repos if the org doesn't exist or the token doesn't have org scope.
 *
 * @param {Octokit} octokit
 * @param {string}  org
 * @returns {Promise<Array<Object>>}
 */
async function _listRepos(octokit, org) {
  try {
    // Paginate to collect all org repos
    const repos = await octokit.paginate(octokit.repos.listForOrg, {
      org,
      type: 'all',
      per_page: 100,
    });
    return repos;
  } catch (err) {
    // If org not found or insufficient permissions, fall back to user repos
    if (err.status === 404 || err.status === 403) {
      const repos = await octokit.paginate(
        octokit.repos.listForAuthenticatedUser,
        { per_page: 100 }
      );
      return repos;
    }
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Check 1: CC8.1 – Branch Protection / PR Reviews Required
// ---------------------------------------------------------------------------

/**
 * Verify that main/master branches require pull request reviews.
 *
 * @param {Octokit} octokit
 * @param {string}  org
 * @param {Array<Object>} repos
 * @returns {Promise<Object>} Check result.
 */
async function checkBranchProtection(octokit, org, repos) {
  try {
    const details = [];
    const unprotectedRepos = [];
    let protectedCount = 0;

    for (const repo of repos) {
      const owner = repo.owner.login;
      const repoName = repo.name;
      const defaultBranch = repo.default_branch || 'main';

      // Try default branch first, then 'main', then 'master'
      const branchesToTry = [
        defaultBranch,
        ...(defaultBranch !== 'main' ? ['main'] : []),
        ...(defaultBranch !== 'master' ? ['master'] : []),
      ];

      let protection = null;
      let checkedBranch = null;

      for (const branch of branchesToTry) {
        try {
          const { data } = await octokit.repos.getBranchProtection({
            owner,
            repo: repoName,
            branch,
          });
          protection = data;
          checkedBranch = branch;
          break; // found protection, stop trying
        } catch (branchErr) {
          if (branchErr.status === 404) {
            // No protection or branch doesn't exist – try next
            continue;
          }
          // Other error (e.g., 403 forbidden) – stop trying
          break;
        }
      }

      const requiredReviewCount =
        protection?.required_pull_request_reviews
          ?.required_approving_review_count || 0;

      const isProtected = requiredReviewCount >= 1;

      if (isProtected) {
        protectedCount++;
      } else {
        unprotectedRepos.push(repoName);
      }

      details.push({
        repo: repoName,
        branch: checkedBranch || defaultBranch,
        protected: isProtected,
        required_review_count: requiredReviewCount,
      });
    }

    await attachGraphqlPullRequests(octokit, repos, details);

    const status = unprotectedRepos.length === 0 ? 'PASS' : 'FAIL';

    return {
      control_code: 'CC8.1',
      control_title: 'Pull Request Reviews Required on Main Branch',
      integration_source: 'GitHub',
      status,
      raw_evidence: {
        repos_checked: repos.length,
        protected_repos: protectedCount,
        unprotected_repos: unprotectedRepos,
        details,
      },
    };
  } catch (err) {
    return {
      control_code: 'CC8.1',
      control_title: 'Pull Request Reviews Required on Main Branch',
      integration_source: 'GitHub',
      status: 'ERROR',
      raw_evidence: { error: err.message },
    };
  }
}

// ---------------------------------------------------------------------------
// Check 2: CC6.8 – Secret Scanning & Dependabot Alerts
// ---------------------------------------------------------------------------

/**
 * Verify that secret scanning and Dependabot alerts are enabled on repos.
 *
 * @param {Octokit} octokit
 * @param {string}  org
 * @param {Array<Object>} repos
 * @returns {Promise<Object>} Check result.
 */
async function attachGraphqlPullRequests(octokit, repos, details) {
  const byName = new Map(details.map((row) => [row.repo, row]));
  const sample = repos.slice(0, 8);
  await Promise.all(sample.map(async (repo) => {
    const row = byName.get(repo.name);
    if (!row) return;
    try {
      const response = await octokit.request('POST /graphql', {
        query: `query ($owner: String!, $name: String!) {
          repository(owner: $owner, name: $name) {
            pullRequests(states: OPEN, first: 5) {
              nodes { number title reviewDecision }
            }
          }
        }`,
        variables: { owner: repo.owner.login, name: repo.name },
      });
      const body = response.data || {};
      const repository = (body.data && body.data.repository) || body.repository;
      row.open_pull_requests = (repository && repository.pullRequests && repository.pullRequests.nodes) || [];
      row.evidence_api = 'github-rest+graphql';
    } catch (err) {
      row.graphql_note = err.message;
      row.evidence_api = 'github-rest';
    }
  }));
}

async function checkSecretScanningAndDependabot(octokit, org, repos) {
  try {
    const secretScanningEnabled = [];
    const secretScanningDisabled = [];
    let dependabotEnabledCount = 0;

    for (const repo of repos) {
      const owner = repo.owner.login;
      const repoName = repo.name;

      // --- Secret Scanning ---
      // The security_and_analysis field is available on the repo object
      // when the token has appropriate permissions
      try {
        const { data: repoDetails } = await octokit.repos.get({
          owner,
          repo: repoName,
        });

        const securityAnalysis = repoDetails.security_and_analysis;
        const secretScanningStatus =
          securityAnalysis?.secret_scanning?.status;

        if (secretScanningStatus === 'enabled') {
          secretScanningEnabled.push(repoName);
        } else {
          secretScanningDisabled.push(repoName);
        }
      } catch {
        // If we can't read repo details, mark as disabled
        secretScanningDisabled.push(repoName);
      }

      // --- Dependabot / Vulnerability Alerts ---
      // GET /repos/{owner}/{repo}/vulnerability-alerts
      // 204 = enabled, 404 = disabled
      try {
        await octokit.request(
          'GET /repos/{owner}/{repo}/vulnerability-alerts',
          { owner, repo: repoName }
        );
        // If no error thrown (status 204), Dependabot is enabled
        dependabotEnabledCount++;
      } catch (depErr) {
        // 404 means disabled; any other error we just skip
        // (no increment)
      }
    }

    const allSecretScanningEnabled = secretScanningDisabled.length === 0;
    const allDependabotEnabled = dependabotEnabledCount === repos.length;
    const status =
      allSecretScanningEnabled && allDependabotEnabled ? 'PASS' : 'FAIL';

    return {
      control_code: 'CC6.8',
      control_title: 'Secret Scanning & Dependabot Alerts Enabled',
      integration_source: 'GitHub',
      status,
      raw_evidence: {
        repos_checked: repos.length,
        secret_scanning_enabled: secretScanningEnabled,
        secret_scanning_disabled: secretScanningDisabled,
        dependabot_enabled_count: dependabotEnabledCount,
      },
    };
  } catch (err) {
    return {
      control_code: 'CC6.8',
      control_title: 'Secret Scanning & Dependabot Alerts Enabled',
      integration_source: 'GitHub',
      status: 'ERROR',
      raw_evidence: { error: err.message },
    };
  }
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/**
 * Run all GitHub security checks and return an array of check results.
 *
 * @param {{ token: string, org: string }} params
 * @returns {Promise<Array<Object>>} Array of check result objects.
 */
async function runAllGithubChecks({ token, org }) {
  const Octokit = await getOctokitClass();
  const octokit = new Octokit({ auth: token });

  let repos;
  try {
    repos = await _listRepos(octokit, org);
  } catch (err) {
    // If we can't even list repos, return ERROR for both checks
    const errorResult = {
      integration_source: 'GitHub',
      status: 'ERROR',
      raw_evidence: { error: err.message },
    };
    return [
      {
        control_code: 'CC8.1',
        control_title: 'Pull Request Reviews Required on Main Branch',
        ...errorResult,
      },
      {
        control_code: 'CC6.8',
        control_title: 'Secret Scanning & Dependabot Alerts Enabled',
        ...errorResult,
      },
    ];
  }

  // Run both checks concurrently
  const [branchProtection, secretScanning] = await Promise.all([
    checkBranchProtection(octokit, org, repos),
    checkSecretScanningAndDependabot(octokit, org, repos),
  ]);

  return [branchProtection, secretScanning];
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
module.exports = {
  runAllGithubChecks,
};

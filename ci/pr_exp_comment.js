const DEFAULT_CLUSTER = 'llm-experiment';
const LARGE_CLUSTER = 'llm-experiment-large';
const DEFAULT_LOCATION = 'us-central1-c';
const LARGE_LOCATION = 'us-central1';
const BENCHMARK_SET = 'comparison';

const TRIGGER_COMMAND = '/gcbrun';
const TRIAL_BUILD_COMMAND_STR = `${TRIGGER_COMMAND} exp `;
const SKIP_COMMAND_STR = `${TRIGGER_COMMAND} skip`;

const PR_LINK_PREFIX = 'https://github.com/google/oss-fuzz-gen/pull';
const JOB_LINK_PREFIX = 'https://console.cloud.google.com/kubernetes/job/<LOCATION>/<CLUSTER>/default';
const REPORT_LINK_PREFIX = 'https://llm-exp.oss-fuzz.com/Result-reports/ofg-pr';
const BUCKET_LINK_PREFIX = 'https://console.cloud.google.com/storage/browser/oss-fuzz-gcb-experiment-run-logs/Result-reports/ofg-pr';
const BUCKET_GS_LINK_PREFIX = 'gs://oss-fuzz-gcb-experiment-run-logs/Result-reports/ofg-pr';

/**
 * Parses command arguments from /gcbrun exp comment.
 * @param {string} comment - The comment body
 * @returns {Object|null} Parsed args {nameSuffix, benchmarkSet} or null if invalid
 */
function parseGcbrunArgs(comment) {
  if (!comment.startsWith(TRIAL_BUILD_COMMAND_STR)) {
    return null;
  }

  const args = comment.slice(TRIAL_BUILD_COMMAND_STR.length).trim().split(/\s+/);
  console.log('Parsed args:', args);

  let nameSuffix = '';
  let benchmarkSet = BENCHMARK_SET;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '-n' && i + 1 < args.length) {
      nameSuffix = args[i + 1];
    } else if (args[i] === '-b' && i + 1 < args.length) {
      benchmarkSet = args[i + 1];
    }
  }

  return { nameSuffix, benchmarkSet };
}

/**
 * Prepares and generates the key experiment information.
 * @param {number} prId - Pull request ID
 * @param {string} nameSuffix - Name suffix for the experiment
 * @param {string} benchmarkSet - Benchmark set name
 * @returns {Object} Generated experiment info with links and job name
 */
function prepareExperimentInfo(prId, nameSuffix, benchmarkSet) {
  const experimentName = `${prId}-${nameSuffix}`;

  const gkeJobName = `ofg-pr-${experimentName}`;

  const now = new Date();
  const date = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;

  // Base path for reports and buckets
  const basePath = `${date}-${prId}-${nameSuffix}-${benchmarkSet}`;

  // GKE job link
  let gkeJobLink = `${JOB_LINK_PREFIX}/ofg-pr-${experimentName}`;
  gkeJobLink = gkeJobLink.replace('<LOCATION>', DEFAULT_LOCATION);
  gkeJobLink = gkeJobLink.replace('<CLUSTER>', DEFAULT_CLUSTER);

  // PR link
  const prLink = `${PR_LINK_PREFIX}/${prId}`;

  // Report link
  const reportLink = `${REPORT_LINK_PREFIX}/${basePath}/index.html`;

  // Bucket links
  const bucketLink = `${BUCKET_LINK_PREFIX}/${basePath}`;
  const bucketGsLink = `${BUCKET_GS_LINK_PREFIX}/${basePath}`;

  return {
    gkeJobName,
    gkeJobLink,
    prLink,
    reportLink,
    bucketLink,
    bucketGsLink
  };
}

/**
 * Parses /gcbrun exp commands from PR comments and posts experiment links.
 * @param {Object} params - Parameters object
 * @param {Object} params.github - GitHub API client from actions/github-script
 * @param {Object} params.context - GitHub Actions context with event payload
 */
async function runPrExperimentCommenter({ github, context }) {
  const comment = context.payload.comment.body;
  const prNumber = context.payload.issue.number;

  const parsedArgs = parseGcbrunArgs(comment);
  if (!parsedArgs) {
    console.log('Not a valid /gcbrun exp command');
    return;
  }

  const { nameSuffix, benchmarkSet } = parsedArgs;
  if (!nameSuffix) {
    await github.rest.issues.createComment({
      owner: context.repo.owner,
      repo: context.repo.repo,
      issue_number: prNumber,
      body: 'Error: Missing required `-n` (name suffix) parameter in /gcbrun command.'
    });
    return;
  }

  const experimentInfo = prepareExperimentInfo(prNumber, nameSuffix, benchmarkSet);

  console.log(
    `Requesting a GKE experiment named ${experimentInfo.gkeJobName}:\n` +
    `PR: ${experimentInfo.prLink}\n` +
    `JOB: ${experimentInfo.gkeJobLink}\n` +
    `REPORT: ${experimentInfo.reportLink}\n` +
    `BUCKET: ${experimentInfo.bucketLink}\n` +
    `BUCKET GS: ${experimentInfo.bucketGsLink}`
  );

  const body = `Requested GKE Job: ${experimentInfo.gkeJobName}

  JOB: ${experimentInfo.gkeJobLink}
  REPORT: ${experimentInfo.reportLink}
  BUCKET: ${experimentInfo.bucketLink}
  BUCKET (GS): ${experimentInfo.bucketGsLink}`;

  await github.rest.issues.createComment({
    owner: context.repo.owner,
    repo: context.repo.repo,
    issue_number: prNumber,
    body: body
  });

  console.log(`Posted experiment links for PR #${prNumber}, job: ${experimentInfo.gkeJobName}`);
}

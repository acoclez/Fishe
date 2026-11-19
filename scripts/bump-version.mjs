#!/usr/bin/env node
// Set Fishe's version everywhere it lives, so the copies never drift:
//
//   npm run version:set -- 0.15.0
//
// Touches package.json, package-lock.json (two entries), src-tauri/tauri.conf.json,
// Cargo.toml (the workspace version both crates inherit) and Cargo.lock (the
// `fishe` and `fishe-core` packages). It does not write CHANGELOG.md, but
// warns when the new version has no entry there yet.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const v = process.argv[2];
if (!/^\d+\.\d+\.\d+$/.test(v ?? "")) {
  console.error("usage: node scripts/bump-version.mjs <major.minor.patch>");
  process.exit(1);
}

/** Rewrite one file; refuse to continue if the pattern did not match. */
function edit(file, fn) {
  const path = resolve(root, file);
  const before = readFileSync(path, "utf8");
  const after = fn(before);
  if (after === before) {
    console.error(`${file}: no version found to replace`);
    process.exit(1);
  }
  writeFileSync(path, after);
  console.log(`${file} → ${v}`);
}

// First `"version": "x.y.z"` only (package.json's own, tauri.conf.json's own).
const firstJsonVersion = (s) => s.replace(/("version":\s*")\d+\.\d+\.\d+(")/, `$1${v}$2`);

edit("package.json", firstJsonVersion);
edit("src-tauri/tauri.conf.json", firstJsonVersion);
edit("package-lock.json", (s) => {
  const lock = JSON.parse(s);
  lock.version = v;
  if (lock.packages?.[""]) lock.packages[""].version = v;
  return JSON.stringify(lock, null, 2) + "\n";
});
edit("Cargo.toml", (s) => s.replace(/^(version\s*=\s*")\d+\.\d+\.\d+(")/m, `$1${v}$2`));
edit("Cargo.lock", (s) => s.replace(/(name = "fishe(?:-core)?"\r?\nversion = ")\d+\.\d+\.\d+(")/g, `$1${v}$2`));

const changelog = readFileSync(resolve(root, "CHANGELOG.md"), "utf8");
if (!changelog.includes(`## ${v}`)) {
  console.warn(`note: CHANGELOG.md has no "## ${v}" entry yet`);
}

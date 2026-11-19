// Regenerates crates/fishe-core/data/oui.tsv.gz, the MAC vendor list bundled in Fishe,
// from the IEEE registries (MA-L 24-bit, MA-M 28-bit, MA-S 36-bit prefixes).
//
//   node scripts/update-oui.mjs              download from standards-oui.ieee.org
//   node scripts/update-oui.mjs <folder>     use oui.csv, mam.csv, oui36.csv from a folder
//
// Output: one "PREFIX\tVendor" line per assignment, PREFIX = 6, 7 or 9 upper-case
// hex digits, sorted, gzip-compressed. Vendor names lose legal suffixes
// ("Apple, Inc." → "Apple") to stay short.
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { gzipSync } from "node:zlib";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "crates", "fishe-core", "data", "oui.tsv.gz");
const sources = [
  ["oui.csv", "https://standards-oui.ieee.org/oui/oui.csv", 6],
  ["mam.csv", "https://standards-oui.ieee.org/oui28/mam.csv", 7],
  ["oui36.csv", "https://standards-oui.ieee.org/oui36/oui36.csv", 9],
];

/** Fields of one CSV line (quotes and doubled quotes). */
function csvFields(line) {
  const f = [];
  let cur = "", q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) {
      if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (c === '"') q = false;
      else cur += c;
    } else if (c === '"') q = true;
    else if (c === ",") { f.push(cur); cur = ""; }
    else cur += c;
  }
  f.push(cur);
  return f;
}

const SUFFIX = /[\s,.]*\b(inc|incorporated|corp|corporation|co|company|ltd|limited|llc|l\.l\.c|gmbh|ag|s\.?a\.?|s\.?r\.?l|s\.?p\.?a|b\.?v|n\.?v|oy|ab|as|a\/s|plc|pty|pte|kk|k\.k|sas|sarl|spa|srl|bv|nv|co\.,? ?ltd|technology|technologies|electronics|international)\.?$/i;

function clean(name) {
  let n = name.replace(/\s+/g, " ").trim();
  for (let i = 0; i < 4; i++) {
    const m = n.replace(SUFFIX, "").replace(/[\s,.]+$/, "").trim();
    if (m === n || m.length < 2) break;
    n = m;
  }
  return n;
}

async function load(file, url) {
  if (process.argv[2]) return readFile(join(process.argv[2], file), "utf8");
  const r = await fetch(url, { headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) fishe-oui-update" } });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  return r.text();
}

const rows = new Map();
for (const [file, url, digits] of sources) {
  const text = await load(file, url);
  let n = 0;
  for (const line of text.split(/\r?\n/).slice(1)) {
    if (!line.trim()) continue;
    const [, assignment, org] = csvFields(line);
    const prefix = (assignment ?? "").trim().toUpperCase();
    if (!/^[0-9A-F]+$/.test(prefix) || prefix.length !== digits || !org?.trim()) continue;
    // "Private" hides the owner; the RA blocks are parents of MA-M/MA-S entries.
    if (/^(private|ieee registration authority)$/i.test(org.trim())) continue;
    rows.set(prefix, clean(org));
    n++;
  }
  console.log(`${file}: ${n} assignments`);
}
const body = [...rows].sort(([a], [b]) => (a < b ? -1 : 1)).map(([p, v]) => `${p}\t${v}`).join("\n") + "\n";
const gz = gzipSync(Buffer.from(body, "utf8"), { level: 9 });
await mkdir(dirname(out), { recursive: true });
await writeFile(out, gz);
console.log(`${rows.size} prefixes, ${(body.length / 1024).toFixed(0)} KiB → ${(gz.length / 1024).toFixed(0)} KiB gzip: ${out}`);

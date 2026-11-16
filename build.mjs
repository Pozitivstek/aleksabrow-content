// Encrypts all week plans into data.enc.json with the site access code.
// Usage: node build.mjs <weeksDir> <accessCodeFile> <outFile>
// The weeks folder and the code file stay OUTSIDE the public repo; only ciphertext is published.
import { readFileSync, writeFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { webcrypto } from "node:crypto";

const PBKDF2_ITERATIONS = 600000;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const WEEK_FILE = /^\d{4}-\d{2}-\d{2}\.json$/;
const REQUIRED_FIELDS = ["start", "end", "title", "reels"];

const fail = (msg) => { console.error("build failed: " + msg); process.exit(1); };
const b64 = (buf) => Buffer.from(buf).toString("base64");

function loadWeeks(dir) {
  if (!existsSync(dir)) fail(`weeks folder not found: ${dir}`);
  const files = readdirSync(dir).filter((f) => WEEK_FILE.test(f));
  if (!files.length) fail(`no week files (YYYY-MM-DD.json) in ${dir}`);
  return files.map((f) => {
    let week;
    try { week = JSON.parse(readFileSync(join(dir, f), "utf8")); }
    catch (e) { fail(`${f} is not valid JSON: ${e.message}`); }
    const missing = REQUIRED_FIELDS.filter((k) => !(k in week));
    if (missing.length) fail(`${f} is missing fields: ${missing.join(", ")}`);
    return { id: f.replace(".json", ""), ...week };
  }).sort((a, b) => b.start.localeCompare(a.start));
}

function readSalt(outFile) {
  if (!existsSync(outFile)) return webcrypto.getRandomValues(new Uint8Array(SALT_BYTES));
  try { return new Uint8Array(Buffer.from(JSON.parse(readFileSync(outFile, "utf8")).salt, "base64")); }
  catch { return webcrypto.getRandomValues(new Uint8Array(SALT_BYTES)); }
}

async function main() {
  const [weeksDir, codeFile, outFile] = process.argv.slice(2);
  if (!weeksDir || !codeFile || !outFile) fail("usage: node build.mjs <weeksDir> <accessCodeFile> <outFile>");
  if (!existsSync(codeFile)) fail(`access code file not found: ${codeFile}`);
  const code = readFileSync(codeFile, "utf8").trim();
  if (code.length < 10) fail("access code must be at least 10 characters");

  const weeks = loadWeeks(weeksDir);
  // Keep the salt stable so devices that already unlocked the site keep working after weekly updates.
  const salt = readSalt(outFile);
  const iv = webcrypto.getRandomValues(new Uint8Array(IV_BYTES));
  const base = await webcrypto.subtle.importKey("raw", new TextEncoder().encode(code), "PBKDF2", false, ["deriveKey"]);
  const key = await webcrypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const plain = new TextEncoder().encode(JSON.stringify({ weeks, builtAt: new Date().toISOString() }));
  const ct = await webcrypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain);

  writeFileSync(outFile, JSON.stringify({ v: 1, iter: PBKDF2_ITERATIONS, salt: b64(salt), iv: b64(iv), ct: b64(ct) }));
  console.log(`encrypted ${weeks.length} week(s) -> ${outFile}`);
}

main().catch((e) => fail(e.message));

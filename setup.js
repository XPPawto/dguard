#!/usr/bin/env node
// Helper: generate password hash dan API key
// Usage: node setup.js

const crypto = require("crypto");
const readline = require("readline");

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const q  = (prompt) => new Promise(r => rl.question(prompt, r));

(async () => {
  console.log("\n🛡️  DriveGuard Server Setup\n" + "─".repeat(40));

  const pw   = await q("Masukkan password kamu: ");
  const hash = crypto.createHash("sha256").update(pw + "driveguard_salt_v1").digest("hex");
  const key  = crypto.randomBytes(32).toString("hex");

  console.log("\n✅ Salin nilai ini ke file .env kamu:\n");
  console.log(`API_KEY=${key}`);
  console.log(`PASSWORD_HASH=${hash}`);
  console.log("\n⚠️  Jangan share API_KEY dan PASSWORD_HASH ke siapapun!");
  console.log("📝 Copy juga API_KEY ke config extension (SERVER_API_KEY)\n");

  rl.close();
})();

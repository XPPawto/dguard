require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const Database = require("better-sqlite3");
const TelegramBot = require("node-telegram-bot-api");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// ─── Config ──────────────────────────────────────────────────────────────────
const PORT         = process.env.PORT || 3000;
const API_KEY      = process.env.API_KEY;          // shared secret extension ↔ server
const BOT_TOKEN    = process.env.TELEGRAM_BOT_TOKEN;
const CHAT_ID      = process.env.TELEGRAM_CHAT_ID;
const TOTP_SECRET  = process.env.TOTP_SECRET;
const PW_HASH      = process.env.PASSWORD_HASH;    // SHA-256 hex of password+salt
const SALT         = "driveguard_salt_v1";
const MAX_FAILS    = 3;                            // foto setelah N kali gagal
const LOCK_AFTER   = 5;                            // lock sesi setelah N kali gagal

// ─── Telegram Bot ─────────────────────────────────────────────────────────────
const bot = new TelegramBot(BOT_TOKEN, { polling: true });

// ─── SQLite DB ────────────────────────────────────────────────────────────────
const db = new Database("driveguard.db");
db.exec(`
  CREATE TABLE IF NOT EXISTS access_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    event     TEXT NOT NULL,
    ip        TEXT,
    ua        TEXT,
    detail    TEXT
  );
  CREATE TABLE IF NOT EXISTS sessions (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    token     TEXT UNIQUE NOT NULL,
    created   TEXT NOT NULL,
    expires   TEXT NOT NULL,
    active    INTEGER DEFAULT 1
  );
  CREATE TABLE IF NOT EXISTS fail_count (
    ip        TEXT PRIMARY KEY,
    count     INTEGER DEFAULT 0,
    last_fail TEXT
  );
`);

const logEvent = (event, ip, ua, detail) => {
  db.prepare("INSERT INTO access_log (ts, event, ip, ua, detail) VALUES (?,?,?,?,?)")
    .run(new Date().toISOString(), event, ip||"", ua||"", detail||"");
};

// ─── In-memory lock state ─────────────────────────────────────────────────────
let globalLocked = false;   // remote lock dari Telegram
const activeSessions = new Set();

// ─── Express App ──────────────────────────────────────────────────────────────
const app = express();
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: "5mb" }));  // 5mb untuk foto base64

// Rate limiter ketat untuk endpoint auth
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { ok: false, error: "Too many requests" }
});

// Middleware: cek API key
const checkKey = (req, res, next) => {
  if (req.headers["x-api-key"] !== API_KEY) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }
  next();
};

const getIP = (req) => req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;

// ─── TOTP ─────────────────────────────────────────────────────────────────────
function base32Decode(s) {
  const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  s = s.toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = 0, val = 0;
  const out = [];
  for (const ch of s) {
    val = (val << 5) | alpha.indexOf(ch);
    bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out);
}

async function generateTOTP(secret, offset = 0) {
  const key     = base32Decode(secret);
  const counter = Math.floor(Date.now() / 1000 / 30) + offset;
  const buf     = Buffer.alloc(8);
  buf.writeUInt32BE(counter, 4);
  const hmac    = crypto.createHmac("sha1", key).update(buf).digest();
  const off2    = hmac[19] & 0xf;
  const code    = ((hmac.readUInt32BE(off2) & 0x7fffffff) % 1000000);
  return code.toString().padStart(6, "0");
}

async function verifyTOTP(secret, token) {
  for (const step of [-1, 0, 1]) {
    if (await generateTOTP(secret, step) === token) return true;
  }
  return false;
}

// ─── Password hash ────────────────────────────────────────────────────────────
function hashPw(pw) {
  return crypto.createHash("sha256").update(pw + SALT).digest("hex");
}

// ─── Fail tracking ────────────────────────────────────────────────────────────
function getFailCount(ip) {
  const row = db.prepare("SELECT count FROM fail_count WHERE ip=?").get(ip);
  return row?.count || 0;
}
function incFail(ip) {
  db.prepare(`INSERT INTO fail_count (ip, count, last_fail) VALUES (?,1,?)
    ON CONFLICT(ip) DO UPDATE SET count=count+1, last_fail=excluded.last_fail`)
    .run(ip, new Date().toISOString());
  return getFailCount(ip);
}
function resetFail(ip) {
  db.prepare("DELETE FROM fail_count WHERE ip=?").run(ip);
}

// ─── Telegram helpers ─────────────────────────────────────────────────────────
const tgSend = (msg) => bot.sendMessage(CHAT_ID, msg, { parse_mode: "HTML" });

const tgPhoto = (base64, caption) => {
  const buf = Buffer.from(base64.replace(/^data:image\/\w+;base64,/, ""), "base64");
  return bot.sendPhoto(CHAT_ID, buf, { caption, parse_mode: "HTML" });
};

function fmtTime() {
  return new Date().toLocaleString("id-ID", { timeZone: "Asia/Jakarta" });
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// Health check
app.get("/health", (req, res) => res.json({ ok: true, locked: globalLocked }));

// Notifikasi: Drive dibuka
app.post("/api/drive-opened", checkKey, (req, res) => {
  const { ua } = req.body;
  const ip = getIP(req);
  logEvent("DRIVE_OPENED", ip, ua, "");

  tgSend(
    `🔔 <b>Drive Dibuka</b>\n` +
    `⏰ ${fmtTime()}\n` +
    `🌐 IP: <code>${ip}</code>\n` +
    `📱 UA: <code>${(ua||"").slice(0,80)}</code>`
  );

  res.json({ ok: true, locked: globalLocked });
});

// Auth: verifikasi password + TOTP
app.post("/api/auth", authLimiter, checkKey, async (req, res) => {
  const { password, totp, photo, ua } = req.body;
  const ip = getIP(req);

  // Cek global lock
  if (globalLocked) {
    logEvent("AUTH_BLOCKED_LOCKED", ip, ua, "");
    return res.json({ ok: false, error: "Akses dikunci oleh admin" });
  }

  const pwOk   = hashPw(password) === PW_HASH;
  const totpOk = pwOk && await verifyTOTP(TOTP_SECRET, totp);

  if (!pwOk || !totpOk) {
    const fails = incFail(ip);
    logEvent("AUTH_FAIL", ip, ua, `fails=${fails} pw=${pwOk}`);

    // Kirim foto kalau >= MAX_FAILS
    if (photo && fails >= MAX_FAILS) {
      await tgPhoto(photo,
        `🚨 <b>INTRUDER ALERT!</b>\n` +
        `Gagal login ${fails}x\n` +
        `⏰ ${fmtTime()}\n` +
        `🌐 IP: <code>${ip}</code>`
      ).catch(() => {});
    }

    await tgSend(
      `⚠️ <b>Gagal Login #${fails}</b>\n` +
      `⏰ ${fmtTime()}\n` +
      `🌐 IP: <code>${ip}</code>\n` +
      `🔑 PW: ${pwOk ? "✅" : "❌"} | TOTP: ${totpOk ? "✅" : "❌"}` +
      (fails >= LOCK_AFTER ? `\n🔒 <b>Sesi auto-dikunci setelah ${fails} kegagalan!</b>` : "")
    );

    if (fails >= LOCK_AFTER) globalLocked = true;

    return res.json({ ok: false, error: pwOk ? "Kode TOTP salah" : "Password salah" });
  }

  // Sukses
  resetFail(ip);
  const token = crypto.randomBytes(32).toString("hex");
  const expires = new Date(Date.now() + 30 * 60 * 1000).toISOString();
  db.prepare("INSERT INTO sessions (token, created, expires) VALUES (?,?,?)")
    .run(token, new Date().toISOString(), expires);
  activeSessions.add(token);
  logEvent("AUTH_SUCCESS", ip, ua, "");

  tgSend(
    `✅ <b>Login Berhasil</b>\n` +
    `⏰ ${fmtTime()}\n` +
    `🌐 IP: <code>${ip}</code>\n` +
    `⏳ Sesi aktif 30 menit`
  );

  res.json({ ok: true, token, expiresAt: expires });
});

// Cek token sesi
app.post("/api/check-session", checkKey, (req, res) => {
  const { token } = req.body;
  if (!token || !activeSessions.has(token)) return res.json({ ok: false });
  const row = db.prepare("SELECT expires, active FROM sessions WHERE token=?").get(token);
  if (!row || !row.active || new Date(row.expires) < new Date()) {
    activeSessions.delete(token);
    return res.json({ ok: false });
  }
  res.json({ ok: true });
});

// Remote lock (dari Telegram)
app.post("/api/remote-lock", checkKey, (req, res) => {
  globalLocked = true;
  activeSessions.clear();
  logEvent("REMOTE_LOCK", getIP(req), "", "via API");
  res.json({ ok: true });
});

// Remote unlock (dari Telegram)
app.post("/api/remote-unlock", checkKey, (req, res) => {
  globalLocked = false;
  logEvent("REMOTE_UNLOCK", getIP(req), "", "via API");
  res.json({ ok: true });
});

// Log akses
app.get("/api/logs", checkKey, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
  const rows = db.prepare("SELECT * FROM access_log ORDER BY id DESC LIMIT ?").all(limit);
  res.json({ ok: true, logs: rows });
});

// ─── Telegram Bot Commands ────────────────────────────────────────────────────
bot.onText(/\/start/, (msg) => {
  if (String(msg.chat.id) !== String(CHAT_ID)) return;
  bot.sendMessage(CHAT_ID,
    `🛡️ <b>DriveGuard Bot</b>\n\n` +
    `Perintah tersedia:\n` +
    `/lock — Kunci semua sesi\n` +
    `/unlock — Buka kunci\n` +
    `/status — Status sistem\n` +
    `/log — 10 akses terakhir\n` +
    `/logall — 30 akses terakhir\n` +
    `/fails — Daftar IP yang gagal\n` +
    `/clearfails — Reset semua fail counter\n` +
    `/sessions — Sesi aktif saat ini`,
    { parse_mode: "HTML" }
  );
});

bot.onText(/\/lock/, async (msg) => {
  if (String(msg.chat.id) !== String(CHAT_ID)) return;
  globalLocked = true;
  activeSessions.clear();
  logEvent("REMOTE_LOCK", "telegram", "", `by user ${msg.from.username}`);
  bot.sendMessage(CHAT_ID, "🔒 <b>Semua sesi dikunci!</b> Drive tidak bisa diakses sampai di-unlock.", { parse_mode: "HTML" });
});

bot.onText(/\/unlock/, async (msg) => {
  if (String(msg.chat.id) !== String(CHAT_ID)) return;
  globalLocked = false;
  logEvent("REMOTE_UNLOCK", "telegram", "", `by user ${msg.from.username}`);
  bot.sendMessage(CHAT_ID, "🔓 <b>Drive di-unlock!</b> Akses normal kembali.", { parse_mode: "HTML" });
});

bot.onText(/\/status/, (msg) => {
  if (String(msg.chat.id) !== String(CHAT_ID)) return;
  const totalLogs  = db.prepare("SELECT COUNT(*) as c FROM access_log").get().c;
  const failsToday = db.prepare("SELECT COUNT(*) as c FROM access_log WHERE event='AUTH_FAIL' AND ts > datetime('now','-24 hours')").get().c;
  const okToday    = db.prepare("SELECT COUNT(*) as c FROM access_log WHERE event='AUTH_SUCCESS' AND ts > datetime('now','-24 hours')").get().c;
  bot.sendMessage(CHAT_ID,
    `📊 <b>Status DriveGuard</b>\n\n` +
    `🔒 Global lock: ${globalLocked ? "AKTIF 🔴" : "tidak aktif 🟢"}\n` +
    `👤 Sesi aktif: ${activeSessions.size}\n` +
    `📋 Total log: ${totalLogs}\n` +
    `✅ Login sukses hari ini: ${okToday}\n` +
    `❌ Login gagal hari ini: ${failsToday}\n` +
    `⏰ Waktu server: ${fmtTime()}`,
    { parse_mode: "HTML" }
  );
});

const sendLogs = (chatId, limit) => {
  const rows = db.prepare("SELECT ts, event, ip, detail FROM access_log ORDER BY id DESC LIMIT ?").all(limit);
  if (!rows.length) return bot.sendMessage(chatId, "Belum ada log.");
  const icons = { AUTH_SUCCESS:"✅", AUTH_FAIL:"❌", DRIVE_OPENED:"🔔", REMOTE_LOCK:"🔒", REMOTE_UNLOCK:"🔓", AUTH_BLOCKED_LOCKED:"🚫" };
  const text = rows.map(r => {
    const ico = icons[r.event] || "📝";
    const t = r.ts.replace("T"," ").slice(0,16);
    return `${ico} <code>${t}</code> ${r.event}\n   IP: <code>${r.ip}</code>${r.detail ? " "+r.detail : ""}`;
  }).join("\n\n");
  bot.sendMessage(chatId, `<b>Log Akses</b>\n\n${text}`, { parse_mode: "HTML" });
};

bot.onText(/\/log$/, (msg) => { if (String(msg.chat.id)!==String(CHAT_ID)) return; sendLogs(CHAT_ID, 10); });
bot.onText(/\/logall/, (msg) => { if (String(msg.chat.id)!==String(CHAT_ID)) return; sendLogs(CHAT_ID, 30); });

bot.onText(/\/fails/, (msg) => {
  if (String(msg.chat.id) !== String(CHAT_ID)) return;
  const rows = db.prepare("SELECT ip, count, last_fail FROM fail_count ORDER BY count DESC").all();
  if (!rows.length) return bot.sendMessage(CHAT_ID, "✅ Tidak ada IP yang gagal login.");
  const text = rows.map(r => `❌ <code>${r.ip}</code> — ${r.count}x gagal\n   Last: ${r.last_fail?.slice(0,16)}`).join("\n\n");
  bot.sendMessage(CHAT_ID, `<b>IP Gagal Login</b>\n\n${text}`, { parse_mode: "HTML" });
});

bot.onText(/\/clearfails/, (msg) => {
  if (String(msg.chat.id) !== String(CHAT_ID)) return;
  db.prepare("DELETE FROM fail_count").run();
  bot.sendMessage(CHAT_ID, "✅ Semua fail counter direset.");
});

bot.onText(/\/sessions/, (msg) => {
  if (String(msg.chat.id) !== String(CHAT_ID)) return;
  const rows = db.prepare("SELECT token, created, expires FROM sessions WHERE active=1 AND expires > datetime('now') ORDER BY created DESC").all();
  if (!rows.length) return bot.sendMessage(CHAT_ID, "Tidak ada sesi aktif saat ini.");
  const text = rows.map(r =>
    `🟢 <code>${r.token.slice(0,12)}...</code>\n   Dibuat: ${r.created.slice(0,16)}\n   Expires: ${r.expires.slice(0,16)}`
  ).join("\n\n");
  bot.sendMessage(CHAT_ID, `<b>Sesi Aktif (${rows.length})</b>\n\n${text}`, { parse_mode: "HTML" });
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ DriveGuard server running on port ${PORT}`);
  tgSend(`🟢 <b>DriveGuard Server Online</b>\n⏰ ${fmtTime()}`).catch(() => {});
});

// Cleanup expired sessions setiap 10 menit
setInterval(() => {
  db.prepare("UPDATE sessions SET active=0 WHERE expires < datetime('now')").run();
  activeSessions.forEach(tok => {
    const row = db.prepare("SELECT active FROM sessions WHERE token=?").get(tok);
    if (!row || !row.active) activeSessions.delete(tok);
  });
}, 10 * 60 * 1000);

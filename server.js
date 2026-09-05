require("dotenv").config();
const express    = require("express");
const helmet     = require("helmet");
const cors       = require("cors");
const rateLimit  = require("express-rate-limit");
const sqlite3    = require("sqlite3").verbose();
const TelegramBot = require("node-telegram-bot-api");
const crypto     = require("crypto");

// ─── Config ───────────────────────────────────────────────────────────────────
const PORT       = process.env.PORT || 3000;
const API_KEY    = (process.env.API_KEY || "").trim();
const BOT_TOKEN  = (process.env.TELEGRAM_BOT_TOKEN || "").trim();
const CHAT_ID    = (process.env.TELEGRAM_CHAT_ID || "").trim();
const PW_HASH    = (process.env.PASSWORD_HASH || "").trim();
const SALT       = "driveguard_salt_v1";
const MAX_FAILS  = 3;
const LOCK_AFTER = 5;
const OTP_EXPIRY = 2 * 60 * 1000; // OTP expired setelah 2 menit

if (!API_KEY || !BOT_TOKEN || !CHAT_ID || !PW_HASH) {
  console.error("❌ .env belum lengkap! Cek API_KEY, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, PASSWORD_HASH");
  process.exit(1);
}

// ─── Telegram ─────────────────────────────────────────────────────────────────
const bot = new TelegramBot(BOT_TOKEN, { polling: true });

// ─── SQLite ───────────────────────────────────────────────────────────────────
const db = new sqlite3.Database("driveguard.db");
const dbRun = (sql, p=[]) => new Promise((res,rej) => db.run(sql, p, function(e){ e?rej(e):res(this); }));
const dbGet = (sql, p=[]) => new Promise((res,rej) => db.get(sql, p, (e,r) => e?rej(e):res(r)));
const dbAll = (sql, p=[]) => new Promise((res,rej) => db.all(sql, p, (e,r) => e?rej(e):res(r)));

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS access_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, event TEXT NOT NULL,
    ip TEXT, ua TEXT, detail TEXT)`);
  db.run(`CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL, created TEXT NOT NULL,
    expires TEXT NOT NULL, active INTEGER DEFAULT 1)`);
  db.run(`CREATE TABLE IF NOT EXISTS fail_count (
    ip TEXT PRIMARY KEY, count INTEGER DEFAULT 0, last_fail TEXT)`);
});

const logEvent = (event, ip, ua, detail) =>
  dbRun("INSERT INTO access_log (ts,event,ip,ua,detail) VALUES (?,?,?,?,?)",
    [new Date().toISOString(), event, ip||"", ua||"", detail||""]).catch(()=>{});

// ─── State ────────────────────────────────────────────────────────────────────
let globalLocked = false;
const activeSessions = new Set();

// ─── OTP Store (in-memory) ────────────────────────────────────────────────────
// { requestId: { code, expiresAt, ip, photo } }
const otpStore = new Map();

// ─── Express ──────────────────────────────────────────────────────────────────
const app = express();
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: "5mb" }));

const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 20,
  message: { ok: false, error: "Too many requests" } });

const checkKey = (req, res, next) => {
  if (req.headers["x-api-key"] !== API_KEY)
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  next();
};

const getIP  = (req) => req.headers["x-forwarded-for"]?.split(",")[0] || req.socket.remoteAddress;
const hashPw = (pw)  => crypto.createHash("sha256").update(pw + SALT).digest("hex");
const fmtTime = ()   => new Date().toLocaleString("id-ID", { timeZone: "Asia/Jakarta" });
const tgSend  = (msg) => bot.sendMessage(CHAT_ID, msg, { parse_mode:"HTML" }).catch(()=>{});
const tgPhoto = (b64, caption) => {
  const buf = Buffer.from(b64.replace(/^data:image\/\w+;base64,/,""), "base64");
  return bot.sendPhoto(CHAT_ID, buf, { caption, parse_mode:"HTML" }).catch(()=>{});
};

// ─── Fail tracking ────────────────────────────────────────────────────────────
async function getFailCount(ip) {
  const row = await dbGet("SELECT count FROM fail_count WHERE ip=?", [ip]);
  return row?.count || 0;
}
async function incFail(ip) {
  await dbRun(`INSERT INTO fail_count (ip,count,last_fail) VALUES (?,1,?)
    ON CONFLICT(ip) DO UPDATE SET count=count+1,last_fail=excluded.last_fail`,
    [ip, new Date().toISOString()]);
  return getFailCount(ip);
}
const resetFail = (ip) => dbRun("DELETE FROM fail_count WHERE ip=?", [ip]).catch(()=>{});

// ─── Routes ───────────────────────────────────────────────────────────────────
app.get("/health", (req, res) => res.json({ ok:true, locked:globalLocked }));

// Notif Drive dibuka
app.post("/api/drive-opened", checkKey, async (req, res) => {
  const { ua } = req.body;
  const ip = getIP(req);
  logEvent("DRIVE_OPENED", ip, ua, "");
  tgSend(`🔔 <b>Drive Dibuka</b>\n⏰ ${fmtTime()}\n🌐 IP: <code>${ip}</code>`);
  res.json({ ok:true, locked:globalLocked });
});

// Step 1: Verifikasi password → kirim OTP ke Telegram
app.post("/api/request-otp", authLimiter, checkKey, async (req, res) => {
  const { password, photo, ua } = req.body;
  const ip = getIP(req);

  if (globalLocked) {
    logEvent("AUTH_BLOCKED_LOCKED", ip, ua, "");
    return res.json({ ok:false, error:"Akses dikunci oleh admin" });
  }

  const pwOk = hashPw(String(password || "").trim()) === PW_HASH;

  if (!pwOk) {
    const fails = await incFail(ip);
    logEvent("AUTH_FAIL_PW", ip, ua, `fails=${fails}`);
    console.log(`[DEBUG] Password mismatch. Computed=${hashPw(String(password||"").trim()).slice(0,16)}... Expected=${PW_HASH.slice(0,16)}...`);

    if (fails >= MAX_FAILS) {
      if (photo) {
        tgPhoto(photo, `🚨 <b>INTRUDER!</b> Gagal login ${fails}x\n⏰ ${fmtTime()}\n🌐 IP: <code>${ip}</code>`);
      } else {
        tgSend(`🚨 <b>INTRUDER ALERT!</b> Gagal login ${fails}x\n⏰ ${fmtTime()}\n🌐 IP: <code>${ip}</code>\n📷 <i>Foto tidak tersedia (kamera diblokir/tidak ada webcam)</i>`);
      }
    }

    tgSend(`⚠️ <b>Password Salah #${fails}</b>\n⏰ ${fmtTime()}\n🌐 IP: <code>${ip}</code>` +
      (fails >= LOCK_AFTER ? `\n🔒 <b>Auto-lock aktif!</b>` : ""));

    if (fails >= LOCK_AFTER) { globalLocked = true; activeSessions.clear(); }
    return res.json({ ok:false, error:"Password salah" });
  }

  // Password benar → generate OTP 6 digit → kirim ke Telegram
  const requestId = crypto.randomBytes(16).toString("hex");
  const code      = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = Date.now() + OTP_EXPIRY;

  otpStore.set(requestId, { code, expiresAt, ip, photo });

  // Kirim OTP ke Telegram
  await tgSend(
    `🔐 <b>Kode Verifikasi DriveGuard</b>\n\n` +
    `<b style="font-size:24px">🔑 ${code}</b>\n\n` +
    `⏰ Berlaku 2 menit\n` +
    `🌐 IP: <code>${ip}</code>\n` +
    `🕐 ${fmtTime()}\n\n` +
    `<i>Jika bukan kamu yang login, abaikan dan ketik /lock</i>`
  );

  logEvent("OTP_SENT", ip, ua, "");
  res.json({ ok:true, requestId, expiresIn: 120 });
});

// Step 2: Verifikasi OTP
app.post("/api/verify-otp", authLimiter, checkKey, async (req, res) => {
  const { requestId, otp, ua } = req.body;
  const ip = getIP(req);

  const entry = otpStore.get(requestId);

  if (!entry) return res.json({ ok:false, error:"Sesi OTP tidak ditemukan. Minta kode baru." });
  if (Date.now() > entry.expiresAt) {
    otpStore.delete(requestId);
    return res.json({ ok:false, error:"Kode OTP expired. Minta kode baru." });
  }
  if (entry.code !== otp) {
    const fails = await incFail(ip);
    logEvent("AUTH_FAIL_OTP", ip, ua, `fails=${fails}`);

    if (entry.photo && fails >= MAX_FAILS)
      tgPhoto(entry.photo, `🚨 <b>INTRUDER!</b> OTP salah ${fails}x\n⏰ ${fmtTime()}\n🌐 IP: <code>${ip}</code>`);

    tgSend(`⚠️ <b>OTP Salah #${fails}</b>\n⏰ ${fmtTime()}\n🌐 IP: <code>${ip}</code>`);

    if (fails >= LOCK_AFTER) { globalLocked = true; activeSessions.clear(); }
    return res.json({ ok:false, error:"Kode salah" });
  }

  // OTP benar!
  otpStore.delete(requestId);
  resetFail(ip);

  const token   = crypto.randomBytes(32).toString("hex");
  const expires = new Date(Date.now() + 30*60*1000).toISOString();
  await dbRun("INSERT INTO sessions (token,created,expires) VALUES (?,?,?)",
    [token, new Date().toISOString(), expires]);
  activeSessions.add(token);
  logEvent("AUTH_SUCCESS", ip, ua, "");

  tgSend(`✅ <b>Login Berhasil!</b>\n⏰ ${fmtTime()}\n🌐 IP: <code>${ip}</code>\n⏳ Sesi aktif 30 menit`);
  res.json({ ok:true, token, expiresAt: expires });
});

// Cek session
app.post("/api/check-session", checkKey, async (req, res) => {
  const { token } = req.body;
  if (!token || !activeSessions.has(token)) return res.json({ ok:false });
  const row = await dbGet("SELECT expires,active FROM sessions WHERE token=?", [token]);
  if (!row || !row.active || new Date(row.expires) < new Date()) {
    activeSessions.delete(token);
    return res.json({ ok:false });
  }
  res.json({ ok:true });
});

app.post("/api/remote-lock", checkKey, (req, res) => {
  globalLocked = true; activeSessions.clear(); otpStore.clear();
  logEvent("REMOTE_LOCK", getIP(req), "", "via API");
  res.json({ ok:true });
});

app.post("/api/remote-unlock", checkKey, (req, res) => {
  globalLocked = false;
  logEvent("REMOTE_UNLOCK", getIP(req), "", "via API");
  res.json({ ok:true });
});

app.get("/api/logs", checkKey, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit)||20, 100);
  const rows  = await dbAll("SELECT * FROM access_log ORDER BY id DESC LIMIT ?", [limit]);
  res.json({ ok:true, logs:rows });
});

// ─── Telegram Bot Commands ────────────────────────────────────────────────────
const guard = (msg, fn) => { if (String(msg.chat.id)===String(CHAT_ID)) fn(); };

bot.onText(/\/start/, (msg) => guard(msg, () => tgSend(
  `🛡️ <b>DriveGuard Bot</b>\n\n` +
  `Perintah:\n` +
  `/lock — Kunci semua sesi\n` +
  `/unlock — Buka kunci\n` +
  `/status — Status sistem\n` +
  `/log — 10 log terakhir\n` +
  `/logall — 30 log terakhir\n` +
  `/fails — IP yang gagal\n` +
  `/clearfails — Reset fail counter\n` +
  `/sessions — Sesi aktif`
)));

bot.onText(/\/lock/, (msg) => guard(msg, () => {
  globalLocked = true; activeSessions.clear(); otpStore.clear();
  logEvent("REMOTE_LOCK", "telegram", "", `by @${msg.from.username}`);
  tgSend("🔒 <b>Semua sesi dikunci!</b>");
}));

bot.onText(/\/unlock/, (msg) => guard(msg, () => {
  globalLocked = false;
  logEvent("REMOTE_UNLOCK", "telegram", "", `by @${msg.from.username}`);
  tgSend("🔓 <b>Drive di-unlock!</b> Akses normal kembali.");
}));

bot.onText(/\/status/, async (msg) => guard(msg, async () => {
  const total     = (await dbGet("SELECT COUNT(*) as c FROM access_log"))?.c || 0;
  const failToday = (await dbGet("SELECT COUNT(*) as c FROM access_log WHERE event LIKE 'AUTH_FAIL%' AND ts > datetime('now','-24 hours')"))?.c || 0;
  const okToday   = (await dbGet("SELECT COUNT(*) as c FROM access_log WHERE event='AUTH_SUCCESS' AND ts > datetime('now','-24 hours')"))?.c || 0;
  tgSend(
    `📊 <b>Status DriveGuard</b>\n\n` +
    `🔒 Global lock: ${globalLocked?"AKTIF 🔴":"tidak aktif 🟢"}\n` +
    `👤 Sesi aktif: ${activeSessions.size}\n` +
    `🔐 OTP pending: ${otpStore.size}\n` +
    `📋 Total log: ${total}\n` +
    `✅ Login sukses hari ini: ${okToday}\n` +
    `❌ Login gagal hari ini: ${failToday}\n` +
    `⏰ ${fmtTime()}`
  );
}));

const sendLogs = async (limit) => {
  const rows = await dbAll("SELECT ts,event,ip,detail FROM access_log ORDER BY id DESC LIMIT ?", [limit]);
  if (!rows.length) return tgSend("Belum ada log.");
  const icons = { AUTH_SUCCESS:"✅", AUTH_FAIL_PW:"❌", AUTH_FAIL_OTP:"❌", DRIVE_OPENED:"🔔",
    REMOTE_LOCK:"🔒", REMOTE_UNLOCK:"🔓", AUTH_BLOCKED_LOCKED:"🚫", OTP_SENT:"📨" };
  const text = rows.map(r =>
    `${icons[r.event]||"📝"} <code>${r.ts.slice(0,16).replace("T"," ")}</code> ${r.event}\n   IP: <code>${r.ip}</code>${r.detail?" "+r.detail:""}`
  ).join("\n\n");
  tgSend(`<b>Log Akses</b>\n\n${text}`);
};

bot.onText(/\/log$/, (msg)   => guard(msg, () => sendLogs(10)));
bot.onText(/\/logall/, (msg) => guard(msg, () => sendLogs(30)));

bot.onText(/\/fails/, async (msg) => guard(msg, async () => {
  const rows = await dbAll("SELECT ip,count,last_fail FROM fail_count ORDER BY count DESC");
  if (!rows.length) return tgSend("✅ Tidak ada IP yang gagal login.");
  tgSend(`<b>IP Gagal Login</b>\n\n` +
    rows.map(r=>`❌ <code>${r.ip}</code> — ${r.count}x\n   Last: ${r.last_fail?.slice(0,16)}`).join("\n\n"));
}));

bot.onText(/\/clearfails/, async (msg) => guard(msg, async () => {
  await dbRun("DELETE FROM fail_count");
  tgSend("✅ Semua fail counter direset.");
}));

bot.onText(/\/sessions/, async (msg) => guard(msg, async () => {
  const rows = await dbAll("SELECT token,created,expires FROM sessions WHERE active=1 AND expires > datetime('now') ORDER BY created DESC");
  if (!rows.length) return tgSend("Tidak ada sesi aktif.");
  tgSend(`<b>Sesi Aktif (${rows.length})</b>\n\n` +
    rows.map(r=>`🟢 <code>${r.token.slice(0,12)}...</code>\n   Dibuat: ${r.created.slice(0,16)}\n   Expires: ${r.expires.slice(0,16)}`).join("\n\n"));
}));

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ DriveGuard server running on port ${PORT}`);
  tgSend(`🟢 <b>DriveGuard Server Online</b>\n⏰ ${fmtTime()}\n\n<i>Mode: Password + OTP via Telegram</i>`);
});

// Cleanup
setInterval(async () => {
  const now = Date.now();
  for (const [id, entry] of otpStore) if (now > entry.expiresAt) otpStore.delete(id);
  await dbRun("UPDATE sessions SET active=0 WHERE expires < datetime('now')").catch(()=>{});
  for (const tok of activeSessions) {
    const row = await dbGet("SELECT active FROM sessions WHERE token=?", [tok]).catch(()=>null);
    if (!row?.active) activeSessions.delete(tok);
  }
}, 5*60*1000);

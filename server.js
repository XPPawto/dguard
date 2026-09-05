require("dotenv").config();
const express    = require("express");
const helmet     = require("helmet");
const cors       = require("cors");
const sqlite3    = require("sqlite3").verbose();
const TelegramBot = require("node-telegram-bot-api");
const crypto     = require("crypto");
const fs         = require("fs");

// ─── Cegah lebih dari 1 instance jalan bersamaan ─────────────────────────────
// Ini penyebab paling umum /lock /unlock "tidak berfungsi": 2 proses node
// polling Telegram bersamaan bikin update dikirim ke proses yang salah.
const LOCK_FILE = "/tmp/driveguard-server.pid";
(function ensureSingleInstance() {
  if (fs.existsSync(LOCK_FILE)) {
    const oldPid = parseInt(fs.readFileSync(LOCK_FILE, "utf8"), 10);
    try {
      process.kill(oldPid, 0); // cek apakah proses lama masih hidup
      console.error(`❌ Instance lain sudah jalan (PID ${oldPid}).`);
      console.error(`   Jalankan: kill ${oldPid}  (atau sudo systemctl stop driveguard)`);
      console.error(`   Lalu hapus lock: rm ${LOCK_FILE}`);
      process.exit(1);
    } catch (e) {
      // Proses lama sudah mati, lock file basi — lanjut aman
    }
  }
  fs.writeFileSync(LOCK_FILE, String(process.pid));
  const cleanup = () => { try { fs.unlinkSync(LOCK_FILE); } catch {} process.exit(0); };
  process.on("exit", () => { try { fs.unlinkSync(LOCK_FILE); } catch {} });
  process.on("SIGINT", cleanup);
  process.on("SIGTERM", cleanup);
})();

// ─── Global safety nets — jangan biarkan proses mati diam-diam ───────────────
process.on("uncaughtException", (err) => {
  console.error("[FATAL] Uncaught exception:", err);
});
process.on("unhandledRejection", (err) => {
  console.error("[FATAL] Unhandled rejection:", err);
});

// ─── Config ───────────────────────────────────────────────────────────────────
const PORT       = process.env.PORT || 3000;
const API_KEY    = (process.env.API_KEY || "").trim();
const BOT_TOKEN  = (process.env.TELEGRAM_BOT_TOKEN || "").trim();
const CHAT_ID    = (process.env.TELEGRAM_CHAT_ID || "").trim();
const PW_HASH    = (process.env.PASSWORD_HASH || "").trim();
const SALT       = "driveguard_salt_v1";
const MAX_FAILS  = 2;   // kirim foto mulai percobaan gagal ke-2 (toleransi 1x typo)
const LOCK_AFTER = 5;
const OTP_EXPIRY = 2 * 60 * 1000;

if (!API_KEY || !BOT_TOKEN || !CHAT_ID || !PW_HASH) {
  console.error("❌ .env belum lengkap! Cek API_KEY, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, PASSWORD_HASH");
  process.exit(1);
}

// ─── Telegram ─────────────────────────────────────────────────────────────────
const bot = new TelegramBot(BOT_TOKEN, { polling: false });

(async () => {
  try {
    // Hapus webhook lama & pending updates yang bisa bikin 409 conflict
    await bot.deleteWebHook({ drop_pending_updates: true });
    await bot.startPolling();
    console.log("✅ Telegram bot polling started");
  } catch (e) {
    console.error("[Telegram] Gagal start polling:", e.message);
  }
})();

bot.on("polling_error", (err) => console.error("[Telegram polling_error]", err.message));

// Debug: log semua pesan masuk supaya bisa cek CHAT_ID cocok atau tidak
bot.on("message", (msg) => {
  console.log(`[Telegram IN] chat_id=${msg.chat.id} (expected=${CHAT_ID}) text="${msg.text}"`);
  if (String(msg.chat.id) !== String(CHAT_ID)) {
    console.log(`[Telegram] ⚠️  Pesan diabaikan — chat_id tidak cocok dengan TELEGRAM_CHAT_ID di .env`);
  }
});

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
    [new Date().toISOString(), event, ip||"", ua||"", detail||""]).catch(e => console.error("[DB] logEvent failed:", e.message));

// ─── State ────────────────────────────────────────────────────────────────────
let globalLocked = false;
const activeSessions = new Set();

// ─── Simple in-memory rate limiter (ganti express-rate-limit yang bermasalah) ─
const rateLimitMap = new Map(); // ip -> array of timestamps
function simpleRateLimit(maxReq, windowMs) {
  return (req, res, next) => {
    try {
      const ip  = getIP(req) || "unknown";
      const now = Date.now();
      const arr = (rateLimitMap.get(ip) || []).filter(t => now - t < windowMs);
      if (arr.length >= maxReq) {
        return res.status(429).json({ ok:false, error:"Terlalu banyak percobaan. Coba lagi nanti." });
      }
      arr.push(now);
      rateLimitMap.set(ip, arr);
      next();
    } catch (e) {
      console.error("[RateLimit] error:", e.message);
      next(); // jangan block request kalau limiter sendiri error
    }
  };
}
// Bersihkan map tiap 30 menit biar ga bocor memori
setInterval(() => {
  const now = Date.now();
  for (const [ip, arr] of rateLimitMap) {
    const fresh = arr.filter(t => now - t < 15*60*1000);
    if (fresh.length === 0) rateLimitMap.delete(ip); else rateLimitMap.set(ip, fresh);
  }
}, 30*60*1000);

const authLimiter = simpleRateLimit(20, 15*60*1000);

// ─── Express ──────────────────────────────────────────────────────────────────
const app = express();
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: "5mb" }));

const checkKey = (req, res, next) => {
  if (req.headers["x-api-key"] !== API_KEY)
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  next();
};

function getIP(req) {
  const fwd = req.headers["x-forwarded-for"];
  if (fwd) return fwd.split(",")[0].trim();
  return req.socket?.remoteAddress || "unknown";
}

const hashPw  = (pw)  => crypto.createHash("sha256").update(pw + SALT).digest("hex");
const fmtTime = ()    => new Date().toLocaleString("id-ID", { timeZone: "Asia/Jakarta" });
const tgSend  = (msg) => bot.sendMessage(CHAT_ID, msg, { parse_mode:"HTML" }).catch(e => console.error("[Telegram] send failed:", e.message));
const tgPhoto = (b64, caption) => {
  try {
    const buf = Buffer.from(b64.replace(/^data:image\/\w+;base64,/,""), "base64");
    return bot.sendPhoto(CHAT_ID, buf, { caption, parse_mode:"HTML" },
      { filename: "capture.jpg", contentType: "image/jpeg" })
      .catch(e => console.error("[Telegram] photo failed:", e.message));
  } catch (e) {
    console.error("[tgPhoto] error:", e.message);
    return Promise.resolve();
  }
};

// Kirim foto kalau ada, fallback ke teks kalau tidak ada (kamera diblokir dll)
const tgMedia = (photo, _mediaType, caption) => {
  if (photo) return tgPhoto(photo, caption);
  return tgSend(caption + "\n📷 <i>Foto tidak tersedia (kamera diblokir/tidak ada webcam)</i>");
};

// ─── Fail tracking ────────────────────────────────────────────────────────────
async function getFailCount(ip) {
  const row = await dbGet("SELECT count FROM fail_count WHERE ip=?", [ip]).catch(()=>null);
  return row?.count || 0;
}
async function incFail(ip) {
  await dbRun(`INSERT INTO fail_count (ip,count,last_fail) VALUES (?,1,?)
    ON CONFLICT(ip) DO UPDATE SET count=count+1,last_fail=excluded.last_fail`,
    [ip, new Date().toISOString()]).catch(e => console.error("[DB] incFail failed:", e.message));
  return getFailCount(ip);
}
const resetFail = (ip) => dbRun("DELETE FROM fail_count WHERE ip=?", [ip]).catch(()=>{});

// ─── Routes ───────────────────────────────────────────────────────────────────
app.get("/health", (req, res) => res.json({ ok:true, locked:globalLocked, uptime:process.uptime() }));

app.post("/api/drive-opened", checkKey, async (req, res) => {
  try {
    const { ua } = req.body;
    const ip = getIP(req);
    logEvent("DRIVE_OPENED", ip, ua, "");
    tgSend(`🔔 <b>Drive Dibuka</b>\n⏰ ${fmtTime()}\n🌐 IP: <code>${ip}</code>\n📱 UA: <code>${(ua||"").slice(0,60)}</code>`);
    res.json({ ok:true, locked:globalLocked });
  } catch (e) {
    console.error("[/api/drive-opened] error:", e);
    res.status(500).json({ ok:false, error:"Server error" });
  }
});

app.post("/api/request-otp", authLimiter, checkKey, async (req, res) => {
  try {
    const { password, photo, mediaType, ua } = req.body;
    const ip = getIP(req);

    if (globalLocked) {
      logEvent("AUTH_BLOCKED_LOCKED", ip, ua, "");
      return res.json({ ok:false, error:"Akses dikunci oleh admin. Ketik /unlock di bot Telegram." });
    }

    const rawPw = String(password || "").trim();
    const pwOk  = hashPw(rawPw) === PW_HASH;

    if (!pwOk) {
      const fails = await incFail(ip);
      logEvent("AUTH_FAIL_PW", ip, ua, `fails=${fails}`);
      console.log(`[DEBUG] Password mismatch. len=${rawPw.length} computed=${hashPw(rawPw).slice(0,12)}... expected=${PW_HASH.slice(0,12)}...`);

      if (fails >= MAX_FAILS) {
        tgMedia(photo, mediaType, `🚨 <b>INTRUDER ALERT!</b>\nGagal login ${fails}x\n⏰ ${fmtTime()}\n🌐 IP: <code>${ip}</code>`);
      }

      tgSend(`⚠️ <b>Password Salah #${fails}</b>\n⏰ ${fmtTime()}\n🌐 IP: <code>${ip}</code>` +
        (fails >= LOCK_AFTER ? `\n🔒 <b>Auto-lock aktif!</b>` : ""));

      if (fails >= LOCK_AFTER) { globalLocked = true; activeSessions.clear(); }
      return res.json({ ok:false, error:"Password salah" });
    }

    const requestId = crypto.randomBytes(16).toString("hex");
    const code      = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + OTP_EXPIRY;
    otpStore.set(requestId, { code, expiresAt, ip, photo, mediaType });

    await tgSend(
      `🔐 <b>Kode Verifikasi DriveGuard</b>\n\n<b>🔑 ${code}</b>\n\n` +
      `⏰ Berlaku 2 menit\n🌐 IP: <code>${ip}</code>\n🕐 ${fmtTime()}\n\n` +
      `<i>Jika bukan kamu, ketik /lock</i>`
    );

    logEvent("OTP_SENT", ip, ua, "");
    res.json({ ok:true, requestId, expiresIn:120 });
  } catch (e) {
    console.error("[/api/request-otp] error:", e);
    res.status(500).json({ ok:false, error:"Server error: " + e.message });
  }
});

const otpStore = new Map();

app.post("/api/verify-otp", authLimiter, checkKey, async (req, res) => {
  try {
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
      if (fails >= MAX_FAILS) {
        tgMedia(entry.photo, entry.mediaType, `🚨 <b>INTRUDER!</b> OTP salah ${fails}x\n⏰ ${fmtTime()}\n🌐 IP: <code>${ip}</code>`);
      }
      tgSend(`⚠️ <b>OTP Salah #${fails}</b>\n⏰ ${fmtTime()}\n🌐 IP: <code>${ip}</code>`);
      if (fails >= LOCK_AFTER) { globalLocked = true; activeSessions.clear(); }
      return res.json({ ok:false, error:"Kode salah" });
    }

    otpStore.delete(requestId);
    resetFail(ip);

    const token   = crypto.randomBytes(32).toString("hex");
    const expires = new Date(Date.now() + 30*60*1000).toISOString();
    await dbRun("INSERT INTO sessions (token,created,expires) VALUES (?,?,?)",
      [token, new Date().toISOString(), expires]);
    activeSessions.add(token);
    logEvent("AUTH_SUCCESS", ip, ua, "");

    tgSend(`✅ <b>Login Berhasil!</b>\n⏰ ${fmtTime()}\n🌐 IP: <code>${ip}</code>\n⏳ Sesi aktif 30 menit`);
    res.json({ ok:true, token, expiresAt:expires });
  } catch (e) {
    console.error("[/api/verify-otp] error:", e);
    res.status(500).json({ ok:false, error:"Server error: " + e.message });
  }
});

app.post("/api/check-session", checkKey, async (req, res) => {
  try {
    const { token } = req.body;
    if (!token || !activeSessions.has(token)) return res.json({ ok:false });
    const row = await dbGet("SELECT expires,active FROM sessions WHERE token=?", [token]);
    if (!row || !row.active || new Date(row.expires) < new Date()) {
      activeSessions.delete(token);
      return res.json({ ok:false });
    }
    res.json({ ok:true });
  } catch (e) {
    console.error("[/api/check-session] error:", e);
    res.json({ ok:false });
  }
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
  const rows  = await dbAll("SELECT * FROM access_log ORDER BY id DESC LIMIT ?", [limit]).catch(()=>[]);
  res.json({ ok:true, logs:rows });
});

// ─── Telegram Bot Commands ────────────────────────────────────────────────────
const guard = (msg, fn) => {
  if (String(msg.chat.id) !== String(CHAT_ID)) return;
  try { fn(); } catch(e) { console.error("[Bot command] error:", e); }
};

bot.onText(/\/start/, (msg) => guard(msg, () => tgSend(
  `🛡️ <b>DriveGuard Bot</b>\n\n` +
  `/lock — Kunci semua sesi\n/unlock — Buka kunci\n` +
  `/status — Status sistem\n/log — 10 log terakhir\n` +
  `/logall — 30 log terakhir\n/fails — IP yang gagal\n` +
  `/clearfails — Reset fail counter\n/sessions — Sesi aktif`
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
  const total     = (await dbGet("SELECT COUNT(*) as c FROM access_log").catch(()=>null))?.c || 0;
  const failToday = (await dbGet("SELECT COUNT(*) as c FROM access_log WHERE event LIKE 'AUTH_FAIL%' AND ts > datetime('now','-24 hours')").catch(()=>null))?.c || 0;
  const okToday   = (await dbGet("SELECT COUNT(*) as c FROM access_log WHERE event='AUTH_SUCCESS' AND ts > datetime('now','-24 hours')").catch(()=>null))?.c || 0;
  tgSend(
    `📊 <b>Status DriveGuard</b>\n\n` +
    `🔒 Global lock: ${globalLocked?"AKTIF 🔴":"tidak aktif 🟢"}\n` +
    `👤 Sesi aktif: ${activeSessions.size}\n` +
    `📋 Total log: ${total}\n✅ Sukses 24 jam: ${okToday}\n❌ Gagal 24 jam: ${failToday}\n` +
    `⏰ ${fmtTime()}\n🖥️ Uptime: ${Math.floor(process.uptime()/60)} menit`
  );
}));

const sendLogs = async (limit) => {
  const rows = await dbAll("SELECT ts,event,ip,detail FROM access_log ORDER BY id DESC LIMIT ?", [limit]).catch(()=>[]);
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
  const rows = await dbAll("SELECT ip,count,last_fail FROM fail_count ORDER BY count DESC").catch(()=>[]);
  if (!rows.length) return tgSend("✅ Tidak ada IP yang gagal login.");
  tgSend(`<b>IP Gagal Login</b>\n\n` +
    rows.map(r=>`❌ <code>${r.ip}</code> — ${r.count}x\n   Last: ${r.last_fail?.slice(0,16)}`).join("\n\n"));
}));

bot.onText(/\/clearfails/, async (msg) => guard(msg, async () => {
  await dbRun("DELETE FROM fail_count").catch(()=>{});
  tgSend("✅ Semua fail counter direset.");
}));

bot.onText(/\/sessions/, async (msg) => guard(msg, async () => {
  const rows = await dbAll("SELECT token,created,expires FROM sessions WHERE active=1 AND expires > datetime('now') ORDER BY created DESC").catch(()=>[]);
  if (!rows.length) return tgSend("Tidak ada sesi aktif.");
  tgSend(`<b>Sesi Aktif (${rows.length})</b>\n\n` +
    rows.map(r=>`🟢 <code>${r.token.slice(0,12)}...</code>\n   Dibuat: ${r.created.slice(0,16)}\n   Expires: ${r.expires.slice(0,16)}`).join("\n\n"));
}));

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ DriveGuard server running on port ${PORT}`);
  tgSend(`🟢 <b>DriveGuard Server Online</b>\n⏰ ${fmtTime()}`);
});

setInterval(async () => {
  const now = Date.now();
  for (const [id, entry] of otpStore) if (now > entry.expiresAt) otpStore.delete(id);
  await dbRun("UPDATE sessions SET active=0 WHERE expires < datetime('now')").catch(()=>{});
  for (const tok of activeSessions) {
    const row = await dbGet("SELECT active FROM sessions WHERE token=?", [tok]).catch(()=>null);
    if (!row?.active) activeSessions.delete(tok);
  }
}, 5*60*1000);

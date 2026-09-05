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
let globalLocked   = false;
let lockReason     = null;
let autoUnlockTimer = null;
let notifMuted     = false;  // kalau true, notif "Drive Dibuka" tidak dikirim (tetap kirim fail/lock)
const activeSessions = new Set();
const sessionMeta   = new Map(); // token -> { createdAt, ip }

function setAutoLock() {
  globalLocked = true;
  lockReason   = "auto";
  activeSessions.clear();
  clearTimeout(autoUnlockTimer);
  autoUnlockTimer = setTimeout(() => {
    if (lockReason === "auto") {
      globalLocked = false;
      lockReason = null;
      tgSend("🔓 <b>Auto-unlock</b>\nKunci sementara (karena banyak percobaan gagal) sudah berakhir setelah 15 menit.");
      console.log("[AutoUnlock] Lock otomatis dibuka setelah 15 menit");
    }
  }, 15 * 60 * 1000);
}

function setManualLock() {
  globalLocked = true;
  lockReason   = "manual";
  clearTimeout(autoUnlockTimer); // manual lock tidak auto-expire
}

function clearLock() {
  globalLocked = false;
  lockReason   = null;
  clearTimeout(autoUnlockTimer);
}

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
    if (!notifMuted) {
      tgSend(`🔔 <b>Drive Dibuka</b>\n⏰ ${fmtTime()}\n🌐 IP: <code>${ip}</code>\n📱 UA: <code>${(ua||"").slice(0,60)}</code>`);
    }
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
      const untilMsg = lockReason === "auto" ? " (otomatis buka lagi ±15 menit, atau ketik /unlock)" : "";
      return res.json({ ok:false, locked:true, error:`🔒 Akses sedang dikunci${untilMsg}. Password TIDAK dicek selama terkunci.` });
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

      if (fails >= LOCK_AFTER) setAutoLock();
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
      if (fails >= LOCK_AFTER) setAutoLock();
      return res.json({ ok:false, error:"Kode salah" });
    }

    otpStore.delete(requestId);
    resetFail(ip);

    const token   = crypto.randomBytes(32).toString("hex");
    const expires = new Date(Date.now() + 30*60*1000).toISOString();
    await dbRun("INSERT INTO sessions (token,created,expires) VALUES (?,?,?)",
      [token, new Date().toISOString(), expires]);
    activeSessions.add(token);
    sessionMeta.set(token, { createdAt: Date.now(), ip });
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
  setManualLock(); activeSessions.clear(); otpStore.clear();
  logEvent("REMOTE_LOCK", getIP(req), "", "via API");
  res.json({ ok:true });
});

app.post("/api/remote-unlock", checkKey, (req, res) => {
  clearLock();
  logEvent("REMOTE_UNLOCK", getIP(req), "", "via API");
  res.json({ ok:true });
});

app.get("/api/logs", checkKey, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit)||20, 100);
  const rows  = await dbAll("SELECT * FROM access_log ORDER BY id DESC LIMIT ?", [limit]).catch(()=>[]);
  res.json({ ok:true, logs:rows });
});

// ─── Telegram Bot Commands ────────────────────────────────────────────────────
const guard = (m, fn) => {
  if (String(m.chat.id) !== String(CHAT_ID)) return;
  try { fn(); } catch(e) { console.error("[Bot command] error:", e); }
};

const HELP_TEXT =
  `🛡️ <b>DriveGuard — Daftar Perintah</b>\n\n` +
  `<b>🔒 Kontrol Akses</b>\n` +
  `/lock — Kunci semua sesi secara manual\n` +
  `/unlock — Buka kunci manual\n` +
  `/lockauto — Lihat status auto-lock\n\n` +
  `<b>📊 Monitoring</b>\n` +
  `/status — Status lengkap sistem\n` +
  `/sessions — Sesi aktif saat ini\n` +
  `/log — 10 log terakhir\n` +
  `/log20 — 20 log terakhir\n` +
  `/today — Ringkasan hari ini\n` +
  `/fails — IP yang sering gagal login\n\n` +
  `<b>⚙️ Pengaturan</b>\n` +
  `/mute — Matikan notif "Drive Dibuka"\n` +
  `/unmute — Nyalakan notif lagi\n` +
  `/clearfails — Reset semua fail counter\n` +
  `/clearsessions — Hapus semua sesi aktif\n\n` +
  `<b>🔧 Utilitas</b>\n` +
  `/ping — Cek server masih hidup\n` +
  `/uptime — Waktu server sudah berjalan\n` +
  `/help — Tampilkan pesan ini`;

bot.onText(/\/start|\/help/, (m) => guard(m, () => tgSend(HELP_TEXT)));

// ── Lock / Unlock ──
bot.onText(/\/lock(?!\w)/, (m) => guard(m, () => {
  setManualLock(); activeSessions.clear(); otpStore.clear(); sessionMeta.clear();
  logEvent("REMOTE_LOCK", "telegram", "", `by @${m.from.username}`);
  tgSend(`🔒 <b>Drive dikunci secara manual</b>\nSemua sesi dihapus. Kirim /unlock untuk membuka kembali.\n⏰ ${fmtTime()}`);
}));

bot.onText(/\/unlock/, (m) => guard(m, () => {
  clearLock();
  logEvent("REMOTE_UNLOCK", "telegram", "", `by @${m.from.username}`);
  tgSend(`🔓 <b>Drive berhasil di-unlock</b>\nAkses normal kembali aktif.\n⏰ ${fmtTime()}`);
}));

bot.onText(/\/lockauto/, (m) => guard(m, () => {
  if (!globalLocked) return tgSend("✅ Tidak ada lock aktif saat ini.");
  tgSend(
    `🔴 <b>Status Lock</b>\n\n` +
    `Tipe: ${lockReason === "auto" ? "Otomatis (terlalu banyak gagal)" : "Manual (/lock)"}\n` +
    `${lockReason === "auto" ? "⏳ Akan otomatis buka dalam ~15 menit\n   atau ketik /unlock untuk segera buka" : "Kirim /unlock untuk membuka"}`
  );
}));

// ── Status ──
bot.onText(/\/status/, async (m) => guard(m, async () => {
  const [total, fail24, ok24, opens24] = await Promise.all([
    dbGet("SELECT COUNT(*) c FROM access_log"),
    dbGet("SELECT COUNT(*) c FROM access_log WHERE event LIKE 'AUTH_FAIL%' AND ts > datetime('now','-24 hours')"),
    dbGet("SELECT COUNT(*) c FROM access_log WHERE event='AUTH_SUCCESS' AND ts > datetime('now','-24 hours')"),
    dbGet("SELECT COUNT(*) c FROM access_log WHERE event='DRIVE_OPENED' AND ts > datetime('now','-24 hours')"),
  ]).then(r => r.map(x => x?.c || 0)).catch(() => [0,0,0,0]);
  const uptimeSec = Math.floor(process.uptime());
  const h = Math.floor(uptimeSec/3600), mn = Math.floor((uptimeSec%3600)/60), s = uptimeSec%60;

  tgSend(
    `📊 <b>Status DriveGuard</b>\n\n` +
    `🔒 Lock: ${globalLocked ? `AKTIF 🔴 (${lockReason==="auto"?"otomatis":"manual"})` : "tidak aktif 🟢"}\n` +
    `🔕 Notif dibuka: ${notifMuted ? "dimatikan 🔕" : "aktif 🔔"}\n` +
    `👤 Sesi aktif: ${activeSessions.size}\n` +
    `🔐 OTP pending: ${otpStore.size}\n\n` +
    `<b>24 jam terakhir:</b>\n` +
    `🔔 Drive dibuka: ${opens24}x\n` +
    `✅ Login sukses: ${ok24}x\n` +
    `❌ Login gagal: ${fail24}x\n\n` +
    `📋 Total log: ${total}\n` +
    `🖥️ Uptime: ${h}j ${mn}m ${s}d\n` +
    `⏰ ${fmtTime()}`
  );
}));

// ── Today summary ──
bot.onText(/\/today/, async (m) => guard(m, async () => {
  const rows = await dbAll(
    "SELECT event, COUNT(*) c, MAX(ts) last FROM access_log WHERE ts > datetime('now','start of day') GROUP BY event ORDER BY c DESC"
  ).catch(() => []);
  if (!rows.length) return tgSend("Belum ada aktivitas hari ini.");
  const icons = { AUTH_SUCCESS:"✅", AUTH_FAIL_PW:"❌", AUTH_FAIL_OTP:"❌",
    DRIVE_OPENED:"🔔", REMOTE_LOCK:"🔒", REMOTE_UNLOCK:"🔓", OTP_SENT:"📨" };
  const lines = rows.map(r => `${icons[r.event]||"📝"} ${r.event}: <b>${r.c}x</b>`).join("\n");
  tgSend(`📅 <b>Aktivitas Hari Ini</b>\n\n${lines}\n\n⏰ ${fmtTime()}`);
}));

// ── Sessions ──
bot.onText(/\/sessions/, async (m) => guard(m, async () => {
  if (!activeSessions.size) return tgSend("Tidak ada sesi aktif saat ini.");
  const lines = [...activeSessions].map(tok => {
    const meta = sessionMeta.get(tok);
    const exp  = meta ? Math.max(0, Math.round((meta.exp - Date.now()) / 60000)) : "?";
    return `🟢 <code>${tok.slice(0,10)}...</code>\n   IP: <code>${meta?.ip||"?"}</code> · exp ${exp} mnt`;
  });
  tgSend(`<b>Sesi Aktif (${activeSessions.size})</b>\n\n${lines.join("\n\n")}`);
}));

bot.onText(/\/clearsessions/, (m) => guard(m, () => {
  const n = activeSessions.size;
  activeSessions.clear(); sessionMeta.clear();
  dbRun("UPDATE sessions SET active=0 WHERE expires > datetime('now')").catch(()=>{});
  tgSend(`✅ ${n} sesi aktif dihapus. Semua tab Drive harus login ulang.`);
}));

// ── Logs ──
const sendLogs = async (limit) => {
  const rows = await dbAll(
    "SELECT ts,event,ip,detail FROM access_log ORDER BY id DESC LIMIT ?", [limit]
  ).catch(()=>[]);
  if (!rows.length) return tgSend("Belum ada log.");
  const ico = { AUTH_SUCCESS:"✅", AUTH_FAIL_PW:"❌", AUTH_FAIL_OTP:"❌",
    DRIVE_OPENED:"🔔", REMOTE_LOCK:"🔒", REMOTE_UNLOCK:"🔓", OTP_SENT:"📨", AUTH_BLOCKED_LOCKED:"🚫" };
  const text = rows.map(r =>
    `${ico[r.event]||"📝"} <code>${r.ts.slice(0,16).replace("T"," ")}</code>\n` +
    `   <code>${r.event}</code> · IP: <code>${r.ip}</code>${r.detail?" · "+r.detail:""}`
  ).join("\n");
  tgSend(`<b>Log ${limit} Terakhir</b>\n\n${text}`);
};

bot.onText(/\/log(?!all|20|\w)/, (m) => guard(m, () => sendLogs(10)));
bot.onText(/\/log20/, (m)        => guard(m, () => sendLogs(20)));

// ── Fails ──
bot.onText(/\/fails/, async (m) => guard(m, async () => {
  const rows = await dbAll("SELECT ip,count,last_fail FROM fail_count ORDER BY count DESC").catch(()=>[]);
  if (!rows.length) return tgSend("✅ Tidak ada IP yang mencurigakan.");
  const lines = rows.map(r => `❌ <code>${r.ip}</code> — ${r.count}x gagal\n   Terakhir: ${r.last_fail?.slice(0,16)||"-"}`);
  tgSend(`<b>🚨 IP Mencurigakan</b>\n\n${lines.join("\n\n")}`);
}));

bot.onText(/\/clearfails/, async (m) => guard(m, async () => {
  await dbRun("DELETE FROM fail_count").catch(()=>{});
  tgSend("✅ Semua fail counter direset.");
}));

// ── Mute / Unmute ──
bot.onText(/\/mute/, (m) => guard(m, () => {
  notifMuted = true;
  tgSend("🔕 <b>Notifikasi dibuka Drive dimatikan.</b>\nKamu tidak akan dapat notif setiap ada yang buka Drive.\nAlert gagal login & lock/unlock tetap aktif.\nKetik /unmute untuk nyalakan kembali.");
}));

bot.onText(/\/unmute/, (m) => guard(m, () => {
  notifMuted = false;
  tgSend("🔔 <b>Notifikasi dibuka Drive dinyalakan kembali.</b>");
}));

// ── Ping ──
bot.onText(/\/ping/, (m) => guard(m, () => {
  const start = Date.now();
  tgSend(`🏓 <b>Pong!</b> (${Date.now()-start}ms)\n⏰ ${fmtTime()}`);
}));

// ── Uptime ──
bot.onText(/\/uptime/, (m) => guard(m, () => {
  const s = Math.floor(process.uptime());
  const h = Math.floor(s/3600), mn = Math.floor((s%3600)/60), sec = s%60;
  tgSend(`🖥️ <b>Server Uptime</b>\n${h} jam ${mn} menit ${sec} detik\n⏰ ${fmtTime()}`);
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

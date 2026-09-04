# DriveGuard — Panduan Deploy Lengkap

## LANGKAH 1 — Upgrade Node.js ke v20+ (wajib)

Node yang lo punya mungkin terlalu lama. Jalankan ini:

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
node -v   # harus tampil v20.x.x
```

---

## LANGKAH 2 — Siapkan folder server

```bash
# Upload folder driveguard-server ke VPS, lalu:
cd ~/driveguard-server
npm install
```

Kalau muncul warning EBADENGINE, pastikan dulu Node sudah v20+ (langkah 1).
Build native module butuh python3 dan build-essential:

```bash
sudo apt-get install -y python3 make g++ build-essential
npm install
```

---

## LANGKAH 3 — Buat Telegram Bot

1. Buka Telegram → cari **@BotFather**
2. Kirim `/newbot`
3. Ikuti instruksi, kasih nama bot (misal: `MyDriveGuardBot`)
4. BotFather akan kasih token seperti: `123456789:ABCdefGHI...`
5. **Simpan token ini** → ini adalah `TELEGRAM_BOT_TOKEN`

### Dapat CHAT_ID lo:
1. Buka Telegram → cari **@userinfobot**
2. Kirim `/start`
3. Bot akan balas dengan info akun lo, catat angka **Id** → ini `TELEGRAM_CHAT_ID`

---

## LANGKAH 4 — Generate API_KEY dan PASSWORD_HASH

```bash
cd ~/driveguard-server
node setup.js
```

Masukkan password yang lo mau pakai untuk login ke Drive.
Script akan output seperti ini:

```
API_KEY=a3f8c2d1e9b7...panjang...
PASSWORD_HASH=5e884898da...
```

**Salin keduanya, simpan dulu di notepad.**

---

## LANGKAH 5 — Setup Extension dulu (dapat TOTP_SECRET)

1. Extract `driveguard-ext/` di laptop
2. Buka `brave://extensions/` → Developer mode ON → Load unpacked → pilih folder `driveguard-ext`
3. Klik icon extension → masukkan password (harus sama dengan yang lo ketik di `node setup.js`)
4. Klik **Generate TOTP →**
5. Di halaman TOTP, lihat kode secret (format: `XXXX XXXX XXXX XXXX XXXX`)
6. **Klik "Salin kode"** — ini adalah `TOTP_SECRET` (tanpa spasi)
7. Scan QR ke Google Authenticator / Authy
8. Masukkan kode 6 digit dari app → klik **Simpan & Aktifkan**

---

## LANGKAH 6 — Isi file .env

```bash
cd ~/driveguard-server
cp .env.example .env
nano .env
```

Isi seperti ini (ganti semua nilai):

```env
PORT=3000

# Dari output node setup.js (langkah 4)
API_KEY=a3f8c2d1e9b7xxxxxxxxxxxxxxxxxxxxx

# Dari @BotFather (langkah 3)
TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrSTUvwxYZ

# Dari @userinfobot (langkah 3)
TELEGRAM_CHAT_ID=123456789

# Dari output node setup.js (langkah 4)
PASSWORD_HASH=5e884898da28047151d0e56f8dc6292773603d0d6aabbddb9b...

# Dari extension popup langkah 5 (tanpa spasi)
TOTP_SECRET=KSHKDZK3YPCFUXBRWQCD
```

Simpan: `Ctrl+X` → `Y` → `Enter`

---

## LANGKAH 7 — Edit background.js extension

Buka file `driveguard-ext/background.js` dengan text editor, cari baris:

```js
const SERVER_URL = "https://DOMAIN_SERVER_LO:3000";
const API_KEY    = "GANTI_DENGAN_API_KEY_SERVER";
```

Ganti dengan:

```js
const SERVER_URL = "http://IP_VPS_LO:3000";       // atau domain kalau punya
const API_KEY    = "a3f8c2d1e9b7xxx...";           // API_KEY dari langkah 4
```

Simpan file. Kalau extension sudah di-load, pergi ke `brave://extensions/` → klik **reload** (ikon putar) di extension.

---

## LANGKAH 8 — Test server dulu sebelum jadi service

```bash
cd ~/driveguard-server
node server.js
```

Kalau berhasil, terminal akan tampil:
```
✅ DriveGuard server running on port 3000
```

Dan bot Telegram lo akan kirim pesan: **"🟢 DriveGuard Server Online"**

Test dari laptop:
```bash
curl http://IP_VPS:3000/health
# → {"ok":true,"locked":false}
```

Kalau sudah oke, stop dengan `Ctrl+C`.

---

## LANGKAH 9 — Jalankan sebagai service (auto-start)

```bash
# Salin server ke /opt
sudo mkdir -p /opt/driveguard-server
sudo cp -r ~/driveguard-server/. /opt/driveguard-server/
sudo chown -R www-data:www-data /opt/driveguard-server

# Install service
sudo cp ~/driveguard-server/driveguard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable driveguard
sudo systemctl start driveguard

# Cek status
sudo systemctl status driveguard
```

Harus ada tulisan `active (running)`.

### Lihat log server:
```bash
sudo journalctl -u driveguard -f
```

---

## LANGKAH 10 — Buka firewall (kalau pakai ufw)

```bash
sudo ufw allow 3000/tcp
sudo ufw status
```

---

## Troubleshooting

**Server tidak bisa diakses dari luar?**
- Cek firewall VPS di panel provider (DigitalOcean/Vultr/dll) — buka port 3000
- Cek `sudo ufw allow 3000/tcp`

**Bot Telegram tidak merespon?**
- Pastikan lo sudah kirim `/start` ke bot dulu
- Pastikan CHAT_ID benar (angka, bukan username)

**Extension tidak connect ke server?**
- Buka DevTools di Brave (F12) → Console → lihat error
- Pastikan `SERVER_URL` di background.js benar (http bukan https kalau belum ada SSL)
- Pastikan `API_KEY` di background.js sama persis dengan di .env

**TOTP selalu salah?**
- Pastikan waktu VPS dan HP sinkron: `sudo timedatectl set-ntp true`
- Pastikan TOTP_SECRET di .env sama persis dengan yang di extension (tanpa spasi)

**Restart server setelah edit .env:**
```bash
sudo systemctl restart driveguard
```

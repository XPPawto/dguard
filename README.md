# DriveGuard Server

## Install di VPS Ubuntu/Debian

```bash
# 1. Install Node.js 18+
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# 2. Copy folder ini ke server
scp -r driveguard-server/ user@SERVER_IP:/opt/driveguard-server
cd /opt/driveguard-server && npm install

# 3. Setup config
cp .env.example .env
node setup.js        # → generate API_KEY dan PASSWORD_HASH, salin ke .env
nano .env            # isi TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, TOTP_SECRET

# 4. Install sebagai service
sudo cp driveguard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable driveguard
sudo systemctl start driveguard
sudo systemctl status driveguard
```

## Cara dapat TELEGRAM_CHAT_ID
1. Buka @userinfobot di Telegram → kirim /start → catat id kamu

## Cara dapat BOT_TOKEN
1. Buka @BotFather → /newbot → ikuti instruksi → salin token

## Cara isi TOTP_SECRET di .env
- Jalankan extension dulu → Setup → copy secret (tanpa spasi) → paste ke TOTP_SECRET

## Config extension (background.js)
Ganti 2 baris ini di file `background.js` extension:
```js
const SERVER_URL = "https://IP_ATAU_DOMAIN_SERVER:3000";
const API_KEY    = "API_KEY_DARI_SETUP_JS";
```

## Firewall (opsional tapi disarankan)
```bash
sudo ufw allow 3000/tcp
sudo ufw enable
```

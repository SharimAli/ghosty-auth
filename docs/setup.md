# GHOSTY Auth — Setup & Deployment Guide

---

## 📌 Table of Contents

- [Requirements](#requirements)
- [Local Development Setup](#local-development-setup)
- [Environment Variables](#environment-variables)
- [Database Setup](#database-setup)
- [Redis Setup](#redis-setup)
- [Production Deployment](#production-deployment)
- [Nginx Configuration](#nginx-configuration)
- [SSL / HTTPS](#ssl--https)
- [Keeping the Server Running](#keeping-the-server-running)
- [Security Hardening Checklist](#security-hardening-checklist)

---

## Requirements

| Dependency | Minimum Version |
|------------|----------------|
| Node.js | v18.x |
| PostgreSQL | 14.x |
| Redis | 7.x |
| npm | 8.x |

---

## Local Development Setup

### 1. Install dependencies

```bash
# Clone the repo
git clone https://github.com/yourname/ghosty-auth
cd ghosty-auth/server

# Install Node packages
npm install
```

### 2. Set up your `.env`

```bash
cp .env.example .env
```

Fill in all values — see [Environment Variables](#environment-variables) below.

### 3. Set up the database

```bash
# Create the PostgreSQL database
createdb ghosty_auth

# Run migrations
npm run migrate
```

### 4. Start development server

```bash
npm run dev
```

The API will be available at `http://localhost:3000`.

### 5. Start the dashboard

```bash
cd ../dashboard
npm install
npm run dev
```

Dashboard will be available at `http://localhost:5173`.

---

## Environment Variables

All variables are stored in `server/.env`. **Never commit this file.**

```env
# ─── App ──────────────────────────────────────────────────────────
NODE_ENV=development
PORT=3000

# ─── Database (PostgreSQL) ────────────────────────────────────────
DB_HOST=localhost
DB_PORT=5432
DB_NAME=ghosty_auth
DB_USER=postgres
DB_PASSWORD=your_db_password

# ─── Redis ────────────────────────────────────────────────────────
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# ─── JWT ──────────────────────────────────────────────────────────
# Generate with: node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
JWT_PRIVATE_KEY=your_rsa_private_key_here
JWT_PUBLIC_KEY=your_rsa_public_key_here
JWT_EXPIRES_IN=1h

# ─── HMAC ─────────────────────────────────────────────────────────
# Generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
HMAC_SECRET=your_hmac_secret_here

# ─── Security ─────────────────────────────────────────────────────
BCRYPT_ROUNDS=12
REQUEST_TIMESTAMP_TOLERANCE_MS=30000

# ─── Rate Limiting ────────────────────────────────────────────────
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_MAX_AUTH=10
RATE_LIMIT_MAX_GENERAL=100

# ─── Admin ────────────────────────────────────────────────────────
ADMIN_REGISTRATION_KEY=change_this_to_a_random_secret
```

### Generating RSA Keys for JWT

```bash
# Generate private key
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048

# Generate public key
openssl rsa -pubout -in private.pem -out public.pem

# Print as single-line for .env (replace newlines with \n)
awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' private.pem
```

---

## Database Setup

### Install PostgreSQL (Ubuntu)

```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

### Create database and user

```bash
sudo -u postgres psql

-- In psql:
CREATE USER ghosty WITH PASSWORD 'your_password';
CREATE DATABASE ghosty_auth OWNER ghosty;
GRANT ALL PRIVILEGES ON DATABASE ghosty_auth TO ghosty;
\q
```

### Run migrations

```bash
cd server
npm run migrate
```

---

## Redis Setup

### Install Redis (Ubuntu)

```bash
sudo apt install redis-server
sudo systemctl start redis
sudo systemctl enable redis
```

### Set a Redis password (recommended)

```bash
sudo nano /etc/redis/redis.conf
# Find and set:
requirepass your_redis_password
```

```bash
sudo systemctl restart redis
```

---

## Production Deployment

### Recommended Stack

```
Internet → Nginx (reverse proxy + SSL) → Node.js API (PM2)
                                       → React Dashboard (static files)
```

### 1. Install PM2

```bash
npm install -g pm2
```

### 2. Build the dashboard

```bash
cd dashboard
npm run build
```

### 3. Start the API with PM2

```bash
cd server
NODE_ENV=production pm2 start server.js --name ghosty-auth-api
pm2 save
pm2 startup
```

### 4. Monitor logs

```bash
pm2 logs ghosty-auth-api
pm2 monit
```

---

## Nginx Configuration

Install Nginx:

```bash
sudo apt install nginx
```

Create a config file at `/etc/nginx/sites-available/ghosty-auth`:

```nginx
# API
server {
    listen 80;
    server_name api.your-domain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_cache_bypass $http_upgrade;
    }
}

# Dashboard
server {
    listen 80;
    server_name dash.your-domain.com;

    root /var/www/ghosty-auth/dashboard/dist;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

Enable the config:

```bash
sudo ln -s /etc/nginx/sites-available/ghosty-auth /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

## SSL / HTTPS

**HTTPS is mandatory in production.** Never run GHOSTY Auth over plain HTTP.

### Using Certbot (Let's Encrypt — Free)

```bash
sudo apt install certbot python3-certbot-nginx

# Issue certificates
sudo certbot --nginx -d api.your-domain.com -d dash.your-domain.com

# Auto-renew
sudo certbot renew --dry-run
```

Certbot will automatically update your Nginx config to redirect HTTP → HTTPS and add the SSL certificate.

---

## Keeping the Server Running

### PM2 Auto-restart

PM2 automatically restarts the process if it crashes:

```bash
pm2 start server.js --name ghosty-auth-api --restart-delay=3000 --max-restarts=10
```

### View running processes

```bash
pm2 list
```

### Reload without downtime

```bash
pm2 reload ghosty-auth-api
```

---

## Security Hardening Checklist

Before going live, verify all of the following:

- [ ] `NODE_ENV` is set to `production`
- [ ] `.env` file is **not** committed to git (add to `.gitignore`)
- [ ] HTTPS is enabled via SSL certificate
- [ ] Firewall only exposes ports 80 and 443 (block direct access to port 3000)
- [ ] PostgreSQL is not publicly accessible (bind to localhost only)
- [ ] Redis is not publicly accessible (bind to localhost only) and has a password
- [ ] JWT uses RS256 (asymmetric) — not HS256 (symmetric)
- [ ] `ADMIN_REGISTRATION_KEY` is changed from default
- [ ] Rate limiting is enabled and tested
- [ ] HMAC secret is at least 32 random bytes
- [ ] `BCRYPT_ROUNDS` is set to 12 or higher
- [ ] Nginx has security headers set:

```nginx
add_header X-Content-Type-Options nosniff;
add_header X-Frame-Options DENY;
add_header X-XSS-Protection "1; mode=block";
add_header Referrer-Policy "no-referrer";
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

- [ ] PM2 is configured to auto-start on server reboot
- [ ] Logs are being monitored (PM2 logs or a logging service)
- [ ] Database backups are scheduled

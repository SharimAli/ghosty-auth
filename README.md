# 👻 GHOSTY Auth

> A secure, self-hosted license authentication system built from scratch.

---

## 📦 What is GHOSTY Auth?

GHOSTY Auth is a full-stack license key authentication system that lets developers protect their software behind a key-based auth system with HWID binding, session tokens, rate limiting, and a seller dashboard.

---

## 🗂️ Project Structure

```
ghosty-auth/
├── server/          # Node.js + Express REST API
├── dashboard/       # React seller/admin panel
├── sdk/             # Client SDKs (C#, Python, C++)
└── docs/            # Documentation
```

---

## ✨ Features

- 🔑 License key generation with configurable expiry
- 🖥️ HWID (Hardware ID) binding per key
- 🔒 HMAC-signed API responses (tamper protection)
- 🪙 Session tokens (short-lived, no repeated key exposure)
- 🚫 Rate limiting per IP and per key
- 📋 Full auth logging (IP, HWID, timestamps)
- 👤 Multi-seller support with isolated applications
- 📊 Web dashboard for key management
- 🧩 SDKs for C#, Python, and C++

---

## 🚀 Quick Start

### Prerequisites

- Node.js v18+
- PostgreSQL 14+
- Redis 7+

### 1. Clone & Install

```bash
git clone https://github.com/yourname/ghosty-auth
cd ghosty-auth/server
npm install
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your DB, Redis, and secret values
```

### 3. Run Database Migrations

```bash
npm run migrate
```

### 4. Start the Server

```bash
# Development
npm run dev

# Production
npm start
```

### 5. Start the Dashboard

```bash
cd ../dashboard
npm install
npm run dev
```

---

## 🔐 Security Overview

| Feature | Implementation |
|---|---|
| API Response Signing | HMAC-SHA256 |
| Key Generation | crypto.randomBytes (128-bit entropy) |
| HWID Binding | SHA-256 hash of hardware fingerprint |
| Password Storage | bcrypt (12 rounds) |
| Session Tokens | JWT (RS256, short TTL) |
| Transport | HTTPS only |
| Rate Limiting | Redis-backed sliding window |

---

## 📚 Documentation

- [API Reference](./docs/api.md)
- [SDK Usage Guide](./docs/sdk-usage.md)
- [Setup & Deployment](./docs/setup.md)

---

## 🧩 SDK Integration (Quick Example)

### C#
```csharp
var auth = new GhostyAuth("YOUR_APP_SECRET");
var result = await auth.Initialize("XXXX-XXXX-XXXX-XXXX");

if (result.Success) {
    Console.WriteLine("Authenticated: " + result.Username);
} else {
    Console.WriteLine("Error: " + result.Message);
    Environment.Exit(0);
}
```

### Python
```python
from ghosty_auth import GhostyAuth

auth = GhostyAuth(app_secret="YOUR_APP_SECRET")
result = auth.initialize("XXXX-XXXX-XXXX-XXXX")

if result["success"]:
    print(f"Authenticated: {result['username']}")
else:
    print(f"Error: {result['message']}")
    exit()
```

---

## ⚙️ API Base URL

```
https://your-domain.com/api/v1
```

---

## 📄 License

MIT — use freely, credit appreciated.

---

## ⚠️ Disclaimer

GHOSTY Auth is intended for legitimate software protection purposes only. You are responsible for how you use this system.

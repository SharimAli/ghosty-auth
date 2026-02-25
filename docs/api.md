# GHOSTY Auth — API Reference

**Base URL:** `https://your-domain.com/api/v1`  
**Content-Type:** `application/json`  
**Auth:** Bearer token (JWT) for protected routes

---

## 📌 Table of Contents

- [Authentication Flow](#authentication-flow)
- [Response Format](#response-format)
- [HMAC Signature Verification](#hmac-signature-verification)
- [Endpoints](#endpoints)
  - [Auth](#auth-endpoints)
  - [Keys](#key-endpoints)
  - [Users](#user-endpoints)
  - [Admin](#admin-endpoints)
- [Error Codes](#error-codes)
- [Rate Limits](#rate-limits)

---

## Authentication Flow

```
Client App                        GHOSTY Auth API
    |                                    |
    |-- POST /auth/init ---------------->|  (license_key + hwid + app_secret)
    |                                    |  Validate key, bind HWID
    |<-- { token, user_data } ----------|  Return signed session token
    |                                    |
    |-- POST /auth/validate ----------->|  (token + hwid)
    |<-- { valid: true } ---------------|  Periodic re-validation
    |                                    |
```

---

## Response Format

All responses follow this structure:

```json
{
  "success": true,
  "message": "Human-readable message",
  "data": { },
  "timestamp": 1700000000000,
  "signature": "hmac_sha256_hex_string"
}
```

**Always verify `signature` on the client side before trusting the response.**

---

## HMAC Signature Verification

The `signature` field is computed as:

```
HMAC-SHA256(secret, timestamp + ":" + JSON.stringify(data))
```

**Client verification example (C#):**
```csharp
var expected = ComputeHMAC(appSecret, response.timestamp + ":" + response.data);
if (expected != response.signature) {
    // Response was tampered — terminate app
    Environment.Exit(1);
}
```

---

## Endpoints

---

### Auth Endpoints

---

#### `POST /auth/init`

Initializes a license session. Validates the key, binds HWID on first use, and returns a session token.

**Request Body:**
```json
{
  "license_key": "GHOST-XXXX-XXXX-XXXX",
  "hwid": "sha256_hardware_fingerprint",
  "app_id": "your_app_uuid"
}
```

> ⚠️ The request body must also include a `request_signature` field.  
> See [Request Signing](./sdk-usage.md#request-signing).

**Success Response `200`:**
```json
{
  "success": true,
  "message": "Authentication successful",
  "data": {
    "token": "eyJhbGci...",
    "token_expires": 1700003600000,
    "username": "john_doe",
    "email": "j***@example.com",
    "expires_at": "2025-12-31T00:00:00Z",
    "hwid_locked": true
  },
  "timestamp": 1700000000000,
  "signature": "abc123..."
}
```

**Error Responses:**

| Status | Code | Reason |
|--------|------|--------|
| 400 | `MISSING_FIELDS` | Required fields not provided |
| 401 | `INVALID_KEY` | License key does not exist |
| 401 | `KEY_EXPIRED` | License has expired |
| 401 | `KEY_BANNED` | License has been banned |
| 401 | `HWID_MISMATCH` | HWID doesn't match bound hardware |
| 403 | `INVALID_SIGNATURE` | Request signature verification failed |
| 429 | `RATE_LIMITED` | Too many requests |

---

#### `POST /auth/validate`

Validates an active session token. Call this periodically (e.g. every 30 minutes) to ensure the session is still valid.

**Request Body:**
```json
{
  "token": "eyJhbGci...",
  "hwid": "sha256_hardware_fingerprint",
  "app_id": "your_app_uuid"
}
```

**Success Response `200`:**
```json
{
  "success": true,
  "message": "Session valid",
  "data": {
    "valid": true,
    "expires_in": 3540
  },
  "timestamp": 1700000000000,
  "signature": "abc123..."
}
```

---

#### `POST /auth/logout`

Invalidates the session token server-side.

**Request Body:**
```json
{
  "token": "eyJhbGci..."
}
```

**Success Response `200`:**
```json
{
  "success": true,
  "message": "Session terminated"
}
```

---

### Key Endpoints

> 🔒 Requires Bearer token (seller/admin JWT)

---

#### `POST /keys/generate`

Generates one or more license keys for an application.

**Headers:**
```
Authorization: Bearer <seller_token>
```

**Request Body:**
```json
{
  "app_id": "your_app_uuid",
  "quantity": 5,
  "expires_in_days": 30,
  "note": "Batch for reseller ABC"
}
```

**Success Response `201`:**
```json
{
  "success": true,
  "message": "5 keys generated",
  "data": {
    "keys": [
      {
        "id": "uuid",
        "key": "GHOST-AB12-CD34-EF56",
        "expires_at": "2025-12-31T00:00:00Z",
        "created_at": "2024-01-01T00:00:00Z"
      }
    ]
  }
}
```

---

#### `GET /keys`

Lists all keys for an application.

**Query Parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `app_id` | string | Filter by application |
| `status` | string | `active`, `expired`, `banned` |
| `page` | number | Page number (default: 1) |
| `limit` | number | Results per page (default: 50, max: 100) |

---

#### `POST /keys/ban`

Bans a license key.

**Request Body:**
```json
{
  "key_id": "uuid",
  "reason": "Chargeback"
}
```

---

#### `POST /keys/reset-hwid`

Resets the HWID binding for a key (allows use on new hardware).

**Request Body:**
```json
{
  "key_id": "uuid"
}
```

---

#### `DELETE /keys/:id`

Permanently deletes a key.

---

### User Endpoints

> 🔒 Requires Bearer token

---

#### `POST /users/register`

Registers a new seller account.

**Request Body:**
```json
{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "SecurePassword123!"
}
```

---

#### `POST /users/login`

Authenticates a seller and returns a JWT.

**Request Body:**
```json
{
  "email": "john@example.com",
  "password": "SecurePassword123!"
}
```

**Success Response `200`:**
```json
{
  "success": true,
  "data": {
    "token": "eyJhbGci...",
    "expires_in": 86400
  }
}
```

---

#### `GET /users/me`

Returns the current authenticated user's profile.

---

### Admin Endpoints

> 🔒 Requires admin-level JWT

---

#### `GET /admin/users`

Lists all seller accounts.

---

#### `POST /admin/users/ban`

Bans a seller account.

**Request Body:**
```json
{
  "user_id": "uuid",
  "reason": "ToS violation"
}
```

---

#### `GET /admin/logs`

Returns system-wide auth logs.

**Query Parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `app_id` | string | Filter by app |
| `key_id` | string | Filter by key |
| `status` | string | `success`, `failed` |
| `from` | ISO date | Start date |
| `to` | ISO date | End date |

---

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `MISSING_FIELDS` | 400 | Required request fields are absent |
| `INVALID_KEY` | 401 | License key not found |
| `KEY_EXPIRED` | 401 | License key has passed its expiry date |
| `KEY_BANNED` | 401 | License key is banned |
| `HWID_MISMATCH` | 401 | HWID does not match bound value |
| `INVALID_TOKEN` | 401 | Session token is invalid or expired |
| `INVALID_SIGNATURE` | 403 | Request HMAC signature check failed |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `RATE_LIMITED` | 429 | Too many requests from this IP/key |
| `SERVER_ERROR` | 500 | Internal server error |

---

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| `POST /auth/init` | 10 requests / minute / IP |
| `POST /auth/validate` | 60 requests / minute / token |
| `POST /keys/generate` | 30 requests / minute / seller |
| All other endpoints | 100 requests / minute / IP |

Rate limit headers are returned on every response:
```
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 7
X-RateLimit-Reset: 1700000060
```

# GHOSTY Auth — SDK Usage Guide

This guide explains how to integrate GHOSTY Auth into your application using the provided SDKs.

---

## 📌 Table of Contents

- [Concepts](#concepts)
- [Request Signing](#request-signing)
- [HWID Generation](#hwid-generation)
- [C# SDK](#c-sdk)
- [Python SDK](#python-sdk)
- [C++ SDK](#c-sdk-1)
- [Anti-Tamper Tips](#anti-tamper-tips)

---

## Concepts

### How It Works

1. Your app generates a **HWID** (hardware fingerprint) at runtime
2. Your app sends the **license key + HWID + app_id** to GHOSTY Auth API
3. The API validates the key and returns a signed **session token**
4. Your app **verifies the HMAC signature** on the response before trusting it
5. Periodically your app calls `/auth/validate` with the token to keep the session alive

### What You Need

| Item | Where to Get It |
|------|----------------|
| `APP_ID` | From your seller dashboard → Applications |
| `APP_SECRET` | From your seller dashboard → Applications (keep this private!) |
| `API_URL` | Your hosted GHOSTY Auth server URL |

> ⚠️ Never hardcode `APP_SECRET` in plain text. Obfuscate your binary.

---

## Request Signing

Every request to the API must include a `request_signature` field to prove the request came from your app (not a replay or spoofed request).

**How to compute it:**

```
request_signature = HMAC-SHA256(APP_SECRET, app_id + ":" + license_key + ":" + hwid + ":" + timestamp)
```

Include `timestamp` (Unix ms) in every request body so the server can reject requests older than 30 seconds.

---

## HWID Generation

HWID should be a stable, unique fingerprint of the machine. Combine multiple hardware identifiers and hash them.

**Recommended components:**

| Component | Windows API |
|-----------|-------------|
| CPU ID | `Win32_Processor.ProcessorId` via WMI |
| Disk Serial | `Win32_DiskDrive.SerialNumber` via WMI |
| Motherboard Serial | `Win32_BaseBoard.SerialNumber` via WMI |
| MAC Address | Network adapter physical address |

**Formula:**
```
hwid = SHA256(cpu_id + disk_serial + motherboard_serial + mac_address)
```

> Do not use the full raw value — always hash it before sending.

---

## C# SDK

### Installation

Copy `GhostyAuth.cs` into your project.

### Quick Start

```csharp
using GhostyAuthSDK;

class Program
{
    static async Task Main(string[] args)
    {
        var auth = new GhostyAuth(
            apiUrl: "https://your-domain.com/api/v1",
            appId: "your-app-uuid",
            appSecret: "your-app-secret"
        );

        // Initialize with license key
        var result = await auth.Initialize("GHOST-XXXX-XXXX-XXXX");

        if (!result.Success)
        {
            Console.WriteLine($"Auth failed: {result.Message}");
            Environment.Exit(0);
        }

        Console.WriteLine($"Welcome, {result.Username}!");
        Console.WriteLine($"License expires: {result.ExpiresAt}");

        // Run your app...

        // Periodically validate session (call this every 30 min)
        var valid = await auth.Validate();
        if (!valid)
        {
            Console.WriteLine("Session expired. Please restart.");
            Environment.Exit(0);
        }
    }
}
```

### Full API Reference

#### `new GhostyAuth(apiUrl, appId, appSecret)`

Creates a new auth client instance.

| Parameter | Type | Description |
|-----------|------|-------------|
| `apiUrl` | string | Your GHOSTY Auth server URL |
| `appId` | string | Your application UUID |
| `appSecret` | string | Your application secret (for signing) |

---

#### `await auth.Initialize(licenseKey)`

Authenticates the user with a license key. Automatically generates HWID, signs the request, and verifies the response signature.

**Returns `AuthResult`:**

| Property | Type | Description |
|----------|------|-------------|
| `Success` | bool | Whether auth succeeded |
| `Message` | string | Status message |
| `Username` | string | Authenticated user's name |
| `ExpiresAt` | DateTime | Key expiry date |
| `Token` | string | Session token (stored internally) |

---

#### `await auth.Validate()`

Re-validates the current session. Returns `bool`.

---

#### `await auth.Logout()`

Terminates the session server-side.

---

#### `auth.GetHWID()`

Returns the current machine's HWID hash (for debugging or display).

---

## Python SDK

### Installation

Copy `ghosty_auth.py` into your project directory.

### Quick Start

```python
from ghosty_auth import GhostyAuth

auth = GhostyAuth(
    api_url="https://your-domain.com/api/v1",
    app_id="your-app-uuid",
    app_secret="your-app-secret"
)

# Initialize with license key
result = auth.initialize("GHOST-XXXX-XXXX-XXXX")

if not result["success"]:
    print(f"Auth failed: {result['message']}")
    exit(1)

print(f"Welcome, {result['username']}!")
print(f"License expires: {result['expires_at']}")

# Your app runs here...

# Periodically validate
if not auth.validate():
    print("Session expired.")
    exit(1)
```

### Full API Reference

#### `GhostyAuth(api_url, app_id, app_secret)`

Creates a new auth client instance.

---

#### `auth.initialize(license_key) -> dict`

Authenticates with a license key.

**Returns:**
```python
{
    "success": True,
    "message": "Authentication successful",
    "username": "john_doe",
    "expires_at": "2025-12-31T00:00:00Z",
    "token": "eyJhbGci..."
}
```

---

#### `auth.validate() -> bool`

Validates the current session.

---

#### `auth.logout() -> bool`

Terminates the session.

---

#### `auth.get_hwid() -> str`

Returns the current machine's HWID hash.

---

## C++ SDK

### Installation

Include `ghosty_auth.hpp` in your project. Requires `libcurl` and `nlohmann/json`.

```cpp
#include "ghosty_auth.hpp"

int main() {
    GhostyAuth auth(
        "https://your-domain.com/api/v1",
        "your-app-uuid",
        "your-app-secret"
    );

    AuthResult result = auth.initialize("GHOST-XXXX-XXXX-XXXX");

    if (!result.success) {
        std::cout << "Auth failed: " << result.message << std::endl;
        return 1;
    }

    std::cout << "Welcome, " << result.username << "!" << std::endl;

    return 0;
}
```

---

## Anti-Tamper Tips

These steps make it significantly harder for users to bypass GHOSTY Auth:

### 1. Always Verify Response Signatures
Never skip HMAC verification. If the signature is wrong, terminate immediately — don't just log a warning.

### 2. Obfuscate Your Binary
- **C#/.NET:** Use ConfuserEx or Obfuscar
- **C++:** Use Themida, VMProtect, or UPX as a baseline
- **Python:** Compile with Nuitka and use PyArmor

### 3. Never Store the APP_SECRET in Plain Text
Encrypt it or split it across multiple constants and assemble at runtime.

### 4. Check Integrity of Your Own Executable
Hash your own binary at startup and compare against a known good value:
```csharp
var hash = ComputeSHA256(Assembly.GetExecutingAssembly().Location);
if (hash != EXPECTED_HASH) Environment.Exit(1);
```

### 5. Detect Debuggers
```csharp
if (System.Diagnostics.Debugger.IsAttached) Environment.Exit(1);
```

### 6. Use Short Session Token TTLs
Set token TTL to 1–4 hours. This forces re-validation frequently and limits the window for token theft.

### 7. Don't Trust Client-Side Checks Alone
All validation must happen server-side. Client-side checks are just extra friction, not real protection.

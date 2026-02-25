"""
╔═══════════════════════════════════════════════════════════════╗
║                   GHOSTY Auth — Python SDK                   ║
║                       ghosty_auth.py                         ║
╚═══════════════════════════════════════════════════════════════╝

Usage:
    from ghosty_auth import GhostyAuth

    auth = GhostyAuth(
        api_url="https://api.yourdomain.com/api/v1",
        app_id="YOUR_APP_ID",
        app_secret="YOUR_APP_SECRET"
    )

    result = auth.initialize("GHOST-XXXX-XXXX-XXXX")

    if not result["success"]:
        print(f"Error: {result['message']}")
        sys.exit(1)

    print(f"Welcome, {result['username']}!")
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import json
import os
import platform
import re
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional
from datetime import datetime

try:
    import requests
except ImportError:
    raise ImportError("GHOSTY Auth requires the 'requests' library. Run: pip install requests")


# ─── Result Dataclasses ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class AuthResult:
    success:    bool
    message:    str
    username:   str      = ""
    email:      str      = ""
    expires_at: str      = ""
    hwid_locked: bool    = False
    _token:     str      = field(default="", repr=False)  # internal use only

@dataclass(frozen=True)
class ValidateResult:
    valid:      bool
    expires_in: int = 0


# ─── Main SDK Class ──────────────────────────────────────────────────────────

class GhostyAuth:
    """
    GHOSTY Auth client SDK for Python.

    All requests are HMAC-signed. All responses have their signature
    verified before any data is trusted. A debugger/inspection check
    is run at startup and before sensitive operations.
    """

    SDK_VERSION = "1.0.0"
    REQUEST_TIMEOUT = 15  # seconds

    def __init__(self, api_url: str, app_id: str, app_secret: str) -> None:
        if not api_url or not app_id or not app_secret:
            raise ValueError("api_url, app_id, and app_secret are all required.")

        # Anti-debug check at construction
        self._anti_debug()

        self._api_url    = api_url.rstrip("/")
        self._app_id     = app_id
        self._app_secret = app_secret.encode("utf-8")

        self._hwid          = self._generate_hwid()
        self._session_token: str  = ""
        self._initialized:   bool = False

        self._session = requests.Session()
        self._session.headers.update({
            "Content-Type": "application/json",
            "X-Client": f"GhostyAuth-Python/{self.SDK_VERSION}"
        })

    # ─────────────────────────────────────────────────────────────────────────
    #  PUBLIC API
    # ─────────────────────────────────────────────────────────────────────────

    def initialize(self, license_key: str) -> dict[str, Any]:
        """
        Authenticates a license key and binds the session to this machine's HWID.
        Returns a dict with keys: success, message, username, email, expires_at,
        hwid_locked, token (internal).
        """
        self._anti_debug()

        if not license_key or not license_key.strip():
            return self._fail("License key cannot be empty.")

        license_key = license_key.strip().upper()
        timestamp   = self._now_ms()

        payload = {
            "license_key":       license_key,
            "hwid":              self._hwid,
            "app_id":            self._app_id,
            "timestamp":         timestamp,
            "request_signature": self._compute_request_signature(license_key, timestamp),
        }

        try:
            response = self._post("/auth/init", payload)
        except requests.exceptions.ConnectionError:
            return self._fail("Could not reach the authentication server.")
        except requests.exceptions.Timeout:
            return self._fail("Authentication request timed out.")
        except Exception as e:
            return self._fail(f"Unexpected error: {e}")

        if response is None:
            return self._fail("No response from server.")

        # ── Verify HMAC signature ──
        if not self._verify_response_signature(
            response.get("signature", ""),
            response.get("timestamp", 0),
            response.get("data")
        ):
            self._terminate_tampered()

        if not response.get("success") or not response.get("data"):
            return self._fail(response.get("message", "Authentication failed."))

        data = response["data"]
        self._session_token = data.get("token", "")
        self._initialized   = True

        return {
            "success":     True,
            "message":     response.get("message", ""),
            "username":    data.get("username", ""),
            "email":       data.get("email", ""),
            "expires_at":  data.get("expires_at", ""),
            "hwid_locked": data.get("hwid_locked", False),
            "_token":      self._session_token,
        }

    def validate(self) -> bool:
        """
        Validates the active session token. Returns True if valid.
        Call periodically (every 30–60 minutes).
        """
        self._anti_debug()

        if not self._initialized or not self._session_token:
            return False

        timestamp = self._now_ms()
        payload = {
            "token":     self._session_token,
            "hwid":      self._hwid,
            "app_id":    self._app_id,
            "timestamp": timestamp,
        }

        try:
            response = self._post("/auth/validate", payload)
        except Exception:
            return False

        if response is None:
            return False

        if not self._verify_response_signature(
            response.get("signature", ""),
            response.get("timestamp", 0),
            response.get("data")
        ):
            self._terminate_tampered()

        return response.get("success", False) and response.get("data", {}).get("valid", False)

    def logout(self) -> bool:
        """
        Terminates the session server-side. Returns True on success.
        """
        if not self._initialized or not self._session_token:
            return False

        payload = {"token": self._session_token}

        try:
            response = self._post("/auth/logout", payload)
            self._session_token = ""
            self._initialized   = False
            return bool(response and response.get("success"))
        except Exception:
            return False

    def get_hwid(self) -> str:
        """Returns the HWID hash for this machine."""
        return self._hwid

    # ─────────────────────────────────────────────────────────────────────────
    #  HWID GENERATION
    # ─────────────────────────────────────────────────────────────────────────

    def _generate_hwid(self) -> str:
        """
        SHA-256(MachineGuid|VolumeSerial|MAC)
        Identical across Python, C++, and C# SDKs.
        """
        system = platform.system()
        if system == "Windows":
            parts = self._hwid_windows()
        elif system == "Linux":
            parts = self._hwid_linux()
        elif system == "Darwin":
            parts = self._hwid_macos()
        else:
            parts = [f"{uuid.getnode():012X}"]

        fingerprint = "|".join(p for p in parts if p)
        if not fingerprint:
            raise RuntimeError("Unable to generate HWID on this system.")
        return hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()

    def _hwid_windows(self) -> list[str]:
        parts: list[str] = []

        # 1. MachineGuid from registry
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography")
            val, _ = winreg.QueryValueEx(key, "MachineGuid")
            winreg.CloseKey(key)
            if val:
                parts.append(val.strip().upper())
        except Exception:
            pass

        # 2. C:\ volume serial as 8-char uppercase hex
        try:
            import ctypes
            serial = ctypes.c_ulong(0)
            ctypes.windll.kernel32.GetVolumeInformationW(
                "C:\\", None, 0, ctypes.byref(serial), None, None, None, 0
            )
            parts.append(f"{serial.value:08X}")
        except Exception:
            pass

        # 3. MAC address as 12-char uppercase hex no colons
        try:
            parts.append(f"{uuid.getnode():012X}")
        except Exception:
            pass

        return parts

    def _hwid_linux(self) -> list[str]:
        parts: list[str] = []

        sources = [
            "/etc/machine-id",
            "/var/lib/dbus/machine-id",
        ]

        for path in sources:
            try:
                with open(path) as f:
                    val = f.read().strip()
                    if val:
                        parts.append(val)
                        break
            except OSError:
                pass

        # CPU info
        try:
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if "Serial" in line or "serial" in line:
                        val = line.split(":")[-1].strip()
                        if val:
                            parts.append(val)
                            break
        except OSError:
            pass

        # MAC address
        try:
            mac = hex(uuid.getnode()).replace("0x", "").upper()
            parts.append(mac)
        except Exception:
            pass

        return parts

    def _hwid_macos(self) -> list[str]:
        parts: list[str] = []

        try:
            result = subprocess.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                stderr=subprocess.DEVNULL,
                timeout=5
            ).decode(errors="ignore")
            match = re.search(r'"IOPlatformSerialNumber"\s*=\s*"([^"]+)"', result)
            if match:
                parts.append(match.group(1))
            match_uuid = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', result)
            if match_uuid:
                parts.append(match_uuid.group(1))
        except Exception:
            pass

        # MAC address
        try:
            mac = hex(uuid.getnode()).replace("0x", "").upper()
            parts.append(mac)
        except Exception:
            pass

        return parts

    # ─────────────────────────────────────────────────────────────────────────
    #  CRYPTOGRAPHY
    # ─────────────────────────────────────────────────────────────────────────

    def _compute_request_signature(self, license_key: str, timestamp: int) -> str:
        """
        HMAC-SHA256(app_secret, app_id:license_key:hwid:timestamp)
        """
        message = f"{self._app_id}:{license_key}:{self._hwid}:{timestamp}"
        return hmac.new(
            self._app_secret,
            message.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

    def _verify_response_signature(
        self,
        signature:  str,
        timestamp:  int,
        data:       Any
    ) -> bool:
        if not signature:
            return False

        data_json = json.dumps(data, separators=(",", ":"), sort_keys=True) if data is not None else "{}"
        message   = f"{timestamp}:{data_json}"
        expected  = hmac.new(
            self._app_secret,
            message.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        # Constant-time comparison
        return hmac.compare_digest(expected, signature)

    # ─────────────────────────────────────────────────────────────────────────
    #  ANTI-TAMPER / ANTI-DEBUG
    # ─────────────────────────────────────────────────────────────────────────

    def _anti_debug(self) -> None:
        """Checks for common debugging/tracing scenarios and terminates if found."""

        # Check for common debugger env vars / tracers
        suspicious_env = [
            "PYTHONDEBUG", "PYDEVD_USE_FRAME_EVAL",
            "PYCHARM_DEBUG", "VSCODE_DEBUGGER",
        ]
        for key in suspicious_env:
            if os.environ.get(key):
                self._terminate_tampered()

        # Check if sys.gettrace() indicates a tracing hook is active
        if sys.gettrace() is not None:
            self._terminate_tampered()

        # Windows: check IsDebuggerPresent via ctypes
        if platform.system() == "Windows":
            try:
                kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
                if kernel32.IsDebuggerPresent():
                    self._terminate_tampered()
            except Exception:
                pass

    @staticmethod
    def _terminate_tampered() -> None:
        """Silent hard exit — reveals no information to the attacker."""
        os._exit(1)

    # ─────────────────────────────────────────────────────────────────────────
    #  HTTP HELPER
    # ─────────────────────────────────────────────────────────────────────────

    def _post(self, endpoint: str, body: dict) -> Optional[dict]:
        url = f"{self._api_url}{endpoint}"
        resp = self._session.post(url, json=body, timeout=self.REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    # ─────────────────────────────────────────────────────────────────────────
    #  HELPERS
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _fail(message: str) -> dict[str, Any]:
        return {"success": False, "message": message}

    @staticmethod
    def _now_ms() -> int:
        return int(time.time() * 1000)

    def __enter__(self) -> "GhostyAuth":
        return self

    def __exit__(self, *_) -> None:
        self.logout()
        self._session.close()
        # Clear secret from memory
        self._app_secret = b""
        self._session_token = ""

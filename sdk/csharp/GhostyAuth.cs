/*
 * ╔═══════════════════════════════════════════════════════════════╗
 * ║                    GHOSTY Auth — C# SDK                      ║
 * ║                      GhostyAuth.cs                           ║
 * ╚═══════════════════════════════════════════════════════════════╝
 *
 * Usage:
 *   var auth = new GhostyAuth("https://api.yourdomain.com/api/v1", "APP_ID", "APP_SECRET");
 *   var result = await auth.Initialize("GHOST-XXXX-XXXX-XXXX");
 *   if (!result.Success) { Environment.Exit(0); }
 */

using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using System.Management;
using System.Reflection;
using System.Diagnostics;

namespace GhostyAuthSDK
{
    // ─── Result Models ───────────────────────────────────────────────────────────

    public sealed class AuthResult
    {
        public bool Success { get; init; }
        public string Message { get; init; } = string.Empty;
        public string Username { get; init; } = string.Empty;
        public string Email { get; init; } = string.Empty;
        public DateTime? ExpiresAt { get; init; }
        public bool HwidLocked { get; init; }
        internal string Token { get; init; } = string.Empty;
    }

    public sealed class ValidateResult
    {
        public bool Valid { get; init; }
        public int ExpiresIn { get; init; }
    }

    // ─── Internal API Response Shapes ────────────────────────────────────────────

    internal sealed class ApiResponse<T>
    {
        [JsonPropertyName("success")]   public bool Success { get; set; }
        [JsonPropertyName("message")]   public string Message { get; set; } = string.Empty;
        [JsonPropertyName("data")]      public T? Data { get; set; }
        [JsonPropertyName("timestamp")] public long Timestamp { get; set; }
        [JsonPropertyName("signature")] public string Signature { get; set; } = string.Empty;
    }

    internal sealed class InitData
    {
        [JsonPropertyName("token")]         public string Token { get; set; } = string.Empty;
        [JsonPropertyName("token_expires")] public long TokenExpires { get; set; }
        [JsonPropertyName("username")]      public string Username { get; set; } = string.Empty;
        [JsonPropertyName("email")]         public string Email { get; set; } = string.Empty;
        [JsonPropertyName("expires_at")]    public string ExpiresAt { get; set; } = string.Empty;
        [JsonPropertyName("hwid_locked")]   public bool HwidLocked { get; set; }
    }

    internal sealed class ValidateData
    {
        [JsonPropertyName("valid")]      public bool Valid { get; set; }
        [JsonPropertyName("expires_in")] public int ExpiresIn { get; set; }
    }

    // ─── Main SDK Class ───────────────────────────────────────────────────────────

    public sealed class GhostyAuth : IDisposable
    {
        // ── Fields ───────────────────────────────────────────────────────────────
        private readonly string _apiUrl;
        private readonly string _appId;
        private readonly byte[] _appSecret;
        private readonly HttpClient _http;

        private string _sessionToken = string.Empty;
        private string _hwid = string.Empty;
        private bool _initialized = false;
        private bool _disposed = false;

        private static readonly JsonSerializerOptions _jsonOpts = new()
        {
            PropertyNameCaseInsensitive = true
        };

        // ── Constructor ──────────────────────────────────────────────────────────
        public GhostyAuth(string apiUrl, string appId, string appSecret)
        {
            if (string.IsNullOrWhiteSpace(apiUrl))   throw new ArgumentNullException(nameof(apiUrl));
            if (string.IsNullOrWhiteSpace(appId))    throw new ArgumentNullException(nameof(appId));
            if (string.IsNullOrWhiteSpace(appSecret)) throw new ArgumentNullException(nameof(appSecret));

            // Anti-tamper: die immediately if debugger is attached
            AntiDebug();

            _apiUrl = apiUrl.TrimEnd('/');
            _appId  = appId;
            _appSecret = Encoding.UTF8.GetBytes(appSecret);
            _hwid   = GenerateHWID();

            _http = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(15)
            };
            _http.DefaultRequestHeaders.Add("X-Client", "GhostyAuth-CSharp/1.0");
        }

        // ─────────────────────────────────────────────────────────────────────────
        //  PUBLIC API
        // ─────────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Authenticates a license key and binds the session to this machine's HWID.
        /// </summary>
        public async Task<AuthResult> Initialize(string licenseKey)
        {
            AntiDebug();

            if (string.IsNullOrWhiteSpace(licenseKey))
                return Fail("License key cannot be empty.");

            licenseKey = licenseKey.Trim().ToUpperInvariant();

            long timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            var payload = new
            {
                license_key       = licenseKey,
                hwid              = _hwid,
                app_id            = _appId,
                timestamp         = timestamp,
                request_signature = ComputeRequestSignature(licenseKey, timestamp)
            };

            try
            {
                var response = await PostAsync<ApiResponse<InitData>>("/auth/init", payload);

                if (response == null)
                    return Fail("No response from server.");

                // ── Verify HMAC signature on response ──
                if (!VerifyResponseSignature(response.Signature, response.Timestamp, response.Data))
                    TerminateTampered();

                if (!response.Success || response.Data == null)
                    return Fail(response.Message);

                _sessionToken = response.Data.Token;
                _initialized  = true;

                DateTime? expiresAt = null;
                if (DateTime.TryParse(response.Data.ExpiresAt, out var parsed))
                    expiresAt = parsed;

                return new AuthResult
                {
                    Success    = true,
                    Message    = response.Message,
                    Username   = response.Data.Username,
                    Email      = response.Data.Email,
                    ExpiresAt  = expiresAt,
                    HwidLocked = response.Data.HwidLocked,
                    Token      = response.Data.Token
                };
            }
            catch (HttpRequestException)
            {
                return Fail("Could not reach the authentication server.");
            }
            catch (TaskCanceledException)
            {
                return Fail("Authentication request timed out.");
            }
        }

        /// <summary>
        /// Validates the active session. Call periodically (every 30–60 min).
        /// </summary>
        public async Task<bool> Validate()
        {
            AntiDebug();

            if (!_initialized || string.IsNullOrEmpty(_sessionToken))
                return false;

            long timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            var payload = new
            {
                token     = _sessionToken,
                hwid      = _hwid,
                app_id    = _appId,
                timestamp = timestamp
            };

            try
            {
                var response = await PostAsync<ApiResponse<ValidateData>>("/auth/validate", payload);

                if (response == null) return false;

                if (!VerifyResponseSignature(response.Signature, response.Timestamp, response.Data))
                    TerminateTampered();

                return response.Success && (response.Data?.Valid ?? false);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Logs out and invalidates the session token server-side.
        /// </summary>
        public async Task<bool> Logout()
        {
            if (!_initialized || string.IsNullOrEmpty(_sessionToken))
                return false;

            var payload = new { token = _sessionToken };

            try
            {
                var response = await PostAsync<ApiResponse<object>>("/auth/logout", payload);
                _sessionToken = string.Empty;
                _initialized  = false;
                return response?.Success ?? false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Returns the HWID hash for this machine (for display/debug purposes).
        /// </summary>
        public string GetHWID() => _hwid;

        // ─────────────────────────────────────────────────────────────────────────
        //  HWID GENERATION
        // ─────────────────────────────────────────────────────────────────────────

        private static string GenerateHWID()
        {
            var parts = new StringBuilder();

            try { parts.Append(GetWmiValue("Win32_Processor", "ProcessorId")); }    catch { /* ignore */ }
            try { parts.Append(GetWmiValue("Win32_DiskDrive", "SerialNumber")); }   catch { /* ignore */ }
            try { parts.Append(GetWmiValue("Win32_BaseBoard", "SerialNumber")); }   catch { /* ignore */ }
            try { parts.Append(GetPrimaryMacAddress()); }                           catch { /* ignore */ }

            if (parts.Length == 0)
                throw new PlatformNotSupportedException("Unable to generate HWID on this platform.");

            return ComputeSHA256(parts.ToString());
        }

        private static string GetWmiValue(string wmiClass, string property)
        {
            using var searcher = new ManagementObjectSearcher($"SELECT {property} FROM {wmiClass}");
            foreach (ManagementObject obj in searcher.Get())
            {
                var val = obj[property]?.ToString()?.Trim();
                if (!string.IsNullOrEmpty(val) && val != "None" && val != "To be filled by O.E.M.")
                    return val;
            }
            return string.Empty;
        }

        private static string GetPrimaryMacAddress()
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up
                         && n.NetworkInterfaceType != NetworkInterfaceType.Loopback
                         && n.GetPhysicalAddress().ToString().Length >= 12)
                .OrderByDescending(n => n.Speed)
                .Select(n => n.GetPhysicalAddress().ToString())
                .FirstOrDefault() ?? string.Empty;
        }

        // ─────────────────────────────────────────────────────────────────────────
        //  CRYPTOGRAPHY
        // ─────────────────────────────────────────────────────────────────────────

        private string ComputeRequestSignature(string licenseKey, long timestamp)
        {
            // HMAC-SHA256(_appSecret, appId:licenseKey:hwid:timestamp)
            var message = $"{_appId}:{licenseKey}:{_hwid}:{timestamp}";
            return ComputeHMAC(_appSecret, message);
        }

        private bool VerifyResponseSignature<T>(string signature, long timestamp, T? data)
        {
            if (string.IsNullOrEmpty(signature)) return false;

            string dataJson = data == null ? "{}" : JsonSerializer.Serialize(data, _jsonOpts);
            string message  = $"{timestamp}:{dataJson}";
            string expected = ComputeHMAC(_appSecret, message);

            // Constant-time comparison to prevent timing attacks
            return CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(expected),
                Encoding.UTF8.GetBytes(signature)
            );
        }

        private static string ComputeHMAC(byte[] key, string message)
        {
            using var hmac = new HMACSHA256(key);
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(message));
            return Convert.ToHexString(hash).ToLowerInvariant();
        }

        private static string ComputeSHA256(string input)
        {
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(input));
            return Convert.ToHexString(hash).ToLowerInvariant();
        }

        // ─────────────────────────────────────────────────────────────────────────
        //  ANTI-TAMPER / ANTI-DEBUG
        // ─────────────────────────────────────────────────────────────────────────

        private static void AntiDebug()
        {
            // Check managed debugger
            if (Debugger.IsAttached)
                TerminateTampered();

            // Check native debugger via kernel32
            if (IsDebuggerPresentNative())
                TerminateTampered();
        }

        [DllImport("kernel32.dll")]
        private static extern bool IsDebuggerPresent();

        private static bool IsDebuggerPresentNative()
        {
            try { return IsDebuggerPresent(); }
            catch { return false; }
        }

        private static void TerminateTampered()
        {
            // Silent crash — don't give any information to the attacker
            Environment.FailFast(null);
        }

        // ─────────────────────────────────────────────────────────────────────────
        //  HTTP HELPER
        // ─────────────────────────────────────────────────────────────────────────

        private async Task<T?> PostAsync<T>(string endpoint, object body)
        {
            var json    = JsonSerializer.Serialize(body, _jsonOpts);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _http.PostAsync($"{_apiUrl}{endpoint}", content);
            var raw      = await response.Content.ReadAsStringAsync();

            if (string.IsNullOrWhiteSpace(raw))
                return default;

            return JsonSerializer.Deserialize<T>(raw, _jsonOpts);
        }

        // ─────────────────────────────────────────────────────────────────────────
        //  HELPERS
        // ─────────────────────────────────────────────────────────────────────────

        private static AuthResult Fail(string message) => new() { Success = false, Message = message };

        public void Dispose()
        {
            if (_disposed) return;
            _http.Dispose();
            // Clear sensitive data from memory
            Array.Clear(_appSecret, 0, _appSecret.Length);
            _sessionToken = string.Empty;
            _disposed = true;
        }
    }
}

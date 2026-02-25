/*
 * ╔═══════════════════════════════════════════════════════════════╗
 * ║                   GHOSTY Auth — C++ SDK                      ║
 * ║                     ghosty_auth.hpp                          ║
 * ╚═══════════════════════════════════════════════════════════════╝
 *
 * Header-only C++ SDK for GHOSTY Auth.
 *
 * Dependencies:
 *   - libcurl          (HTTP requests)
 *   - nlohmann/json    (JSON parsing)
 *   - OpenSSL          (HMAC-SHA256, SHA256)
 *
 * Compile example:
 *   g++ -std=c++17 main.cpp -lcurl -lssl -lcrypto -o app
 *
 * Usage:
 *   GhostyAuth auth("https://api.yourdomain.com/api/v1", "APP_ID", "APP_SECRET");
 *   auto result = auth.Initialize("GHOST-XXXX-XXXX-XXXX");
 *   if (!result.success) { std::exit(1); }
 */

#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// ── libcurl ──────────────────────────────────────────────────────────────────
#include <curl/curl.h>
#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#endif

// ── OpenSSL ──────────────────────────────────────────────────────────────────
#include <openssl/hmac.h>
#include <openssl/sha.h>

// ── nlohmann/json ─────────────────────────────────────────────────────────────
#include <nlohmann/json.hpp>
using json = nlohmann::json;

// ── Windows-specific headers ─────────────────────────────────────────────────
#ifdef _WIN32
#  include <windows.h>
#  include <intrin.h>
#  include <iphlpapi.h>
#  include <wbemidl.h>
#  pragma comment(lib, "wbemuuid.lib")
#  pragma comment(lib, "iphlpapi.lib")
#else
#  include <fstream>
#  include <net/if.h>
#  include <sys/ioctl.h>
#  include <unistd.h>
#  include <ifaddrs.h>
#  include <netpacket/packet.h>
#endif

namespace ghosty {

// ─── Result Types ─────────────────────────────────────────────────────────────

struct AuthResult {
    bool        success    = false;
    std::string message;
    std::string username;
    std::string email;
    std::string expires_at;
    bool        hwid_locked = false;
    // Internal — do not expose or log
    std::string _token;
};

struct ValidateResult {
    bool valid      = false;
    int  expires_in = 0;
};

// ─── GhostyAuth Class ────────────────────────────────────────────────────────

class GhostyAuth {
public:

    // ── Constructor ──────────────────────────────────────────────────────────
    GhostyAuth(
        const std::string& api_url,
        const std::string& app_id,
        const std::string& app_secret
    )
        : api_url_(api_url)
        , app_id_(app_id)
        , app_secret_(app_secret)
        , initialized_(false)
    {
        if (api_url.empty() || app_id.empty() || app_secret.empty())
            throw std::invalid_argument("[GhostyAuth] api_url, app_id, and app_secret are required.");

        // Anti-debug check at construction
        AntiDebug();

        // Generate HWID once at startup
        hwid_ = GenerateHWID();

        // Initialize libcurl globally (safe to call multiple times)
        curl_global_init(CURL_GLOBAL_ALL);
    }

    ~GhostyAuth() {
        // Securely zero sensitive memory
        SecureZero(app_secret_);
        SecureZero(session_token_);
        curl_global_cleanup();
    }

    // Prevent copy
    GhostyAuth(const GhostyAuth&)            = delete;
    GhostyAuth& operator=(const GhostyAuth&) = delete;

    // ─────────────────────────────────────────────────────────────────────────
    //  PUBLIC API
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Authenticates a license key. Binds HWID on first use.
     * Returns an AuthResult with success/failure details.
     */
    AuthResult Initialize(const std::string& license_key) {
        AntiDebug();

        if (license_key.empty())
            return Fail("License key cannot be empty.");

        std::string key = ToUpper(Trim(license_key));
        int64_t     ts  = NowMs();

        json payload = {
            {"license_key",       key},
            {"hwid",              hwid_},
            {"app_id",            app_id_},
            {"timestamp",         ts},
            {"request_signature", ComputeRequestSignature(key, ts)}
        };

        std::string raw;
        if (!PostJSON("/auth/init", payload.dump(), raw))
            return Fail("Could not reach the authentication server.");

        json response;
        try {
            response = json::parse(raw);
        } catch (...) {
            return Fail("Invalid response from server.");
        }

        // ── If server returned failure, no signature to verify ──
        if (!response.value("success", false) || !response.contains("data"))
            return Fail(response.value("message", "Authentication failed."));

        // ── Verify HMAC signature on successful responses only ──
        if (!VerifyResponseSignature(
                response.value("signature", ""),
                response.value("timestamp", (int64_t)0),
                response.contains("data") ? response["data"] : json(nullptr)
        )) {
            TerminateTampered();
        }

        auto& data    = response["data"];
        session_token_ = data.value("token", "");
        initialized_   = true;

        AuthResult result;
        result.success    = true;
        result.message    = response.value("message", "");
        result.username   = data.value("username", "");
        result.email      = data.value("email", "");
        result.expires_at = data.value("expires_at", "");
        result.hwid_locked= data.value("hwid_locked", false);
        result._token     = session_token_;

        return result;
    }

    /**
     * Validates the active session. Returns true if still valid.
     * Call periodically every 30–60 minutes.
     */
    bool Validate() {
        AntiDebug();

        if (!initialized_ || session_token_.empty())
            return false;

        int64_t ts = NowMs();
        json payload = {
            {"token",     session_token_},
            {"hwid",      hwid_},
            {"app_id",    app_id_},
            {"timestamp", ts}
        };

        std::string raw;
        if (!PostJSON("/auth/validate", payload.dump(), raw))
            return false;

        json response;
        try {
            response = json::parse(raw);
        } catch (...) {
            return false;
        }

        if (!VerifyResponseSignature(
                response.value("signature", ""),
                response.value("timestamp", (int64_t)0),
                response.contains("data") ? response["data"] : json(nullptr)
        )) {
            TerminateTampered();
        }

        return response.value("success", false) &&
               response["data"].value("valid", false);
    }

    /**
     * Logs out and invalidates the session server-side.
     */
    bool Logout() {
        if (!initialized_ || session_token_.empty())
            return false;

        json payload = {{"token", session_token_}};
        std::string raw;

        bool ok = PostJSON("/auth/logout", payload.dump(), raw);
        SecureZero(session_token_);
        initialized_ = false;

        if (!ok) return false;

        try {
            auto response = json::parse(raw);
            return response.value("success", false);
        } catch (...) {
            return false;
        }
    }

    /**
     * Returns the HWID hash for this machine.
     */
    std::string GetHWID() const { return hwid_; }

private:

    // ─────────────────────────────────────────────────────────────────────────
    //  HWID GENERATION
    // ─────────────────────────────────────────────────────────────────────────

    static std::string GenerateHWID() {
        // SHA-256(MachineGuid|VolumeSerial|MAC)
        // Identical format across C++, Python, and C# SDKs.
        std::string fingerprint;

#ifdef _WIN32
        std::string machineGuid = GetMachineGuid();
        std::string volumeSerial = GetVolumeSerial();
        std::string mac = GetMACAddress();

        if (!machineGuid.empty())  fingerprint += machineGuid;
        if (!volumeSerial.empty()) fingerprint += "|" + volumeSerial;
        if (!mac.empty())          fingerprint += "|" + mac;
#else
        // Linux/Mac handled below
        fingerprint = GetMachineIDLinux() + "|" + GetMACAddressLinux();
#endif

        if (fingerprint.empty() || fingerprint == "||")
            throw std::runtime_error("[GhostyAuth] Unable to generate HWID.");

        return SHA256Hex(fingerprint);
    }

#ifdef _WIN32

    // MachineGuid from HKLM\SOFTWARE\Microsoft\Cryptography — stable, unique per install
    static std::string GetMachineGuid() {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
            return "";

        char buf[256] = {};
        DWORD size = sizeof(buf);
        DWORD type = REG_SZ;
        RegQueryValueExA(hKey, "MachineGuid", nullptr, &type, (LPBYTE)buf, &size);
        RegCloseKey(hKey);

        std::string val(buf);
        for (auto& c : val) c = (char)toupper((unsigned char)c);
        return val;
    }

    // C:\ volume serial as 8-char uppercase hex
    static std::string GetVolumeSerial() {
        DWORD serial = 0;
        ::GetVolumeInformationA("C:\\", nullptr, 0, &serial, nullptr, nullptr, nullptr, 0);
        std::ostringstream oss;
        oss << std::uppercase << std::hex << std::setfill('0') << std::setw(8) << serial;
        return oss.str();
    }

    // MAC address as 12-char uppercase hex no colons (matches Python uuid.getnode() format)
    static std::string GetMACAddress() {
        ULONG bufLen = sizeof(IP_ADAPTER_INFO);
        std::vector<BYTE> buf(bufLen);
        auto* info = reinterpret_cast<PIP_ADAPTER_INFO>(buf.data());

        if (::GetAdaptersInfo(info, &bufLen) == ERROR_BUFFER_OVERFLOW) {
            buf.resize(bufLen);
            info = reinterpret_cast<PIP_ADAPTER_INFO>(buf.data());
        }

        if (::GetAdaptersInfo(info, &bufLen) == NO_ERROR && info->AddressLength == 6) {
            std::ostringstream oss;
            for (int i = 0; i < 6; i++) {
                oss << std::uppercase << std::hex << std::setfill('0')
                    << std::setw(2) << (int)info->Address[i];
            }
            return oss.str();
        }
        return "";
    }


#else

    static std::string GetMachineIDLinux() {
        const std::vector<std::string> paths = {
            "/etc/machine-id",
            "/var/lib/dbus/machine-id"
        };
        for (const auto& p : paths) {
            std::ifstream f(p);
            if (f.good()) {
                std::string id;
                std::getline(f, id);
                if (!id.empty()) return id;
            }
        }
        return "";
    }

    static std::string GetMACAddressLinux() {
        struct ifaddrs* ifaddr = nullptr;
        if (getifaddrs(&ifaddr) == -1) return "";

        std::string result;
        for (auto* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_PACKET) continue;
            std::string name(ifa->ifa_name);
            if (name == "lo") continue;

            auto* s = reinterpret_cast<struct sockaddr_ll*>(ifa->ifa_addr);
            std::ostringstream oss;
            for (int i = 0; i < 6; i++) {
                if (i > 0) oss << ":";
                oss << std::hex << std::setfill('0')
                    << std::setw(2) << (int)(s->sll_addr[i]);
            }
            result = oss.str();
            break;
        }

        freeifaddrs(ifaddr);
        return result;
    }

#endif

    // ─────────────────────────────────────────────────────────────────────────
    //  CRYPTOGRAPHY
    // ─────────────────────────────────────────────────────────────────────────

    std::string ComputeRequestSignature(const std::string& license_key, int64_t ts) const {
        // HMAC-SHA256(app_secret, app_id:license_key:hwid:timestamp)
        std::string message = app_id_ + ":" + license_key + ":" + hwid_ + ":" + std::to_string(ts);
        return HMACHex(app_secret_, message);
    }

    bool VerifyResponseSignature(
        const std::string& signature,
        int64_t            timestamp,
        const json&        data
    ) const {
        if (signature.empty()) return false;

        std::string data_json = data.is_null() ? "{}" : data.dump();
        std::string message   = std::to_string(timestamp) + ":" + data_json;
        std::string expected  = HMACHex(app_secret_, message);

        // Constant-time comparison
        return ConstTimeEquals(expected, signature);
    }

    static std::string HMACHex(const std::string& key, const std::string& message) {
        unsigned char raw[EVP_MAX_MD_SIZE];
        unsigned int  raw_len = 0;

        HMAC(
            EVP_sha256(),
            key.data(), static_cast<int>(key.size()),
            reinterpret_cast<const unsigned char*>(message.data()),
            message.size(),
            raw, &raw_len
        );

        return BytesToHex(raw, raw_len);
    }

    static std::string SHA256Hex(const std::string& input) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(
            reinterpret_cast<const unsigned char*>(input.data()),
            input.size(),
            hash
        );
        return BytesToHex(hash, SHA256_DIGEST_LENGTH);
    }

    static std::string BytesToHex(const unsigned char* data, size_t len) {
        std::ostringstream oss;
        for (size_t i = 0; i < len; i++)
            oss << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
        return oss.str();
    }

    static bool ConstTimeEquals(const std::string& a, const std::string& b) {
        if (a.size() != b.size()) return false;
        unsigned char result = 0;
        for (size_t i = 0; i < a.size(); i++)
            result |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
        return result == 0;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  ANTI-TAMPER / ANTI-DEBUG
    // ─────────────────────────────────────────────────────────────────────────

    static void AntiDebug() {
#ifdef _WIN32
        if (::IsDebuggerPresent())
            TerminateTampered();

        // Check NtGlobalFlag via raw GS register read — no PPEB needed
        ULONG_PTR pebAddr = __readgsqword(0x60);
        if (pebAddr) {
            BYTE ntGlobalFlag = *reinterpret_cast<BYTE*>(pebAddr + 0xBC);
            if (ntGlobalFlag & 0x70)
                TerminateTampered();
        }
#else
        // Linux: check TracerPid in /proc/self/status
        std::ifstream status("/proc/self/status");
        if (status.good()) {
            std::string line;
            while (std::getline(status, line)) {
                if (line.find("TracerPid:") != std::string::npos) {
                    int tracer = std::stoi(line.substr(line.find_last_of('\t') + 1));
                    if (tracer != 0) TerminateTampered();
                    break;
                }
            }
        }
#endif
    }

    [[noreturn]] static void TerminateTampered() {
        // Hard exit — gives attacker no information
        std::quick_exit(1);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  HTTP (libcurl)
    // ─────────────────────────────────────────────────────────────────────────

    bool PostJSON(
        const std::string& endpoint,
        const std::string& body,
        std::string&       out_response
    ) const {
        CURL* curl = curl_easy_init();
        if (!curl) return false;

        std::string url = api_url_ + endpoint;
        out_response.clear();

        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "X-Client: GhostyAuth-CPP/1.0");

        curl_easy_setopt(curl, CURLOPT_URL,            url.c_str());
        curl_easy_setopt(curl, CURLOPT_POST,           1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS,     body.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER,     headers);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT,        15L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);  // Always verify SSL
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA,      &out_response);

        CURLcode res = curl_easy_perform(curl);

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        return res == CURLE_OK;
    }

    static size_t WriteCallback(void* ptr, size_t size, size_t nmemb, std::string* out) {
        out->append(static_cast<char*>(ptr), size * nmemb);
        return size * nmemb;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  HELPERS
    // ─────────────────────────────────────────────────────────────────────────

    static AuthResult Fail(const std::string& message) {
        AuthResult r;
        r.success = false;
        r.message = message;
        return r;
    }

    static int64_t NowMs() {
        using namespace std::chrono;
        return duration_cast<milliseconds>(
            system_clock::now().time_since_epoch()
        ).count();
    }

    static std::string ToUpper(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), ::toupper);
        return s;
    }

    static std::string Trim(const std::string& s) {
        auto start = s.find_first_not_of(" \t\r\n");
        auto end   = s.find_last_not_of(" \t\r\n");
        return (start == std::string::npos) ? "" : s.substr(start, end - start + 1);
    }

    static void SecureZero(std::string& s) {
        if (!s.empty()) {
            // Volatile to prevent compiler from optimizing the clear away
            volatile char* p = &s[0];
            for (size_t i = 0; i < s.size(); i++) p[i] = '\0';
            s.clear();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  MEMBER VARIABLES
    // ─────────────────────────────────────────────────────────────────────────

    std::string api_url_;
    std::string app_id_;
    std::string app_secret_;   // zeroed in destructor
    std::string hwid_;
    std::string session_token_; // zeroed in destructor
    bool        initialized_;
};

} // namespace ghosty

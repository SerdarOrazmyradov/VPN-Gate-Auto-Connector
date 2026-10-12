// main.cpp
// VPN Gate background agent using SoftEther vpncmd.exe
// Build: cl /std:c++17 /W4 /EHsc /MT /DUNICODE /D_UNICODE main.cpp
// Single file. Win32 API + standard library only.

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <shellapi.h>
#include <wininet.h>

#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <cstdio>
#include <cwchar>
#include <cstdint>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
static const wchar_t* kAccountName = L"vpngate_auto";
static const wchar_t* kHubName     = L"VPNGATE";
static const wchar_t* kNicName     = L"VPN";
static const wchar_t* kUserName    = L"vpn";
static const wchar_t* kCsvUrl      = L"https://disaster-2ad1a.firebaseapp.com/vpngate.csv";
static const wchar_t* kVpnCmdPath  = L"C:\\Program Files\\SoftEther VPN Client\\vpncmd.exe";

static const DWORD kCsvMaxAgeSec  = 45u * 60u;   // 45 minutes
static const DWORD kVpnCmdTimeout = 10000;       // ms, per vpncmd call
static const DWORD kNetTimeoutMs  = 5000;        // ms, HEAD check
static const int   kPollCount     = 3;           // status polls after connect
static const DWORD kPollSleepMs   = 1000;        // between polls

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------
static HWND                 g_msgWnd        = nullptr;
static HANDLE               g_wakeEvent     = nullptr;
static std::atomic<bool>    g_stop{ false };
static std::atomic<bool>    g_accountReady{ false };
static std::atomic<bool>    g_trayIconAdded{ false };
static std::mutex           g_logMutex;

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------
static std::string ToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}

static std::wstring FromAcp(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_ACP, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return {};
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), (int)s.size(), w.data(), n);
    return w;
}

static std::wstring ToLower(const std::wstring& s) {
    std::wstring r;
    r.reserve(s.size());
    for (wchar_t c : s) r.push_back((wchar_t)towlower(c));
    return r;
}

static bool ContainsCI(const std::wstring& haystack, const wchar_t* needle) {
    if (!needle || !*needle) return false;
    std::wstring h = ToLower(haystack);
    std::wstring n = ToLower(needle);
    return h.find(n) != std::wstring::npos;
}

static std::wstring FormatDouble2(double v) {
    wchar_t buf[32];
    swprintf_s(buf, L"%.2f", v);
    return buf;
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------
static std::wstring GetExeDir() {
    wchar_t buf[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return L".";
    std::wstring p(buf, n);
    size_t pos = p.find_last_of(L"\\/");
    return (pos == std::wstring::npos) ? L"." : p.substr(0, pos);
}
static const std::wstring& ExeDir() {
    static const std::wstring d = GetExeDir();
    return d;
}
static std::wstring LogPath()   { return ExeDir() + L"\\vpnagent.log"; }
static std::wstring StatePath() { return ExeDir() + L"\\state.txt"; }
static std::wstring CsvPath()   { return ExeDir() + L"\\vpngate.csv"; }

// ---------------------------------------------------------------------------
// Logging (rotating, 256 KB)
// ---------------------------------------------------------------------------
static void Log(const wchar_t* level, const std::wstring& msg) {
    std::lock_guard<std::mutex> lk(g_logMutex);
    const std::wstring path = LogPath();

    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad)) {
        ULARGE_INTEGER sz;
        sz.LowPart  = fad.nFileSizeLow;
        sz.HighPart = fad.nFileSizeHigh;
        if (sz.QuadPart > 256ULL * 1024ULL) {
            std::wstring oldp = path + L".old";
            DeleteFileW(oldp.c_str());
            MoveFileW(path.c_str(), oldp.c_str());
        }
    }

    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t ts[64];
    swprintf_s(ts, L"%04d-%02d-%02d %02d:%02d:%02d",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    std::wstring line = std::wstring(ts) + L" [" + level + L"] " + msg + L"\r\n";
    std::string utf8 = ToUtf8(line);
    if (utf8.empty()) return;

    HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(h, utf8.data(), (DWORD)utf8.size(), &written, nullptr);
    CloseHandle(h);
}

// ---------------------------------------------------------------------------
// State file (index)
// ---------------------------------------------------------------------------
static size_t LoadIndex() {
    std::ifstream f(StatePath());
    if (!f) return 0;
    unsigned long long v = 0;
    f >> v;
    if (!f) return 0;
    return (size_t)v;
}

static void SaveIndex(size_t idx) {
    std::ofstream f(StatePath(), std::ios::trunc);
    if (!f) return;
    f << (unsigned long long)idx << "\n";
}

// ---------------------------------------------------------------------------
// Internet (WinINet)
// ---------------------------------------------------------------------------
static bool HasInternet() {
    HINTERNET hInet = InternetOpenW(L"VpnAgent/1.0", INTERNET_OPEN_TYPE_PRECONFIG,
                                    nullptr, nullptr, 0);
    if (!hInet) return false;

    DWORD t = kNetTimeoutMs;
    InternetSetOptionW(hInet, INTERNET_OPTION_CONNECT_TIMEOUT, &t, sizeof(t));
    InternetSetOptionW(hInet, INTERNET_OPTION_RECEIVE_TIMEOUT, &t, sizeof(t));
    InternetSetOptionW(hInet, INTERNET_OPTION_SEND_TIMEOUT,    &t, sizeof(t));

    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256] = {};
    wchar_t path[2048] = {};
    uc.lpszHostName = host; uc.dwHostNameLength = 255;
    uc.lpszUrlPath  = path; uc.dwUrlPathLength  = 2047;

    if (!InternetCrackUrlW(kCsvUrl, 0, 0, &uc)) {
        InternetCloseHandle(hInet);
        return false;
    }

    HINTERNET hConn = InternetConnectW(hInet, host, uc.nPort, nullptr, nullptr,
                                       INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConn) { InternetCloseHandle(hInet); return false; }

    DWORD flags = INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD |
                  INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
    HINTERNET hReq = HttpOpenRequestW(hConn, L"HEAD", path, nullptr, nullptr, nullptr, flags, 0);
    if (!hReq) {
        InternetCloseHandle(hConn);
        InternetCloseHandle(hInet);
        return false;
    }

    BOOL ok = HttpSendRequestW(hReq, nullptr, 0, nullptr, 0);

    InternetCloseHandle(hReq);
    InternetCloseHandle(hConn);
    InternetCloseHandle(hInet);
    return ok != FALSE;
}

static bool CsvCacheFresh() {
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(CsvPath().c_str(), GetFileExInfoStandard, &fad)) return false;
    FILETIME now;
    GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER a, b;
    a.LowPart  = fad.ftLastWriteTime.dwLowDateTime;
    a.HighPart = fad.ftLastWriteTime.dwHighDateTime;
    b.LowPart  = now.dwLowDateTime;
    b.HighPart = now.dwHighDateTime;
    unsigned long long age = (b.QuadPart - a.QuadPart) / 10000000ULL;
    return age < (unsigned long long)kCsvMaxAgeSec;
}

static bool DownloadCsv() {
    HINTERNET hInet = InternetOpenW(L"VpnAgent/1.0", INTERNET_OPEN_TYPE_PRECONFIG,
                                    nullptr, nullptr, 0);
    if (!hInet) return false;

    DWORD t = 30000;
    InternetSetOptionW(hInet, INTERNET_OPTION_CONNECT_TIMEOUT, &t, sizeof(t));
    InternetSetOptionW(hInet, INTERNET_OPTION_RECEIVE_TIMEOUT, &t, sizeof(t));
    InternetSetOptionW(hInet, INTERNET_OPTION_SEND_TIMEOUT,    &t, sizeof(t));

    DWORD flags = INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD |
                  INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
    HINTERNET hUrl = InternetOpenUrlW(hInet, kCsvUrl, nullptr, 0, flags, 0);
    if (!hUrl) { InternetCloseHandle(hInet); return false; }

    std::string data;
    char buf[8192];
    DWORD rd = 0;
    while (InternetReadFile(hUrl, buf, (DWORD)sizeof(buf), &rd) && rd > 0) {
        data.append(buf, rd);
        if (data.size() > 32u * 1024u * 1024u) break; // safety cap
    }

    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInet);

    if (data.size() < 100) return false;

    HANDLE h = CreateFileW(CsvPath().c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    BOOL ok = WriteFile(h, data.data(), (DWORD)data.size(), &written, nullptr);
    CloseHandle(h);
    if (!ok || written != data.size()) return false;

    Log(L"INFO", L"CSV downloaded (" + std::to_wstring(data.size()) + L" bytes)");
    return true;
}

static bool ReadFileToString(const std::wstring& path, std::string& out) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > (LONGLONG)(64 * 1024 * 1024)) {
        CloseHandle(h);
        return false;
    }
    out.resize((size_t)sz.QuadPart);
    DWORD total = 0;
    while (total < out.size()) {
        DWORD rd = 0;
        if (!ReadFile(h, out.data() + total, (DWORD)(out.size() - total), &rd, nullptr) || rd == 0) break;
        total += rd;
    }
    CloseHandle(h);
    out.resize(total);
    return total > 0;
}

// ---------------------------------------------------------------------------
// CSV parsing (RFC 4180-ish)
// ---------------------------------------------------------------------------
static std::vector<std::vector<std::string>> ParseCsvRows(const std::string& data) {
    std::vector<std::vector<std::string>> rows;
    std::vector<std::string> row;
    std::string field;
    bool inQuotes = false;
    bool fieldStarted = false;

    for (size_t i = 0; i < data.size(); ++i) {
        char c = data[i];
        if (inQuotes) {
            if (c == '"') {
                if (i + 1 < data.size() && data[i + 1] == '"') { field.push_back('"'); ++i; }
                else inQuotes = false;
            } else {
                field.push_back(c);
            }
        } else {
            if (c == '"' && !fieldStarted) { inQuotes = true; fieldStarted = true; }
            else if (c == ',') { row.push_back(field); field.clear(); fieldStarted = false; }
            else if (c == '\n') {
                row.push_back(field); field.clear(); fieldStarted = false;
                rows.push_back(row); row.clear();
            } else if (c == '\r') {
                // ignore
            } else {
                field.push_back(c);
                fieldStarted = true;
            }
        }
    }
    if (!field.empty() || !row.empty()) {
        row.push_back(field);
        rows.push_back(row);
    }
    return rows;
}

// ---------------------------------------------------------------------------
// Base64 decoder + port extraction
// ---------------------------------------------------------------------------
static int B64Val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static bool Base64Decode(const std::string& in, std::string& out) {
    out.clear();
    out.reserve(in.size() * 3 / 4);
    int val = 0, bits = 0;
    for (char c : in) {
        if (c == '=') break;
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        int v = B64Val(c);
        if (v < 0) return false;
        val = (val << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((char)((val >> bits) & 0xFF));
        }
    }
    return true;
}

static int ExtractPortFromBase64(const std::string& b64) {
    if (b64.empty()) return 443;
    std::string cfg;
    if (!Base64Decode(b64, cfg)) return 443;

    size_t pos = 0;
    while (pos < cfg.size()) {
        size_t eol = cfg.find('\n', pos);
        std::string line = (eol == std::string::npos) ? cfg.substr(pos) : cfg.substr(pos, eol - pos);
        pos = (eol == std::string::npos) ? cfg.size() : eol + 1;

        while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t'))
            line.pop_back();

        if (line.rfind("remote ", 0) == 0) {
            std::istringstream iss(line);
            std::string tok, host, port;
            iss >> tok >> host >> port;
            if (!port.empty()) {
                int p = 0;
                for (char c : port) { if (c < '0' || c > '9') break; p = p * 10 + (c - '0'); if (p > 100000) break; }
                if (p > 0 && p <= 65535) return p;
            }
        }
    }
    return 443;
}

// ---------------------------------------------------------------------------
// Server list
// ---------------------------------------------------------------------------
struct Server {
    std::wstring host;
    std::wstring ip;
    int port = 443;
};

static std::vector<Server> ParseServers(const std::string& data) {
    std::vector<Server> out;
    out.reserve(128);
    auto rows = ParseCsvRows(data);
    for (auto& r : rows) {
        if (r.empty()) continue;
        const std::string& first = r[0];
        if (!first.empty() && first[0] == '*') continue;
        if (first.rfind("#HostName", 0) == 0) continue;
        if (r.size() < 15) continue;
        Server s;
        s.host = FromAcp(r[0]);
        s.ip   = FromAcp(r[1]);
        if (s.ip.empty()) continue;
        s.port = ExtractPortFromBase64(r[14]);
        out.push_back(std::move(s));
    }
    return out;
}

static bool LoadServers(std::vector<Server>& out, bool forceDownload) {
    if (forceDownload || !CsvCacheFresh()) {
        if (!DownloadCsv()) {
            Log(L"WARN", L"CSV download failed; using cached copy if available");
        }
    }
    std::string data;
    if (!ReadFileToString(CsvPath(), data)) {
        Log(L"ERROR", L"cannot read CSV file");
        out.clear();
        return false;
    }
    out = ParseServers(data);
    Log(L"INFO", L"loaded " + std::to_wstring(out.size()) + L" servers");
    return !out.empty();
}

// ---------------------------------------------------------------------------
// vpncmd execution (CreateProcess + pipe + timeout)
// ---------------------------------------------------------------------------
static bool RunVpnCmd(const std::wstring& args, std::wstring& output, DWORD timeoutMs) {
    output.clear();
    if (args.empty()) return false;

    std::wstring cmdLine = L"\"" + std::wstring(kVpnCmdPath) + L"\" /CLIENT localhost /CMD " + args;

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    HANDLE hRead = nullptr, hWrite = nullptr;
    if (!CreatePipe(&hRead, &hWrite, &sa, 65536)) return false;
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWrite;
    si.hStdError  = hWrite;
    si.hStdInput  = nullptr;

    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> buf(cmdLine.begin(), cmdLine.end());
    buf.push_back(0);

    BOOL ok = CreateProcessW(nullptr, buf.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(hWrite); // must close our copy so EOF propagates
    if (!ok) { CloseHandle(hRead); return false; }

    std::string acc;
    std::thread reader([&]() {
        char tmp[4096];
        DWORD rd = 0;
        while (ReadFile(hRead, tmp, (DWORD)sizeof(tmp), &rd, nullptr) && rd > 0) {
            acc.append(tmp, rd);
        }
    });

    DWORD w = WaitForSingleObject(pi.hProcess, timeoutMs);
    bool timedOut = (w == WAIT_TIMEOUT);
    if (timedOut) {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 2000);
    }

    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    reader.join();
    CloseHandle(hRead);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    output = FromAcp(acc);
    return !timedOut && exitCode == 0;
}

// ---------------------------------------------------------------------------
// vpncmd output parsing
// ---------------------------------------------------------------------------
static std::wstring ExtractSessionStatus(const std::wstring& out) {
    size_t pos = 0;
    while (pos < out.size()) {
        size_t eol = out.find(L'\n', pos);
        std::wstring line = (eol == std::wstring::npos) ? out.substr(pos) : out.substr(pos, eol - pos);
        pos = (eol == std::wstring::npos) ? out.size() : eol + 1;

        while (!line.empty() && (line.back() == L'\r' || line.back() == L' ' || line.back() == L'\t'))
            line.pop_back();

        std::wstring low = ToLower(line);
        size_t sp = low.find(L"session status");
        if (sp == std::wstring::npos) continue;

        size_t bar = line.find(L'|', sp);
        if (bar == std::wstring::npos) bar = line.find(L'|');
        if (bar == std::wstring::npos) continue;

        std::wstring val = line.substr(bar + 1);
        size_t a = val.find_first_not_of(L" \t\r");
        size_t b = val.find_last_not_of(L" \t\r");
        if (a == std::wstring::npos) return L"";
        return val.substr(a, b - a + 1);
    }
    return L"";
}

static std::wstring FirstLines(const std::wstring& text, int maxLines = 3) {
    std::wstring res;
    int count = 0;
    size_t pos = 0;
    while (pos < text.size() && count < maxLines) {
        size_t eol = text.find(L'\n', pos);
        std::wstring line = (eol == std::wstring::npos) ? text.substr(pos) : text.substr(pos, eol - pos);
        pos = (eol == std::wstring::npos) ? text.size() : eol + 1;
        while (!line.empty() && (line.back() == L'\r' || line.back() == L' ' || line.back() == L'\t'))
            line.pop_back();
        if (line.empty()) continue;

        std::wstring low = ToLower(line);
        if (low.find(L"softether") != std::wstring::npos) continue;
        if (low.find(L"copyright") != std::wstring::npos) continue;
        if (low.find(L"all rights reserved") != std::wstring::npos) continue;
        if (low.rfind(L"version ", 0) == 0) continue;
        if (low.rfind(L"compiled ", 0) == 0) continue;
        if (low.rfind(L"vpncmd ", 0) == 0) continue;
        if (low.rfind(L"vpn client>", 0) == 0) continue;

        if (!res.empty()) res += L" | ";
        res += line;
        ++count;
    }
    return res;
}

static bool StatusIsConnected(const std::wstring& st) {
    return ContainsCI(st, L"Connection Completed") || ContainsCI(st, L"Session Established");
}

static bool AccountExists() {
    std::wstring out;
    bool ok = RunVpnCmd(L"AccountGet " + std::wstring(kAccountName), out, kVpnCmdTimeout);
    if (!ok) return false;
    std::wstring low = ToLower(out);
    if (low.find(L"not found") != std::wstring::npos) return false;
    if (low.find(L"does not exist") != std::wstring::npos) return false;
    if (low.find(L"not exist") != std::wstring::npos) return false;
    return true;
}

static bool IsTunnelConnected() {
    std::wstring out;
    if (!RunVpnCmd(L"AccountStatusGet " + std::wstring(kAccountName), out, kVpnCmdTimeout))
        return false;
    return StatusIsConnected(ExtractSessionStatus(out));
}

// ---------------------------------------------------------------------------
// One server attempt
// ---------------------------------------------------------------------------
enum class AttemptResult { Success, Fail };

static std::wstring ServerSpec(const Server& s) {
    return s.ip + L":" + std::to_wstring(s.port);
}

static void DisconnectQuiet() {
    std::wstring o;
    RunVpnCmd(L"AccountDisconnect " + std::wstring(kAccountName), o, kVpnCmdTimeout);
}

static AttemptResult TryServer(size_t index, const Server& s) {
    using clock = std::chrono::steady_clock;
    auto t0 = clock::now();
    auto elapsed = [&]() { return std::chrono::duration<double>(clock::now() - t0).count(); };

    auto logResult = [&](const wchar_t* result) {
        std::wstring line = L"idx=" + std::to_wstring(index) +
                            L" " + ServerSpec(s) +
                            L" result=" + result +
                            L" elapsed=" + FormatDouble2(elapsed()) + L"s";
        Log(L"INFO", line);
    };

    // 1. Disconnect previous (ignore result)
    DisconnectQuiet();

    // 2. Ensure account exists (create once)
    if (!g_accountReady.load()) {
        if (AccountExists()) {
            g_accountReady = true;
        } else {
            std::wstring args = L"AccountCreate " + std::wstring(kAccountName) +
                                L" /SERVER:" + ServerSpec(s) +
                                L" /HUB:" + std::wstring(kHubName) +
                                L" /USERNAME:" + std::wstring(kUserName) +
                                L" /NICNAME:" + std::wstring(kNicName);
            std::wstring o;
            if (!RunVpnCmd(args, o, kVpnCmdTimeout)) {
                Log(L"ERROR", L"AccountCreate " + ServerSpec(s) + L": " + FirstLines(o));
                logResult(L"create-failed");
                return AttemptResult::Fail;
            }
            std::wstring o2;
            if (!RunVpnCmd(L"AccountAnonymousSet " + std::wstring(kAccountName), o2, kVpnCmdTimeout)) {
                Log(L"WARN", L"AccountAnonymousSet: " + FirstLines(o2));
            }
            g_accountReady = true;
        }
    }

    // 3. AccountSet to desired server
    {
        std::wstring args = L"AccountSet " + std::wstring(kAccountName) +
                            L" /SERVER:" + ServerSpec(s) +
                            L" /HUB:" + std::wstring(kHubName);
        std::wstring o;
        if (!RunVpnCmd(args, o, kVpnCmdTimeout)) {
            Log(L"ERROR", L"AccountSet " + ServerSpec(s) + L": " + FirstLines(o));
            logResult(L"set-failed");
            return AttemptResult::Fail;
        }
    }

    // 4. AccountGet confirmation (best effort)
    {
        std::wstring o;
        if (RunVpnCmd(L"AccountGet " + std::wstring(kAccountName), o, kVpnCmdTimeout)) {
            if (o.find(s.ip) == std::wstring::npos) {
                Log(L"WARN", L"AccountGet does not show " + s.ip + L" - continuing");
            }
        }
    }

    // 5. AccountConnect
    {
        std::wstring o;
        if (!RunVpnCmd(L"AccountConnect " + std::wstring(kAccountName), o, kVpnCmdTimeout)) {
            Log(L"ERROR", L"AccountConnect " + ServerSpec(s) + L": " + FirstLines(o));
            logResult(L"connect-failed");
            DisconnectQuiet();
            return AttemptResult::Fail;
        }
    }

    // 6. Poll status up to kPollCount times
    for (int i = 0; i < kPollCount; ++i) {
        Sleep(kPollSleepMs);
        std::wstring st;
        if (!RunVpnCmd(L"AccountStatusGet " + std::wstring(kAccountName), st, kVpnCmdTimeout))
            continue;
        std::wstring status = ExtractSessionStatus(st);
        if (status.empty()) continue;

        if (StatusIsConnected(status)) {
            logResult(L"success");
            return AttemptResult::Success;
        }
        if (ContainsCI(status, L"Retrying")) {
            logResult(L"retrying");
            DisconnectQuiet();
            return AttemptResult::Fail;
        }
        // still connecting -> continue polling
    }

    logResult(L"connecting-timeout");
    DisconnectQuiet();
    return AttemptResult::Fail;
}

// ---------------------------------------------------------------------------
// One full pass through the list
// ---------------------------------------------------------------------------
enum class PassResult { Connected, Exhausted, Offline, Stopped };

static PassResult RunOnePass(std::vector<Server>& servers, size_t& currentIdx) {
    for (; currentIdx < servers.size(); ++currentIdx) {
        if (g_stop.load()) return PassResult::Stopped;

        SaveIndex(currentIdx);
        const Server s = servers[currentIdx];
        AttemptResult r = TryServer(currentIdx, s);
        if (r == AttemptResult::Success) {
            SaveIndex(currentIdx);
            return PassResult::Connected;
        }
        // failure: loop advances the index
        SaveIndex(currentIdx + 1); // remember we already tried this one
    }
    return PassResult::Exhausted;
}

// ---------------------------------------------------------------------------
// Tray balloon notification
// ---------------------------------------------------------------------------
static void RemoveTrayIcon() {
    if (!g_msgWnd) return;
    if (!g_trayIconAdded.load()) return;
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = g_msgWnd;
    nid.uID  = 1;
    Shell_NotifyIconW(NIM_DELETE, &nid);
    g_trayIconAdded = false;
}

static void ShowTrayBalloon() {
    if (!g_msgWnd) return;

    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd   = g_msgWnd;
    nid.uID    = 1;
    nid.uFlags = NIF_INFO | NIF_ICON | NIF_MESSAGE;
    nid.uCallbackMessage = WM_APP + 2;
    nid.hIcon  = LoadIconW(nullptr, IDI_INFORMATION);
    nid.dwInfoFlags = NIIF_INFO;
    wcscpy_s(nid.szInfoTitle, L"VPN Gate Agent");
    wcscpy_s(nid.szInfo, L"No reachable relay. Retrying in 10 minutes.");
    nid.uTimeout = 10000;

    if (!g_trayIconAdded.load()) {
        if (Shell_NotifyIconW(NIM_ADD, &nid)) {
            g_trayIconAdded = true;
        } else {
            Shell_NotifyIconW(NIM_MODIFY, &nid);
        }
    } else {
        Shell_NotifyIconW(NIM_MODIFY, &nid);
    }

    // Auto-remove after a while
    SetTimer(g_msgWnd, 1, 20000, nullptr);
}

// ---------------------------------------------------------------------------
// Worker thread
// ---------------------------------------------------------------------------
static void WorkerThread() {
    int consecutiveExhausted = 0;

    while (!g_stop.load()) {
        // If tunnel is up, just keep-alive
        if (IsTunnelConnected()) {
            consecutiveExhausted = 0;
            WaitForSingleObject(g_wakeEvent, 30000);
            continue;
        }

        // Offline? Wait, do not advance index
        if (!HasInternet()) {
            Log(L"WARN", L"offline, waiting 30s");
            WaitForSingleObject(g_wakeEvent, 30000);
            continue;
        }

        // Load servers (reload from CSV after an exhausted pass)
        std::vector<Server> servers;
        bool force = (consecutiveExhausted > 0);
        if (!LoadServers(servers, force)) {
            WaitForSingleObject(g_wakeEvent, 30000);
            continue;
        }

        size_t idx = LoadIndex();
        if (idx >= servers.size()) { idx = 0; SaveIndex(0); }

        PassResult r = RunOnePass(servers, idx);

        if (r == PassResult::Stopped) break;

        if (r == PassResult::Connected) {
            consecutiveExhausted = 0;
            WaitForSingleObject(g_wakeEvent, 1000);
            continue;
        }

        if (r == PassResult::Offline) {
            WaitForSingleObject(g_wakeEvent, 30000);
            continue;
        }

        // Exhausted
        ++consecutiveExhausted;
        Log(L"WARN", L"pass exhausted (" + std::to_wstring(consecutiveExhausted) + L"/2)");

        if (consecutiveExhausted >= 2) {
            Log(L"WARN", L"two full passes with no success");
            ShowTrayBalloon();
            WaitForSingleObject(g_wakeEvent, 600000); // 10 minutes
            consecutiveExhausted = 0;
        }

        // Reset and try again with a fresh list next iteration
        SaveIndex(0);
        WaitForSingleObject(g_wakeEvent, 1000);
    }
}

// ---------------------------------------------------------------------------
// Hotkey handler
// ---------------------------------------------------------------------------
static void OnHotkey() {
    Log(L"INFO", L"hotkey Ctrl+Alt+S");
    if (g_stop.load()) return;

    // Signal the worker to check now.
    // The worker itself is single-threaded per pass, so no two passes overlap.
    if (g_wakeEvent) SetEvent(g_wakeEvent);
}

// ---------------------------------------------------------------------------
// Message-only window
// ---------------------------------------------------------------------------
static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_HOTKEY:
        if (w == 1) OnHotkey();
        return 0;
    case WM_TIMER:
        if (w == 1) {
            KillTimer(h, 1);
            RemoveTrayIcon();
        }
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        break;
    }
    return DefWindowProcW(h, m, w, l);
}

static bool CreateMsgWindow(HINSTANCE hInst) {
    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = L"VpnGateAgentMsgWnd";
    if (!RegisterClassExW(&wc)) return false;
    g_msgWnd = CreateWindowExW(0, wc.lpszClassName, L"", 0,
                               0, 0, 0, 0,
                               HWND_MESSAGE, nullptr, hInst, nullptr);
    return g_msgWnd != nullptr;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
int wmain() {
    // Hide any console that might be attached
    if (HWND cw = GetConsoleWindow()) ShowWindow(cw, SW_HIDE);

    // Single-instance guard
    HANDLE hMutex = CreateMutexW(nullptr, TRUE, L"Global\\VpnGateAgent_9F3A71C2");
    if (!hMutex) return 1;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return 0;
    }

    Log(L"INFO", L"agent starting (pid=" + std::to_wstring(GetCurrentProcessId()) + L")");

    HINSTANCE hInst = GetModuleHandleW(nullptr);
    if (!CreateMsgWindow(hInst)) {
        Log(L"ERROR", L"cannot create message window");
        CloseHandle(hMutex);
        return 1;
    }

    g_wakeEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!g_wakeEvent) {
        Log(L"ERROR", L"cannot create wake event");
        CloseHandle(hMutex);
        return 1;
    }

    if (!RegisterHotKey(g_msgWnd, 1, MOD_CONTROL | MOD_ALT | MOD_NOREPEAT, 'S')) {
        DWORD err = GetLastError();
        Log(L"WARN", L"RegisterHotKey failed, error=" + std::to_wstring(err));
    } else {
        Log(L"INFO", L"hotkey Ctrl+Alt+S registered");
    }

    std::thread worker(WorkerThread);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // Shutdown
    g_stop = true;
    if (g_wakeEvent) SetEvent(g_wakeEvent);
    if (worker.joinable()) worker.join();

    UnregisterHotKey(g_msgWnd, 1);
    RemoveTrayIcon();
    if (g_wakeEvent) CloseHandle(g_wakeEvent);
    CloseHandle(hMutex);
    Log(L"INFO", L"agent stopped");
    return 0;
}

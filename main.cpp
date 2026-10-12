// main.cpp
// VPN Gate background agent using SoftEther vpncmd.exe
// Build: cl /std:c++17 /W4 /EHsc /MT /DUNICODE /D_UNICODE main.cpp
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
#include <cwctype>
#include <cwchar>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------
static HWND                     g_msgWnd = nullptr;
static HANDLE                   g_wakeEvent = nullptr;
static std::atomic<bool>        g_stop{ false };
static std::mutex               g_attemptMutex;
static std::atomic<int>         g_failedPasses{ 0 };
static std::mutex               g_logMutex;

static const wchar_t* kCsvUrl = L"https://disaster-2ad1.firebaseapp.com/vpngate.csv";
static const wchar_t* kVpnCmdPath = L"C:\\Program Files\\SoftEther VPN Client\\vpncmd.exe";
static const wchar_t* kAccountName = L"vpngate_auto";

static void OnHotkey();
static LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------
static std::string ToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s((size_t)n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}

static std::wstring FromUtf8(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return {};
    std::wstring w((size_t)n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), n);
    return w;
}

static std::wstring FromAcp(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_ACP, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return {};
    std::wstring w((size_t)n, 0);
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), (int)s.size(), w.data(), n);
    return w;
}

static int ParseIntSimple(const std::string& s) {
    int v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') break;
        v = v * 10 + (c - '0');
        if (v > 1000000) break;
    }
    return v;
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------
static std::wstring GetExeDir() {
    wchar_t buf[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return L".";
    std::wstring p(buf, n);
    size_t pos = p.find_last_of(L"\\/");
    return (pos == std::wstring::npos) ? L"." : p.substr(0, pos);
}

static std::wstring LogPath()   { return GetExeDir() + L"\\vpnagent.log"; }
static std::wstring StatePath() { return GetExeDir() + L"\\state.txt"; }
static std::wstring CsvPath()   { return GetExeDir() + L"\\vpngate.csv"; }

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------
static void RotateLogIfNeeded(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad)) return;
    ULARGE_INTEGER sz;
    sz.LowPart = fad.nFileSizeLow;
    sz.HighPart = fad.nFileSizeHigh;
    if (sz.QuadPart > 256ULL * 1024ULL) {
        std::wstring oldp = path + L".old";
        DeleteFileW(oldp.c_str());
        MoveFileW(path.c_str(), oldp.c_str());
    }
}

static void Log(const wchar_t* level, const std::wstring& msg) {
    std::lock_guard<std::mutex> lk(g_logMutex);
    std::wstring path = LogPath();
    RotateLogIfNeeded(path);

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
// State (server index)
// ---------------------------------------------------------------------------
static size_t LoadIndex() {
    std::ifstream f(StatePath());
    if (!f) return 0;
    long long v = 0;
    f >> v;
    if (v < 0) v = 0;
    return (size_t)v;
}

static void SaveIndex(size_t v) {
    std::ofstream f(StatePath(), std::ios::trunc);
    if (!f) return;
    f << (unsigned long long)v;
}

// ---------------------------------------------------------------------------
// HTTP (WinINet)
// ---------------------------------------------------------------------------
static bool HttpRequest(const std::wstring& url, const wchar_t* verb,
                        std::string* out, DWORD timeoutMs, DWORD* statusOut) {
    HINTERNET hInet = InternetOpenW(L"VpnAgent/1.0", INTERNET_OPEN_TYPE_PRECONFIG,
                                    nullptr, nullptr, 0);
    if (!hInet) return false;

    InternetSetOptionW(hInet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeoutMs, sizeof(timeoutMs));
    InternetSetOptionW(hInet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeoutMs, sizeof(timeoutMs));
    InternetSetOptionW(hInet, INTERNET_OPTION_SEND_TIMEOUT,    &timeoutMs, sizeof(timeoutMs));

    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256] = {};
    wchar_t path[2048] = {};
    uc.lpszHostName = host; uc.dwHostNameLength = 255;
    uc.lpszUrlPath  = path; uc.dwUrlPathLength  = 2047;

    if (!InternetCrackUrlW(url.c_str(), (DWORD)url.size(), 0, &uc)) {
        InternetCloseHandle(hInet);
        return false;
    }

    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_KEEP_CONNECTION;
    if (uc.nScheme == INTERNET_SCHEME_HTTPS) {
        flags |= INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
    }

    HINTERNET hConn = InternetConnectW(hInet, host, uc.nPort, nullptr, nullptr,
                                       INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConn) { InternetCloseHandle(hInet); return false; }

    HINTERNET hReq = HttpOpenRequestW(hConn, verb, path, nullptr, nullptr, nullptr, flags, 0);
    if (!hReq) { InternetCloseHandle(hConn); InternetCloseHandle(hInet); return false; }

    bool ok = HttpSendRequestW(hReq, nullptr, 0, nullptr, 0) != FALSE;

    if (statusOut) {
        DWORD code = 0, len = sizeof(code);
        if (HttpQueryInfoW(hReq, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &code, &len, nullptr))
            *statusOut = code;
        else
            *statusOut = 0;
    }

    if (ok && out) {
        out->clear();
        char buf[8192];
        DWORD read = 0;
        while (InternetReadFile(hReq, buf, (DWORD)sizeof(buf), &read) && read > 0) {
            out->append(buf, read);
        }
    }

    InternetCloseHandle(hReq);
    InternetCloseHandle(hConn);
    InternetCloseHandle(hInet);
    return ok;
}

static bool HasInternet() {
    DWORD status = 0;
    bool ok = HttpRequest(kCsvUrl, L"HEAD", nullptr, 5000, &status);
    return ok && status != 0;
}

static bool CsvCacheFresh(DWORD maxAgeSec) {
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
    return age < (unsigned long long)maxAgeSec;
}

static bool DownloadCsv() {
    std::string data;
    DWORD status = 0;
    if (!HttpRequest(kCsvUrl, L"GET", &data, 30000, &status)) {
        Log(L"ERROR", L"CSV download failed (network)");
        return false;
    }
    if (status != 200 || data.empty()) {
        Log(L"ERROR", L"CSV download bad status " + std::to_wstring(status));
        return false;
    }
    HANDLE h = CreateFileW(CsvPath().c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        Log(L"ERROR", L"CSV cannot open for write");
        return false;
    }
    DWORD written = 0;
    BOOL ok = WriteFile(h, data.data(), (DWORD)data.size(), &written, nullptr);
    CloseHandle(h);
    if (!ok || written != data.size()) {
        Log(L"ERROR", L"CSV write incomplete");
        return false;
    }
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
// CSV parsing
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
            else if (c == '\n') { row.push_back(field); field.clear(); fieldStarted = false; rows.push_back(row); row.clear(); }
            else if (c == '\r') { /* skip */ }
            else { field.push_back(c); fieldStarted = true; }
        }
    }
    if (!field.empty() || !row.empty()) { row.push_back(field); rows.push_back(row); }
    return rows;
}

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
                int p = ParseIntSimple(port);
                if (p > 0 && p <= 65535) return p;
            }
        }
    }
    return 443;
}

struct Server {
    std::wstring host;
    std::wstring ip;
    int port = 443;
};

static std::vector<Server> ParseServers(const std::string& data) {
    std::vector<Server> out;
    auto rows = ParseCsvRows(data);
    for (auto& r : rows) {
        if (r.empty()) continue;
        const std::string& first = r[0];
        if (!first.empty() && first[0] == '*') continue;
        if (first.rfind("#HostName", 0) == 0) continue;
        if (r.size() < 15) continue;
        Server s;
        s.host = FromUtf8(r[0]);
        s.ip   = FromUtf8(r[1]);
        if (s.ip.empty()) continue;
        s.port = ExtractPortFromBase64(r[14]);
        out.push_back(std::move(s));
    }
    return out;
}

static std::vector<Server> LoadServers(bool forceDownload) {
    bool need = forceDownload || !CsvCacheFresh(45 * 60);
    if (need) {
        if (!DownloadCsv()) {
            Log(L"WARN", L"download failed; using cached CSV if any");
        }
    }
    std::string data;
    if (!ReadFileToString(CsvPath(), data)) {
        Log(L"ERROR", L"cannot read CSV file");
        return {};
    }
    auto servers = ParseServers(data);
    Log(L"INFO", L"loaded " + std::to_wstring(servers.size()) + L" servers");
    return servers;
}

// ---------------------------------------------------------------------------
// vpncmd execution
// ---------------------------------------------------------------------------
static bool RunVpnCmd(const std::wstring& args, std::wstring& output, DWORD timeoutMs) {
    output.clear();
    if (args.empty()) return false;

    std::wstring cmdLine = L"\"" + std::wstring(kVpnCmdPath) + L"\" " + args;

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    HANDLE hRead = nullptr, hWrite = nullptr;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return false;
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
    CloseHandle(hWrite);
    if (!ok) { CloseHandle(hRead); return false; }

    std::string acc;
    DWORD start = GetTickCount();
    bool timedOut = false;
    bool exited = false;

    for (;;) {
        DWORD avail = 0;
        if (PeekNamedPipe(hRead, nullptr, 0, nullptr, &avail, nullptr) && avail > 0) {
            char tmp[4096];
            DWORD toRead = (avail < (DWORD)sizeof(tmp)) ? avail : (DWORD)sizeof(tmp);
            DWORD rd = 0;
            if (ReadFile(hRead, tmp, toRead, &rd, nullptr) && rd > 0)
                acc.append(tmp, rd);
        } else {
            DWORD w = WaitForSingleObject(pi.hProcess, 50);
            if (w == WAIT_OBJECT_0) {
                for (;;) {
                    DWORD a2 = 0;
                    if (!PeekNamedPipe(hRead, nullptr, 0, nullptr, &a2, nullptr) || a2 == 0) break;
                    char tmp[4096];
                    DWORD toRead = (a2 < (DWORD)sizeof(tmp)) ? a2 : (DWORD)sizeof(tmp);
                    DWORD rd = 0;
                    if (!ReadFile(hRead, tmp, toRead, &rd, nullptr) || rd == 0) break;
                    acc.append(tmp, rd);
                }
                exited = true;
                break;
            }
        }
        if (GetTickCount() - start > timeoutMs) { timedOut = true; break; }
    }

    if (timedOut) {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 2000);
    }

    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hRead);

    output = FromAcp(acc);
    if (timedOut) return false;
    return exited && exitCode == 0;
}

// ---------------------------------------------------------------------------
// vpncmd output helpers
// ---------------------------------------------------------------------------
static std::wstring ShortErr(const std::wstring& out) {
    std::wstring res;
    int count = 0;
    size_t pos = 0;
    while (pos < out.size() && count < 3) {
        size_t e = out.find(L'\n', pos);
        std::wstring line = (e == std::wstring::npos) ? out.substr(pos) : out.substr(pos, e - pos);
        pos = (e == std::wstring::npos) ? out.size() : e + 1;
        while (!line.empty() && (line.back() == L'\r' || line.back() == L' ' || line.back() == L'\t'))
            line.pop_back();
        if (line.empty()) continue;
        std::wstring low;
        low.reserve(line.size());
        for (wchar_t c : line) low.push_back((wchar_t)towlower(c));
        if (low.find(L"vpncmd command") != std::wstring::npos) continue;
        if (low.find(L"softether vpn command line") != std::wstring::npos) continue;
        if (low.rfind(L"version ", 0) == 0) continue;
        res += line;
        res += L" | ";
        count++;
    }
    return res;
}

static bool StatusConnected(const std::wstring& out) {
    size_t pos = 0;
    while (pos <= out.size()) {
        size_t e = out.find(L'\n', pos);
        std::wstring line = (e == std::wstring::npos) ? out.substr(pos) : out.substr(pos, e - pos);
        pos = (e == std::wstring::npos) ? out.size() + 1 : e + 1;

        size_t bar = line.find(L'|');
        if (bar == std::wstring::npos) continue;

        std::wstring left  = line.substr(0, bar);
        std::wstring right = line.substr(bar + 1);

        auto trim = [](std::wstring& s) {
            size_t a = s.find_first_not_of(L" \t\r");
            size_t b = s.find_last_not_of(L" \t\r");
            if (a == std::wstring::npos) { s.clear(); return; }
            s = s.substr(a, b - a + 1);
        };
        trim(left);
        trim(right);

        std::wstring llow, rlow;
        llow.reserve(left.size());
        rlow.reserve(right.size());
        for (wchar_t c : left)  llow.push_back((wchar_t)towlower(c));
        for (wchar_t c : right) rlow.push_back((wchar_t)towlower(c));

        if (llow.find(L"status") != std::wstring::npos && rlow == L"connected")
            return true;
    }
    return false;
}

static bool IsTunnelConnected() {
    std::wstring out;
    if (!RunVpnCmd(L"/CLIENT localhost /CMD AccountStatusGet " + std::wstring(kAccountName), out, 8000))
        return false;
    return StatusConnected(out);
}

// ---------------------------------------------------------------------------
// Connection attempt for one server
// ---------------------------------------------------------------------------
enum class AttemptResult { Success, Fail, Timeout };

static AttemptResult ConnectServer(const std::wstring& ip, int port) {
    using clock = std::chrono::steady_clock;
    auto start = clock::now();
    const long long TOTAL_MS = 25000;

    auto remaining = [&]() -> DWORD {
        auto el = std::chrono::duration_cast<std::chrono::milliseconds>(clock::now() - start).count();
        long long r = TOTAL_MS - el;
        if (r < 0) r = 0;
        return (DWORD)r;
    };

    auto disconnect = [&]() {
        std::wstring tmp;
        RunVpnCmd(L"/CLIENT localhost /CMD AccountDisconnect " + std::wstring(kAccountName), tmp, 5000);
    };

    std::wstring out;
    std::wstring spec = ip + L":" + std::to_wstring(port);
    std::wstring acct = kAccountName;

    // 1. delete previous account (ignore failure)
    RunVpnCmd(L"/CLIENT localhost /CMD AccountDelete " + acct, out, 8000);

    // 2. create account
    {
        std::wstring args = L"/CLIENT localhost /CMD AccountCreate " + acct +
                            L" /SERVER:" + spec +
                            L" /HUB:VPNGATE /USERNAME:vpn /NICNAME:VPN";
        DWORD t = remaining();
        if (t > 10000) t = 10000;
        if (t == 0 || !RunVpnCmd(args, out, t)) {
            Log(L"ERROR", L"AccountCreate " + spec + L": " + ShortErr(out));
            disconnect();
            return AttemptResult::Fail;
        }
    }

    // 3. anonymous authentication
    {
        std::wstring o1;
        DWORD t = remaining();
        if (t > 8000) t = 8000;
        if (t == 0 || !RunVpnCmd(L"/CLIENT localhost /CMD AccountAnonymousSet " + acct, o1, t)) {
            std::wstring o2;
            DWORD t2 = remaining();
            if (t2 > 8000) t2 = 8000;
            if (t2 == 0 || !RunVpnCmd(L"/CLIENT localhost /CMD AccountPasswordSet " + acct +
                                      L" /PASSWORD: /TYPE:anonymous", o2, t2)) {
                Log(L"WARN", L"anonymous set failed: " + ShortErr(o1) + L" || " + ShortErr(o2));
                // continue; some builds may still connect
            }
        }
    }

    // 4. connect
    {
        DWORD t = remaining();
        if (t > 10000) t = 10000;
        std::wstring o;
        if (t == 0 || !RunVpnCmd(L"/CLIENT localhost /CMD AccountConnect " + acct, o, t)) {
            Log(L"ERROR", L"AccountConnect " + spec + L": " + ShortErr(o));
            disconnect();
            return AttemptResult::Fail;
        }
    }

    // 5. poll status
    for (;;) {
        DWORD rem = remaining();
        if (rem == 0) break;
        Sleep(rem > 1500 ? 1500 : rem);
        rem = remaining();
        if (rem == 0) break;
        DWORD t = rem > 8000 ? 8000 : rem;
        std::wstring st;
        if (RunVpnCmd(L"/CLIENT localhost /CMD AccountStatusGet " + acct, st, t)) {
            if (StatusConnected(st)) {
                Log(L"INFO", L"connected " + spec);
                return AttemptResult::Success;
            }
        }
    }

    Log(L"WARN", L"timeout " + spec);
    disconnect();
    return AttemptResult::Timeout;
}

// ---------------------------------------------------------------------------
// Tray balloon
// ---------------------------------------------------------------------------
static void NotifyTrayBalloon() {
    if (!g_msgWnd) return;
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = g_msgWnd;
    nid.uID = 1;
    nid.uFlags = NIF_INFO | NIF_ICON | NIF_MESSAGE;
    nid.uCallbackMessage = WM_APP + 2;
    nid.hIcon = LoadIconW(nullptr, IDI_INFORMATION);
    nid.dwInfoFlags = NIIF_INFO;
    wcscpy_s(nid.szInfoTitle, L"VPN Agent");
    wcscpy_s(nid.szInfo, L"VPN Gate: no server reachable. Retrying in 10 minutes.");
    nid.uTimeout = 10000;

    if (!Shell_NotifyIconW(NIM_ADD, &nid)) {
        Shell_NotifyIconW(NIM_MODIFY, &nid);
    }
    SetTimer(g_msgWnd, 1, 15000, nullptr);
}

// ---------------------------------------------------------------------------
// Window / hotkey
// ---------------------------------------------------------------------------
static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_HOTKEY:
        if (w == 1) OnHotkey();
        return 0;
    case WM_TIMER:
        if (w == 1) {
            KillTimer(h, 1);
            NOTIFYICONDATAW nid{};
            nid.cbSize = sizeof(nid);
            nid.hWnd = h;
            nid.uID = 1;
            Shell_NotifyIconW(NIM_DELETE, &nid);
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
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"VpnAgentMsgWnd";
    if (!RegisterClassExW(&wc)) return false;
    g_msgWnd = CreateWindowExW(0, wc.lpszClassName, L"", 0, 0, 0, 0, 0,
                               HWND_MESSAGE, nullptr, hInst, nullptr);
    return g_msgWnd != nullptr;
}

// ---------------------------------------------------------------------------
// Attempt cycle / worker
// ---------------------------------------------------------------------------
enum class CycleResult { Connected, Exhausted, Busy, Offline, NoServers };

static CycleResult AttemptCycle() {
    std::unique_lock<std::mutex> lk(g_attemptMutex, std::try_to_lock);
    if (!lk.owns_lock()) return CycleResult::Busy;

    if (IsTunnelConnected()) return CycleResult::Connected;
    if (!HasInternet())      return CycleResult::Offline;

    std::vector<Server> servers = LoadServers(false);
    if (servers.empty()) servers = LoadServers(true);
    if (servers.empty()) return CycleResult::NoServers;

    size_t idx = LoadIndex();
    if (idx >= servers.size()) idx = 0;

    for (; idx < servers.size(); ++idx) {
        if (g_stop.load()) return CycleResult::Exhausted;
        if (!HasInternet()) return CycleResult::Offline;

        SaveIndex(idx);
        Log(L"INFO", L"try " + servers[idx].ip + L":" + std::to_wstring(servers[idx].port));

        AttemptResult r = ConnectServer(servers[idx].ip, servers[idx].port);
        if (r == AttemptResult::Success) {
            g_failedPasses = 0;
            return CycleResult::Connected;
        }
    }

    SaveIndex(0);
    LoadServers(true);
    return CycleResult::Exhausted;
}

static void WorkerThread() {
    for (;;) {
        if (g_stop.load()) return;

        CycleResult r = AttemptCycle();
        switch (r) {
        case CycleResult::Connected:
            WaitForSingleObject(g_wakeEvent, 10000);
            break;
        case CycleResult::Busy:
            WaitForSingleObject(g_wakeEvent, 1000);
            break;
        case CycleResult::Offline:
            WaitForSingleObject(g_wakeEvent, 30000);
            break;
        case CycleResult::NoServers:
            WaitForSingleObject(g_wakeEvent, 60000);
            break;
        case CycleResult::Exhausted: {
            int fp = ++g_failedPasses;
            if (fp >= 2) {
                g_failedPasses = 0;
                Log(L"WARN", L"two full passes without success; waiting 10 minutes");
                NotifyTrayBalloon();
                WaitForSingleObject(g_wakeEvent, 600000);
            } else {
                WaitForSingleObject(g_wakeEvent, 2000);
            }
            break;
        }
        }
    }
}

static void OnHotkey() {
    Log(L"INFO", L"hotkey Ctrl+Alt+S");
    if (g_stop.load()) return;
    if (IsTunnelConnected()) {
        Log(L"INFO", L"hotkey: already connected");
        return;
    }
    std::thread([] {
        AttemptCycle();
    }).detach();
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
int wmain() {
    // Hide console if any (background agent)
    if (HWND cw = GetConsoleWindow()) ShowWindow(cw, SW_HIDE);

    HANDLE hMutex = CreateMutexW(nullptr, TRUE, L"Global\\VpnGateAgent_9F3A71C2");
    if (!hMutex) return 1;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return 0;
    }

    Log(L"INFO", L"agent starting");

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
        Log(L"WARN", L"RegisterHotKey failed");
    }

    std::thread worker(WorkerThread);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    g_stop = true;
    if (g_wakeEvent) SetEvent(g_wakeEvent);
    if (worker.joinable()) worker.join();

    UnregisterHotKey(g_msgWnd, 1);
    if (g_wakeEvent) CloseHandle(g_wakeEvent);
    CloseHandle(hMutex);
    Log(L"INFO", L"agent stopped");
    return 0;
}

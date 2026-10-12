// ============================================================================
//  VPN Gate auto-connector for SoftEther VPN Client
//  - Win32 only, no GUI, no console window, no keystroke injection
//  - Runs as a resident background process (Task Scheduler, logon, highest priv)
//  - Ctrl+Alt+S hotkey, tray balloon on total failure, rolling log file
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <winhttp.h>
#include <shellapi.h>

#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <cstdio>
#include <cstdlib>
#include <sstream>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")

// ---------------------------------------------------------------------------
//  Configuration
// ---------------------------------------------------------------------------
static const std::wstring kCsvUrl  = L"https://disaster-2ad1a.firebaseapp.com/vpngate.csv";
static const std::wstring kVpnCmd  = L"C:\\Program Files\\SoftEther VPN Client\\vpncmd.exe";
static const std::wstring kAccount = L"vpngate_auto";
static const std::wstring kHub     = L"VPNGATE";
static const std::wstring kUser    = L"vpn";
static const std::wstring kPass    = L"vpn";
static const std::wstring kNic     = L"VPN";

static const DWORD kCsvMaxAgeMin   = 45;      // cache lifetime
static const DWORD kConnectTimeout = 20000;   // vpncmd AccountConnect
static const DWORD kVerifyTimeout  = 8000;    // status poll after connect
static const DWORD kAttemptTimeout = 28000;   // whole attempt bound
static const DWORD kRetryWaitMs    = 10 * 60 * 1000;  // silent retry after failure

// ---------------------------------------------------------------------------
//  Globals
// ---------------------------------------------------------------------------
static std::wstring      g_dir;
static HWND              g_hwnd    = NULL;
static HANDLE            g_wake    = NULL;   // auto-reset: "something happened"
static std::atomic<bool> g_stop(false);
static std::atomic<bool> g_hotkey(false);
static std::mutex        g_logMx;

// ---------------------------------------------------------------------------
//  Small helpers
// ---------------------------------------------------------------------------
static std::string WideToUtf8(const std::wstring& w)
{
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), NULL, 0, NULL, NULL);
    std::string s(n, 0);
    if (n) WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, NULL, NULL);
    return s;
}

static std::wstring Utf8ToWide(const std::string& s)
{
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), NULL, 0);
    std::wstring w(n, 0);
    if (n) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

static std::wstring TimeStamp()
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buf[64];
    swprintf_s(buf, L"%04d-%02d-%02d %02d:%02d:%02d",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

static ULONGLONG FileTimeToU64(const FILETIME& ft)
{
    ULARGE_INTEGER u;
    u.LowPart  = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}

// ---------------------------------------------------------------------------
//  Logging (rotating, ~256 KB)
// ---------------------------------------------------------------------------
static void Log(const std::wstring& msg)
{
    std::lock_guard<std::mutex> lk(g_logMx);
    if (g_dir.empty()) return;

    std::wstring path = g_dir + L"vpnagent.log";

    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad))
    {
        ULARGE_INTEGER sz;
        sz.LowPart  = fad.nFileSizeLow;
        sz.HighPart = fad.nFileSizeHigh;
        if (sz.QuadPart > 256 * 1024)
        {
            std::wstring oldPath = g_dir + L"vpnagent.old.log";
            DeleteFileW(oldPath.c_str());
            MoveFileW(path.c_str(), oldPath.c_str());
        }
    }

    std::wstring line = TimeStamp() + L"  " + msg + L"\r\n";
    std::string  u8   = WideToUtf8(line);

    FILE* f = NULL;
    if (_wfopen_s(&f, path.c_str(), L"ab") == 0 && f)
    {
        fwrite(u8.data(), 1, u8.size(), f);
        fclose(f);
    }
}

// ---------------------------------------------------------------------------
//  File helpers
// ---------------------------------------------------------------------------
static bool ReadFileAll(const std::wstring& path, std::string& out)
{
    out.clear();
    FILE* f = NULL;
    if (_wfopen_s(&f, path.c_str(), L"rb") != 0 || !f) return false;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n > 0)
    {
        out.resize((size_t)n);
        size_t got = fread(&out[0], 1, (size_t)n, f);
        out.resize(got);
    }
    fclose(f);
    return true;
}

static bool WriteFileAll(const std::wstring& path, const std::string& data)
{
    FILE* f = NULL;
    if (_wfopen_s(&f, path.c_str(), L"wb") != 0 || !f) return false;
    if (!data.empty()) fwrite(data.data(), 1, data.size(), f);
    fclose(f);
    return true;
}

// ---------------------------------------------------------------------------
//  Base64
// ---------------------------------------------------------------------------
static int B64Val(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static std::string Base64Decode(const std::string& in)
{
    std::string out;
    out.reserve(in.size() * 3 / 4 + 4);
    int buf = 0, bits = 0;
    for (size_t i = 0; i < in.size(); ++i)
    {
        unsigned char c = (unsigned char)in[i];
        if (c == '=') break;
        int v = B64Val(c);
        if (v < 0) continue;             // skip CR/LF/space
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8)
        {
            bits -= 8;
            out.push_back((char)((buf >> bits) & 0xFF));
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
//  WinHTTP
// ---------------------------------------------------------------------------
static bool HttpRequest(const std::wstring& url, const wchar_t* verb,
                        std::string* out, DWORD timeoutMs, DWORD* statusOut)
{
    if (statusOut) *statusOut = 0;

    URL_COMPONENTS uc;
    ZeroMemory(&uc, sizeof(uc));
    uc.dwStructSize      = sizeof(uc);
    uc.dwSchemeLength    = (DWORD)-1;
    uc.dwHostNameLength  = (DWORD)-1;
    uc.dwUrlPathLength   = (DWORD)-1;
    uc.dwExtraInfoLength = (DWORD)-1;

    if (!WinHttpCrackUrl(url.c_str(), (DWORD)url.size(), 0, &uc)) return false;

    std::wstring host(uc.lpszHostName, uc.dwHostNameLength);
    std::wstring path(uc.lpszUrlPath, uc.dwUrlPathLength);
    if (uc.dwExtraInfoLength)
        path.append(uc.lpszExtraInfo, uc.dwExtraInfoLength);
    bool https = (uc.nScheme == INTERNET_SCHEME_HTTPS);

    HINTERNET hSession = WinHttpOpen(L"VpnGateAgent/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    WinHttpSetTimeouts(hSession, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

    DWORD retries = 1;
    WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_RETRIES, &retries, sizeof(retries));

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), uc.nPort, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, verb, path.c_str(), NULL,
                                            WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            https ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest)
    {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_REDIRECT_POLICY, &policy, sizeof(policy));

    BOOL ok = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                 WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (ok) ok = WinHttpReceiveResponse(hRequest, NULL);

    DWORD status = 0;
    if (ok)
    {
        DWORD len = sizeof(status);
        WinHttpQueryHeaders(hRequest,
                            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &len,
                            WINHTTP_NO_HEADER_INDEX);
    }
    if (statusOut) *statusOut = status;

    bool result = ok && status >= 200 && status < 300;

    if (result && out)
    {
        out->clear();
        for (;;)
        {
            DWORD avail = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &avail) || avail == 0) break;
            std::string buf(avail, 0);
            DWORD read = 0;
            if (!WinHttpReadData(hRequest, &buf[0], avail, &read) || read == 0) break;
            out->append(buf.data(), read);
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return result;
}

// Light internet probe: HEAD on the CSV host. Any HTTP status means "online".
static bool HasInternet()
{
    DWORD status = 0;
    HttpRequest(kCsvUrl, L"HEAD", NULL, 5000, &status);
    return status != 0;
}

// ---------------------------------------------------------------------------
//  vpncmd wrapper
// ---------------------------------------------------------------------------
static bool RunVpnCmd(const std::wstring& args, std::string& output, DWORD timeoutMs)
{
    output.clear();

    if (GetFileAttributesW(kVpnCmd.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        output = "vpncmd.exe not found";
        return false;
    }

    std::wstring cmd = L"\"" + kVpnCmd + L"\" localhost /CLIENT /CMD " + args;

    SECURITY_ATTRIBUTES sa;
    sa.nLength        = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    HANDLE rd = NULL, wr = NULL;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return false;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    HANDLE hNul = CreateFileW(L"NUL", GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              &sa, OPEN_EXISTING, 0, NULL);

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput  = wr;
    si.hStdError   = wr;
    si.hStdInput   = hNul;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    std::vector<wchar_t> buf(cmd.begin(), cmd.end());
    buf.push_back(0);

    BOOL created = CreateProcessW(NULL, buf.data(), NULL, NULL, TRUE,
                                  CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    CloseHandle(wr);
    if (hNul) CloseHandle(hNul);

    if (!created)
    {
        CloseHandle(rd);
        return false;
    }

    DWORD start = GetTickCount();
    bool  killed = false;

    for (;;)
    {
        DWORD avail = 0;
        if (PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL) && avail > 0)
        {
            char  tmp[4096];
            DWORD got = 0;
            DWORD toRead = avail > sizeof(tmp) ? (DWORD)sizeof(tmp) : avail;
            if (ReadFile(rd, tmp, toRead, &got, NULL) && got > 0)
                output.append(tmp, got);
            continue;
        }

        if (WaitForSingleObject(pi.hProcess, 50) == WAIT_OBJECT_0)
        {
            // drain remaining
            for (;;)
            {
                DWORD a2 = 0;
                if (!PeekNamedPipe(rd, NULL, 0, NULL, &a2, NULL) || a2 == 0) break;
                char  tmp[4096];
                DWORD got = 0;
                DWORD toRead = a2 > sizeof(tmp) ? (DWORD)sizeof(tmp) : a2;
                if (!ReadFile(rd, tmp, toRead, &got, NULL) || got == 0) break;
                output.append(tmp, got);
            }
            break;
        }

        if (GetTickCount() - start > timeoutMs)
        {
            TerminateProcess(pi.hProcess, 1);
            killed = true;
            break;
        }
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(rd);
    return !killed;
}

static bool CmdSucceeded(const std::string& out)
{
    return out.find("completed successfully") != std::string::npos;
}

// ---------------------------------------------------------------------------
//  Connection state
// ---------------------------------------------------------------------------
static bool IsAccountConnected()
{
    std::string out;
    if (!RunVpnCmd(L"AccountList", out, 15000)) return false;

    const std::string acct = WideToUtf8(kAccount);
    size_t pos = 0;
    while ((pos = out.find(acct, pos)) != std::string::npos)
    {
        size_t eol  = out.find('\n', pos);
        std::string line = out.substr(pos, (eol == std::string::npos ? out.size() : eol) - pos);

        if (line.find("Not Connected") != std::string::npos)
        {
            pos += acct.size();
            continue;
        }
        if (line.find("Connected") != std::string::npos)
            return true;

        pos += acct.size();
    }
    return false;
}

static bool DisconnectAccount()
{
    std::string out;
    RunVpnCmd(L"AccountDisconnect " + kAccount, out, 15000);
    return true;
}

// Creates the account (delete + create). Tries the explicit anonymous auth
// type first; if the vpncmd build rejects the option, retries without it.
static bool CreateAccount(const std::string& ip, int port)
{
    std::string out;
    RunVpnCmd(L"AccountDelete " + kAccount, out, 15000);   // ignore result

    std::wstring server = Utf8ToWide(ip) + L":" + std::to_wstring(port);

    std::wstring base =
        L"AccountCreate " + kAccount +
        L" /SERVER:"   + server +
        L" /HUB:"      + kHub +
        L" /USERNAME:" + kUser +
        L" /PASSWORD:" + kPass +
        L" /NICNAME:"  + kNic;

    std::string o1;
    RunVpnCmd(base + L" /AUTHTYPE:anonymous", o1, 20000);
    if (CmdSucceeded(o1)) return true;

    std::string o2;
    RunVpnCmd(base, o2, 20000);
    if (CmdSucceeded(o2)) return true;

    Log(L"AccountCreate failed: " + Utf8ToWide(o2));
    return false;
}

// ---------------------------------------------------------------------------
//  CSV handling
// ---------------------------------------------------------------------------
struct Server
{
    std::string ip;
    std::string country;
    int         port;
};

static std::vector<std::string> SplitCsvLine(const std::string& line)
{
    std::vector<std::string> f;
    std::string cur;
    bool inq = false;

    for (size_t i = 0; i < line.size(); ++i)
    {
        char c = line[i];
        if (inq)
        {
            if (c == '"')
            {
                if (i + 1 < line.size() && line[i + 1] == '"') { cur += '"'; ++i; }
                else inq = false;
            }
            else cur += c;
        }
        else
        {
            if (c == '"')      inq = true;
            else if (c == ',') { f.push_back(cur); cur.clear(); }
            else               cur += c;
        }
    }
    f.push_back(cur);
    return f;
}

static int ExtractPort(const std::string& b64)
{
    if (b64.empty()) return 443;

    std::string cfg = Base64Decode(b64);
    std::istringstream iss(cfg);
    std::string line;

    while (std::getline(iss, line))
    {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t'))
            line.pop_back();
        size_t p = line.find_first_not_of(" \t");
        if (p == std::string::npos) continue;
        line = line.substr(p);

        if (line.rfind("remote", 0) == 0 &&
            (line.size() == 6 || line[6] == ' ' || line[6] == '\t'))
        {
            std::istringstream ls(line);
            std::string kw, ip, port;
            ls >> kw >> ip >> port;
            if (!port.empty())
            {
                int v = atoi(port.c_str());
                if (v > 0 && v < 65536) return v;
            }
        }
    }
    return 443;
}

static bool ParseCsv(const std::string& data, std::vector<Server>& servers)
{
    servers.clear();
    std::istringstream iss(data);
    std::string line;

    while (std::getline(iss, line))
    {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        if (line[0] == '*' || line[0] == '#') continue;   // comments / header

        std::vector<std::string> f = SplitCsvLine(line);
        if (f.size() < 15) continue;

        Server s;
        s.ip      = f[1];
        s.country = f[5];
        if (s.ip.empty()) continue;

        s.port = ExtractPort(f[14]);
        servers.push_back(s);
    }
    return !servers.empty();
}

static bool CsvAgeMinutes(DWORD& outMinutes)
{
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW((g_dir + L"vpngate.csv").c_str(),
                              GetFileExInfoStandard, &fad))
        return false;

    FILETIME nowFt;
    GetSystemTimeAsFileTime(&nowFt);

    ULONGLONG now  = FileTimeToU64(nowFt);
    ULONGLONG then = FileTimeToU64(fad.ftLastWriteTime);
    if (now <= then) { outMinutes = 0; return true; }

    outMinutes = (DWORD)((now - then) / (60ULL * 10000000ULL));
    return true;
}

static bool DownloadCsv()
{
    std::string data;
    DWORD status = 0;

    if (!HttpRequest(kCsvUrl, L"GET", &data, 20000, &status))
    {
        Log(L"CSV download failed (http status " + std::to_wstring(status) + L")");
        return false;
    }
    if (data.size() < 256 || data.find("OpenVPN_ConfigData_Base64") == std::string::npos)
    {
        Log(L"CSV download looks invalid (size " + std::to_wstring(data.size()) + L")");
        return false;
    }

    std::wstring tmp = g_dir + L"vpngate.csv.tmp";
    std::wstring dst = g_dir + L"vpngate.csv";

    if (!WriteFileAll(tmp, data))
    {
        Log(L"Cannot write CSV cache");
        return false;
    }
    if (!MoveFileExW(tmp.c_str(), dst.c_str(), MOVEFILE_REPLACE_EXISTING))
    {
        DeleteFileW(tmp.c_str());
        Log(L"Cannot replace CSV cache");
        return false;
    }

    Log(L"CSV downloaded (" + std::to_wstring(data.size()) + L" bytes)");
    return true;
}

static bool EnsureCsv(std::vector<Server>& servers, bool force)
{
    DWORD age = 0;
    bool  haveCache = CsvAgeMinutes(age);
    bool  stale     = !haveCache || age >= kCsvMaxAgeMin;

    if (force || stale)
        DownloadCsv();

    std::string data;
    if (!ReadFileAll(g_dir + L"vpngate.csv", data))
    {
        Log(L"No CSV cache available");
        return false;
    }
    if (!ParseCsv(data, servers))
    {
        Log(L"CSV parse produced no servers");
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
//  Index state file
// ---------------------------------------------------------------------------
static int LoadIndex()
{
    std::string s;
    if (!ReadFileAll(g_dir + L"state.txt", s)) return 0;
    int v = atoi(s.c_str());
    return v < 0 ? 0 : v;
}

static void SaveIndex(int idx)
{
    WriteFileAll(g_dir + L"state.txt", std::to_string(idx));
}

// ---------------------------------------------------------------------------
//  Tray notification
// ---------------------------------------------------------------------------
static void NotifyTray(const std::wstring& msg)
{
    if (!g_hwnd) return;

    NOTIFYICONDATAW nid;
    ZeroMemory(&nid, sizeof(nid));
    nid.cbSize = sizeof(nid);
    nid.hWnd   = g_hwnd;
    nid.uID    = 1;
    nid.uFlags = NIF_ICON | NIF_TIP | NIF_INFO;
    nid.hIcon  = LoadIconW(NULL, IDI_APPLICATION);
    wcscpy_s(nid.szTip, L"VPN Gate Agent");
    wcscpy_s(nid.szInfoTitle, L"VPN Gate Agent");
    wcsncpy_s(nid.szInfo, msg.c_str(), _TRUNCATE);
    nid.dwInfoFlags = NIIF_INFO;
    nid.uTimeout    = 10000;

    if (Shell_NotifyIconW(NIM_ADD, &nid))
        Shell_NotifyIconW(NIM_MODIFY, &nid);
}

// ---------------------------------------------------------------------------
//  Interruptible wait
// ---------------------------------------------------------------------------
static bool WaitWake(DWORD ms)
{
    return WaitForSingleObject(g_wake, ms) == WAIT_OBJECT_0;
}

// ---------------------------------------------------------------------------
//  Single connection attempt
// ---------------------------------------------------------------------------
static bool TryConnect(const Server& s)
{
    Log(L"Trying " + Utf8ToWide(s.ip) + L":" + std::to_wstring(s.port) +
        L" (" + Utf8ToWide(s.country) + L")");

    DisconnectAccount();

    if (!CreateAccount(s.ip, s.port))
        return false;

    std::string out;
    RunVpnCmd(L"AccountConnect " + kAccount, out, kConnectTimeout);

    DWORD start = GetTickCount();
    for (;;)
    {
        if (IsAccountConnected()) return true;
        if (GetTickCount() - start > kVerifyTimeout) break;
        Sleep(1000);
    }

    DisconnectAccount();
    Log(L"Attempt failed for " + Utf8ToWide(s.ip));
    return false;
}

// ---------------------------------------------------------------------------
//  Full connect cycle (all servers, up to two passes)
// ---------------------------------------------------------------------------
static void ConnectCycle()
{
    std::vector<Server> servers;
    if (!EnsureCsv(servers, false))
    {
        Log(L"Cannot obtain server list, retrying in 60 s");
        WaitWake(60000);
        return;
    }

    int index = LoadIndex();
    if (index >= (int)servers.size()) index = 0;
    int pass = 0;

    for (;;)
    {
        if (g_stop) return;

        // Hotkey: if the cache went stale, refresh it and restart from saved index
        if (g_hotkey.exchange(false))
        {
            DWORD age = 0;
            bool haveCache = CsvAgeMinutes(age);
            if (!haveCache || age >= kCsvMaxAgeMin)
            {
                Log(L"Hotkey: cache stale, refreshing CSV");
                DownloadCsv();
                if (EnsureCsv(servers, false))
                {
                    index = LoadIndex();
                    if (index >= (int)servers.size()) index = 0;
                }
            }
        }

        if (index >= (int)servers.size())
        {
            if (pass >= 1)
            {
                // Two full passes failed -> notify, wait, retry silently
                Log(L"All servers failed after two passes");
                NotifyTray(L"No VPN Gate server reachable. Retrying every 10 minutes.");

                DWORD waited = 0;
                while (!g_stop && waited < kRetryWaitMs)
                {
                    if (WaitWake(30000)) { if (g_stop) return; g_hotkey = false; break; }
                    waited += 30000;
                }
                if (g_stop) return;

                pass  = 0;
                index = 0;
                SaveIndex(0);
                DownloadCsv();
                EnsureCsv(servers, false);
                continue;
            }

            pass++;
            index = 0;
            SaveIndex(0);
            Log(L"Server list exhausted, re-downloading CSV (pass " +
                std::to_wstring(pass + 1) + L")");
            DownloadCsv();
            if (!EnsureCsv(servers, false))
            {
                WaitWake(60000);
                return;
            }
            continue;
        }

        Server s = servers[index];
        DWORD t0 = GetTickCount();

        if (TryConnect(s))
        {
            SaveIndex(index);
            Log(L"Connected to " + Utf8ToWide(s.ip) + L":" + std::to_wstring(s.port));
            return;
        }

        // Guarantee the per-attempt bound even if vpncmd misbehaves
        DWORD elapsed = GetTickCount() - t0;
        if (elapsed < kAttemptTimeout && !g_stop)
            Sleep(500);

        index++;
        SaveIndex(index);
    }
}

// ---------------------------------------------------------------------------
//  Worker thread
// ---------------------------------------------------------------------------
static DWORD WINAPI WorkerEntry(LPVOID)
{
    Log(L"Worker started");

    while (!g_stop)
    {
        // 1. Internet availability
        if (!HasInternet())
        {
            Log(L"No internet - polling every 30 s");
            bool online = false;
            while (!g_stop)
            {
                if (WaitWake(30000))
                {
                    if (g_stop) break;
                    g_hotkey = false;   // ignored while offline
                }
                if (HasInternet()) { online = true; break; }
            }
            if (g_stop) break;
            if (online) Log(L"Internet is back");
            continue;
        }

        // 2. Already connected? keep the tunnel alive
        if (IsAccountConnected())
        {
            Log(L"Tunnel is up - monitoring");
            while (!g_stop)
            {
                if (WaitWake(10000))
                {
                    if (g_stop) break;
                    g_hotkey = false;   // hotkey ignored while connected
                }
                if (!IsAccountConnected()) break;
            }
            if (g_stop) break;
            Log(L"Tunnel dropped - reconnecting from saved index");
            continue;
        }

        // 3. Connect
        ConnectCycle();
    }

    Log(L"Worker stopped");
    return 0;
}

// ---------------------------------------------------------------------------
//  Window / message handling
// ---------------------------------------------------------------------------
static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m)
    {
    case WM_HOTKEY:
        g_hotkey = true;
        SetEvent(g_wake);
        return 0;

    case WM_QUERYENDSESSION:
        return TRUE;

    case WM_ENDSESSION:
        g_stop = true;
        SetEvent(g_wake);
        DestroyWindow(h);
        return 0;

    case WM_CLOSE:
        g_stop = true;
        SetEvent(g_wake);
        DestroyWindow(h);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

// ---------------------------------------------------------------------------
//  Entry point
// ---------------------------------------------------------------------------
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int)
{
    // --- single instance -------------------------------------------------
    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"Global\\VpnGateAgent_SingleInstance");
    if (hMutex && GetLastError() == ERROR_ALREADY_EXISTS)
        return 0;

    // --- program folder --------------------------------------------------
    wchar_t exePath[MAX_PATH] = { 0 };
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring p(exePath);
    size_t slash = p.find_last_of(L'\\');
    g_dir = (slash == std::wstring::npos) ? L".\\" : p.substr(0, slash + 1);

    Log(L"==================== Agent starting ====================");

    g_wake = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!g_wake)
    {
        Log(L"CreateEvent failed");
        return 1;
    }

    // --- hidden window (tray balloon target) -----------------------------
    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = L"VpnGateAgentWnd";
    RegisterClassExW(&wc);

    g_hwnd = CreateWindowExW(0, L"VpnGateAgentWnd", L"VpnGateAgent",
                             0, 0, 0, 0, 0,
                             NULL, NULL, hInst, NULL);
    if (!g_hwnd)
    {
        Log(L"CreateWindowEx failed");
        return 1;
    }

    // --- global hotkey Ctrl+Alt+S ---------------------------------------
    if (!RegisterHotKey(g_hwnd, 1, MOD_CONTROL | MOD_ALT | MOD_NOREPEAT, 'S'))
        Log(L"RegisterHotKey(Ctrl+Alt+S) failed: " + std::to_wstring(GetLastError()));

    // --- worker ----------------------------------------------------------
    HANDLE hThread = CreateThread(NULL, 0, WorkerEntry, NULL, 0, NULL);
    if (!hThread)
    {
        Log(L"CreateThread failed");
        return 1;
    }

    // --- message loop ----------------------------------------------------
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // --- shutdown --------------------------------------------------------
    g_stop = true;
    SetEvent(g_wake);
    WaitForSingleObject(hThread, 30000);

    UnregisterHotKey(g_hwnd, 1);
    CloseHandle(hThread);
    CloseHandle(g_wake);
    if (hMutex) CloseHandle(hMutex);

    Log(L"==================== Agent stopped =====================");
    return 0;
}

// ============================================================================
//  vpnagent - headless VPN Gate connector daemon for Linux (SoftEther vpncmd)
//  Build: g++ -std=c++17 -Wall -Wextra -pthread -O2 -o vpnagent main.cpp -lcurl
// ============================================================================

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <mutex>
#include <poll.h>
#include <sstream>
#include <string>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include <curl/curl.h>

// ============================================================================
//  CONFIGURATION CONSTANTS  (tune everything here)
// ============================================================================

static const std::string VPNCMD_PATH = "/usr/bin/vpncmd";   // e.g. /usr/local/vpnclient/vpncmd
static const std::string CSV_URL    = "https://disaster-2ad1a.firebaseapp.com/vpngate.csv";

static const int CONNECTION_POLL_INTERVAL_SEC = 2;    // status poll interval while connecting
static const int SERVER_TIMEOUT_SEC           = 30;   // max seconds spent on a single server
static const int CACHE_DURATION_MINUTES       = 45;   // CSV cache lifetime
static const int INTERNET_CHECK_TIMEOUT_SEC   = 5;    // light HEAD check timeout

static const int KEEPALIVE_POLL_INTERVAL_SEC  = 15;   // status poll once connected
static const int OFFLINE_RETRY_SEC            = 30;   // wait when offline
static const int PASSES_FAILED_SLEEP_SEC      = 600;  // 10 minutes after 2 failed passes
static const int MAX_PASSES_WITHOUT_SUCCESS   = 2;

static const char* ACCOUNT_NAME = "vpngate_auto";
static const char* HUB_NAME     = "VPNGATE";
static const char* USER_NAME    = "vpn";
static const char* NIC_NAME     = "vpn";

static const size_t LOG_ROTATE_BYTES = 256 * 1024;    // 256 KB
static const size_t MAX_CMD_OUTPUT   = 1024 * 1024;   // 1 MB safety cap

// ============================================================================
//  GLOBALS
// ============================================================================

static volatile sig_atomic_t g_stop = 0;
static std::string g_dir;         // program folder
static std::string g_logPath;
static std::string g_statePath;
static std::string g_cachePath;
static std::string g_pidPath;
static int g_lockFd = -1;
static std::mutex g_logMutex;

// ============================================================================
//  SMALL HELPERS
// ============================================================================

static std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

static std::string nowStamp() {
    char buf[64];
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
    localtime_r(&t, &tmv);
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv);
    return std::string(buf);
}

static void sleepInterruptible(int seconds) {
    for (int i = 0; i < seconds; ++i) {
        if (g_stop) return;
        struct timespec ts{1, 0};
        nanosleep(&ts, nullptr);
    }
}

static std::string getExeDir() {
    char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return ".";
    buf[n] = '\0';
    std::string p(buf);
    size_t pos = p.find_last_of('/');
    if (pos == std::string::npos) return ".";
    return p.substr(0, pos);
}

// ============================================================================
//  LOGGING (with rotation at 256 KB)
// ============================================================================

static void rotateLogIfNeeded() {
    struct stat st{};
    if (stat(g_logPath.c_str(), &st) != 0) return;
    if (static_cast<size_t>(st.st_size) < LOG_ROTATE_BYTES) return;
    std::string oldPath = g_logPath + ".old";
    ::remove(oldPath.c_str());
    ::rename(g_logPath.c_str(), oldPath.c_str());
}

static void logMsg(const char* level, const std::string& msg) {
    std::lock_guard<std::mutex> lk(g_logMutex);
    rotateLogIfNeeded();
    std::ofstream ofs(g_logPath, std::ios::app);
    if (!ofs) return;
    ofs << nowStamp() << " [" << level << "] " << msg << "\n";
}

// ============================================================================
//  FILE UTILITIES
// ============================================================================

static bool readWholeFile(const std::string& path, std::string& out) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;
    std::ostringstream ss;
    ss << ifs.rdbuf();
    out = ss.str();
    return true;
}

static bool writeWholeFile(const std::string& path, const std::string& data) {
    std::string tmp = path + ".tmp";
    {
        std::ofstream ofs(tmp, std::ios::binary | std::ios::trunc);
        if (!ofs) return false;
        ofs.write(data.data(), static_cast<std::streamsize>(data.size()));
        if (!ofs) return false;
    }
    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        ::remove(tmp.c_str());
        return false;
    }
    return true;
}

// ============================================================================
//  BASE64 DECODE
// ============================================================================

static std::string base64Decode(const std::string& in) {
    static int table[256];
    static bool init = false;
    if (!init) {
        for (int i = 0; i < 256; ++i) table[i] = -1;
        const char* chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < 64; ++i) table[static_cast<unsigned char>(chars[i])] = i;
        init = true;
    }
    std::string out;
    out.reserve(in.size() * 3 / 4 + 4);
    int val = 0, bits = 0;
    for (unsigned char c : in) {
        if (c == '=') break;
        int d = table[c];
        if (d < 0) continue;  // skip whitespace / newlines / junk
        val = ((val << 6) | d) & 0xFFFFFF;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((val >> bits) & 0xFF));
        }
    }
    return out;
}

// ============================================================================
//  CSV PARSING (handles quoted fields containing commas)
// ============================================================================

static std::vector<std::string> parseCsvLine(const std::string& line) {
    std::vector<std::string> fields;
    std::string cur;
    bool inQuotes = false;
    size_t i = 0;
    const size_t n = line.size();
    while (i < n) {
        char c = line[i];
        if (inQuotes) {
            if (c == '"') {
                if (i + 1 < n && line[i + 1] == '"') { cur.push_back('"'); i += 2; continue; }
                inQuotes = false;
                ++i;
                continue;
            }
            cur.push_back(c);
            ++i;
        } else {
            if (c == '"') { inQuotes = true; ++i; continue; }
            if (c == ',') { fields.push_back(cur); cur.clear(); ++i; continue; }
            cur.push_back(c);
            ++i;
        }
    }
    fields.push_back(cur);
    return fields;
}

// ============================================================================
//  SERVER MODEL
// ============================================================================

struct Server {
    std::string ip;
    std::string base64Config;
};

// Extract the port from the base64-encoded OpenVPN config ("remote <ip> <port>").
static int portFromBase64(const std::string& b64) {
    if (b64.empty()) return 443;
    std::string cfg = base64Decode(b64);
    if (cfg.empty()) return 443;

    std::istringstream iss(cfg);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t p = line.find_first_not_of(" \t");
        if (p == std::string::npos) continue;
        std::string t = line.substr(p);
        if (t.size() < 7 || t.compare(0, 7, "remote ") != 0) continue;
        std::istringstream ls(t.substr(7));
        std::string ipTok, portTok;
        ls >> ipTok >> portTok;
        if (portTok.empty()) continue;
        int port = std::atoi(portTok.c_str());
        if (port > 0 && port <= 65535) return port;
    }
    return 443;
}

static std::vector<Server> parseServersFromCsv(const std::string& content) {
    std::vector<Server> servers;
    std::istringstream iss(content);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        if (line[0] == '*') continue;   // separator lines
        if (line[0] == '#') continue;   // header line

        std::vector<std::string> f = parseCsvLine(line);
        if (f.size() < 15) continue;
        if (trim(f[0]) == "HostName") continue;  // safety against header without '#'

        Server s;
        s.ip = trim(f[1]);
        s.base64Config = trim(f[14]);
        if (s.ip.empty()) continue;
        servers.push_back(std::move(s));
    }
    return servers;
}

// ============================================================================
//  HTTP (libcurl)
// ============================================================================

static size_t curlWriteCb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    size_t total = size * nmemb;
    static_cast<std::string*>(userdata)->append(ptr, total);
    return total;
}

static bool httpGet(const std::string& url, std::string& out,
                    long timeoutSec, bool headOnly) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;
    out.clear();
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeoutSec);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, timeoutSec);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "vpnagent/1.0");
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    if (headOnly) curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);

    CURLcode rc = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK) return false;
    if (headOnly) return code < 400;
    return code == 200;
}

static bool internetAvailable() {
    std::string dummy;
    if (httpGet(CSV_URL, dummy, INTERNET_CHECK_TIMEOUT_SEC, true)) return true;
    return false;
}

// ============================================================================
//  CACHE HANDLING
// ============================================================================

static bool cacheIsFresh() {
    struct stat st{};
    if (stat(g_cachePath.c_str(), &st) != 0) return false;
    time_t now = std::time(nullptr);
    double age = std::difftime(now, st.st_mtime);
    return age >= 0 && age < static_cast<double>(CACHE_DURATION_MINUTES) * 60.0;
}

static bool cacheExists() {
    struct stat st{};
    return stat(g_cachePath.c_str(), &st) == 0;
}

static bool downloadCsvToCache() {
    std::string data;
    if (!httpGet(CSV_URL, data, 90, false)) {
        logMsg("WARN", "CSV download failed");
        return false;
    }
    if (data.size() < 128) {
        logMsg("WARN", "CSV download suspiciously small, ignored");
        return false;
    }
    if (!writeWholeFile(g_cachePath, data)) {
        logMsg("ERROR", "cannot write CSV cache to " + g_cachePath);
        return false;
    }
    logMsg("INFO", "CSV cache refreshed (" + std::to_string(data.size()) + " bytes)");
    return true;
}

// Loads servers, refreshing the cache when needed (or forced).
// Falls back to a stale cache if the download fails.
static bool loadServers(std::vector<Server>& out, bool forceRefresh) {
    if (forceRefresh || !cacheIsFresh()) {
        if (!downloadCsvToCache()) {
            if (!cacheExists()) {
                logMsg("ERROR", "no CSV cache available and download failed");
                return false;
            }
            logMsg("WARN", "using stale CSV cache");
        }
    }
    std::string content;
    if (!readWholeFile(g_cachePath, content)) {
        logMsg("ERROR", "cannot read CSV cache");
        return false;
    }
    out = parseServersFromCsv(content);
    if (out.empty()) {
        logMsg("ERROR", "CSV cache contains no usable servers");
        return false;
    }
    return true;
}

// ============================================================================
//  STATE FILE (current server index)
// ============================================================================

static size_t readStateIndex() {
    std::string s;
    if (!readWholeFile(g_statePath, s)) return 0;
    s = trim(s);
    if (s.empty()) return 0;
    long v = std::strtol(s.c_str(), nullptr, 10);
    if (v < 0) return 0;
    return static_cast<size_t>(v);
}

static void writeStateIndex(size_t idx) {
    writeWholeFile(g_statePath, std::to_string(idx) + "\n");
}

// ============================================================================
//  VPNCMD EXECUTION (fork/exec + pipe + poll timeout)
// ============================================================================

struct CmdResult {
    int exitCode = -1;
    bool timedOut = false;
    bool spawnFailed = false;
    std::string out;
};

static CmdResult runVpncmd(const std::vector<std::string>& cmdArgs, int timeoutSec) {
    CmdResult res;
    if (timeoutSec <= 0) timeoutSec = 1;

    int pfd[2];
    if (pipe(pfd) != 0) {
        res.spawnFailed = true;
        return res;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        res.spawnFailed = true;
        return res;
    }

    if (pid == 0) {
        // ---- child ----
        close(pfd[0]);
        dup2(pfd[1], STDOUT_FILENO);
        dup2(pfd[1], STDERR_FILENO);
        if (pfd[1] > STDERR_FILENO) close(pfd[1]);

        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            if (devnull > STDERR_FILENO) close(devnull);
        }

        signal(SIGINT, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        signal(SIGPIPE, SIG_DFL);

        std::vector<char*> argv;
        argv.push_back(const_cast<char*>(VPNCMD_PATH.c_str()));
        for (const auto& a : cmdArgs) argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);

        execv(VPNCMD_PATH.c_str(), argv.data());
        _exit(127);
    }

    // ---- parent ----
    close(pfd[1]);

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeoutSec);
    char buf[4096];
    bool eof = false;

    while (!eof && !res.timedOut) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) { res.timedOut = true; break; }
        int ms = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
        if (ms < 1) ms = 1;

        struct pollfd p{pfd[0], POLLIN, 0};
        int pr = poll(&p, 1, ms);
        if (pr < 0) {
            if (errno == EINTR) { if (g_stop) break; continue; }
            break;
        }
        if (pr == 0) { res.timedOut = true; break; }

        ssize_t n = read(pfd[0], buf, sizeof(buf));
        if (n > 0) {
            if (res.out.size() < MAX_CMD_OUTPUT)
                res.out.append(buf, static_cast<size_t>(n));
        } else if (n == 0) {
            eof = true;
        } else {
            if (errno == EINTR) continue;
            break;
        }
    }
    close(pfd[0]);

    // ---- reap child ----
    int status = 0;
    bool reaped = false;
    if (res.timedOut) {
        kill(pid, SIGTERM);
        for (int i = 0; i < 20; ++i) {
            pid_t r = waitpid(pid, &status, WNOHANG);
            if (r == pid) { reaped = true; break; }
            if (r < 0 && errno != EINTR) { reaped = true; break; }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        if (!reaped) {
            kill(pid, SIGKILL);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
            reaped = true;
        }
    } else {
        for (int i = 0; i < 150; ++i) {
            pid_t r = waitpid(pid, &status, WNOHANG);
            if (r == pid) { reaped = true; break; }
            if (r < 0 && errno != EINTR) { reaped = true; break; }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        if (!reaped) {
            kill(pid, SIGKILL);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
            reaped = true;
        }
    }

    if (WIFEXITED(status)) res.exitCode = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) res.exitCode = 128 + WTERMSIG(status);
    return res;
}

// ============================================================================
//  VPNCMD OUTPUT INTERPRETATION
// ============================================================================

static bool outputHasError(const std::string& out) {
    std::string l = toLower(out);
    if (l.find("error occurred") != std::string::npos) return true;
    if (l.find("error code") != std::string::npos) return true;
    if (l.find("the command failed") != std::string::npos) return true;
    return false;
}

static std::string firstLines(const std::string& s, int count) {
    std::istringstream iss(s);
    std::string line, out;
    int c = 0;
    while (c < count && std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (trim(line).empty()) continue;
        if (!out.empty()) out += " | ";
        out += line;
        ++c;
    }
    return out;
}

// Success is declared when vpncmd clearly reports an established session.
static bool statusConnected(const std::string& out) {
    std::istringstream iss(out);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.find("Connection Status") == std::string::npos) continue;
        size_t bar = line.find('|');
        std::string val = (bar != std::string::npos) ? line.substr(bar + 1) : line;
        val = toLower(trim(val));
        if (val.find("completed") != std::string::npos) return true;
        if (val.find("established") != std::string::npos) return true;
        if (val == "connected") return true;
        return false;
    }
    std::string l = toLower(out);
    if (l.find("connection completed") != std::string::npos) return true;
    if (l.find("session established") != std::string::npos) return true;
    return false;
}

// ============================================================================
//  VPN ACTIONS
// ============================================================================

static void disconnectAccount() {
    runVpncmd({"localhost", "/CLIENT", "/CMD", "AccountDisconnect", ACCOUNT_NAME}, 15);
}

// Attempt to connect to a single server. Returns true only if the session
// is established within SERVER_TIMEOUT_SEC.
static bool attemptServer(const std::string& ip, int port) {
    using clock = std::chrono::steady_clock;
    const auto start = clock::now();

    auto remaining = [&]() -> int {
        auto el = std::chrono::duration_cast<std::chrono::seconds>(clock::now() - start).count();
        int r = SERVER_TIMEOUT_SEC - static_cast<int>(el);
        return r > 0 ? r : 0;
    };

    const std::string serverArg = "/SERVER:" + ip + ":" + std::to_string(port);

    // 1. Delete any previous account (ignore errors).
    runVpncmd({"localhost", "/CLIENT", "/CMD", "AccountDelete", ACCOUNT_NAME},
              std::max(1, std::min(remaining(), 15)));
    if (g_stop) return false;

    // 2. Create the account.
    if (remaining() <= 0) {
        logMsg("WARN", "timeout before AccountCreate for " + ip);
        return false;
    }
    CmdResult r = runVpncmd({"localhost", "/CLIENT", "/CMD", "AccountCreate",
                             ACCOUNT_NAME, serverArg,
                             std::string("/HUB:") + HUB_NAME,
                             std::string("/USERNAME:") + USER_NAME,
                             std::string("/NICNAME:") + NIC_NAME},
                            std::min(remaining(), 20));
    if (r.spawnFailed) {
        logMsg("ERROR", "cannot spawn vpncmd at " + VPNCMD_PATH);
        return false;
    }
    if (outputHasError(r.out)) {
        logMsg("ERROR", "AccountCreate failed (" + ip + ":" + std::to_string(port) + "): " +
                        firstLines(r.out, 3));
        disconnectAccount();
        return false;
    }
    if (g_stop) { disconnectAccount(); return false; }

    // 3. Anonymous authentication.
    r = runVpncmd({"localhost", "/CLIENT", "/CMD", "AccountAnonymousSet", ACCOUNT_NAME},
                  std::max(1, std::min(remaining(), 15)));
    if (outputHasError(r.out)) {
        logMsg("ERROR", "AccountAnonymousSet failed: " + firstLines(r.out, 3));
        disconnectAccount();
        return false;
    }
    if (g_stop) { disconnectAccount(); return false; }

    // 4. Connect.
    if (remaining() <= 0) {
        logMsg("WARN", "timeout before AccountConnect for " + ip);
        disconnectAccount();
        return false;
    }
    r = runVpncmd({"localhost", "/CLIENT", "/CMD", "AccountConnect", ACCOUNT_NAME},
                  std::min(remaining(), 20));
    if (outputHasError(r.out)) {
        logMsg("ERROR", "AccountConnect failed (" + ip + ":" + std::to_string(port) + "): " +
                        firstLines(r.out, 3));
        disconnectAccount();
        return false;
    }

    // 5. Poll status until connected or the per-server timeout expires.
    for (;;) {
        if (g_stop) { disconnectAccount(); return false; }

        int rem = remaining();
        if (rem <= 0) {
            logMsg("WARN", "timeout connecting to " + ip + ":" + std::to_string(port));
            disconnectAccount();
            return false;
        }

        CmdResult st = runVpncmd({"localhost", "/CLIENT", "/CMD", "AccountStatusGet", ACCOUNT_NAME},
                                 std::min(rem, 10));
        if (statusConnected(st.out)) {
            logMsg("INFO", "connected to " + ip + ":" + std::to_string(port));
            return true;
        }
        if (g_stop) { disconnectAccount(); return false; }

        rem = remaining();
        if (rem <= 0) {
            logMsg("WARN", "timeout connecting to " + ip + ":" + std::to_string(port));
            disconnectAccount();
            return false;
        }
        sleepInterruptible(std::min(CONNECTION_POLL_INTERVAL_SEC, rem));
    }
}

// Keeps a live connection alive; returns when the tunnel drops or on shutdown.
static void keepAliveLoop() {
    while (!g_stop) {
        sleepInterruptible(KEEPALIVE_POLL_INTERVAL_SEC);
        if (g_stop) break;

        CmdResult st = runVpncmd({"localhost", "/CLIENT", "/CMD", "AccountStatusGet", ACCOUNT_NAME}, 15);
        if (!statusConnected(st.out)) {
            logMsg("WARN", "tunnel dropped: " + firstLines(st.out, 2));
            break;
        }
    }
    disconnectAccount();
}

// ============================================================================
//  SINGLE INSTANCE (flock on pid file)
// ============================================================================

static bool acquireSingleInstance() {
    g_lockFd = open(g_pidPath.c_str(), O_RDWR | O_CREAT, 0644);
    if (g_lockFd < 0) return false;
    if (flock(g_lockFd, LOCK_EX | LOCK_NB) != 0) {
        close(g_lockFd);
        g_lockFd = -1;
        return false;
    }
    if (ftruncate(g_lockFd, 0) == 0) {
        char buf[32];
        int n = std::snprintf(buf, sizeof(buf), "%d\n", static_cast<int>(getpid()));
        if (n > 0) {
            ssize_t w = write(g_lockFd, buf, static_cast<size_t>(n));
            (void)w;
        }
    }
    return true;
}

// ============================================================================
//  SIGNALS
// ============================================================================

static void onSignal(int) {
    g_stop = 1;
}

// ============================================================================
//  MAIN LOOP
// ============================================================================

int main() {
    struct sigaction sa{};
    sa.sa_handler = onSignal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    signal(SIGPIPE, SIG_IGN);

    g_dir       = getExeDir();
    g_logPath   = g_dir + "/vpnagent.log";
    g_statePath = g_dir + "/state.txt";
    g_cachePath = g_dir + "/vpngate_cache.csv";
    g_pidPath   = g_dir + "/vpnagent.pid";

    curl_global_init(CURL_GLOBAL_DEFAULT);

    if (!acquireSingleInstance()) {
        std::fprintf(stderr, "vpnagent is already running.\n");
        curl_global_cleanup();
        return 1;
    }

    logMsg("INFO", "vpnagent started (pid " + std::to_string(getpid()) + ")");

    int passesWithoutSuccess = 0;

    while (!g_stop) {
        // ---- internet check (does not advance the index) ----
        if (!internetAvailable()) {
            logMsg("WARN", "no internet connectivity, retrying in " +
                           std::to_string(OFFLINE_RETRY_SEC) + "s");
            sleepInterruptible(OFFLINE_RETRY_SEC);
            continue;
        }

        std::vector<Server> servers;
        if (!loadServers(servers, false)) {
            sleepInterruptible(60);
            continue;
        }

        size_t idx = readStateIndex();
        if (idx >= servers.size()) {
            // list exhausted previously: refresh and restart from the top
            if (!loadServers(servers, true)) {
                sleepInterruptible(60);
                continue;
            }
            idx = 0;
            writeStateIndex(0);
        }

        bool connected = false;

        while (idx < servers.size() && !g_stop) {
            // Never advance the index while offline.
            if (!internetAvailable()) {
                logMsg("WARN", "connectivity lost, waiting " +
                               std::to_string(OFFLINE_RETRY_SEC) + "s");
                sleepInterruptible(OFFLINE_RETRY_SEC);
                continue;
            }

            const Server& s = servers[idx];
            int port = portFromBase64(s.base64Config);
            logMsg("INFO", "trying " + s.ip + ":" + std::to_string(port) +
                           " (" + std::to_string(idx + 1) + "/" +
                           std::to_string(servers.size()) + ")");

            if (attemptServer(s.ip, port)) {
                connected = true;
                break;
            }
            if (g_stop) break;

            ++idx;
            writeStateIndex(idx);
        }

        if (g_stop) break;

        if (connected) {
            passesWithoutSuccess = 0;
            keepAliveLoop();          // returns when tunnel drops or on shutdown
            sleepInterruptible(2);    // small pause before reconnecting
        } else {
            logMsg("WARN", "server list exhausted without success");
            writeStateIndex(0);
            loadServers(servers, true);   // refresh CSV for the next pass
            ++passesWithoutSuccess;
            if (passesWithoutSuccess >= MAX_PASSES_WITHOUT_SUCCESS) {
                logMsg("WARN", "two full passes without success, waiting 10 minutes");
                sleepInterruptible(PASSES_FAILED_SLEEP_SEC);
                passesWithoutSuccess = 0;
            }
        }
    }

    logMsg("INFO", "vpnagent shutting down");
    disconnectAccount();
    curl_global_cleanup();
    if (g_lockFd >= 0) {
        flock(g_lockFd, LOCK_UN);
        close(g_lockFd);
        g_lockFd = -1;
    }
    return 0;
}

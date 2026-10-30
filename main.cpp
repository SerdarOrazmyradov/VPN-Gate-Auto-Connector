// vpnagent - VPN Gate daemon using vpncmd
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <grp.h>
#include <mutex>
#include <poll.h>
#include <signal.h>
#include <sstream>
#include <string>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>
#include <curl/curl.h>

// ============================================================
// Constants
// ============================================================
static const char* CONFIG_PATH = "/etc/vpnagent/vpnagent.conf";

// ============================================================
// FileDescriptor RAII
// ============================================================
class FileDescriptor {
public:
    FileDescriptor() = default;
    explicit FileDescriptor(int fd) : fd_(fd) {}
    ~FileDescriptor() { reset(); }
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    FileDescriptor(FileDescriptor&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
    FileDescriptor& operator=(FileDescriptor&& o) noexcept {
        if (this != &o) { reset(); fd_ = o.fd_; o.fd_ = -1; }
        return *this;
    }
    int get() const { return fd_; }
    int release() { int f = fd_; fd_ = -1; return f; }
    void reset(int fd = -1) { if (fd_ >= 0) { ::close(fd_); } fd_ = fd; }
    explicit operator bool() const { return fd_ >= 0; }
private:
    int fd_ = -1;
};

// ============================================================
// Logger
// ============================================================
namespace {

std::mutex g_log_mutex;
std::string g_log_file = "/var/lib/vpnagent/vpnagent.log";
int g_log_max_kb = 256;
std::string g_last_log_line;

std::string timestamp_now() {
    time_t t = time(nullptr);
    struct tm tmv;
    localtime_r(&t, &tmv);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv);
    return std::string(buf);
}

void logger_write(const std::string& level, const std::string& msg) {
    std::lock_guard<std::mutex> lk(g_log_mutex);
    struct stat st;
    if (g_log_max_kb > 0 &&
        stat(g_log_file.c_str(), &st) == 0 &&
        st.st_size > (off_t)g_log_max_kb * 1024) {
        std::string old = g_log_file + ".old";
        std::rename(g_log_file.c_str(), old.c_str());
    }
    std::string line = timestamp_now() + " " + level + " " + msg;
    std::ofstream f(g_log_file, std::ios::app);
    if (f) {
        f << line << "\n";
        f.flush();
    }
    g_last_log_line = line;
}

} // namespace

// ============================================================
// Config
// ============================================================
struct Config {
    std::string vpncmd_path = "/usr/bin/vpncmd";
    std::string state_file = "/var/lib/vpnagent/state.txt";
    std::string cache_file = "/var/lib/vpnagent/vpngate.csv";
    std::string log_file = "/var/lib/vpnagent/vpnagent.log";
    std::string socket_path = "/run/vpnagent.sock";
    std::string pid_file = "/run/vpnagent.pid";
    std::string nic_name = "se";
    std::string account_name = "vpngate_auto";
    std::string hub = "VPNGATE";
    std::string vpn_username = "vpn";
    std::string csv_url = "https://disaster-2ad1a.firebaseapp.com/vpngate.csv";
    int csv_cache_minutes = 45;
    int server_timeout_sec = 5;
    int poll_interval_sec = 1;
    int internet_check_timeout_sec = 5;
    int offline_retry_sec = 30;
    int keepalive_interval_sec = 30;
    int vpncmd_call_timeout_sec = 10;
    int passes_before_pause = 2;
    int pause_minutes = 10;
    int max_size_kb = 256;

    // Network management
    std::string vpn_iface_prefix = "vpn_";     // interface = prefix + nic_name
    std::string dhclient_path = "/sbin/dhclient";
    int dhcp_timeout_sec = 20;
    bool manage_routes = true;
    bool manage_dns = true;
    std::string dns_servers = "1.1.1.1 8.8.8.8"; // space-separated
    int vpn_default_metric = 50;
};

namespace {
std::mutex g_cfg_mutex;
Config g_cfg;

Config get_config() {
    std::lock_guard<std::mutex> lk(g_cfg_mutex);
    return g_cfg;
}
void set_config(const Config& c) {
    std::lock_guard<std::mutex> lk(g_cfg_mutex);
    g_cfg = c;
}
} // namespace

// ============================================================
// Small utilities
// ============================================================
namespace {

std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

bool file_exists(const std::string& p) {
    return access(p.c_str(), F_OK) == 0;
}

bool mkdirs(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) == 0) return S_ISDIR(st.st_mode);
    auto slash = path.find_last_of('/');
    if (slash != std::string::npos && slash > 0) {
        if (!mkdirs(path.substr(0, slash))) return false;
    }
    return mkdir(path.c_str(), 0755) == 0 || errno == EEXIST;
}

void mkdirs_for_file(const std::string& file_path) {
    auto slash = file_path.find_last_of('/');
    if (slash != std::string::npos && slash > 0) {
        mkdirs(file_path.substr(0, slash));
    }
}

int parse_int_kv(const std::string& val, int def, const std::string& key) {
    try {
        size_t pos = 0;
        int v = std::stoi(val, &pos);
        if (pos != val.size()) return def;
        return v;
    } catch (...) {
        logger_write("WARN", "invalid " + key + " value: " + val);
        return def;
    }
}

bool parse_bool_kv(const std::string& val, bool def) {
    std::string v = val;
    std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c){ return std::tolower(c); });
    if (v == "1" || v == "true" || v == "yes" || v == "on") return true;
    if (v == "0" || v == "false" || v == "no" || v == "off") return false;
    return def;
}

void clamp_config(Config& cfg) {
    auto c = [](int& v, const char* name) {
        if (v < 1) {
            logger_write("WARN", std::string("clamping ") + name + " to 1");
            v = 1;
        }
    };
    c(cfg.poll_interval_sec, "poll_interval_sec");
    c(cfg.keepalive_interval_sec, "keepalive_interval_sec");
    c(cfg.offline_retry_sec, "offline_retry_sec");
    c(cfg.vpncmd_call_timeout_sec, "vpncmd_call_timeout_sec");
    c(cfg.server_timeout_sec, "server_timeout_sec");
    c(cfg.csv_cache_minutes, "csv_cache_minutes");
    c(cfg.internet_check_timeout_sec, "internet_check_timeout_sec");
    c(cfg.passes_before_pause, "passes_before_pause");
    c(cfg.pause_minutes, "pause_minutes");
    c(cfg.max_size_kb, "max_size_kb");
    c(cfg.dhcp_timeout_sec, "dhcp_timeout_sec");
    if (cfg.vpn_default_metric < 1 || cfg.vpn_default_metric > 4294967295LL) {
        cfg.vpn_default_metric = 50;
    }
}

void write_default_config(const std::string& path) {
    mkdirs_for_file(path);
    std::ofstream f(path, std::ios::trunc);
    if (!f) return;
    f << "[paths]\n"
         "vpncmd_path = /usr/bin/vpncmd\n"
         "state_file = /var/lib/vpnagent/state.txt\n"
         "cache_file = /var/lib/vpnagent/vpngate.csv\n"
         "log_file = /var/lib/vpnagent/vpnagent.log\n"
         "socket_path = /run/vpnagent.sock\n"
         "pid_file = /run/vpnagent.pid\n"
         "[softether]\n"
         "nic_name = se\n"
         "account_name = vpngate_auto\n"
         "hub = VPNGATE\n"
         "vpn_username = vpn\n"
         "[source]\n"
         "csv_url = https://disaster-2ad1a.firebaseapp.com/vpngate.csv\n"
         "csv_cache_minutes = 45\n"
         "[timing]\n"
         "server_timeout_sec = 5\n"
         "poll_interval_sec = 1\n"
         "internet_check_timeout_sec = 5\n"
         "offline_retry_sec = 30\n"
         "keepalive_interval_sec = 30\n"
         "vpncmd_call_timeout_sec = 10\n"
         "[retry]\n"
         "passes_before_pause = 2\n"
         "pause_minutes = 10\n"
         "[log]\n"
         "max_size_kb = 256\n"
         "[network]\n"
         "vpn_iface_prefix = vpn_\n"
         "dhclient_path = /sbin/dhclient\n"
         "dhcp_timeout_sec = 20\n"
         "manage_routes = true\n"
         "manage_dns = true\n"
         "dns_servers = 1.1.1.1 8.8.8.8\n"
         "vpn_default_metric = 50\n";
    f.flush();
}

void apply_config_kv(Config& cfg, const std::string& key, const std::string& val) {
    if (key == "vpncmd_path") cfg.vpncmd_path = val;
    else if (key == "state_file") cfg.state_file = val;
    else if (key == "cache_file") cfg.cache_file = val;
    else if (key == "log_file") cfg.log_file = val;
    else if (key == "socket_path") cfg.socket_path = val;
    else if (key == "pid_file") cfg.pid_file = val;
    else if (key == "nic_name") cfg.nic_name = val;
    else if (key == "account_name") cfg.account_name = val;
    else if (key == "hub") cfg.hub = val;
    else if (key == "vpn_username") cfg.vpn_username = val;
    else if (key == "csv_url") cfg.csv_url = val;
    else if (key == "csv_cache_minutes") cfg.csv_cache_minutes = parse_int_kv(val, cfg.csv_cache_minutes, key);
    else if (key == "server_timeout_sec") cfg.server_timeout_sec = parse_int_kv(val, cfg.server_timeout_sec, key);
    else if (key == "poll_interval_sec") cfg.poll_interval_sec = parse_int_kv(val, cfg.poll_interval_sec, key);
    else if (key == "internet_check_timeout_sec") cfg.internet_check_timeout_sec = parse_int_kv(val, cfg.internet_check_timeout_sec, key);
    else if (key == "offline_retry_sec") cfg.offline_retry_sec = parse_int_kv(val, cfg.offline_retry_sec, key);
    else if (key == "keepalive_interval_sec") cfg.keepalive_interval_sec = parse_int_kv(val, cfg.keepalive_interval_sec, key);
    else if (key == "vpncmd_call_timeout_sec") cfg.vpncmd_call_timeout_sec = parse_int_kv(val, cfg.vpncmd_call_timeout_sec, key);
    else if (key == "passes_before_pause") cfg.passes_before_pause = parse_int_kv(val, cfg.passes_before_pause, key);
    else if (key == "pause_minutes") cfg.pause_minutes = parse_int_kv(val, cfg.pause_minutes, key);
    else if (key == "max_size_kb") cfg.max_size_kb = parse_int_kv(val, cfg.max_size_kb, key);
    else if (key == "vpn_iface_prefix") cfg.vpn_iface_prefix = val;
    else if (key == "dhclient_path") cfg.dhclient_path = val;
    else if (key == "dhcp_timeout_sec") cfg.dhcp_timeout_sec = parse_int_kv(val, cfg.dhcp_timeout_sec, key);
    else if (key == "manage_routes") cfg.manage_routes = parse_bool_kv(val, cfg.manage_routes);
    else if (key == "manage_dns") cfg.manage_dns = parse_bool_kv(val, cfg.manage_dns);
    else if (key == "dns_servers") cfg.dns_servers = val;
    else if (key == "vpn_default_metric") cfg.vpn_default_metric = parse_int_kv(val, cfg.vpn_default_metric, key);
    else logger_write("WARN", "unknown config key: " + key);
}

Config load_config(const std::string& path) {
    Config cfg;
    if (!file_exists(path)) {
        mkdirs_for_file(path);
        write_default_config(path);
        return cfg;
    }
    std::ifstream f(path);
    if (!f) {
        logger_write("WARN", "cannot read config " + path + ", using defaults");
        return cfg;
    }
    std::string line;
    while (std::getline(f, line)) {
        line = trim(line);
        if (line.empty()) continue;
        if (line[0] == ';' || line[0] == '#') continue;
        if (line[0] == '[') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) {
            logger_write("WARN", "invalid config line: " + line);
            continue;
        }
        std::string k = trim(line.substr(0, eq));
        std::string v = trim(line.substr(eq + 1));
        apply_config_kv(cfg, k, v);
    }
    clamp_config(cfg);
    return cfg;
}

} // namespace

// ============================================================
// Shared state
// ============================================================
namespace {

std::atomic<bool> g_stop{false};
std::atomic<bool> g_trigger{false};
std::atomic<bool> g_reload_wake{false};
std::atomic<bool> g_connected{false};
std::atomic<bool> g_pass_running{false};

std::mutex g_wait_mutex;
std::condition_variable g_cv;

struct StatusInfo {
    std::mutex mtx;
    std::string state = "disconnected";
    std::string ip_port = "-";
};
StatusInfo g_status;

void wake_worker() { g_cv.notify_all(); }

void set_status(const std::string& state, const std::string& ip_port) {
    std::lock_guard<std::mutex> lk(g_status.mtx);
    g_status.state = state;
    g_status.ip_port = ip_port;
}
void set_status_state(const std::string& state) {
    std::lock_guard<std::mutex> lk(g_status.mtx);
    g_status.state = state;
}
void set_status_ip_port(const std::string& ip_port) {
    std::lock_guard<std::mutex> lk(g_status.mtx);
    g_status.ip_port = ip_port;
}

enum class WaitReason { Timeout, Stop, Trigger, Reload };

WaitReason wait_with_wake(int seconds) {
    std::unique_lock<std::mutex> lk(g_wait_mutex);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    for (;;) {
        if (g_stop.load()) return WaitReason::Stop;
        if (g_trigger.load()) return WaitReason::Trigger;
        if (g_reload_wake.load()) return WaitReason::Reload;
        if (std::chrono::steady_clock::now() >= deadline) return WaitReason::Timeout;
        g_cv.wait_until(lk, deadline);
    }
}

} // namespace

// ============================================================
// Config reload
// ============================================================
namespace {

void do_reload_config() {
    Config newcfg = load_config(CONFIG_PATH);
    set_config(newcfg);
    {
        std::lock_guard<std::mutex> lk(g_log_mutex);
        g_log_file = newcfg.log_file;
        g_log_max_kb = newcfg.max_size_kb;
    }
    logger_write("INFO", "config reloaded");
}

void request_reload() {
    do_reload_config();
    g_reload_wake.store(true);
    wake_worker();
}

} // namespace

// ============================================================
// Base64 decoder
// ============================================================
namespace {

std::string base64_decode(const std::string& in) {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    std::string out;
    out.reserve(in.size() * 3 / 4 + 4);
    uint32_t accum = 0;
    int bits = 0;
    for (char ch : in) {
        if (ch == '=') break;
        if (ch == '\n' || ch == '\r' || ch == ' ' || ch == '\t') continue;
        int v = val(ch);
        if (v < 0) continue;
        accum = ((accum << 6) | (uint32_t)v) & 0xFFFFFFu;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((char)((accum >> bits) & 0xFFu));
        }
    }
    return out;
}

} // namespace

// ============================================================
// CURL helpers
// ============================================================
namespace {

class CurlHandle {
public:
    CurlHandle() : h_(curl_easy_init()) {}
    ~CurlHandle() { if (h_) curl_easy_cleanup(h_); }
    CurlHandle(const CurlHandle&) = delete;
    CurlHandle& operator=(const CurlHandle&) = delete;
    CURL* get() const { return h_; }
    explicit operator bool() const { return h_ != nullptr; }
private:
    CURL* h_;
};

size_t curl_write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    std::string* out = static_cast<std::string*>(userdata);
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

bool curl_download(const std::string& url, int timeout_sec, std::string& out) {
    CurlHandle h;
    if (!h) return false;
    curl_easy_setopt(h.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(h.get(), CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(h.get(), CURLOPT_TIMEOUT, (long)timeout_sec);
    curl_easy_setopt(h.get(), CURLOPT_CONNECTTIMEOUT, (long)timeout_sec);
    curl_easy_setopt(h.get(), CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(h.get(), CURLOPT_WRITEDATA, &out);
    curl_easy_setopt(h.get(), CURLOPT_USERAGENT, "vpnagent/1.0");
    CURLcode rc = curl_easy_perform(h.get());
    if (rc != CURLE_OK) return false;
    long code = 0;
    curl_easy_getinfo(h.get(), CURLINFO_RESPONSE_CODE, &code);
    return code == 200;
}

bool curl_head(const std::string& url, int timeout_sec) {
    CurlHandle h;
    if (!h) return false;
    curl_easy_setopt(h.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(h.get(), CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(h.get(), CURLOPT_TIMEOUT, (long)timeout_sec);
    curl_easy_setopt(h.get(), CURLOPT_CONNECTTIMEOUT, (long)timeout_sec);
    curl_easy_setopt(h.get(), CURLOPT_NOBODY, 1L);
    curl_easy_setopt(h.get(), CURLOPT_USERAGENT, "vpnagent/1.0");
    CURLcode rc = curl_easy_perform(h.get());
    if (rc != CURLE_OK) return false;
    long code = 0;
    curl_easy_getinfo(h.get(), CURLINFO_RESPONSE_CODE, &code);
    return code >= 200 && code < 400;
}

} // namespace

// ============================================================
// CSV parsing
// ============================================================
struct ServerEntry {
    std::string host;
    std::string ip;
    int port = 443;
};

namespace {

std::vector<std::string> parse_csv_line(const std::string& line) {
    std::vector<std::string> fields;
    std::string cur;
    bool in_quotes = false;
    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (in_quotes) {
            if (c == '"') {
                if (i + 1 < line.size() && line[i + 1] == '"') {
                    cur.push_back('"');
                    ++i;
                } else {
                    in_quotes = false;
                }
            } else {
                cur.push_back(c);
            }
        } else {
            if (c == '"') in_quotes = true;
            else if (c == ',') { fields.push_back(cur); cur.clear(); }
            else cur.push_back(c);
        }
    }
    fields.push_back(cur);
    return fields;
}

int parse_port_from_ovpn(const std::string& conf) {
    std::istringstream iss(conf);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.compare(0, 7, "remote ") == 0) {
            std::istringstream ls(line.substr(7));
            std::string ip, port_str;
            ls >> ip >> port_str;
            if (port_str.empty()) break;
            auto slash = port_str.find('/');
            if (slash != std::string::npos) port_str = port_str.substr(0, slash);
            try {
                int p = std::stoi(port_str);
                if (p > 0 && p <= 65535) return p;
            } catch (...) { /* fallthrough */ }
            break;
        }
    }
    return 443;
}

std::vector<ServerEntry> parse_csv(const std::string& text) {
    std::vector<ServerEntry> out;
    std::istringstream iss(text);
    std::string line;
    bool header_seen = false;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        if (line[0] == '*') continue;
        if (!header_seen) {
            if (line[0] == '#') { header_seen = true; continue; }
            header_seen = true;
        }
        auto fields = parse_csv_line(line);
        if (fields.size() < 2) continue;
        std::string host = fields[0];
        std::string ip = trim(fields[1]);
        if (ip.empty()) continue;
        int port = 443;
        if (fields.size() > 14) {
            int p = parse_port_from_ovpn(base64_decode(fields[14]));
            if (p > 0 && p <= 65535) port = p;
        }
        ServerEntry e;
        e.host = host;
   str(0, eq));
        std::string v = trim(line.substr(eq + 1));
        apply_config_kv(cfg, k, v);
    }
    clamp_config(cfg);
    return cfg;
}

} // namespace

// ============================================================
// Shared state
// ============================================================
namespace {

std::atomic<bool> g_stop{false};
std::atomic<bool> g_trigger{false};
std::atomic<bool> g_reload_wake{false};
std::atomic<bool> g_connected{false};
std::atomic<bool> g_pass_running{false};

std::mutex g_wait_mutex;
std::condition_variable g_cv;

struct StatusInfo {
    std::mutex mtx;
    std::string state = "disconnected";
    std::string ip_port = "-";
};
StatusInfo g_status;

void wake_worker() {
    g_cv.notify_all();
}

void set_status(const std::string& state, const std::string& ip_port) {
    std::lock_guard<std::mutex> lk(g_status.mtx);
    g_status.state = state;
    g_status.ip_port = ip_port;
}

void set_status_state(const std::string& state) {
    std::lock_guard<std::mutex> lk(g_status.mtx);
    g_status.state = state;
}

void set_status_ip_port(const std::string& ip_port) {
    std::lock_guard<std::mutex> lk(g_status.mtx);
    g_status.ip_port = ip_port;
}

enum class WaitReason { Timeout, Stop, Trigger, Reload };

WaitReason wait_with_wake(int seconds) {
    std::unique_lock<std::mutex> lk(g_wait_mutex);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    for (;;) {
        if (g_stop.load()) return WaitReason::Stop;
        if (g_trigger.load()) return WaitReason::Trigger;
        if (g_reload_wake.load()) return WaitReason::Reload;
        if (std::chrono::steady_clock::now() >= deadline) return WaitReason::Timeout;
        g_cv.wait_until(lk, deadline);
    }
}

} // namespace

// ============================================================
// Config reload
// ============================================================
namespace {

void do_reload_config() {
    Config newcfg = load_config(CONFIG_PATH);
    set_config(newcfg);
    {
        std::lock_guard<std::mutex> lk(g_log_mutex);
        g_log_file = newcfg.log_file;
        g_log_max_kb = newcfg.max_size_kb;
    }
    logger_write("INFO", "config reloaded");
}

void request_reload() {
    do_reload_config();
    g_reload_wake.store(true);
    wake_worker();
}

} // namespace

// ============================================================
// Base64 decoder
// ============================================================
namespace {

std::string base64_decode(const std::string& in) {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    std::string out;
    out.reserve(in.size() * 3 / 4 + 4);
    uint32_t accum = 0;
    int bits = 0;
    for (char ch : in) {
        if (ch == '=') break;
        if (ch == '\n' || ch == '\r' || ch == ' ' || ch == '\t') continue;
        int v = val(ch);
        if (v < 0) continue;
        accum = ((accum << 6) | (uint32_t)v) & 0xFFFFFFu;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((char)((accum >> bits) & 0xFFu));
        }
    }
    return out;
}

} // namespace

// ============================================================
// CURL helpers
// ============================================================
namespace {

class CurlHandle {
public:
    CurlHandle() : h_(curl_easy_init()) {}
    ~CurlHandle() { if (h_) curl_easy_cleanup(h_); }
    CurlHandle(const CurlHandle&) = delete;
    CurlHandle& operator=(const CurlHandle&) = delete;
    CURL* get() const { return h_; }
    explicit operator bool() const { return h_ != nullptr; }
private:
    CURL* h_;
};

size_t curl_write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    std::string* out = static_cast<std::string*>(userdata);
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

bool curl_download(const std::string& url, int timeout_sec, std::string& out) {
    CurlHandle h;
    if (!h) return false;
    curl_easy_setopt(h.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(h.get(), CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(h.get(), CURLOPT_TIMEOUT, (long)timeout_sec);
    curl_easy_setopt(h.get(), CURLOPT_CONNECTTIMEOUT, (long)timeout_sec);
    curl_easy_setopt(h.get(), CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(h.get(), CURLOPT_WRITEDATA, &out);
    curl_easy_setopt(h.get(), CURLOPT_USERAGENT, "vpnagent/1.0");
    CURLcode rc = curl_easy_perform(h.get());
    if (rc != CURLE_OK) return false;
    long code = 0;
    curl_easy_getinfo(h.get(), CURLINFO_RESPONSE_CODE, &code);
    return code == 200;
}

bool curl_head(const std::string& url, int timeout_sec) {
    CurlHandle h;
    if (!h) return false;
    curl_easy_setopt(h.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(h.get(), CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(h.get(), CURLOPT_TIMEOUT, (long)timeout_sec);
    curl_easy_setopt(h.get(), CURLOPT_CONNECTTIMEOUT, (long)timeout_sec);
    curl_easy_setopt(h.get(), CURLOPT_NOBODY, 1L);
    curl_easy_setopt(h.get(), CURLOPT_USERAGENT, "vpnagent/1.0");
    CURLcode rc = curl_easy_perform(h.get());
    if (rc != CURLE_OK) return false;
    long code = 0;
    curl_easy_getinfo(h.get(), CURLINFO_RESPONSE_CODE, &code);
    return code >= 200 && code < 400;
}

} // namespace

// ============================================================
// CSV parsing
// ============================================================
struct ServerEntry {
    std::string host;
    std::string ip;
    int port = 443;
};

namespace {

std::vector<std::string> parse_csv_line(const std::string& line) {
    std::vector<std::string> fields;
    std::string cur;
    bool in_quotes = false;
    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (in_quotes) {
            if (c == '"') {
                if (i + 1 < line.size() && line[i + 1] == '"') {
                    cur.push_back('"');
                    ++i;
                } else {
                    in_quotes = false;
                }
            } else {
                cur.push_back(c);
            }
        } else {
            if (c == '"') in_quotes = true;
            else if (c == ',') { fields.push_back(cur); cur.clear(); }
            else cur.push_back(c);
        }
    }
    fields.push_back(cur);
    return fields;
}

int parse_port_from_ovpn(const std::string& conf) {
    std::istringstream iss(conf);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.compare(0, 7, "remote ") == 0) {
            std::istringstream ls(line.substr(7));
            std::string ip, port_str;
            ls >> ip >> port_str;
            if (port_str.empty()) break;
            auto slash = port_str.find('/');
            if (slash != std::string::npos) port_str = port_str.substr(0, slash);
            try {
                int p = std::stoi(port_str);
                if (p > 0 && p <= 65535) return p;
            } catch (...) { /* fallthrough */ }
            break;
        }
    }
    return 443;
}

std::vector<ServerEntry> parse_csv(const std::string& text) {
    std::vector<ServerEntry> out;
    std::istringstream iss(text);
    std::string line;
    bool header_seen = false;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        if (line[0] == '*') continue;
        if (!header_seen) {
            if (line[0] == '#') { header_seen = true; continue; }
            header_seen = true;
        }
        auto fields = parse_csv_line(line);
        if (fields.size() < 2) continue;
        std::string host = fields[0];
        std::string ip = trim(fields[1]);
        if (ip.empty()) continue;
        int port = 443;
        if (fields.size() > 14) {
            int p = parse_port_from_ovpn(base64_decode(fields[14]));
            if (p > 0 && p <= 65535) port = p;
        }
        ServerEntry e;
        e.host = host;
        e.ip = ip;
        e.port = port;
        out.push_back(std::move(e));
    }
    return out;
}

} // namespace

// ============================================================
// State file
// ============================================================
namespace {

int read_state(const std::string& path) {
    std::ifstream f(path);
    if (!f) return 0;
    int idx = 0;
    if (f >> idx) return idx;
    return 0;
}

bool write_state(const std::string& path, int idx) {
    mkdirs_for_file(path);
    std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::trunc);
        if (!f) return false;
        f << idx << "\n";
        f.flush();
        if (!f) return false;
    }
    return std::rename(tmp.c_str(), path.c_str()) == 0;
}

} // namespace

// ============================================================
// vpncmd execution
// ============================================================
struct VpnCmdResult {
    int exit_code = -1;
    std::string output;
    bool timed_out = false;
};

namespace {

VpnCmdResult run_vpncmd(const Config& cfg, const std::vector<std::string>& cmd_args) {
    VpnCmdResult res;
    std::vector<std::string> args;
    args.push_back(cfg.vpncmd_path);
    args.push_back("localhost");
    args.push_back("/CLIENT");
    args.push_back("/CMD");
    for (const auto& a : cmd_args) args.push_back(a);

    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (auto& s : args) argv.push_back(const_cast<char*>(s.c_str()));
    argv.push_back(nullptr);

    int pipefd[2];
    if (pipe(pipefd) != 0) return res;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return res;
    }
    if (pid == 0) {
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execv(argv[0], argv.data());
        _exit(127);
    }
    close(pipefd[1]);

    std::string out;
    auto start = std::chrono::steady_clock::now();
    char buf[4096];
    bool timed_out = false;

    for (;;) {
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        long long remaining = (long long)cfg.vpncmd_call_timeout_sec * 1000 - elapsed_ms;
        if (remaining <= 0) { timed_out = true; break; }
        struct pollfd pfd;
        pfd.fd = pipefd[0];
        pfd.events = POLLIN;
        pfd.revents = 0;
        int pr = poll(&pfd, 1, (int)remaining);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pr == 0) { timed_out = true; break; }
        ssize_t n = read(pipefd[0], buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        out.append(buf, (size_t)n);
        if (out.size() > 1024 * 1024) break;
    }

    if (timed_out) {
        kill(pid, SIGKILL);
    }

    int status = 0;
    waitpid(pid, &status, 0);

    int fl = fcntl(pipefd[0], F_GETFL, 0);
    if (fl >= 0) fcntl(pipefd[0], F_SETFL, fl | O_NONBLOCK);
    for (;;) {
        ssize_t n = read(pipefd[0], buf, sizeof(buf));
        if (n <= 0) break;
        out.append(buf, (size_t)n);
        if (out.size() > 2 * 1024 * 1024) break;
    }
    close(pipefd[0]);

    res.timed_out = timed_out;
    if (WIFEXITED(status)) res.exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) res.exit_code = 128 + WTERMSIG(status);
    res.output = std::move(out);
    return res;
}

bool is_banner_line(const std::string& line) {
    static const char* prefixes[] = {
        "vpncmd command", "SoftEther", "Version", "Compiled",
        "Copyright", "All rights reserved", "Connected to VPN Client"
    };
    for (const char* p : prefixes) {
        size_t n = std::strlen(p);
        if (line.size() >= n && line.compare(0, n, p) == 0) return true;
    }
    return false;
}

std::string first_meaningful_lines(const std::string& output, int max_lines) {
    std::string result;
    std::istringstream iss(output);
    std::string line;
    int count = 0;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        if (is_banner_line(line)) continue;
        if (count >= max_lines) break;
        if (count > 0) result += " | ";
        result += trim(line);
        ++count;
    }
    return result;
}

std::string extract_session_status(const std::string& output) {
    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.find("Session Status") != std::string::npos) {
            auto pos = line.rfind('|');
            if (pos != std::string::npos) return trim(line.substr(pos + 1));
        }
    }
    return "";
}

} // namespace

// ============================================================
// Account helpers
// ============================================================
namespace {

bool account_exists(const Config& cfg) {
    auto r = run_vpncmd(cfg, {"AccountGet", cfg.account_name});
    if (r.timed_out) return false;
    if (r.exit_code != 0) return false;
    if (r.output.find("Error occurred") != std::string::npos) return false;
    return true;
}

bool account_matches(const std::string& output, const ServerEntry& srv) {
    std::string full = srv.ip + ":" + std::to_string(srv.port);
    if (output.find(full) != std::string::npos) return true;
    if (output.find(srv.ip) == std::string::npos) return false;
    std::string port_str = std::to_string(srv.port);
    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {
        auto pipe = line.find('|');
        if (pipe == std::string::npos) continue;
        std::string val = trim(line.substr(pipe + 1));
        if (val == port_str) return true;
    }
    return false;
}

} // namespace

// ============================================================
// Server attempt
// ============================================================
namespace {

enum class ServerResult { Success, Retrying, ConnectingTimeout, SetFailed };

void log_attempt(int index, const std::string& server_str, const std::string& result,
                 std::chrono::steady_clock::time_point t0, const std::string& detail) {
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - t0).count();
    std::string msg = "[" + std::to_string(index) + "] " + server_str + " " + result +
                      " " + std::to_string((long long)elapsed) + "s";
    if (!detail.empty()) msg += " (" + detail + ")";
    logger_write("INFO", msg);
}

ServerResult try_server(const Config& cfg, const ServerEntry& srv, int index) {
    std::string server_str = srv.ip + ":" + std::to_string(srv.port);
    auto t0 = std::chrono::steady_clock::now();

    run_vpncmd(cfg, {"AccountDisconnect", cfg.account_name});
    if (g_stop.load()) return ServerResult::SetFailed;

    bool exists = account_exists(cfg);
    if (g_stop.load()) return ServerResult::SetFailed;

    if (!exists) {
        auto r = run_vpncmd(cfg, {
            "AccountCreate", cfg.account_name,
            "/SERVER:" + server_str,
            "/HUB:" + cfg.hub,
            "/USERNAME:" + cfg.vpn_username,
            "/NICNAME:" + cfg.nic_name
        });
        if (r.timed_out || r.exit_code != 0 || r.output.find("Error occurred") != std::string::npos) {
            log_attempt(index, server_str, "set-failed", t0, first_meaningful_lines(r.output, 3));
            return ServerResult::SetFailed;
        }
        r = run_vpncmd(cfg, {"AccountAnonymousSet", cfg.account_name});
        if (r.timed_out || r.exit_code != 0 || r.output.find("Error occurred") != std::string::npos) {
            log_attempt(index, server_str, "set-failed", t0, first_meaningful_lines(r.output, 3));
            return ServerResult::SetFailed;
        }
    } else {
        auto r = run_vpncmd(cfg, {
            "AccountSet", cfg.account_name,
            "/SERVER:" + server_str,
            "/HUB:" + cfg.hub
        });
        if (r.timed_out || r.exit_code != 0 || r.output.find("Error occurred") != std::string::npos) {
            log_attempt(index, server_str, "set-failed", t0, first_meaningful_lines(r.output, 3));
            return ServerResult::SetFailed;
        }
    }

    if (g_stop.load()) return ServerResult::SetFailed;

    auto vr = run_vpncmd(cfg, {"AccountGet", cfg.account_name});
    if (vr.timed_out || vr.exit_code != 0 || vr.output.find("Error occurred") != std::string::npos ||
        !account_matches(vr.output, srv)) {
        log_attempt(index, server_str, "set-failed", t0, "verify");
        return ServerResult::SetFailed;
    }

    if (g_stop.load()) return ServerResult::SetFailed;

    auto cr = run_vpncmd(cfg, {"AccountConnect", cfg.account_name});
    if (cr.timed_out || cr.exit_code != 0 || cr.output.find("Error occurred") != std::string::npos) {
        log_attempt(index, server_str, "set-failed", t0, first_meaningful_lines(cr.output, 3));
        return ServerResult::SetFailed;
    }

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(cfg.server_timeout_sec);
    for (;;) {
        if (g_stop.load()) {
            run_vpncmd(cfg, {"AccountDisconnect", cfg.account_name});
            return ServerResult::SetFailed;
        }
        auto st = run_vpncmd(cfg, {"AccountStatusGet", cfg.account_name});
        if (!st.timed_out) {
            std::string status = extract_session_status(st.output);
            if (status.find("Session Established") != std::string::npos) {
                log_attempt(index, server_str, "success", t0, "");
                return ServerResult::Success;
            }
            if (status.find("Retrying") != std::string::npos) {
                run_vpncmd(cfg, {"AccountDisconnect", cfg.account_name});
                log_attempt(index, server_str, "retrying", t0, "");
                return ServerResult::Retrying;
            }
        }
        auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        if (rem <= 0) break;
        long long wait_ms = std::min<long long>((long long)cfg.poll_interval_sec * 1000, rem);
        std::unique_lock<std::mutex> lk(g_wait_mutex);
        g_cv.wait_for(lk, std::chrono::milliseconds(wait_ms), [] {
            return g_stop.load() || g_trigger.load();
        });
        if (g_trigger.load()) {
            g_trigger.store(false);
        }
    }

    run_vpncmd(cfg, {"AccountDisconnect", cfg.account_name});
    log_attempt(index, server_str, "connecting-timeout", t0, "");
    return ServerResult::ConnectingTimeout;
}

} // namespace

// ============================================================
// Internet check
// ============================================================
namespace {

bool wait_for_internet(const Config& cfg) {
    bool logged = false;
    while (!g_stop.load()) {
        if (curl_head(cfg.csv_url, cfg.internet_check_timeout_sec)) return true;
        if (!logged) {
            logger_write("WARN", "internet offline, retrying every " +
                         std::to_string(cfg.offline_retry_sec) + "s");
            logged = true;
        }
        std::unique_lock<std::mutex> lk(g_wait_mutex);
        g_cv.wait_for(lk, std::chrono::seconds(cfg.offline_retry_sec), [] {
            return g_stop.load();
        });
    }
    return false;
}

} // namespace

// ============================================================
// CSV loading
// ============================================================
namespace {

bool cache_fresh(const std::string& path, int max_minutes) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return false;
    time_t now = time(nullptr);
    return (now - st.st_mtime) < (time_t)max_minutes * 60;
}

bool read_file_string(const std::string& path, std::string& out) {
    std::ifstream f(path);
    if (!f) return false;
    std::stringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
}

void save_cache(const std::string& path, const std::string& data) {
    mkdirs_for_file(path);
    std::ofstream f(path, std::ios::trunc);
    if (f) { f << data; f.flush(); }
}

bool reload_servers(const Config& cfg, std::vector<ServerEntry>& servers, bool force_download) {
    std::string csv;
    bool used_cache = false;

    if (!force_download && cache_fresh(cfg.cache_file, cfg.csv_cache_minutes)) {
        if (read_file_string(cfg.cache_file, csv)) used_cache = true;
    }

    if (!used_cache) {
        std::string dl;
        if (curl_download(cfg.csv_url, cfg.internet_check_timeout_sec, dl)) {
            csv = std::move(dl);
            save_cache(cfg.cache_file, csv);
        } else {
            if (read_file_string(cfg.cache_file, csv)) {
                logger_write("WARN", "download failed, using cache");
            }
        }
    }

    if (csv.empty()) {
        logger_write("WARN", "no server list available");
        return false;
    }

    auto parsed = parse_csv(csv);
    if (parsed.empty()) {
        logger_write("WARN", "csv parse yielded zero servers");
        return false;
    }
    servers = std::move(parsed);
    logger_write("INFO", "loaded " + std::to_string(servers.size()) + " servers");
    return true;
}

} // namespace

// ============================================================
// Pass
// ============================================================
namespace {

bool run_pass_from(const Config& cfg, std::vector<ServerEntry>& servers, int start_idx) {
    {
        std::lock_guard<std::mutex> lk(g_wait_mutex);
        g_trigger.store(false);
    }
    for (int i = start_idx; i < (int)servers.size(); ++i) {
        if (g_stop.load()) return false;
        auto& srv = servers[(size_t)i];
        set_status_ip_port(srv.ip + ":" + std::to_string(srv.port));

        ServerResult res = try_server(cfg, srv, i);

        if (g_stop.load()) return false;

        if (res == ServerResult::Success) {
            write_state(cfg.state_file, i);
            set_status("connected", srv.ip + ":" + std::to_string(srv.port));
            g_connected.store(true);
            return true;
        }

        write_state(cfg.state_file, i + 1);
    }
    set_status("disconnected", "-");
    return false;
}

void do_keepalive(const Config& cfg) {
    WaitReason r = wait_with_wake(cfg.keepalive_interval_sec);
    if (r == WaitReason::Stop) return;
    if (r == WaitReason::Trigger) {
        g_trigger.store(false);
        g_connected.store(false);
        logger_write("INFO", "keep-alive: trigger, reconnecting");
        return;
    }
    if (r == WaitReason::Reload) {
        g_reload_wake.store(false);
        return;
    }

    auto res = run_vpncmd(cfg, {"AccountStatusGet", cfg.account_name});
    std::string status = extract_session_status(res.output);
    if (status.find("Session Established") == std::string::npos) {
        logger_write("WARN", "keep-alive: connection lost");
        g_connected.store(false);
        set_status("disconnected", "-");
    }
}

void worker_main() {
    int full_failures = 0;
    std::vector<ServerEntry> servers;

    while (!g_stop.load()) {
        if (g_reload_wake.load()) {
            g_reload_wake.store(false);
        }

        if (g_connected.load()) {
            Config cfg = get_config();
            do_keepalive(cfg);
            continue;
        }

        Config cfg = get_config();

        if (!wait_for_internet(cfg)) {
            if (g_stop.load()) return;
            continue;
        }

        if (servers.empty()) {
            if (!reload_servers(cfg, servers, true)) {
                wait_with_wake(cfg.offline_retry_sec);
                continue;
            }
        }

        int start_idx = read_state(cfg.state_file);
        bool started_at_zero = (start_idx == 0);
        if (start_idx >= (int)servers.size()) {
            start_idx = 0;
            started_at_zero = true;
        }

        set_status("pass-running", "-");
        g_pass_running.store(true);

        bool success = run_pass_from(cfg, servers, start_idx);

        g_pass_running.store(false);

        if (g_stop.load()) return;

        if (success) {
            full_failures = 0;
            continue;
        }

        if (started_at_zero) {
            ++full_failures;
        }

        reload_servers(cfg, servers, true);
        write_state(cfg.state_file, 0);
        if (servers.empty()) {
            wait_with_wake(cfg.offline_retry_sec);
            continue;
        }

        if (full_failures >= cfg.passes_before_pause) {
            logger_write("ERROR", "no server connected, pausing " +
                         std::to_string(cfg.pause_minutes) + " minutes");
            set_status("paused", "-");
            WaitReason r = wait_with_wake(cfg.pause_minutes * 60);
            if (r == WaitReason::Stop) return;
            if (r == WaitReason::Trigger) g_trigger.store(false);
            if (r == WaitReason::Reload) g_reload_wake.store(false);
            full_failures = 0;
            write_state(cfg.state_file, 0);
        }
    }
}

} // namespace

// ============================================================
// Socket server
// ============================================================
namespace {

int create_listener(const std::string& path) {
    unlink(path.c_str());
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    std::string sp = path;
    if (sp.size() >= sizeof(addr.sun_path)) sp.resize(sizeof(addr.sun_path) - 1);
    std::memcpy(addr.sun_path, sp.c_str(), sp.size() + 1);
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 5) < 0) {
        close(fd);
        return -1;
    }
    struct group* gr = getgrnam("vpnagent");
    if (gr) {
        if (chown(path.c_str(), 0, gr->gr_gid) != 0) {
            logger_write("WARN", "chown socket failed");
        }
        chmod(path.c_str(), 0660);
    } else {
        logger_write("WARN", "group vpnagent not found");
        chmod(path.c_str(), 0600);
    }
    return fd;
}

std::string handle_check() {
    if (g_pass_running.load()) return "BUSY";
    Config cfg = get_config();
    auto res = run_vpncmd(cfg, {"AccountStatusGet", cfg.account_name});
    std::string status = extract_session_status(res.output);
    if (status.find("Session Established") != std::string::npos) {
        return "CONNECTED";
    }
    g_trigger.store(true);
    wake_worker();
    return "STARTED";
}

std::string handle_status() {
    std::string state;
    std::string ip_port;
    {
        std::lock_guard<std::mutex> lk(g_status.mtx);
        state = g_status.state;
        ip_port = g_status.ip_port;
    }
    std::string last_log;
    {
        std::lock_guard<std::mutex> lk(g_log_mutex);
        last_log = g_last_log_line;
    }
    if (ip_port.empty()) ip_port = "-";
    if (last_log.empty()) last_log = "-";
    return state + " " + ip_port + " " + last_log;
}

void handle_client(int fd) {
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    char buf[512];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) { close(fd); return; }
    buf[n] = '\0';
    std::string cmd = trim(std::string(buf));

    std::string reply;
    if (cmd == "CHECK") reply = handle_check();
    else if (cmd == "STATUS") reply = handle_status();
    else if (cmd == "RELOAD") { request_reload(); reply = "OK"; }
    else reply = "ERR unknown command";

    reply += "\n";
    ssize_t w = write(fd, reply.c_str(), reply.size());
    (void)w;
    close(fd);
}

} // namespace

// ============================================================
// Signals
// ============================================================
namespace {

int g_sig_pipe[2] = {-1, -1};
volatile sig_atomic_t g_sig_stop = 0;
volatile sig_atomic_t g_sig_hup = 0;

void signal_handler(int sig) {
    if (sig == SIGHUP) g_sig_hup = 1;
    else g_sig_stop = 1;
    char c = 1;
    ssize_t r = write(g_sig_pipe[1], &c, 1);
    (void)r;
}

bool install_signals() {
    if (pipe(g_sig_pipe) != 0) return false;
    int fl = fcntl(g_sig_pipe[1], F_GETFL, 0);
    if (fl >= 0) fcntl(g_sig_pipe[1], F_SETFL, fl | O_NONBLOCK);
    fl = fcntl(g_sig_pipe[0], F_GETFL, 0);
    if (fl >= 0) fcntl(g_sig_pipe[0], F_SETFL, fl | O_NONBLOCK);

    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGTERM, &sa, nullptr) != 0) return false;
    if (sigaction(SIGINT, &sa, nullptr) != 0) return false;
    if (sigaction(SIGHUP, &sa, nullptr) != 0) return false;

    struct sigaction sp;
    std::memset(&sp, 0, sizeof(sp));
    sp.sa_handler = SIG_IGN;
    sigemptyset(&sp.sa_mask);
    if (sigaction(SIGPIPE, &sp, nullptr) != 0) return false;
    return true;
}

} // namespace

// ============================================================
// Client mode
// ============================================================
namespace {

int client_mode(const std::string& mode, const std::string& cmd) {
    Config cfg = load_config(CONFIG_PATH);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        std::fprintf(stderr, "vpnagent is not running\n");
        return 2;
    }
    struct sockaddr_un addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    std::string sp = cfg.socket_path;
    if (sp.size() >= sizeof(addr.sun_path)) sp.resize(sizeof(addr.sun_path) - 1);
    std::memcpy(addr.sun_path, sp.c_str(), sp.size() + 1);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        std::fprintf(stderr, "vpnagent is not running\n");
        return 2;
    }

    std::string req = cmd + "\n";
    if (write(fd, req.c_str(), req.size()) < 0) {
        close(fd);
        std::fprintf(stderr, "vpnagent is not running\n");
        return 2;
    }

    std::string reply;
    char buf[512];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        reply.append(buf, (size_t)n);
    }
    close(fd);

    while (!reply.empty() && (reply.back() == '\n' || reply.back() == '\r')) {
        reply.pop_back();
    }
    std::printf("%s\n", reply.c_str());

    if (mode == "--check") {
        if (reply == "STARTED" || reply == "CONNECTED" || reply == "BUSY") return 0;
        return 1;
    }
    if (reply.compare(0, 3, "ERR") == 0) return 1;
    return 0;
}

} // namespace

// ============================================================
// Daemon
// ============================================================
namespace {

int acquire_pid_lock(const std::string& path) {
    mkdirs_for_file(path);
    int fd = open(path.c_str(), O_RDWR | O_CREAT, 0644);
    if (fd < 0) return -1;
    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        if (errno == EWOULDBLOCK) {
            std::fprintf(stderr, "already running\n");
            close(fd);
            return -2;
        }
        close(fd);
        return -1;
    }
    if (ftruncate(fd, 0) != 0) { /* ignore */ }
    std::string pid_str = std::to_string(getpid()) + "\n";
    ssize_t w = write(fd, pid_str.c_str(), pid_str.size());
    (void)w;
    return fd;
}

struct CurlGlobal {
    CurlGlobal() { curl_global_init(CURL_GLOBAL_DEFAULT); }
    ~CurlGlobal() { curl_global_cleanup(); }
    CurlGlobal(const CurlGlobal&) = delete;
    CurlGlobal& operator=(const CurlGlobal&) = delete;
};

int daemon_main() {
    if (geteuid() != 0) {
        std::fprintf(stderr, "vpnagent must be run as root\n");
        return 1;
    }

    mkdirs("/etc/vpnagent");
    mkdirs("/var/lib/vpnagent");

    Config cfg = load_config(CONFIG_PATH);

    {
        std::lock_guard<std::mutex> lk(g_log_mutex);
        g_log_file = cfg.log_file;
        g_log_max_kb = cfg.max_size_kb;
    }
    set_config(cfg);

    if (access(cfg.vpncmd_path.c_str(), X_OK) != 0) {
        logger_write("ERROR", "vpncmd not executable: " + cfg.vpncmd_path);
        std::fprintf(stderr, "vpncmd not executable: %s\n", cfg.vpncmd_path.c_str());
        return 1;
    }

    CurlGlobal curl_global;

    int pid_fd = acquire_pid_lock(cfg.pid_file);
    if (pid_fd == -2) return 1;
    if (pid_fd < 0) {
        std::fprintf(stderr, "cannot lock pid file\n");
        return 1;
    }

    if (!install_signals()) {
        std::fprintf(stderr, "cannot install signals\n");
        close(pid_fd);
        return 1;
    }

    FileDescriptor listener(create_listener(cfg.socket_path));
    if (!listener) {
        std::fprintf(stderr, "cannot bind socket\n");
        close(pid_fd);
        return 1;
    }

    logger_write("INFO", "vpnagent started");

    std::thread worker(worker_main);

    bool running = true;
    while (running) {
        if (g_stop.load()) break;
        struct pollfd fds[2];
        fds[0].fd = listener.get();
        fds[0].events = POLLIN;
        fds[0].revents = 0;
        fds[1].fd = g_sig_pipe[0];
        fds[1].events = POLLIN;
        fds[1].revents = 0;

        int pr = poll(fds, 2, 500);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (fds[1].revents & POLLIN) {
            char drain[64];
            while (read(g_sig_pipe[0], drain, sizeof(drain)) > 0) {}
            if (g_sig_stop) {
                g_stop.store(true);
                wake_worker();
                running = false;
            }
            if (g_sig_hup) {
                g_sig_hup = 0;
                request_reload();
            }
        }

        if (fds[0].revents & POLLIN) {
            int cfd = accept(listener.get(), nullptr, nullptr);
            if (cfd >= 0) handle_client(cfd);
        }

        if (g_stop.load()) break;
    }

    g_stop.store(true);
    wake_worker();
    wake_worker();

    listener.reset();
    unlink(cfg.socket_path.c_str());

    if (worker.joinable()) worker.join();

    close(pid_fd);
    unlink(cfg.pid_file.c_str());

    logger_write("INFO", "vpnagent stopped");
    return 0;
}

} // namespace

// ============================================================
// main
// ============================================================
int main(int argc, char** argv) {
    if (argc >= 2) {
        std::string arg = argv[1];
        if (arg == "--check") return client_mode("--check", "CHECK");
        if (arg == "--status") return client_mode("--status", "STATUS");
        if (arg == "--reload") return client_mode("--reload", "RELOAD");
    }
    return daemon_main();
}

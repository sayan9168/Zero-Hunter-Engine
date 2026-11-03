/*
 * Zero-Hunter-Engine v3.0 - Checksum-Guarded Binary Container Benchmark (vuln_vault)
 * Educational & Authorized Defensive Security Research Only
 *
 * Frame format (minimum 12 bytes):
 *   [0..3]  Magic "ZHV3"
 *   [4..5]  uint16_t body_len (LE)
 *   [6..9]  uint32_t crc32(data[10 .. len-1]) (IEEE 802.3 CRC32, LE)
 *   [10]    uint8_t  record_type
 *   [11]    uint8_t  flags
 *   [12..]  body bytes
 *
 * Demonstrates Checksum-Aware Fuzzing + UBSan + ASan + CmpLog discovering bugs
 * hidden behind a 32-bit CRC32 integrity check.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t compute_crc32(const uint8_t *buf, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= buf[i];
        for (int b = 0; b < 8; b++) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

__attribute__((noinline))
static int handle_quota_calc(const uint8_t *body, size_t len) {
    if (len < 4) return 0;
    int32_t units = 0;
    memcpy(&units, body, 4);
    /* Bug 1: Signed 32-bit integer overflow (caught by UBSan -fsanitize=undefined!) */
    if (units > 40000) {
        int32_t total_bytes = units * 65537;
        return (total_bytes < 0) ? 1 : 0;
    }
    return 0;
}

__attribute__((noinline))
static int handle_heartbeat_read(const uint8_t *body, size_t len, uint16_t declared_len) {
    char *heap_pkt = (char *)malloc(len > 0 ? len : 1);
    if (!heap_pkt) return 0;
    if (len > 0) memcpy(heap_pkt, body, len);

    /* Bug 2: Heartbleed-style Out-of-Bounds Heap Read (CWE-125) when declared_len > len */
    volatile uint8_t acc = 0;
    for (uint16_t i = 0; i < declared_len; i++) {
        acc ^= (uint8_t)heap_pkt[i];
    }
    free(heap_pkt);
    return (int)acc;
}

__attribute__((noinline))
static int handle_rle_unpack(const uint8_t *body, size_t len) {
    if (len < 2) return 0;
    char out_buf[32];
    size_t out_pos = 0;
    /* Bug 3: RLE expansion Heap/Stack Buffer Overflow (CWE-787) */
    for (size_t i = 0; i + 1 < len; i += 2) {
        uint8_t count = body[i];
        char sym = (char)body[i + 1];
        if (count > 48) count = 48;
        memset(out_buf + out_pos, sym, count);
        out_pos += count;
    }
    return (int)(out_pos & 0xFF);
}

int parse_vault(const uint8_t *data, size_t len) {
    if (len < 12) return 0;
    if (memcmp(data, "ZHV3", 4) != 0) {
        return 0;
    }

    uint16_t declared_len = 0;
    uint32_t expected_crc = 0;
    memcpy(&declared_len, data + 4, 2);
    memcpy(&expected_crc, data + 6, 4);

    uint32_t actual_crc = compute_crc32(data + 10, len - 10);
    if (actual_crc != expected_crc) {
        return 1; /* Rejected by CRC32 gate! */
    }

    uint8_t rec_type = data[10];
    const uint8_t *body = data + 12;
    size_t body_len = len - 12;

    if (rec_type == 0x10) {
        return handle_quota_calc(body, body_len);
    }
    if (rec_type == 0x20 && declared_len > 8) {
        return handle_heartbeat_read(body, body_len, declared_len);
    }
    if (rec_type == 0x30) {
        return handle_rle_unpack(body, body_len);
    }
    return 0;
}

int main(int argc, char **argv) {
    FILE *fp = stdin;
    int close_fp = 0;
    if (argc >= 2 && strcmp(argv[1], "-") != 0) {
        fp = fopen(argv[1], "rb");
        if (!fp) return 1;
        close_fp = 1;
    }
    uint8_t buf[4096];
    size_t n = fread(buf, 1, sizeof(buf), fp);
    if (close_fp) fclose(fp);
    return parse_vault(buf, n);
}

/*
 * Zero-Hunter-Engine - Multi-Bug Coverage & CmpLog Benchmark Target (vuln_maze)
 * Educational & Authorized Defensive Security Research Only
 *
 * Intentionally contains gated paths with distinct memory safety bugs:
 *   1. Heap Buffer Overflow   (CWE-787)
 *   2. Heap Use-After-Free    (CWE-416)
 *   3. Double Free            (CWE-415)
 *   4. Stack Buffer Overflow  (CWE-787)
 *   5. NULL Dereference       (CWE-476)
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char name[16];
    uint32_t flags;
    void (*callback)(const char *);
} session_obj_t;

static void safe_cb(const char *msg) {
    if (msg) {
        printf("Session msg: %.8s\n", msg);
    }
}

__attribute__((noinline))
static void trigger_heap_overflow(const uint8_t *payload, size_t len) {
    char *chunk = (char *)malloc(24);
    if (!chunk) return;
    /* Bug 1: Unbounded memcpy into 24-byte heap buffer */
    memcpy(chunk, payload, len);
    printf("Chunk: %.8s\n", chunk);
    free(chunk);
}

__attribute__((noinline))
static void trigger_use_after_free(const uint8_t *payload, size_t len) {
    session_obj_t * volatile sess = (session_obj_t *)malloc(sizeof(session_obj_t));
    if (!sess) return;
    memset(sess, 0, sizeof(*sess));
    sess->callback = safe_cb;
    if (len > 4) {
        free(sess); /* Premature free on error path */
    }
    /* Bug 2: Write + read after free */
    sess->flags = (uint32_t)payload[0] | 0x41410000u;
    if (sess->flags == 0xdeadbeefu) {
        sess->callback("uaf");
    }
    if (len <= 4) {
        free(sess);
    }
}

__attribute__((noinline))
static void trigger_double_free(const uint8_t *payload, size_t len) {
    char *buf = (char *)malloc(32);
    if (!buf) return;
    memcpy(buf, payload, len < 16 ? len : 16);
    free(buf);
    if (len > 6 && payload[0] == '!') {
        /* Bug 3: Double free */
        free(buf);
    }
}

__attribute__((noinline))
static void trigger_stack_overflow(const uint8_t *payload, size_t len) {
    char stack_buf[32];
    /* Bug 4: Stack buffer overflow when len > 32 */
    memcpy(stack_buf, payload, len);
    stack_buf[31] = '\0';
    printf("Stack: %s\n", stack_buf);
}

__attribute__((noinline))
static void trigger_null_deref(uint32_t val) {
    volatile uint32_t * volatile ptr = NULL;
    if (val == 0xbad00000u) {
        /* Bug 5: NULL pointer write */
        *ptr = val;
    }
}

int parse_packet(const uint8_t *data, size_t len) {
    if (len < 8) return 0;

    /* Gate 1: 4-byte magic header (solvable via CmpLog memcmp hook) */
    if (memcmp(data, "ZH26", 4) != 0) {
        return 0;
    }

    uint8_t opcode = data[4];
    uint8_t subop  = data[5];
    uint16_t plen  = 0;
    memcpy(&plen, data + 6, sizeof(uint16_t));

    const uint8_t *body = data + 8;
    size_t body_len = len - 8;

    /* Gate 2: Opcode dispatch */
    if (opcode == 'H' && body_len >= 4) {
        uint32_t token = 0;
        memcpy(&token, body, 4);
        if (token == 0x1337c0deu && body_len > 28) {
            trigger_heap_overflow(body + 4, body_len - 4);
        }
        return 1;
    }

    if (opcode == 'U' && subop == 'F') {
        if (body_len >= 6 && memcmp(body, "FREE", 4) == 0) {
            trigger_use_after_free(body + 4, body_len - 4);
        }
        return 2;
    }

    if (opcode == 'D' && body_len >= 8) {
        trigger_double_free(body, body_len);
        return 3;
    }

    if (opcode == 'S' && plen > 40 && body_len > 40) {
        trigger_stack_overflow(body, body_len);
        return 4;
    }

    if (opcode == 'N' && body_len >= 4) {
        uint32_t code = 0;
        memcpy(&code, body, 4);
        trigger_null_deref(code);
        return 5;
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

    return parse_packet(buf, n);
}

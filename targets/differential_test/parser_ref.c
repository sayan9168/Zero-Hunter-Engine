/*
 * Zero-Hunter-Engine v3.0 - Differential Fuzzing Reference Implementation (parser_ref)
 * Educational & Authorized Defensive Security Research Only
 *
 * Strictly validates token packet:
 *   "TOK:" + uint32_t requested_credits (LE) + uint8_t role
 *   Allows ONLY when role == 'U' and 1 <= requested_credits <= 1000.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    FILE *fp = stdin;
    int close_fp = 0;
    if (argc >= 2 && strcmp(argv[1], "-") != 0) {
        fp = fopen(argv[1], "rb");
        if (!fp) return 1;
        close_fp = 1;
    }

    uint8_t buf[256];
    size_t n = fread(buf, 1, sizeof(buf), fp);
    if (close_fp) fclose(fp);

    if (n < 9 || memcmp(buf, "TOK:", 4) != 0) {
        printf("REJECT:FORMAT\n");
        return 1;
    }

    uint32_t credits = 0;
    memcpy(&credits, buf + 4, 4);
    uint8_t role = buf[8];

    if (role == 'U' && credits >= 1u && credits <= 1000u) {
        printf("ALLOW:%u\n", credits);
        return 0;
    }

    printf("DENY\n");
    return 2;
}

/*
 * Zero-Hunter-Engine v3.0 - Buggy Candidate Implementation (parser_buggy)
 * Educational & Authorized Defensive Security Research Only
 *
 * Contains a NON-CRASHING 16-bit integer truncation logic flaw:
 * Checks `(uint16_t)credits <= 1000` instead of full 32-bit `credits`,
 * allowing e.g. credits = 65537 (0x00010001 -> low16 = 1) to bypass the quota cap!
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

    /* Subtle logic bug: 16-bit truncation check approves 65537+ credits! */
    uint16_t truncated_check = (uint16_t)(credits & 0xFFFFu);
    if (role == 'U' && truncated_check >= 1u && truncated_check <= 1000u) {
        printf("ALLOW:%u\n", credits);
        return 0;
    }

    printf("DENY\n");
    return 2;
}

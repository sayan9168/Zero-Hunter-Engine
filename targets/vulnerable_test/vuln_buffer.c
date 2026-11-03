#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function(const char *input, size_t len) {
    char buffer[64];          // Small stack buffer
    if (len > 0 && input[0] == 'Z' && len > 4 && memcmp(input, "ZERO", 4) == 0) {
        // Secondary branch for coverage demonstration
        char tag[24];
        memcpy(tag, input + 4, len - 4);
        tag[23] = '\0';
        printf("Tag: %s\n", tag);
    }
    strcpy(buffer, input);    // Classic buffer overflow (no bounds check)
    printf("Received: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    FILE *fp = stdin;
    int close_fp = 0;

    if (argc >= 2 && strcmp(argv[1], "-") != 0) {
        fp = fopen(argv[1], "rb");
        if (!fp) {
            perror("fopen");
            return 1;
        }
        close_fp = 1;
    }

    size_t cap = 4096;
    char *data = malloc(cap + 1);
    if (!data) {
        if (close_fp) fclose(fp);
        return 1;
    }

    size_t size = fread(data, 1, cap, fp);
    data[size] = '\0';
    if (close_fp) fclose(fp);

    vulnerable_function(data, size);
    free(data);
    return 0;
}

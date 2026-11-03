#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function(char *input) {
    char buffer[64];          // Small stack buffer
    strcpy(buffer, input);    // Classic buffer overflow (no bounds check)
    printf("Received: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *data = malloc(size + 1);
    if (!data) {
        fclose(fp);
        return 1;
    }

    fread(data, 1, size, fp);
    data[size] = '\0';
    fclose(fp);

    vulnerable_function(data);
    free(data);
    return 0;
}

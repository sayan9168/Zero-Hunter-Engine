/*
 * Zero-Hunter-Engine - Safe Loopback Network Protocol Test Target (vuln_net)
 * Educational & Authorized Defensive Security Research Only
 *
 * Binds strictly to 127.0.0.1 for local network protocol fuzzing tests.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

__attribute__((noinline))
static void handle_protocol_frame(const uint8_t *buf, ssize_t n, int client_fd) {
    if (n < 4) {
        const char *err = "ERR SHORT\n";
        (void)send(client_fd, err, strlen(err), 0);
        return;
    }

    if (memcmp(buf, "PING", 4) == 0) {
        const char *pong = "PONG\n";
        (void)send(client_fd, pong, strlen(pong), 0);
        return;
    }

    /* Binary ZHTP frame: "ZHTP" + uint16_t declared_len + payload */
    if (memcmp(buf, "ZHTP", 4) == 0 && n >= 6) {
        uint16_t declared_len = 0;
        memcpy(&declared_len, buf + 4, 2);
        char frame_buf[48];
        /* Intentional vulnerability: trusts declared_len / network length without clamping to 48! */
        size_t copy_n = (declared_len > 0 && declared_len <= (uint16_t)(n - 6))
                            ? declared_len
                            : (size_t)(n - 6);
        memcpy(frame_buf, buf + 6, copy_n);
        const char *ok = "OK ZHTP\n";
        (void)send(client_fd, ok, strlen(ok), 0);
        return;
    }

    /* Text command AUTH <username> */
    if (n > 5 && memcmp(buf, "AUTH ", 5) == 0) {
        char user[32];
        /* Intentional stack overflow on long username */
        memcpy(user, buf + 5, (size_t)(n - 5));
        const char *ok = "OK AUTH\n";
        (void)send(client_fd, ok, strlen(ok), 0);
        return;
    }

    const char *unk = "ERR UNKNOWN\n";
    (void)send(client_fd, unk, strlen(unk), 0);
}

int main(int argc, char **argv) {
    int port = 9999;
    int once = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--once") == 0) {
            once = 1;
        }
    }

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* Strictly 127.0.0.1 */

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(srv);
        return 1;
    }

    if (listen(srv, 64) < 0) {
        perror("listen");
        close(srv);
        return 1;
    }

    printf("[vuln_net] Listening on 127.0.0.1:%d\n", port);
    fflush(stdout);

    while (1) {
        int client = accept(srv, NULL, NULL);
        if (client < 0) continue;

        uint8_t buf[2048];
        ssize_t n = recv(client, buf, sizeof(buf), 0);
        if (n > 0) {
            handle_protocol_frame(buf, n, client);
        }
        close(client);
        if (once) break;
    }

    close(srv);
    return 0;
}

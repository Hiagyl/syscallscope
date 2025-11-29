#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int main() {
    printf("[TEST] connect to 8.8.8.8:4444\n");

    int sock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4444);
    inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);

    connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    perror("connect");

    close(sock);
    return 0;
}

// client.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>

#define BUFFER_SIZE 1024

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <Server_IP> <Server_Port>\n", argv[0]);
        return 1;
    }

    char *server_ip = argv[1];
    int server_port = atoi(argv[2]);

    // 建立 socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("Socket creation failed");
        return 1;
    }

    // 設定 server 地址
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0)
    {
        perror("Invalid address/ Address not supported");
        close(sockfd);
        return 1;
    }

    // 連接到 server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Connection Failed");
        close(sockfd);
        return 1;
    }

    // 不顯示任何額外訊息
    // printf("Connected to server %s:%d\n", server_ip, server_port);
    // printf("Type your messages below. Type 'Exit' to quit.\n");

    // 使用 select 來同時監聽 stdin 和 socket
    while (1)
    {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds); // 標準輸入
        FD_SET(sockfd, &read_fds);       // socket

        int max_fd = sockfd > STDIN_FILENO ? sockfd : STDIN_FILENO;

        // 等待其中一個文件描述符有可讀事件
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, NULL);

        if (activity < 0)
        {
            perror("select error");
            break;
        }

        // 檢查是否有來自標準輸入的訊息
        if (FD_ISSET(STDIN_FILENO, &read_fds))
        {
            // 留出1個字元給 null terminator
            char input[BUFFER_SIZE - 1];
            if (fgets(input, sizeof(input), stdin) == NULL)
            {
                // EOF 或錯誤
                break;
            }

            // 移除換行符
            input[strcspn(input, "\n")] = 0;

            // 檢查是否退出
            if (strcmp(input, "Exit") == 0)
            {
                // 發送 "Exit" 給 Server
                ssize_t bytes_sent = send(sockfd, input, strlen(input), 0);
                if (bytes_sent < 0)
                {
                    perror("Send failed");
                }
                // 等待接收 "Bye" 後關閉
                break;
            }

            // 準備訊息，不加上 <CRLF>
            char message[BUFFER_SIZE];
            // 使用 snprintf 並確保不會超過 buffer 大小
            int ret = snprintf(message, sizeof(message), "%s", input);
            if (ret < 0)
            {
                perror("snprintf error");
                break;
            }
            else if (ret >= sizeof(message))
            {
                // 訊息被截斷
                // 這裡根據需要可以選擇繼續或中斷
                // 目前選擇繼續
            }

            // 發送訊息到 server
            ssize_t bytes_sent = send(sockfd, message, strlen(message), 0);
            if (bytes_sent < 0)
            {
                perror("Send failed");
                break;
            }
        }

        // 檢查是否有來自 socket 的訊息
        if (FD_ISSET(sockfd, &read_fds))
        {
            char buffer[BUFFER_SIZE];
            ssize_t bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received < 0)
            {
                perror("Receive failed");
                break;
            }
            else if (bytes_received == 0)
            {
                // 伺服器關閉連接
                // printf("Server closed the connection.\n");
                break;
            }

            buffer[bytes_received] = '\0';
            printf("%s\n", buffer);

            // 如果收到 "Bye"，則退出循環
            if (strcmp(buffer, "Bye") == 0 || strcmp(buffer, "Bye\r\n") == 0)
            {
                break;
            }
        }
    }

    // 關閉 socket
    close(sockfd);
    return 0;
}

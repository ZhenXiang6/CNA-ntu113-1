#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

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

    // create socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("socket");
        return 1;
    }

    // set server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0)
    {
        perror("inet_pton");
        return 1;
    }

    // connect to server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("connect");
        return 1;
    }

    printf("Connected to server %s:%d\n", server_ip, server_port);

    // menu while loop
    while (1)
    {
        printf("\n=== Main Menu ===\n");
        printf("1. Register\n");
        printf("2. Login\n");
        printf("3. Exit\n");
        printf("Choose an option: ");

        int choice;
        scanf("%d", &choice);
        getchar(); // clear change line

        if (choice == 1)
        {
            // register function
            char username[50];
            printf("Enter username: ");
            fgets(username, sizeof(username), stdin);
            username[strcspn(username, "\n")] = 0; // remove change line

            char message[BUFFER_SIZE];
            snprintf(message, sizeof(message), "REGISTER#%s\r\n", username);
            send(sockfd, message, strlen(message), 0);

            char buffer[BUFFER_SIZE];
            int bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received > 0)
            {
                buffer[bytes_received] = '\0';
                if (strncmp(buffer, "100 OK", 6) == 0)
                {
                    printf("Registration successful.\n");
                }
                else if (strncmp(buffer, "210 FAIL", 7) == 0)
                {
                    printf("Registration failed.\n");
                }
                else
                {
                    printf("Unknown response: %s\n", buffer);
                }
            }
        }
        else if (choice == 2)
        {
            // login function
            char username[50];
            int portNum;
            printf("Enter username: ");
            fgets(username, sizeof(username), stdin);
            username[strcspn(username, "\n")] = 0; // remove change line

            printf("Enter port number: ");
            scanf("%d", &portNum);
            getchar(); // clear change line

            char message[BUFFER_SIZE];
            snprintf(message, sizeof(message), "%s#%d\r\n", username, portNum);
            send(sockfd, message, strlen(message), 0);

            char buffer[BUFFER_SIZE];
            int bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received > 0)
            {
                buffer[bytes_received] = '\0';
                if (strncmp(buffer, "220 AUTH_FAIL", 13) == 0)
                {
                    printf("Authentication failed.\n");
                }
                else
                {
                    // login success，show account remainder、online list etc.
                    printf("Login successful. Server response:\n%s\n", buffer);
                    // other processing
                }
            }
        }
        else if (choice == 3)
        {
            // offline function
            char exit_msg[] = "Exit\r\n";
            send(sockfd, exit_msg, strlen(exit_msg), 0);

            char buffer[BUFFER_SIZE];
            int bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received > 0)
            {
                buffer[bytes_received] = '\0';
                if (strncmp(buffer, "Bye", 3) == 0)
                {
                    printf("Successfully exited.\n");
                }
                else
                {
                    printf("Unknown response: %s\n", buffer);
                }
            }
            break;
        }
        else
        {
            printf("Invalid option. Please try again.\n");
        }
    }

    close(sockfd);
    return 0;
}

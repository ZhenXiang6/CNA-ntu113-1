// server.cpp

// C 庫
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>

// C++ 庫
#include <string>
#include <algorithm>
#include <iostream>
#include <vector>
#include <sstream>
#include <mutex>

// OpenSSL 庫
#include <openssl/ssl.h>
#include <openssl/err.h>

#define WORKER_COUNT 64
#define WORKER_IDLE 0
#define WORKER_WORKING 1
#define BUFFER_SIZE 4096
#define SERVER_PUBLIC_KEY "INFORMATION_MANAGEMENT"

struct User {
    std::string name;
    int balance = 10000;
    bool logged_in = false;
    std::string hostname;
    int p2p_port = -1;
};

class Server {
public:
    Server(int port);
    ~Server();
    void run();

private:
    int server_fd;
    int hosting_port;
    struct sockaddr_in address;
    socklen_t addrlen;
    std::vector<User> users;
    pthread_t workers[WORKER_COUNT];
    int worker_status[WORKER_COUNT];
    int worker_sockets[WORKER_COUNT];
    SSL* worker_ssls[WORKER_COUNT];
    char worker_buffer[WORKER_COUNT][BUFFER_SIZE];
    std::mutex user_mutex;

    SSL_CTX* ssl_ctx;

    static void signal_handler(int signum);
    void setup_signal_handler();
    std::string generate_list(int user_index);
    static void* handle_client(void* arg);
    int find_idle_worker();
    void close_worker(int index);
};

// 全局指針，用於信號處理
Server* global_server_ptr = nullptr;

// Constructor
Server::Server(int port) : hosting_port(port), addrlen(sizeof(address)), ssl_ctx(nullptr) {
    // 初始化工作者狀態為閒置
    std::fill_n(worker_status, WORKER_COUNT, WORKER_IDLE);
    std::fill_n(worker_sockets, WORKER_COUNT, -1);
    std::fill_n(worker_ssls, WORKER_COUNT, nullptr);

    // 初始化 OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // 創建 SSL_CTX
    const SSL_METHOD* method = TLS_server_method();
    ssl_ctx = SSL_CTX_new(method);
    if (ssl_ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // 載入伺服器憑證和私鑰
    if (SSL_CTX_use_certificate_file(ssl_ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "server.key", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // 驗證私鑰是否與憑證相符
    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        exit(EXIT_FAILURE);
    }

    // 創建 socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 設置 socket 選項
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // 綁定 socket 到指定端口
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(hosting_port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // 監聽連接
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    std::cout << "Server listening on port " << hosting_port << std::endl;
}

// Destructor
Server::~Server() {
    // 關閉所有工作者的 SSL 連線與 socket
    for (int i = 0; i < WORKER_COUNT; ++i) {
        if (worker_ssls[i]) {
            SSL_shutdown(worker_ssls[i]);
            SSL_free(worker_ssls[i]);
            worker_ssls[i] = nullptr;
        }
        if (worker_sockets[i] > 0) {
            close(worker_sockets[i]);
            worker_sockets[i] = -1;
        }
    }

    // 關閉伺服器 socket
    close(server_fd);

    // 釋放 SSL_CTX
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = nullptr;
    }

    // 清理 OpenSSL
    EVP_cleanup();
}

// 設置信號處理器
void Server::setup_signal_handler() {
    global_server_ptr = this;
    signal(SIGINT, Server::signal_handler);
}

// 靜態信號處理器
void Server::signal_handler(int signum) {
    if (global_server_ptr) {
        close(global_server_ptr->server_fd);
        std::cout << "\nServer terminated gracefully." << std::endl;
        exit(EXIT_SUCCESS);
    }
}

// 生成在線用戶列表和伺服器信息
std::string Server::generate_list(int user_index) {
    if (user_index < 0 || user_index >= users.size() || !users[user_index].logged_in) {
        return "500 Internal Error\r\n";
    }

    std::stringstream ss;
    ss << users[user_index].balance << "\n";
    ss << SERVER_PUBLIC_KEY << "\n";

    std::vector<User> online_users;
    for (const auto& user : users) {
        if (user.logged_in) {
            online_users.push_back(user);
        }
    }

    ss << online_users.size() << "\n";
    for (const auto& user : online_users) {
        ss << user.name << '#' << user.hostname << '#' << user.p2p_port << "\r\n";
    }

    return ss.str();
}

// 靜態成員函數處理客戶端連接
void* Server::handle_client(void* arg) {
    int worker_index = *((int*)arg);
    free(arg);

    // 獲取伺服器實例
    Server* server = global_server_ptr;

    SSL* ssl = server->worker_ssls[worker_index];
    if (!ssl) {
        std::cerr << "SSL is null for worker " << worker_index << std::endl;
        server->close_worker(worker_index);
        pthread_exit(NULL);
    }

    int client_socket = server->worker_sockets[worker_index];
    char client_host[32];
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    // 獲取客戶端地址信息
    if (getpeername(client_socket, (struct sockaddr*)&client_addr, &client_len) == -1) {
        perror("getpeername failed");
        server->close_worker(worker_index);
        pthread_exit(NULL);
    }

    inet_ntop(AF_INET, &client_addr.sin_addr, client_host, sizeof(client_host));
    int client_port = ntohs(client_addr.sin_port);

    std::cout << "Worker " << worker_index << " handling client from " << client_host << ":" << client_port << std::endl;

    int login_status = -1;
    char buffer[BUFFER_SIZE];

    while (true) {
        memset(buffer, 0, BUFFER_SIZE);
        int message_len = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        if (message_len <= 0) {
            std::cout << "Worker " << worker_index << " client disconnected." << std::endl;
            break;
        }

        std::string clean_message(buffer, message_len);

        // 移除換行符號
        clean_message.erase(std::remove(clean_message.begin(), clean_message.end(), '\n'), clean_message.end());
        clean_message.erase(std::remove(clean_message.begin(), clean_message.end(), '\r'), clean_message.end());

        std::cout << "Worker " << worker_index << " received: " << clean_message << std::endl;

        std::string return_message = "290 Server failed to handle\r\n";

        if (clean_message == "Exit") {
            return_message = "Bye\r\n";
            if (login_status >= 0) {
                std::lock_guard<std::mutex> lock(server->user_mutex);
                server->users[login_status].logged_in = false;
            }
            SSL_write(ssl, return_message.c_str(), return_message.length());
            break;
        }
        else if (clean_message == "List") {
            if (login_status < 0) {
                return_message = "230 Unauthorized\r\n";
            }
            else {
                return_message = server->generate_list(login_status);
            }
        }
        else if (clean_message.find("REGISTER#") == 0) {
            std::string new_username = clean_message.substr(clean_message.find('#') + 1);
            bool error_flag = false;

            {
                std::lock_guard<std::mutex> lock(server->user_mutex);
                for (const auto& user : server->users) {
                    if (user.name == new_username) {
                        error_flag = true;
                        break;
                    }
                }

                if (error_flag) {
                    return_message = "210 FAIL\r\n";
                }
                else {
                    User new_user;
                    new_user.name = new_username;
                    server->users.push_back(new_user);
                    return_message = "100 OK\r\n";
                    std::cout << "New user registered: " << new_user.name << std::endl;
                }
            }
        }
        else if (std::count(clean_message.begin(), clean_message.end(), '#') == 2) {
            std::string sender_name, amount_str, receiver_name;
            std::stringstream ss(clean_message);
            std::getline(ss, sender_name, '#');
            std::getline(ss, amount_str, '#');
            std::getline(ss, receiver_name, '#');

            if (login_status < 0) {
                return_message = "230 Unauthorized\r\n";
            }
            else if (receiver_name != server->users[login_status].name) {
                return_message = "250 Forbidden\r\n";
            }
            else {
                int amount = std::stoi(amount_str);
                bool transaction_success = false;

                {
                    std::lock_guard<std::mutex> lock(server->user_mutex);
                    for (auto& user : server->users) {
                        if (user.name == sender_name) {
                            if (user.balance >= amount) {
                                user.balance -= amount;
                                server->users[login_status].balance += amount;
                                return_message = "100 OK\r\n";
                                transaction_success = true;
                                break;
                            }
                            else {
                                return_message = "270 Insufficient Funds\r\n";
                                transaction_success = true;
                                break;
                            }
                        }
                    }
                }

                if (!transaction_success) {
                    return_message = "260 User Not Found\r\n";
                }
            }
        }
        else if (std::count(clean_message.begin(), clean_message.end(), '#') == 1) {
            std::string username, port_string;
            std::stringstream ss(clean_message);
            std::getline(ss, username, '#');
            std::getline(ss, port_string, '#');

            int port = std::stoi(port_string);
            bool valid_user = false;

            {
                std::lock_guard<std::mutex> lock(server->user_mutex);
                for (size_t i = 0; i < server->users.size(); ++i) {
                    if (server->users[i].name == username && !server->users[i].logged_in && login_status < 0) {
                        server->users[i].logged_in = true;
                        server->users[i].p2p_port = port;
                        server->users[i].hostname = std::string(client_host);
                        login_status = i;
                        return_message = server->generate_list(login_status);
                        valid_user = true;
                        std::cout << "User " << username << " logged in from " << client_host << ":" << port << std::endl;
                        break;
                    }
                }
            }

            if (!valid_user) {
                return_message = "220 AUTH_FAIL\r\n";
            }
        }
        else {
            return_message = "240 Format Error\r\n";
        }

        SSL_write(ssl, return_message.c_str(), return_message.length());
    }

    std::cout << "Worker " << worker_index << " terminating." << std::endl;
    server->close_worker(worker_index);
    pthread_exit(NULL);
}

// 找到一個閒置的工作者
int Server::find_idle_worker() {
    for (int i = 0; i < WORKER_COUNT; ++i) {
        if (worker_status[i] == WORKER_IDLE) {
            return i;
        }
    }
    return -1; // 沒有閒置的工作者
}

// 關閉一個工作者的連接並標記為閒置
void Server::close_worker(int index) {
    if (worker_ssls[index]) {
        SSL_shutdown(worker_ssls[index]);
        SSL_free(worker_ssls[index]);
        worker_ssls[index] = nullptr;
    }

    if (worker_sockets[index] > 0) {
        close(worker_sockets[index]);
        worker_sockets[index] = -1;
    }

    worker_status[index] = WORKER_IDLE;
    std::cout << "Worker " << index << " marked as idle." << std::endl;
}

// 運行服務器，接受並處理連接
void Server::run() {
    setup_signal_handler();

    while (true) {
        int idle_worker = find_idle_worker();
        if (idle_worker == -1) {
            // 沒有閒置的工作者，等待
            usleep(1000); // 1ms
            continue;
        }

        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("Accept failed");
            continue;
        }

        std::cout << "Accepted new connection on worker " << idle_worker << std::endl;

        // 使用 SSL 包裝連線
        SSL* ssl = SSL_new(ssl_ctx);
        if (!ssl) {
            ERR_print_errors_fp(stderr);
            close(client_socket);
            continue;
        }

        SSL_set_fd(ssl, client_socket);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_socket);
            continue;
        }

        // 分配資源給工作者
        worker_sockets[idle_worker] = client_socket;
        worker_ssls[idle_worker] = ssl;
        worker_status[idle_worker] = WORKER_WORKING;

        // 分配線程處理客戶端
        int* arg = (int*)malloc(sizeof(*arg));
        if (arg == NULL) {
            fprintf(stderr, "Couldn't allocate memory for thread arg.\n");
            close_worker(idle_worker);
            continue;
        }
        *arg = idle_worker;

        int ret = pthread_create(&workers[idle_worker], NULL, Server::handle_client, arg);
        if (ret) {
            perror("Failed to create thread");
            close_worker(idle_worker);
            free(arg);
            continue;
        }

        pthread_detach(workers[idle_worker]);
    }
}

int main(int argc, char const *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <Port>" << std::endl;
        return EXIT_FAILURE;
    }

    int port = atoi(argv[1]);
    Server server(port);
    server.run();

    return 0;
}

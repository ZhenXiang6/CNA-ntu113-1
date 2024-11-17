// client.cpp

// C 庫
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>

// C++ 庫
#include <iostream>
#include <sstream>
#include <vector>
#include <string>

#define BUFFER_SIZE 1024

// 用於存儲在線用戶信息的結構體
struct ActiveUser {
    std::string username;
    std::string host;
    int port;
};

// 前置聲明 Client 類
class Client;

// 全局指針，用於信號處理器訪問 Client 實例
Client* global_client_ptr = nullptr;

// Client 類，封裝客戶端功能
class Client {
public:
    Client() : server_socket(-1), p2p_socket(-1), is_running(true), p2p_port_number(0) {
        // 初始化互斥鎖
        if (pthread_mutex_init(&mutex, nullptr) != 0) {
            perror("Mutex initialization failed");
            exit(EXIT_FAILURE);
        }
    }

    ~Client() {
        // 關閉 socket
        if (server_socket != -1) close(server_socket);
        if (p2p_socket != -1) close(p2p_socket);

        // 銷毀互斥鎖
        pthread_mutex_destroy(&mutex);
    }

    // 設置信號處理器
    void setup_signal_handler() {
        global_client_ptr = this;
        signal(SIGINT, Client::signal_handler);
    }

    // 連接到服務器
    bool connect_to_server(const std::string& host, int port) {
        // 創建 socket
        server_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket < 0) {
            perror("Socket creation failed");
            return false;
        }

        // 設置服務器地址
        struct sockaddr_in serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);

        // 將主機地址轉換為二進制形式
        if (inet_pton(AF_INET, host.c_str(), &serv_addr.sin_addr) <= 0) {
            perror("Invalid server address");
            close(server_socket);
            server_socket = -1;
            return false;
        }

        // 連接到服務器
        if (connect(server_socket, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
            perror("Failed to establish connection to server");
            close(server_socket);
            server_socket = -1;
            return false;
        }

        std::cout << "Successfully connected to socket server at " << host << ":" << port << std::endl;
        return true;
    }

    // 註冊用戶
    bool register_user(const std::string& username) {
        std::string message = "REGISTER#" + username;
        if (send_message(message) < 0) {
            std::cerr << "Failed to send register message to server." << std::endl;
            return false;
        }

        std::string response = receive_message();
        if (response == "100 OK\n" || response == "100 OK\r\n") {
            std::cout << "Registration successful." << std::endl;
            return true;
        }
        else if (response == "210 FAIL\n" || response == "210 FAIL\r\n") {
            std::cout << "Registration failed: User already exists." << std::endl;
            return false;
        }
        else {
            std::cout << "Unrecognized server response: " << response << std::endl;
            return false;
        }
    }

    // 登錄用戶
    bool login_user(const std::string& username, int p2p_port) {
        this->username = username;
        p2p_port_number = p2p_port;
        std::string message = username + "#" + std::to_string(p2p_port);
        if (send_message(message) < 0) {
            std::cerr << "Failed to send login message to server." << std::endl;
            return false;
        }

        std::string response = receive_message();
        if (response == "220 AUTH_FAIL\n" || response == "220 AUTH_FAIL\r\n") {
            std::cout << "Login failed: User does not exist on the designated server." << std::endl;
            return false;
        }
        else {
            std::cout << "Login successful." << std::endl;
            std::cout << "Setting up P2P listener on port: " << p2p_port_number << std::endl;
            // 啟動 P2P 監聽線程
            if (!start_p2p_listener(p2p_port_number)) {
                std::cerr << "Failed to start P2P listener." << std::endl;
                return false;
            }
            return true;
        }
    }

    // 列出服務器狀態（帳戶餘額和在線用戶）
    bool list_server_status() {
        std::string message = "List";
        if (send_message(message) < 0) {
            std::cerr << "Failed to send List message to server." << std::endl;
            return false;
        }

        std::string response = receive_message();
        if (response.empty()) {
            std::cerr << "Received empty response from server." << std::endl;
            return false;
        }

        // 解析服務器響應：<accountBalance><CRLF><serverPublicKey><CRLF><number of accounts online><CRLF><user1>#<ip>#<port><CRLF>...
        std::stringstream ss(response);
        std::string line;
        if (!std::getline(ss, line)) {
            std::cerr << "Failed to parse account balance." << std::endl;
            return false;
        }
        int account_balance = std::stoi(line);

        if (!std::getline(ss, line)) {
            std::cerr << "Failed to parse server public key." << std::endl;
            return false;
        }
        std::string server_public_key = line;

        if (!std::getline(ss, line)) {
            std::cerr << "Failed to parse number of active users." << std::endl;
            return false;
        }
        int num_active_users = std::stoi(line);

        active_users.clear();
        for (int i = 0; i < num_active_users; ++i) {
            if (!std::getline(ss, line)) {
                std::cerr << "Failed to parse active user info." << std::endl;
                break;
            }
            size_t pos1 = line.find('#');
            size_t pos2 = line.find('#', pos1 + 1);
            if (pos1 == std::string::npos || pos2 == std::string::npos) {
                std::cerr << "Invalid active user format: " << line << std::endl;
                continue;
            }
            std::string uname = line.substr(0, pos1);
            std::string uhost = line.substr(pos1 + 1, pos2 - pos1 - 1);
            int uport = std::stoi(line.substr(pos2 + 1));

            active_users.push_back({ uname, uhost, uport });
        }

        // 顯示解析後的信息
        std::cout << "Balance: " << account_balance << std::endl;
        std::cout << "Server Public Key: " << server_public_key << std::endl;
        std::cout << "Active Users (" << num_active_users << "):" << std::endl;
        for (const auto& user : active_users) {
            std::cout << user.username << "@" << user.host << ":" << user.port << std::endl;
        }

        return true;
    }

    // 發起 P2P 支付
    bool initiate_payment(const std::string& payee_username, int amount) {
        // 在 active_users 中查找收款人
        ActiveUser* payee = nullptr;
        for (auto& user : active_users) {
            if (user.username == payee_username) {
                payee = &user;
                break;
            }
        }
        if (!payee) {
            std::cout << "Payee not found or unavailable." << std::endl;
            return false;
        }

        // 創建一個新的 socket 連接到收款人的 P2P 端口
        int payment_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (payment_fd < 0) {
            perror("Failed to create payment socket");
            return false;
        }

        struct sockaddr_in payee_addr;
        memset(&payee_addr, 0, sizeof(payee_addr));
        payee_addr.sin_family = AF_INET;
        payee_addr.sin_port = htons(payee->port);

        if (inet_pton(AF_INET, payee->host.c_str(), &payee_addr.sin_addr) <= 0) {
            perror("Invalid payee server address");
            close(payment_fd);
            return false;
        }

        // 連接到收款人
        if (connect(payment_fd, (struct sockaddr*)&payee_addr, sizeof(payee_addr)) < 0) {
            perror("Failed to establish payment connection");
            close(payment_fd);
            return false;
        }

        // 準備並發送支付消息
        std::string payment_message = username + "#" + std::to_string(amount) + "#" + payee_username;
        if (send(payment_fd, payment_message.c_str(), payment_message.length(), 0) < 0) {
            perror("Failed to send payment message");
            close(payment_fd);
            return false;
        }

        std::cout << "Payment of " << amount << " to " << payee_username << " sent successfully." << std::endl;

        // 讀取服務器的響應
        std::string response = receive_message();
        if (!response.empty()) {
            std::cout << "Server response: " << response << std::endl;
        }

        close(payment_fd);
        return true;
    }

    // 終止連接
    void terminate() {
        if (is_running) {
            std::string message = "Exit";
            send_message(message);
            if (server_socket != -1) {
                close(server_socket);
                server_socket = -1;
            }
            is_running = false;
            std::cout << "\nConnection terminated." << std::endl;
        }
    }

    // 主命令循環
    void command_loop() {
        while (is_running) {
            std::cout << "---------------------------------" << std::endl;
            std::cout << "Commands:" << std::endl
                      << "1. Register" << std::endl
                      << "2. Login" << std::endl
                      << "3. List" << std::endl
                      << "4. Initiate Payment" << std::endl
                      << "5. Terminate connection" << std::endl;
            std::cout << "Command: ";
            std::string command_string;
            std::cin >> command_string;

            int command;
            try {
                command = std::stoi(command_string);
            }
            catch (...) {
                command = -1;
            }

            std::cout << "-----------------------" << std::endl;

            switch (command) {
                case 1: { // Register
                    std::cout << "Command: Register" << std::endl;
                    std::string username_input;
                    std::cout << "Enter your name: ";
                    std::cin >> username_input;
                    register_user(username_input);
                    break;
                }
                case 2: { // Login
                    std::cout << "Command: Login" << std::endl;
                    std::string username_input;
                    int p2p_port;
                    std::cout << "Enter your name: ";
                    std::cin >> username_input;
                    std::cout << "Enter port number for P2P communication: ";
                    std::cin >> p2p_port;
                    if (login_user(username_input, p2p_port)) {
                        // 登錄成功
                    }
                    break;
                }
                case 3: { // List
                    std::cout << "Command: List" << std::endl;
                    list_server_status();
                    break;
                }
                case 4: { // Initiate Payment
                    std::cout << "Command: Initiate Payment" << std::endl;
                    std::string payee_username;
                    int amount;
                    std::cout << "Enter payee username: ";
                    std::cin >> payee_username;
                    std::cout << "Enter amount: ";
                    std::cin >> amount;
                    initiate_payment(payee_username, amount);
                    break;
                }
                case 5: { // Terminate
                    std::cout << "Command: Terminate connection" << std::endl;
                    terminate();
                    break;
                }
                default:
                    std::cout << "Invalid Command" << std::endl;
                    break;
            }
        }
    }

private:
    int server_socket;            // 與服務器的 socket
    int p2p_socket;              // P2P 監聽 socket
    pthread_t payment_thread;     // 處理 P2P 支付的線程
    pthread_mutex_t mutex;       // 互斥鎖，保護共享資源
    bool is_running;             // 程式是否運行中
    std::string username;        // 用戶名
    std::vector<ActiveUser> active_users; // 在線用戶列表
    int p2p_port_number;         // P2P 監聽端口號

    // 靜態信號處理器，調用對應的 terminate 方法
    static void signal_handler(int signum) {
        if (global_client_ptr) {
            global_client_ptr->terminate();
        }
    }

    // 啟動 P2P 監聽線程
    bool start_p2p_listener(int port) {
        // 設置 P2P 端口號
        p2p_port_number = port;

        // 創建線程
        if (pthread_create(&payment_thread, nullptr, Client::receive_payment_static, this) != 0) {
            perror("Failed to create P2P listener thread");
            return false;
        }

        // 分離線程，使其獨立運行
        pthread_detach(payment_thread);
        return true;
    }

    // 靜態包裝函數，用於調用實例的 receive_payment 方法
    static void* receive_payment_static(void* arg) {
        Client* client = static_cast<Client*>(arg);
        client->receive_payment();
        return nullptr;
    }

    // P2P 接收支付的函數
    void receive_payment() {
        // 創建 P2P socket
        p2p_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (p2p_socket < 0) {
            perror("Failed to create P2P socket");
            return;
        }

        // 設置 socket 選項
        int opt = 1;
        if (setsockopt(p2p_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            perror("setsockopt failed");
            close(p2p_socket);
            return;
        }

        // 綁定 socket
        struct sockaddr_in p2p_addr;
        memset(&p2p_addr, 0, sizeof(p2p_addr));
        p2p_addr.sin_family = AF_INET;
        p2p_addr.sin_addr.s_addr = INADDR_ANY;
        p2p_addr.sin_port = htons(p2p_port_number);

        if (bind(p2p_socket, (struct sockaddr*)&p2p_addr, sizeof(p2p_addr)) < 0) {
            perror("Failed to bind P2P socket");
            close(p2p_socket);
            return;
        }

        // 監聽
        if (listen(p2p_socket, 3) < 0) {
            perror("Failed to listen on P2P socket");
            close(p2p_socket);
            return;
        }

        std::cout << "P2P Listener started on port " << p2p_port_number << std::endl;

        while (is_running) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int conn_fd = accept(p2p_socket, (struct sockaddr*)&client_addr, &client_len);
            if (conn_fd < 0) {
                perror("Failed to accept P2P connection");
                continue;
            }

            // 讀取支付消息
            char buffer[BUFFER_SIZE];
            memset(buffer, 0, BUFFER_SIZE);
            ssize_t bytes_read = read(conn_fd, buffer, BUFFER_SIZE - 1);
            if (bytes_read > 0) {
                std::string payment_message(buffer, bytes_read);
                std::cout << "Received payment: " << payment_message << std::endl;

                // 將支付消息轉發給服務器
                if (send_message(payment_message) < 0) {
                    std::cerr << "Failed to forward payment to server." << std::endl;
                }
            }

            close(conn_fd);
        }

        close(p2p_socket);
    }

    // 發送消息到服務器，並確保線程安全
    int send_message(const std::string& message) {
        pthread_mutex_lock(&mutex);
        ssize_t total_sent = 0;
        ssize_t to_send = message.length();
        const char* msg = message.c_str();

        while (total_sent < to_send) {
            ssize_t sent = send(server_socket, msg + total_sent, to_send - total_sent, 0);
            if (sent < 0) {
                perror("Failed to send message");
                pthread_mutex_unlock(&mutex);
                return -1;
            }
            total_sent += sent;
        }
        pthread_mutex_unlock(&mutex);
        return 0;
    }

    // 從服務器接收消息，並確保線程安全
    std::string receive_message() {
        pthread_mutex_lock(&mutex);
        char buffer[BUFFER_SIZE];
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t bytes_received = recv(server_socket, buffer, BUFFER_SIZE - 1, 0);
        pthread_mutex_unlock(&mutex);

        if (bytes_received < 0) {
            perror("Failed to receive message from server");
            return "";
        }
        else if (bytes_received == 0) {
            std::cerr << "Server closed the connection." << std::endl;
            is_running = false;
            return "";
        }

        return std::string(buffer, bytes_received);
    }
};

int main(int argc, char* argv[]) {
    // 確保正確的使用方式
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <Server_IP> <Server_Port>" << std::endl;
        return 1;
    }

    std::string server_ip = argv[1];
    int server_port = atoi(argv[2]);

    Client client;
    client.setup_signal_handler();

    if (!client.connect_to_server(server_ip, server_port)) {
        std::cerr << "Failed to connect to server. Exiting." << std::endl;
        return 1;
    }

    client.command_loop();

    return 0;
}

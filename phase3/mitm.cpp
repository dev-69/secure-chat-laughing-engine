#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <iostream>
#include <cstring>
#include <vector>
#include <fstream>

bool sendAll(int socket, const unsigned char* data, size_t length) {

    size_t totalSent = 0;

    while (totalSent < length) {

        ssize_t sent = send(
            socket,
            data + totalSent,
            length - totalSent,
            0
        );

        if (sent <= 0)
            return false;

        totalSent += sent;
    }

    return true;
}

bool recvAll(int socket, unsigned char* data, size_t length) {

    size_t totalReceived = 0;

    while (totalReceived < length) {

        ssize_t received = recv(
            socket,
            data + totalReceived,
            length - totalReceived,
            0
        );

        if (received <= 0)
            return false;

        totalReceived += received;
    }

    return true;
}

std::vector<unsigned char> readFile(const char* filename) {

    std::ifstream file(filename, std::ios::binary);

    if (!file) {
        std::cerr << "[MITM] Failed to open " << filename << "\n";
        return {};
    }

    return std::vector<unsigned char>(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
}

int main() {

    /*
     * ----------------------------------------------------
     * STEP 1:
     * Connect to the REAL server.
     * ----------------------------------------------------
     */

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (server_fd < 0) {
        std::cerr << "[MITM] Failed to create server socket\n";
        return 1;
    }

    sockaddr_in real_server_addr{};

    real_server_addr.sin_family = AF_INET;
    real_server_addr.sin_port = htons(1111);

    inet_pton(
        AF_INET,
        "127.0.0.1",
        &real_server_addr.sin_addr
    );

    if (connect(
            server_fd,
            (struct sockaddr*)&real_server_addr,
            sizeof(real_server_addr)) < 0) {

        std::cerr << "[MITM] Failed to connect to real server\n";
        close(server_fd);
        return 1;
    }

    std::cout << "[MITM] Connected to real server.\n";


    /*
     * ----------------------------------------------------
     * STEP 2:
     * Create listening socket for victim client.
     * ----------------------------------------------------
     */

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (listen_fd < 0) {
        std::cerr << "[MITM] Failed to create listening socket\n";
        close(server_fd);
        return 1;
    }

    int opt = 1;

    setsockopt(
        listen_fd,
        SOL_SOCKET,
        SO_REUSEADDR,
        &opt,
        sizeof(opt)
    );

    sockaddr_in mitm_addr{};

    mitm_addr.sin_family = AF_INET;
    mitm_addr.sin_port = htons(9999);
    mitm_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(
            listen_fd,
            (struct sockaddr*)&mitm_addr,
            sizeof(mitm_addr)) < 0) {

        std::cerr << "[MITM] Bind failed\n";
        close(server_fd);
        close(listen_fd);
        return 1;
    }

    if (listen(listen_fd, 1) < 0) {

        std::cerr << "[MITM] Listen failed\n";
        close(server_fd);
        close(listen_fd);
        return 1;
    }

    std::cout
        << "[MITM] Waiting for victim client on port 9999...\n";


    /*
     * ----------------------------------------------------
     * STEP 3:
     * Wait for victim.
     * ----------------------------------------------------
     */

    int client_fd = accept(
        listen_fd,
        nullptr,
        nullptr
    );

    if (client_fd < 0) {

        std::cerr << "[MITM] Accept failed\n";

        close(server_fd);
        close(listen_fd);

        return 1;
    }

    std::cout << "[MITM] Victim client connected!\n";


    /*
     * ----------------------------------------------------
     * STEP 4:
     *
     * REAL SERVER has already sent its certificate
     * because the Phase 3 server sends the certificate
     * immediately after connection.
     *
     * We receive it here but DO NOT forward it.
     * ----------------------------------------------------
     */

    uint32_t realCertLengthNetwork;

    if (!recvAll(
            server_fd,
            reinterpret_cast<unsigned char*>(&realCertLengthNetwork),
            sizeof(realCertLengthNetwork))) {

        std::cerr
            << "[MITM] Failed to receive real certificate length\n";

        close(client_fd);
        close(server_fd);
        close(listen_fd);

        return 1;
    }

    uint32_t realCertLength = ntohl(realCertLengthNetwork);

    std::vector<unsigned char> realCertificate(realCertLength);

    if (!recvAll(
            server_fd,
            realCertificate.data(),
            realCertificate.size())) {

        std::cerr
            << "[MITM] Failed to receive real certificate\n";

        close(client_fd);
        close(server_fd);
        close(listen_fd);

        return 1;
    }

    std::cout
        << "[MITM] Captured real server certificate ("
        << realCertificate.size()
        << " bytes)\n";


    /*
     * ----------------------------------------------------
     * STEP 5:
     *
     * Load Mallory's fake certificate.
     * ----------------------------------------------------
     */

    std::vector<unsigned char> malloryCertificate =
        readFile("certs/mallory/mallory-server.crt");

    if (malloryCertificate.empty()) {

        std::cerr
            << "[MITM] Mallory certificate could not be loaded\n";

        close(client_fd);
        close(server_fd);
        close(listen_fd);

        return 1;
    }

    std::cout
        << "[MITM] Loaded Mallory certificate ("
        << malloryCertificate.size()
        << " bytes)\n";


    /*
     * ----------------------------------------------------
     * STEP 6:
     *
     * Send Mallory's certificate to the victim
     * instead of the legitimate server certificate.
     * ----------------------------------------------------
     */

    uint32_t malloryCertLengthNetwork =
        htonl(malloryCertificate.size());

    if (!sendAll(
            client_fd,
            reinterpret_cast<unsigned char*>(
                &malloryCertLengthNetwork
            ),
            sizeof(malloryCertLengthNetwork))) {

        std::cerr
            << "[MITM] Failed to send certificate length\n";

        close(client_fd);
        close(server_fd);
        close(listen_fd);

        return 1;
    }

    if (!sendAll(
            client_fd,
            malloryCertificate.data(),
            malloryCertificate.size())) {

        std::cerr
            << "[MITM] Failed to send Mallory certificate\n";

        close(client_fd);
        close(server_fd);
        close(listen_fd);

        return 1;
    }

    std::cout
        << "[MITM] Sent Mallory certificate to victim.\n";

    std::cout
        << "[MITM] Waiting for victim to validate certificate...\n";


    /*
     * ----------------------------------------------------
     * STEP 7:
     *
     * The client should now reject the certificate.
     *
     * Therefore we expect the client to close the
     * connection.
     * ----------------------------------------------------
     */

    unsigned char buffer[1024];

    int bytes = recv(
        client_fd,
        buffer,
        sizeof(buffer),
        0
    );

    if (bytes <= 0) {

        std::cout
            << "[MITM] Victim closed the connection.\n";

        std::cout
            << "[MITM] Certificate validation successfully "
               "blocked the attack!\n";
    }
    else {

        std::cout
            << "[MITM] Victim continued communicating.\n";

        std::cout
            << "[MITM] Unexpected: certificate validation "
               "did not stop the attack.\n";
    }

    close(client_fd);
    close(server_fd);
    close(listen_fd);

    return 0;
}
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

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

    // ============================================
    // 1. Connect to the real server
    // ============================================

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


    // ============================================
    // 2. Listen for victim client
    // ============================================

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);

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

    listen(listen_fd, 1);

    std::cout
        << "[MITM] Waiting for victim client on port 9999...\n";


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


    // ============================================
    // 3. Receive REAL certificate from server
    // ============================================

    uint32_t certLengthNetwork;

    if (!recvAll(
            server_fd,
            reinterpret_cast<unsigned char*>(&certLengthNetwork),
            sizeof(certLengthNetwork))) {

        std::cerr
            << "[MITM] Failed to receive certificate length\n";

        return 1;
    }

    uint32_t certLength = ntohl(certLengthNetwork);

    std::vector<unsigned char> realCertificate(certLength);

    if (!recvAll(
            server_fd,
            realCertificate.data(),
            realCertificate.size())) {

        std::cerr
            << "[MITM] Failed to receive certificate\n";

        return 1;
    }

    std::cout
        << "[MITM] Captured legitimate server certificate ("
        << realCertificate.size()
        << " bytes)\n";


    // ============================================
    // 4. Forward LEGITIMATE certificate
    //    to victim
    // ============================================

    uint32_t certLengthToClient =
        htonl(realCertificate.size());

    sendAll(
        client_fd,
        reinterpret_cast<unsigned char*>(&certLengthToClient),
        sizeof(certLengthToClient)
    );

    sendAll(
        client_fd,
        realCertificate.data(),
        realCertificate.size()
    );

    std::cout
        << "[MITM] Forwarded legitimate certificate to victim.\n";


    // ============================================
    // 5. Load Mallory's WRONG private key
    // ============================================

    FILE* keyFile =
        fopen("certs/mallory/mallory-server.key", "r");

    if (!keyFile) {

        std::cerr
            << "[MITM] Failed to open Mallory private key\n";

        close(client_fd);
        close(server_fd);
        close(listen_fd);

        return 1;
    }

    EVP_PKEY* malloryPrivateKey =
        PEM_read_PrivateKey(
            keyFile,
            nullptr,
            nullptr,
            nullptr
        );

    fclose(keyFile);

    if (!malloryPrivateKey) {

        std::cerr
            << "[MITM] Failed to load Mallory private key\n";

        close(client_fd);
        close(server_fd);
        close(listen_fd);

        return 1;
    }

    std::cout
        << "[MITM] Loaded Mallory's DIFFERENT private key.\n";


    // ============================================
    // 6. Receive challenge from victim
    // ============================================

    unsigned char challenge[32];

    if (!recvAll(
            client_fd,
            challenge,
            sizeof(challenge))) {

        std::cerr
            << "[MITM] Failed to receive challenge\n";

        EVP_PKEY_free(malloryPrivateKey);

        close(client_fd);
        close(server_fd);
        close(listen_fd);

        return 1;
    }

    std::cout
        << "[MITM] Received client's challenge.\n";


    // ============================================
    // 7. Sign challenge using WRONG private key
    // ============================================

    EVP_MD_CTX* signCtx =
        EVP_MD_CTX_new();

    if (!signCtx) {

        std::cerr
            << "[MITM] Failed to create signing context\n";

        EVP_PKEY_free(malloryPrivateKey);

        return 1;
    }


    if (EVP_DigestSignInit(
            signCtx,
            nullptr,
            EVP_sha256(),
            nullptr,
            malloryPrivateKey) != 1) {

        std::cerr
            << "[MITM] Failed to initialize signing\n";

        EVP_MD_CTX_free(signCtx);
        EVP_PKEY_free(malloryPrivateKey);

        return 1;
    }


    if (EVP_DigestSignUpdate(
            signCtx,
            challenge,
            sizeof(challenge)) != 1) {

        std::cerr
            << "[MITM] Failed to process challenge\n";

        EVP_MD_CTX_free(signCtx);
        EVP_PKEY_free(malloryPrivateKey);

        return 1;
    }


    size_t signatureLength = 0;

    if (EVP_DigestSignFinal(
            signCtx,
            nullptr,
            &signatureLength) != 1) {

        std::cerr
            << "[MITM] Failed to determine signature length\n";

        EVP_MD_CTX_free(signCtx);
        EVP_PKEY_free(malloryPrivateKey);

        return 1;
    }


    std::vector<unsigned char> signature(signatureLength);

    if (EVP_DigestSignFinal(
            signCtx,
            signature.data(),
            &signatureLength) != 1) {

        std::cerr
            << "[MITM] Failed to create signature\n";

        EVP_MD_CTX_free(signCtx);
        EVP_PKEY_free(malloryPrivateKey);

        return 1;
    }

    signature.resize(signatureLength);

    EVP_MD_CTX_free(signCtx);


    std::cout
        << "[MITM] Signed challenge using WRONG private key.\n";


    // ============================================
    // 8. Send bogus signature to victim
    // ============================================

    uint32_t signatureLengthNetwork =
        htonl(signature.size());

    sendAll(
        client_fd,
        reinterpret_cast<unsigned char*>(
            &signatureLengthNetwork
        ),
        sizeof(signatureLengthNetwork)
    );

    sendAll(
        client_fd,
        signature.data(),
        signature.size()
    );

    std::cout
        << "[MITM] Sent bogus signature to victim.\n";


    // ============================================
    // 9. Wait for client to reject us
    // ============================================

    unsigned char response[1024];

    int bytes = recv(
        client_fd,
        response,
        sizeof(response),
        0
    );

    if (bytes <= 0) {

        std::cout
            << "[MITM] Victim closed the connection.\n";

        std::cout
            << "[MITM] Proof-of-possession successfully "
               "blocked the attack!\n";

    } else {

        std::cout
            << "[MITM] Victim continued communicating.\n";

        std::cout
            << "[MITM] Unexpected result.\n";
    }


    EVP_PKEY_free(malloryPrivateKey);

    close(client_fd);
    close(server_fd);
    close(listen_fd);

    return 0;
}
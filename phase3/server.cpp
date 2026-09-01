#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <cstring>
#include <thread>
#include <unordered_map>
#include <mutex>
#include <fstream>
#include <vector>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "dh.cpp"

// std::unordered_map<std::string, int> clients;

struct ClientData {
    int socket;
    DHE* dh_ptr;
};
std::unordered_map<std::string, ClientData> clients;

std::mutex clients_mutex;
std::mutex console_mutex;

void logToConsole(const std::string& logText) {
    std::lock_guard<std::mutex> lock(console_mutex);
    std::cout << logText << std::endl;
}

std::vector<unsigned char> readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);

    if (!file) {
        throw std::runtime_error("Could not open file: " + filename);
    }

    return std::vector<unsigned char>(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>()
    );
}

bool sendAll(int socket, const unsigned char* data, size_t length) {
    size_t totalSent = 0;

    while (totalSent < length) {
        ssize_t sent = send(
            socket,
            data + totalSent,
            length - totalSent,
            0
        );

        if (sent <= 0) {
            return false;
        }

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

        if (received <= 0) {
            return false;
        }

        totalReceived += received;
    }

    return true;
}

void handleClient(int clientSocket) {

    std::vector<unsigned char> certificate;

    try {
        certificate = readFile("certs/server.crt");
    }
    catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        close(clientSocket);
        return;
    }

    uint32_t certLength = htonl(certificate.size());
    if (!sendAll(
        clientSocket,
        reinterpret_cast<unsigned char*>(&certLength),
        sizeof(certLength))) {

        close(clientSocket);
        return;
    }

    if (!sendAll(
        clientSocket,
        certificate.data(),
        certificate.size())) {

        close(clientSocket);
        return;
    }

    unsigned char challenge[32];

    if (!recvAll(
        clientSocket,
        challenge,
        sizeof(challenge))) {

        std::cerr << "Failed to receive challenge\n";
        close(clientSocket);
        return;
    }

    std::cout << "Challenge received from client\n";
    
    FILE* keyFile = fopen("certs/server.key", "r");

    if (!keyFile) {
        std::cerr << "Could not open server private key\n";
        close(clientSocket);
        return;
    }

    EVP_PKEY* privateKey = PEM_read_PrivateKey(
        keyFile,
        nullptr,
        nullptr,
        nullptr
    );

    fclose(keyFile);

    if (!privateKey) {
        std::cerr << "Failed to load server private key\n";
        close(clientSocket);
        return;
    }

    EVP_MD_CTX* signCtx = EVP_MD_CTX_new();

    if (!signCtx) {
        std::cerr << "Failed to create signing context\n";
        EVP_PKEY_free(privateKey);
        close(clientSocket);
        return;
    }

    if (EVP_DigestSignInit(
        signCtx,
        nullptr,
        EVP_sha256(),
        nullptr,
        privateKey) != 1) {

        std::cerr << "Failed to initialize signing\n";

        EVP_MD_CTX_free(signCtx);
        EVP_PKEY_free(privateKey);
        close(clientSocket);
        return;
    }

    if (EVP_DigestSignUpdate(
        signCtx,
        challenge,
        sizeof(challenge)) != 1) {

        std::cerr << "Failed to process challenge\n";

        EVP_MD_CTX_free(signCtx);
        EVP_PKEY_free(privateKey);
        close(clientSocket);
        return;
    }
    size_t signatureLength = 0;

    if (EVP_DigestSignFinal(
        signCtx,
        nullptr,
        &signatureLength) != 1) {

        std::cerr << "Failed to determine signature size\n";

        EVP_MD_CTX_free(signCtx);
        EVP_PKEY_free(privateKey);
        close(clientSocket);
        return;
    }

    std::vector<unsigned char> signature(signatureLength);

    if (EVP_DigestSignFinal(
            signCtx,
            signature.data(),
            &signatureLength) != 1) {

        std::cerr << "Failed to sign challenge\n";

        EVP_MD_CTX_free(signCtx);
        EVP_PKEY_free(privateKey);
        close(clientSocket);
        return;
    }
    signature.resize(signatureLength);

    uint32_t signatureLengthNetwork = htonl(signature.size());

    if (!sendAll(
            clientSocket,
            reinterpret_cast<unsigned char*>(&signatureLengthNetwork),
            sizeof(signatureLengthNetwork))) {

        std::cerr << "Failed to send signature length\n";

        EVP_MD_CTX_free(signCtx);
        EVP_PKEY_free(privateKey);
        close(clientSocket);
        return;
    }

    if (!sendAll(
        clientSocket,
        signature.data(),
        signature.size())) {

        std::cerr << "Failed to send signature\n";

        EVP_MD_CTX_free(signCtx);
        EVP_PKEY_free(privateKey);
        close(clientSocket);
        return; 
    }
    std::cout << "Challenge signed and signature sent to client\n";
    EVP_MD_CTX_free(signCtx);
    EVP_PKEY_free(privateKey);


    DHE dh;
    //generating keys
    dh.generateKeys();

    //serializing my own (server key)
    int public_key_len = BN_num_bytes(dh.pub_key);
    std::vector<unsigned char> public_key_bytes(public_key_len);
    BN_bn2bin(dh.pub_key, public_key_bytes.data());

    //send to send my public key (server) to client
    unsigned char client_pub_key[256] = {0};
    send(clientSocket, public_key_bytes.data(), public_key_len, 0);
    int bytesReceived = recv(clientSocket, client_pub_key, sizeof(client_pub_key), 0); 

    if(bytesReceived <= 0) {
        std::cout << "Client Disconnected \n";
        close(clientSocket);
        return;
    }

    //converting received bytes back to bigNum
    BIGNUM* bn = BN_new();
    BN_bin2bn(client_pub_key, bytesReceived, bn);

    //fingerprint
    dh.compute_key(bn);
    std::cout << "DH Fingerprint: " << dh.getFingerPrint() << std::endl;
    BN_free(bn);

    std::cout << "New client connected" << std::endl;

    std::string prompt = "Server: Enter your username: ";
    std::vector<unsigned char> enc_prompt = dh.encrypt(prompt);
    send(clientSocket, enc_prompt.data(), enc_prompt.size(), 0);

    //receiving data from client
    unsigned char buffer[2048] = {0};
    bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);

    if(bytesReceived <= 0) {
        std::cout << "Client Disconnected \n";
        close(clientSocket);
        return;
        
    }
    std::vector<unsigned char> payload(buffer, buffer + bytesReceived);
    std::string username = dh.decrypt(payload);

    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        if (clients.find(username) != clients.end()) {
            std::string errMsg = "Server: Username already taken.\n";
            std::vector<unsigned char> enc_err = dh.encrypt(errMsg);
            send(clientSocket, enc_err.data(), enc_err.size(), 0);
            close(clientSocket);
            return; 
        }
        // Save both!
        clients[username] = {clientSocket, &dh};
    }
    logToConsole("[INFO] " + username + " connected.");


    while(true) {
        memset(buffer, 0, sizeof(buffer));
        
        bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0); 

        if(bytesReceived <= 0) {
            break; 
        }
        std::vector<unsigned char> chat_payload(buffer, buffer + bytesReceived);
        std::string msg = dh.decrypt(chat_payload);
                
        if(msg == "/quit") {
            break;
        }
        else if(msg == "/who") {
            std::string who_list = "\n--- Online Users ---\n";
            
            std::lock_guard<std::mutex> lock(clients_mutex);
            for (const auto& pair : clients) {
                who_list += "- " + pair.first + "\n";
            }
            who_list += "--------------------\n";
            

            std::vector<unsigned char> who_list_enc = dh.encrypt(who_list);
            send(clientSocket, who_list_enc.data(), who_list_enc.size(), 0);
        }
        
        else if(msg[0] == '@') {
            //username part   
            int space_pos = msg.find(' ');
            if(space_pos != std::string::npos) {
                std::string target_user = msg.substr(1, space_pos-1);
                std::string actual_msg = msg.substr(space_pos+1);

                std::string formatted = "\n[" + username + "] says: " + actual_msg;

                std::lock_guard<std::mutex> lock(clients_mutex);

                //user exists in map
                if(clients.find(target_user) != clients.end()) {
                    int target_socket = clients[target_user].socket;
                    std::vector<unsigned char> enc_formatted = clients[target_user].dh_ptr->encrypt(formatted);
                    send(target_socket, enc_formatted.data(), enc_formatted.size(), 0);
                    logToConsole("[CHAT] " + username + " -> " + target_user + " : " + actual_msg);
                }
                else {
                    std::string err = "\nServer: User '" + target_user + "' is not online or does not exist.\n";
                    std::vector<unsigned char> enc_err = dh.encrypt(err);
                    send(clientSocket, enc_err.data(), enc_err.size(), 0);
                }
            }
        }
    }
    //cleanup
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        clients.erase(username);
    }
    close(clientSocket);
    logToConsole("[INFO] " + username + " disconnected.");
}

int main() {

    //creating the server socket
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    //for immediate port reuse
    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "setsockopt failed\n";
        return 1;
    }

    //defining server address
    sockaddr_in serverAddress;

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(1111);
    serverAddress.sin_addr.s_addr = INADDR_ANY;


    //bind the server socket to the server address
    if(bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        std::cerr << "Bind failed" << std::endl;
        return 1;
    }

    //listen for incoming connections
    listen(serverSocket, 5);

    std::cout << "Server ready waiting for client connections " << std::endl; 


    while(true) {
        //now multiple threads will be accepting client connection
        int clientSocket = accept(serverSocket, nullptr, nullptr);
        
        //creating a thread and running it individually
        std::thread clientThread (handleClient, clientSocket);
        clientThread.detach();
    }

    close(serverSocket);

}

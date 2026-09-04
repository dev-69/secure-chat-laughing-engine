#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <thread>
#include <cstring>

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509_vfy.h>

#include "dh.cpp"

DHE* e2eDh = nullptr;
bool e2eEstablished = false;
std::string e2ePartner = "";

std::string getE2EFingerprint(DHE& dh)
{
    return dh.getFingerPrint();
}

std::vector<unsigned char> getPublicKeyBytes(DHE& dh)
{
    int len = BN_num_bytes(dh.pub_key);

    std::vector<unsigned char> key(len);

    BN_bn2bin(dh.pub_key, key.data());

    return key;
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

std::string toHex(const std::vector<unsigned char>& data)
{
    static const char hex[] = "0123456789ABCDEF";

    std::string result;

    for (unsigned char c : data) {
        result += hex[c >> 4];
        result += hex[c & 0x0F];
    }

    return result;
}

std::vector<unsigned char> fromHex(const std::string& hex)
{
    std::vector<unsigned char> result;

    for (size_t i = 0; i < hex.size(); i += 2) {

        unsigned int value;

        sscanf(
            hex.substr(i, 2).c_str(),
            "%02X",
            &value
        );

        result.push_back(
            static_cast<unsigned char>(value)
        );
    }

    return result;
}

void receiveMessages(int socket, DHE* dh) {
    unsigned char buffer[4096] = {0}; 
    while(true) {

        memset(buffer, 0, sizeof(buffer));
        int bytesReceived = recv(socket, buffer, sizeof(buffer),0);
        
        if(bytesReceived <= 0) {
            std::cout << "\nDisconnected from server.\n";
            break;
        }
        
        // Decrypt the incoming bytes
        std::vector<unsigned char> payload(buffer, buffer + bytesReceived);
        
        std::string decrypted_msg = dh->decrypt(payload);

        // if (payload.size() > 28) { 
        //     std::cout << "\n[TEST] Flipping one bit in the received ciphertext..." << std::endl;
        //     payload[30] ^= 0x01; 
        // }
        if (decrypted_msg.rfind("__E2E_FROM__", 0) == 0) {

            size_t prefixLen = strlen("__E2E_FROM__");

            size_t initPos = decrypted_msg.find("__E2E_INIT__", prefixLen);
            size_t ackPos = decrypted_msg.find("__E2E_ACK__", prefixLen);
            size_t msgPos = decrypted_msg.find("__E2E_MSG__", prefixLen);

            size_t messagePos = std::string::npos;

            if (initPos != std::string::npos)
                messagePos = initPos;
            else if (ackPos != std::string::npos)
                messagePos = ackPos;
            else if (msgPos != std::string::npos)
                messagePos = msgPos;

            if (messagePos != std::string::npos) {

                size_t senderEnd = messagePos;

                while (senderEnd > prefixLen &&
                    decrypted_msg[senderEnd - 1] == '_') {
                    senderEnd--;
                }

                e2ePartner = decrypted_msg.substr(
                    prefixLen,
                    senderEnd - prefixLen
                );

                decrypted_msg = decrypted_msg.substr(messagePos);
            }
        }
        if (decrypted_msg.rfind("__E2E_INIT__", 0) == 0) {

            std::cout << "\n[E2E] Received E2E initialization\n";
            std::string keyData = decrypted_msg.substr(strlen("__E2E_INIT__"));

            // Convert hexadecimal public key back to bytes
            std::vector<unsigned char> peerKey = fromHex(keyData);
            // Convert bytes to BIGNUM
            BIGNUM* peerPubKey = BN_new();
            BN_bin2bn(
                peerKey.data(),
                peerKey.size(),
                peerPubKey
            );
            // Generate our E2E DH key pair
            DHE* newE2eDh = new DHE();
            newE2eDh->generateKeys();

            // Compute C1 <-> C2 shared secret
            newE2eDh->compute_key(peerPubKey);

                BN_free(peerPubKey);

                // Store E2E DH object
                if (e2eDh != nullptr) {
                    delete e2eDh;
                }

                e2eDh = newE2eDh;
                e2eEstablished = true;

                std::cout << "[E2E] Shared key established\n";

                std::cout << "[E2E] Fingerprint: " << e2eDh->getFingerPrint() << std::endl;
                std::vector<unsigned char> myKey = getPublicKeyBytes(*e2eDh);

                std::string ack = "@" + e2ePartner + " __E2E_ACK__" + toHex(myKey);

                // Encrypt ACK using CLIENT-SERVER key
                std::vector<unsigned char> encryptedAck = dh->encrypt(ack);
                if (!sendAll(socket, encryptedAck.data(), encryptedAck.size())) {
                    std::cout << "[E2E] Failed to send ACK\n";
                }
                else {
                    std::cout << "[E2E] ACK sent to " << e2ePartner << std::endl;
                }
                continue;
        }

        else if (decrypted_msg.rfind("__E2E_ACK__", 0) == 0) {
            std::cout << "\n[E2E] Received E2E acknowledgment\n";

            std::string keyData = decrypted_msg.substr(strlen("__E2E_ACK__"));
            std::vector<unsigned char> peerKey = fromHex(keyData);

            BIGNUM* peerPubKey = BN_new();

            BN_bin2bn(
                peerKey.data(),
                peerKey.size(),
                peerPubKey
            );

            if (e2eDh != nullptr) {
                // Compute C1 <-> C2 shared secret
                e2eDh->compute_key(peerPubKey);
                e2eEstablished = true;
                std::cout << "[E2E] Shared key established\n";
                std::cout << "[E2E] Fingerprint: " << e2eDh->getFingerPrint() << std::endl;
            }

            BN_free(peerPubKey);

            continue;
        }

        else if (decrypted_msg.rfind("__E2E_MSG__", 0) == 0) {
            if (!e2eEstablished || e2eDh == nullptr) {
                std::cout << "\n[E2E] No E2E key established\n";
                continue;
            }

            std::string encryptedData = decrypted_msg.substr(strlen("__E2E_MSG__"));

            // convert hex ciphertext back to binary
            std::vector<unsigned char> e2ePayload = fromHex(encryptedData);

            // decrypt using C1 <-> C2 key
            std::string plaintext = e2eDh->decrypt(e2ePayload);

            std::cout << "\n[E2E MESSAGE] " << plaintext << "\n" << std::flush;
            continue;
        }

        else {
            std::cout << "\n" << decrypted_msg << "\n" << std::flush;
        }
    }
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

int main(int argc, char* argv[]) {

    if (argc != 3) {
        std::cout << "Usage: " << argv[0] << " <server_ip> <port>" << std::endl;
        return 1;
    }

    const char* serverIP = argv[1];
    int serverPort = std::stoi(argv[2]);

    //creating socket
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    //defining server address
    sockaddr_in serverAddress;

    serverAddress.sin_family = AF_INET;
    // serverAddress.sin_port = htons(1111);
    // serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(serverPort);
    inet_pton(AF_INET, serverIP, &serverAddress.sin_addr);

    //connecting to server
    if(connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        std::cerr << "Connection Failed \n";
        return 1;
    }

    std::cout << "Connected to the server \n";

    uint32_t certLengthNetwork;

    if (!recvAll(
        clientSocket,
        reinterpret_cast<unsigned char*>(&certLengthNetwork),
        sizeof(certLengthNetwork))) {

        std::cerr << "Failed to receive certificate length\n";
        close(clientSocket);
        return 1;
    }

    uint32_t certLength = ntohl(certLengthNetwork);

    std::vector<unsigned char> serverCertificate(certLength);

    if (!recvAll(
        clientSocket,
        serverCertificate.data(),
        serverCertificate.size())) {

        std::cerr << "Failed to receive server certificate\n";
        close(clientSocket);
        return 1;
    }

    std::cout << "Received server certificate ("
          << serverCertificate.size()
          << " bytes)\n";

    BIO* certBio = BIO_new_mem_buf(
        serverCertificate.data(),
        serverCertificate.size()
    );

    X509* serverCert = PEM_read_bio_X509(
        certBio,
        nullptr,
        nullptr,
        nullptr
    );
    
    if (!serverCert) {
        std::cerr << "Failed to parse server certificate\n";
        BIO_free(certBio);
        close(clientSocket);
        return 1;
    }

    FILE* caFile = fopen("certs/ca.crt", "r");

    if (!caFile) {
        std::cerr << "Could not open trusted CA certificate\n";
        X509_free(serverCert);
        BIO_free(certBio);
        close(clientSocket);
        return 1;
    }

    X509* caCert = PEM_read_X509(
        caFile,
        nullptr,
        nullptr,
        nullptr
    );

    fclose(caFile);


    if (!caCert) {
        std::cerr << "Failed to parse CA certificate\n";
        X509_free(serverCert);
        BIO_free(certBio);
        close(clientSocket);
        return 1;
    }
    X509_STORE* store = X509_STORE_new();

    if (!store) {
        std::cerr << "Failed to create certificate store\n";

        X509_free(caCert);
        X509_free(serverCert);
        BIO_free(certBio);

        close(clientSocket);
        return 1;
    }

    if (X509_STORE_add_cert(store, caCert) != 1) {
    std::cerr << "Failed to add CA certificate to trust store\n";

        X509_STORE_free(store);
        X509_free(caCert);
        X509_free(serverCert);
        BIO_free(certBio);

        close(clientSocket);
        return 1;
    }

    X509_STORE_CTX* verifyCtx = X509_STORE_CTX_new();

    if (!verifyCtx) {
        std::cerr << "Failed to create verification context\n";

        X509_STORE_free(store);
        X509_free(caCert);
        X509_free(serverCert);
        BIO_free(certBio);

        close(clientSocket);
        return 1;

    }

    if (X509_STORE_CTX_init(
        verifyCtx,
        store,
        serverCert,
        nullptr) != 1) {

        std::cerr << "Failed to initialize certificate verification\n";

        X509_STORE_CTX_free(verifyCtx);
        X509_STORE_free(store);
        X509_free(caCert);
        X509_free(serverCert);
        BIO_free(certBio);

        close(clientSocket);
        return 1;
    }
    
    int verifyResult = X509_verify_cert(verifyCtx);

    if (verifyResult != 1) {

        std::cerr << "SERVER CERTIFICATE VALIDATION FAILED\n";

        int error = X509_STORE_CTX_get_error(verifyCtx);

        std::cerr << "Reason: "
                  << X509_verify_cert_error_string(error)
                  << std::endl;

        X509_STORE_CTX_free(verifyCtx);
        X509_STORE_free(store);
        X509_free(caCert);
        X509_free(serverCert);
        BIO_free(certBio);

        close(clientSocket);
        return 1;
    }

    std::cout << "Server certificate validation SUCCESS\n";
    X509_STORE_CTX_free(verifyCtx);
    X509_STORE_free(store);
    X509_free(caCert);
    BIO_free(certBio);

    //sednign a challenge for proof of possession
    unsigned char challenge[32];
    if (RAND_bytes(challenge, sizeof(challenge)) != 1) {
        std::cerr << "Failed to generate challenge\n";
        close(clientSocket);
        return 1;
    }

    if (!sendAll(
            clientSocket,
            challenge,
            sizeof(challenge))) {

        std::cerr << "Failed to send challenge\n";
        close(clientSocket);
        return 1;
    }
    std::cout << "Challenge sent to server\n";


    EVP_PKEY* serverPublicKey = X509_get_pubkey(serverCert);
    if (!serverPublicKey) {
        std::cerr << "Failed to extract public key from server certificate\n";

        X509_free(serverCert);
        close(clientSocket);
        return 1;
    }

    uint32_t signatureLengthNetwork;

    if (!recvAll(
            clientSocket,
            reinterpret_cast<unsigned char*>(&signatureLengthNetwork),
            sizeof(signatureLengthNetwork))) {

        std::cerr << "Failed to receive signature length\n";

        EVP_PKEY_free(serverPublicKey);
        X509_free(serverCert);
        close(clientSocket);
        return 1;
    }
    uint32_t signatureLength = ntohl(signatureLengthNetwork);
    std::vector<unsigned char> signature(signatureLength);
    
    if (!recvAll(
            clientSocket,
            signature.data(),
            signature.size())) {

        std::cerr << "Failed to receive signature\n";

        EVP_PKEY_free(serverPublicKey);
        X509_free(serverCert);
        close(clientSocket);
        return 1;
    }
    std::cout << "Received server signature\n";
    
    EVP_MD_CTX* verifyCtx2 = EVP_MD_CTX_new();
    if (!verifyCtx2) {
    std::cerr << "Failed to create signature verification context\n";

    EVP_PKEY_free(serverPublicKey);
    X509_free(serverCert);
    close(clientSocket);
    return 1;
}

    if (EVP_DigestVerifyInit(
            verifyCtx2,
            nullptr,
            EVP_sha256(),
            nullptr,
            serverPublicKey) != 1) {

        std::cerr << "Failed to initialize signature verification\n";

        EVP_MD_CTX_free(verifyCtx2);
        EVP_PKEY_free(serverPublicKey);
        X509_free(serverCert);
        close(clientSocket);
        return 1;
    }

    if (EVP_DigestVerifyUpdate(
            verifyCtx2,
            challenge,
            sizeof(challenge)) != 1) {

        std::cerr << "Failed to process challenge for verification\n";

        EVP_MD_CTX_free(verifyCtx2);
        EVP_PKEY_free(serverPublicKey);
        X509_free(serverCert);
        close(clientSocket);
        return 1;
    }

    int signatureResult = EVP_DigestVerifyFinal(
        verifyCtx2,
        signature.data(),
        signature.size()
    );

    if (signatureResult != 1) {

        std::cerr << "SERVER PROOF-OF-POSSESSION FAILED\n";

        EVP_MD_CTX_free(verifyCtx2);
        EVP_PKEY_free(serverPublicKey);
        X509_free(serverCert);

        close(clientSocket);
        return 1;
    }
    std::cout << "Server proof-of-possession SUCCESS\n";

    EVP_MD_CTX_free(verifyCtx2);
    EVP_PKEY_free(serverPublicKey);
    X509_free(serverCert);
    
    //as soon as we connect to the serve we should exchange information
    DHE dh;
    dh.generateKeys();

    //creating my own client side keys
    int public_key_len = BN_num_bytes(dh.pub_key);
    std::vector<unsigned char> public_key_bytes(public_key_len);
    BN_bn2bin(dh.pub_key, public_key_bytes.data());

    //sending server my (client's) public key
    send(clientSocket, public_key_bytes.data(), public_key_len, 0);

    //receiving server public key
    unsigned char server_pub_key[256] = {0}; // 2048 bits is exactly 256 bytes
    int bytesReceived = recv(clientSocket, server_pub_key, sizeof(server_pub_key), 0);

    if(bytesReceived <= 0) {
        std::cout << "Server Disconnected during handshake\n";
        close(clientSocket);
        return 1;
    }

    BIGNUM* bn = BN_new();
    BN_bin2bn(server_pub_key, bytesReceived, bn);

    dh.compute_key(bn);
    std::cout << "DH Fingerprint: " << dh.getFingerPrint() << std::endl;
    BN_free(bn); 

    // char promptBuffer[1024] = {0};
    // recv(clientSocket, promptBuffer, sizeof(promptBuffer)-1, 0);
    // std::cout << promptBuffer; 
    
    // std::string username;
    // std::getline(std::cin, username);
    // send(clientSocket, username.c_str(), username.length(), 0);
    unsigned char promptBuffer[1024] = {0};
    int promptBytes = recv(clientSocket, promptBuffer, sizeof(promptBuffer), 0);
    if(promptBytes > 0) {
        std::vector<unsigned char> payload(promptBuffer, promptBuffer + promptBytes);
        std::string decrypted_prompt = dh.decrypt(payload);
        std::cout << decrypted_prompt; 
    }

    std::string username;
    std::getline(std::cin, username);

    std::vector<unsigned char> enc_username = dh.encrypt(username);
    send(clientSocket, enc_username.data(), enc_username.size(), 0);


    //incoming messages thread
    //std::thread receiver(receiveMessages, clientSocket);
    std::thread receiver(receiveMessages, clientSocket, &dh);
    receiver.detach();

    std::string message;
    std::string currentPartner = "";

    while(true) {
        std::cout << "Enter message: ";
        std::getline(std::cin, message);

        if(message.empty())
            continue;

        if(message == "/quit") {
            std::vector<unsigned char> encrypted_msg = dh.encrypt("/quit");
            send(clientSocket, encrypted_msg.data(), encrypted_msg.size(), 0);
            break;
        }
        
        //else if(message.length() >= 5 && message.substr(0, 5) == "/e2e") {
        else if(message.rfind("/e2e ", 0) == 0) {

            std::string target = message.substr(5);

            if(target.empty()) {
                std::cout
                    << "[SYSTEM] Usage: /e2e username"
                    << std::endl;
                continue;
            }

            e2ePartner = target;
            currentPartner = target;

            // Generate our E2E DH key pair
            if(e2eDh != nullptr) {
                delete e2eDh;
            }

            e2eDh = new DHE();
            e2eDh->generateKeys();

            std::vector<unsigned char> publicKey =
                getPublicKeyBytes(*e2eDh);

            std::string e2eInit = "__E2E_INIT__" + toHex(publicKey);

            // Route through server
            std::string routedMessage = "@" + target + " " + e2eInit;

            std::vector<unsigned char> encrypted = dh.encrypt(routedMessage);

            if(!sendAll(clientSocket, encrypted.data(),encrypted.size())) {
                std::cout << "[E2E] Failed to send initialization" << std::endl;
                continue;
            }

            std::cout << "[E2E] Initialization sent to " << target << std::endl;
        }
        else if(message == "/who") {
            std::vector<unsigned char> encrypted_msg = dh.encrypt("/who");
            send(clientSocket, encrypted_msg.data(), encrypted_msg.size(), 0);
        }
        
        else if(message.length() >= 5 && message.substr(0, 5) == "/chat") {

            if(message.length() > 6) {
                currentPartner = message.substr(6);
                std::cout << "Chat partner set to " << currentPartner << std::endl;
            }
            else {
                std::cout << "Invalid Format. Use: /chat username" << std::endl;
            }
        }

        else if(message[0] == '@') {
            int space_pos = message.find(' ');
            if(space_pos != std::string::npos) {
                currentPartner = message.substr(1, space_pos-1);
                std::cout << "[SYSTEM] Chat partner sent to: " << currentPartner << std::endl;
                //std::vector<unsigned char> encrypted_msg = dh.encrypt(message);

                std::string target = message.substr(1, space_pos - 1);

                std::string actualMessage =
                    message.substr(space_pos + 1);

                std::string formatted_msg;

                if (e2eEstablished && e2eDh != nullptr && target == e2ePartner) {

                    std::vector<unsigned char> e2eEncrypted =
                        e2eDh->encrypt(actualMessage);

                    formatted_msg = 
                        "@" + target +
                        " __E2E_MSG__" +
                        toHex(e2eEncrypted);
                }
                else {
                    formatted_msg = message;
                }

                std::vector<unsigned char> encrypted_msg = dh.encrypt(formatted_msg);

                send(clientSocket, encrypted_msg.data(), encrypted_msg.size(), 0);
            }
            else {
                std::cout << "[System] Invalid format. Use: @username message" << std::endl;
            }
        }
        else {
            if (currentPartner.empty()) {
                std::cout << "[SYSTEM] No chat partner selected. Use /chat username first." << std::endl;
            } 
            else {
                std::string formatted_msg;

                if (currentPartner == e2ePartner && !e2eEstablished) {
                    std::cout << "[E2E] Waiting for E2E handshake to complete" << std::endl;
                    continue;
                }

                if (e2eEstablished && e2eDh != nullptr && currentPartner == e2ePartner) {

                    std::vector<unsigned char> e2eEncrypted = e2eDh->encrypt(message);
                    std::string e2ePayload = toHex(e2eEncrypted);
                    formatted_msg = "@" + currentPartner + " __E2E_MSG__" + e2ePayload;
                }      
                else {
                    formatted_msg = "@" + currentPartner + " " + message;
                }
                std::vector<unsigned char> encrypted_msg = dh.encrypt(formatted_msg);

                send(clientSocket, encrypted_msg.data(), encrypted_msg.size(), 0);
            }
        }
    }

    close(clientSocket);
}
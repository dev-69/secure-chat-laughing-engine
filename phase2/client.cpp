#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <thread>
#include <cstring>
#include "dh.cpp"

void receiveMessages(int socket, DHE* dh) {
    unsigned char buffer[2048] = {0}; 
    while(true) {
        memset(buffer, 0, sizeof(buffer));
        int bytesReceived = recv(socket, buffer, sizeof(buffer), 0);
        
        if(bytesReceived <= 0) {
            std::cout << "\nDisconnected from server.\n";
            break;
        }
        
        // Decrypt the incoming bytes
        std::vector<unsigned char> payload(buffer, buffer + bytesReceived);
        std::string decrypted_msg = dh->decrypt(payload);
        
        std::cout << "\n" << decrypted_msg << "\n" << std::flush; 
    }
}

int main() {

    //creating socket
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    //defining server address
    sockaddr_in serverAddress;

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(1111);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    //connecting to server
    if(connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        std::cerr << "Connection Failed \n";
        return 1;
    }

    std::cout << "Connected to the server \n";

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

                std::vector<unsigned char> encrypted_msg = dh.encrypt(message);
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
                std::string formatted_msg = "@" + currentPartner + " " + message;
                std::vector<unsigned char> encrypted_msg = dh.encrypt(formatted_msg);
                send(clientSocket, encrypted_msg.data(), encrypted_msg.size(), 0);
            }
        }
    }

    close(clientSocket);
}
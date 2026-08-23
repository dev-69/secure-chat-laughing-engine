#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <thread>
#include <cstring>

void receiveMessages(int socket) {
    char buffer[1024] = {0};
    while(true) {
        memset(buffer, 0, sizeof(buffer));
        int bytesReceived = recv(socket, buffer, sizeof(buffer)-1, 0);
        
        if(bytesReceived <= 0) {
            std::cout << "\nDisconnected from server.\n";
            break;
        }
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

    //incoming messages thread
    std::thread receiver(receiveMessages, clientSocket);
    receiver.detach();

    std::string message;
    std::string currentPartner = "";

    while(true) {
        std::cout << "Enter message: ";
        std::getline(std::cin, message);

        if(message == "/quit") {
            send(clientSocket, "/quit", 5, 0);
            break;
        }

        else if(message == "/who") {
            send(clientSocket, "/who", 4, 0);
        }
        
        else if(message.substr(0, 6) == "/chat") {
            currentPartner = message.substr(6);
            std::cout << "Chat partner set to " << currentPartner << std::endl;
        }

        else if(message[0] == '@') {
            int space_pos = message.find(' ');
            if(space_pos != std::string::npos) {
                currentPartner = message.substr(1, space_pos-1);
                std::cout << "[SYSTEM] Chat partner sent to: " << currentPartner << std::endl;

                send(clientSocket, message.c_str(), message.length(), 0);
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
                send(clientSocket, formatted_msg.c_str(), formatted_msg.length(), 0);
            }
        }
    }

    close(clientSocket);
}
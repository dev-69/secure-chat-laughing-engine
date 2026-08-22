
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <cstring>

int main() {

    //creating the server socket
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    //defining server address
    sockaddr_in serverAddress;

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(1111);
    serverAddress.sin_addr.s_addr = INADDR_ANY;


    //bind the server socket to the server address
    bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress));

    //listen for incoming connections
    listen(serverSocket, 5);

    std::cout << "Server ready waiting for client connections " << std::endl; 

    //accepting client connection
    int clientSocket = accept(serverSocket, nullptr, nullptr);

    //receiving data from client
    char buffer[1024] = {0};

    while(true) {
        memset(buffer, 0, sizeof(buffer));

        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer)-1, 0); 

        if(bytesReceived == 0) {
            std::cout << "Client Disconnected \n";
            break;
        }
        std::cout << "Message from client: " << buffer << std::endl;

    }
    
    close(clientSocket);
    close(serverSocket);

}

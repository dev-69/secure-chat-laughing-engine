#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <cstring>


int main() {

    //creating socket
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);


    //defining server address
    sockaddr_in serverAddress;

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(1111);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    //connecting to server
    connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress));

    std::string message;

    while(true) {
        std::cout << "Enter message: ";
        std::getline(std::cin, message);

        if(message == "quit")
            break;

        //send data to server
        send(clientSocket, message.c_str(), strlen(message.c_str()), 0);    
    }

    close(clientSocket);
}

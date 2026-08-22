/*
TODO 
1. Create a socket
2. Bind it
3. Listen
4. Accept
5. Receive
6. Print
*/

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <cstring>


#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

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

    //accepting client connection
    int clientSocket = accept(serverSocket, nullptr, nullptr);

    //receiving data from client
    char buffer[1024] = {0};
    recv(clientSocket, buffer, sizeof(buffer), 0);
    std::cout << "Message from client: " << buffer << std::endl;

    close(serverSocket);

}

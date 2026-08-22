/*
TODO 
1. Create a socket
2. Connect
3. Send
4. Close
*/

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

    //send data to server
    const char* message = "Hello, server!";
    
    send(clientSocket, message, strlen(message), 0);    

    close(clientSocket);
}

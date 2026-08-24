
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <cstring>
#include <thread>
#include <unordered_map>
#include <mutex>

std::unordered_map<std::string, int> clients;
std::mutex clients_mutex;
std::mutex console_mutex;

void logToConsole(const std::string& logText) {
    std::lock_guard<std::mutex> lock(console_mutex);
    std::cout << logText << std::endl;
}

void handleClient(int clientSocket) {
    std::cout << "New client connected" << std::endl;
    //receiving data from client
    char buffer[1024] = {0};

    std::string prompt = "Server: Enter your username: ";
    send(clientSocket, prompt.c_str(), prompt.length(), 0);

    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer)-1, 0); 

    if(bytesReceived <= 0) {
        std::cout << "Client Disconnected \n";
        close(clientSocket);
        return;
    }

    std::string username(buffer);

    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        if (clients.find(username) != clients.end()) {
            std::string errMsg = "Server: Username already taken. Disconnecting...\n";
            send(clientSocket, errMsg.c_str(), errMsg.length(), 0);
            close(clientSocket);
            return; 
        }
        clients[username] = clientSocket;
    }
    logToConsole("[INFO] " + username + " connected.");

    while(true) {
        memset(buffer, 0, sizeof(buffer));
        
        bytesReceived = recv(clientSocket, buffer, sizeof(buffer)-1, 0); 

        if(bytesReceived <= 0) {
            break; 
        }
        
        std::string msg(buffer);
        
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
            
            send(clientSocket, who_list.c_str(), who_list.length(), 0);
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
                    int target_socket = clients[target_user];
                    send(target_socket, formatted.c_str(), formatted.length(), 0);
                    logToConsole("[CHAT] " + username + " -> " + target_user + " : " + actual_msg);
                }
                else {
                    std::string err = "\nServer: User '" + target_user + "' is not online or does not exist.\n";
                    send(clientSocket, err.c_str(), err.length(), 0);
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

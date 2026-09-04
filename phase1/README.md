# Phase 1: Baseline Chat Application

## Overview
Phase 1 implements a baseline one-to-one TCP chat application between two clients connected through a central server. All traffic is transmitted as plaintext over TCP.

## Compilation
```bash
g++ -O2 -pthread server.cpp -o server
g++ -O2 -pthread client.cpp -o client
```

## Running the Application
1. **Start the Server** (listens on port 1111):
   ```bash
   ./server
   ```

2. **Start the Clients**:
   ```bash
   ./client <server_ip> 1111
   ```

## Client Commands
- `@username <message>` : Send a direct message to `username`.
- `/chat <username>`    : Set default recipient for subsequent messages.
- `/who`               : Query the server for a list of online users.
- `/quit`              : Cleanly disconnect from the server and exit.

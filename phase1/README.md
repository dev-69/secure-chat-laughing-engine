# Phase 1 - Baseline Chat Application

## Compile
```bash
g++ -O2 -pthread server.cpp -o server
g++ -O2 -pthread client.cpp -o client
```

## Run
1. Start server:
   ```bash
   ./server
   ```

2. Start client(s):
   ```bash
   ./client <server_ip> 1111
   ```

## Commands
- `@username message` : Send message to user
- `/chat username`    : Set default chat partner
- `/who`              : List online users
- `/quit`             : Disconnect and exit


# Phase 4 - End-to-End Encryption Between Clients

## Compile
```bash
g++ -O2 -pthread server.cpp -lssl -lcrypto -o server
g++ -O2 -pthread client.cpp -lssl -lcrypto -o client
```

## Run
1. Start server:
   ```bash
   ./server
   ```

2. Start Client 1 (e.g. Alice):
   ```bash
   ./client <server_ip> 1111
   ```

3. Start Client 2 (e.g. Bob):
   ```bash
   ./client <server_ip> 1111
   ```

## Commands
- `/e2e <username>`   : Initiate E2E key exchange with peer
- `@username message` : Send message (encrypted with E2E key if session active)
- `/chat username`    : Set default chat partner
- `/who`              : List online users
- `/quit`             : Disconnect and exit


# Phase 2 - Client-Server Confidentiality (Diffie-Hellman + AES-GCM)

## Compile
```bash
g++ -O2 -pthread server.cpp -lssl -lcrypto -o server
g++ -O2 -pthread client.cpp -lssl -lcrypto -o client
g++ -O2 -pthread mitm.cpp -lssl -lcrypto -o mitm
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

3. Run MITM proxy (Mallory):
   ```bash
   ./mitm <server_ip> 1111 2222
   ```
   Victim client connects to Mallory:
   ```bash
   ./client <mallory_ip> 2222
   ```

## Commands
- `@username message` : Send encrypted message to user
- `/chat username`    : Set default chat partner
- `/who`              : List online users
- `/quit`             : Disconnect and exit


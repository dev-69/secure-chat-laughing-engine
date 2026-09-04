# Phase 5 - Forward Secrecy via Key Rotation

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

2. Start Client 1:
   ```bash
   ./client <server_ip> 1111
   ```

3. Start Client 2:
   ```bash
   ./client <server_ip> 1111
   ```

## Commands
- `/e2e <username>`   : Initiate E2E key exchange
- `@username message` : Send message
- `/chat username`    : Set default chat partner
- `/who`              : List online users
- `/quit`             : Disconnect and exit

## Notes
- E2E session key automatically renegotiates every 60 seconds on a timer.
- Old session key is destroyed once the new key rotation is confirmed.


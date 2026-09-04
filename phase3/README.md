# Phase 3 - Server Authentication via PKI

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

3. Run MITM proxy attack test:
   ```bash
   ./mitm <server_ip> 1111 2222
   ```
   Victim client connects to:
   ```bash
   ./client <mallory_ip> 2222
   ```

## Notes
- CA and server certificates are located in `certs/` (`ca.crt`, `server.crt`, `server.key`).
- Client validates server certificate against `certs/ca.crt` and verifies challenge signature before proceeding with DH.


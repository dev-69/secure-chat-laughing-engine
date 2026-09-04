# Phase 3: Server Authentication via PKI

## Overview
Phase 3 prevents the Phase 2 MITM attack using Public Key Infrastructure (PKI). The server presents an X.509 certificate signed by a trusted Certificate Authority (CA). The client verifies the certificate chain and enforces proof-of-possession using a signed random challenge before initiating the Diffie-Hellman handshake.

## Certificate Files
Pre-generated OpenSSL certificates are stored in `certs/`:
- `certs/ca.crt` / `certs/ca.key` : Trusted root CA certificate and private key.
- `certs/server.crt` / `certs/server.key` : Server certificate signed by the CA and matching private key.
- `certs/mallory/` : Mallory's rogue certificates used for attack testing.

## Compilation
```bash
g++ -O2 -pthread server.cpp -lssl -lcrypto -o server
g++ -O2 -pthread client.cpp -lssl -lcrypto -o client
g++ -O2 -pthread mitm.cpp -lssl -lcrypto -o mitm
```

## Running the Application
1. **Start the Legitimate Server**:
   ```bash
   ./server
   ```

2. **Connect Legitimate Client**:
   ```bash
   ./client <server_ip> 1111
   ```

3. **Running the MITM Attack Test**:
   ```bash
   ./mitm <server_ip> 1111 2222
   ./client <mallory_ip> 2222
   ```
   *Expected result:* The client rejects the connection with a certificate validation failure because Mallory's certificate is not signed by the trusted CA.


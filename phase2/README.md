# Phase 2: Client-Server Confidentiality (Diffie-Hellman & AES-GCM)

## Overview
Phase 2 adds channel confidentiality to the chat application. Each client performs an independent Diffie-Hellman key exchange (RFC 3526 Group 14) with the server, derives an AES-256 key via SHA-256, and encrypts all communication using AES-256-GCM. A separate MITM proxy (`mitm.cpp`) demonstrates why unauthenticated DH is vulnerable to interception.

## Compilation
```bash
g++ -O2 -pthread server.cpp -lssl -lcrypto -o server
g++ -O2 -pthread client.cpp -lssl -lcrypto -o client
g++ -O2 -pthread mitm.cpp -lssl -lcrypto -o mitm
```

## Running the Application
1. **Start the Server**:
   ```bash
   ./server
   ```

2. **Start Clients**:
   ```bash
   ./client <server_ip> 1111
   ```

3. **Running the MITM Attack (Mallory)**:
   Start the proxy to intercept between client and server:
   ```bash
   ./mitm <server_ip> 1111 2222
   ```
   Point the victim client to Mallory's port:
   ```bash
   ./client <mallory_ip> 2222
   ```

## Key Verifications
- **Fingerprint Matching**: Both endpoints print matching SHA-256 fingerprints of the derived AES key.
- **Tamper Detection**: AES-GCM tag verification rejects any modified or corrupted ciphertext.
- **MITM Attack**: Mallory establishes separate DH keys with the victim and server, reading plaintext messages in transit.

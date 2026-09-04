# Phase 5: Forward Secrecy via Key Rotation

## Overview
Phase 5 extends the Phase 4 E2E session with Forward Secrecy. The client-to-client shared key is renegotiated automatically on a 60-second fixed timer. Each rotation generates a completely new Diffie-Hellman key pair, and the old key is erased once rotation completes. Simultaneous rekey requests are resolved deterministically based on username priority (`user1 < user2`).

## Key Properties
- **Automatic Rekeying**: Background timer thread triggers a fresh DH exchange every 60 seconds.
- **Old Key Destruction**: Previous key is zeroed and freed (`destroyDHE`) upon receiving confirmation, ensuring past conversations cannot be decrypted if the current key is compromised.
- **Collision Avoidance**: If both clients trigger rotation at the same time, the client with lower username priority yields to avoid key disagreement.
- **Uninterrupted Chat**: Ongoing messages continue over the confirmed session key without packet drops during handshake.

## Compilation
```bash
g++ -O2 -pthread server.cpp -lssl -lcrypto -o server
g++ -O2 -pthread client.cpp -lssl -lcrypto -o client
```

## Running the Application
1. **Start the Server**:
   ```bash
   ./server
   ```

2. **Start Both Clients**:
   ```bash
   ./client <server_ip> 1111
   ```

3. **Start E2E Session**:
   ```text
   /e2e <partner_username>
   ```
   Both clients establish the session and periodically log new matching fingerprints every 60 seconds.

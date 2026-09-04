# Phase 4: End-to-End (E2E) Encryption Between Clients

## Overview
Phase 4 introduces end-to-end encryption between Client 1 and Client 2 on top of the Phase 3 authenticated transport. Clients perform an independent Diffie-Hellman key exchange directly with each other using the server as a message relay. The server only sees opaque ciphertext and cannot read chat content.

## Wire-Level Protocol Tags
- `__E2E_INIT__<pubkey_hex>` : Initiates end-to-end key exchange.
- `__E2E_ACK__<pubkey_hex>`  : Completes end-to-end key exchange.
- `__E2E_MSG__<payload_hex>` : Application chat message encrypted with the client-to-client AES key.

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

2. **Start Client 1 (e.g. Alice)**:
   ```bash
   ./client <server_ip> 1111
   ```

3. **Start Client 2 (e.g. Bob)**:
   ```bash
   ./client <server_ip> 1111
   ```

4. **Initiate E2E Session**:
   From Alice's terminal, type:
   ```text
   /e2e bob
   ```
   Both clients verify matching E2E fingerprints. Subsequent messages sent with `@bob <msg>` or via active chat are encrypted with the E2E key.

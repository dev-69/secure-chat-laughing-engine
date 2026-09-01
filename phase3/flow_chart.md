                    ┌─────────────────┐
                    │       CA        │
                    │                 │
                    │ CA private key  │
                    │ CA certificate  │
                    └────────┬────────┘
                             │
                             │ signs
                             ▼
                    ┌─────────────────┐
                    │ Server          │
                    │ certificate     │
                    │                 │
                    │ Server public   │
                    │ key             │
                    └─────────────────┘


Client                                      Server
  │                                            │
  │------------- TCP connect ----------------->│
  │                                            │
  │<---------- server certificate ------------│
  │                                            │
  │                                            │
  │ Verify CA signature                       │
  │ Check validity period                     │
  │ Check server identity                     │
  │                                            │
  │------------- random challenge ----------->│
  │                                            │
  │<------------ signed challenge -------------│
  │                                            │
  │ Verify using certificate's public key     │
  │                                            │
  │                                            │
  │-------------- DH exchange --------------->│
  │                                            │
  │                                            │
  │          Shared secret established        │
  │                                            │
  │============= encrypted chat ==============│


----------------------------------------------------------------------------------------------------------------------

                    ┌─────────────────┐
                    │       CA        │
                    │                 │
                    │ CA private key  │
                    │ CA certificate  │
                    └────────┬────────┘
                             │
                             │ signs
                             ▼
                    ┌─────────────────┐
                    │ Server          │
                    │ certificate     │
                    │                 │
                    │ Server public   │
                    │ key             │
                    └─────────────────┘


Client                                      Server
  │                                            │
  │------------- TCP connect ----------------->│
  │                                            │
  │<---------- server certificate ------------│
  │                                            │
  │                                            │
  │ Verify CA signature                       │
  │ Check validity period                     │
  │ Check server identity                     │
  │                                            │
  │------------- random challenge ----------->│
  │                                            │
  │<------------ signed challenge -------------│
  │                                            │
  │ Verify using certificate's public key     │
  │                                            │
  │                                            │
  │-------------- DH exchange --------------->│
  │                                            │
  │                                            │
  │          Shared secret established        │
  │                                            │
  │============= encrypted chat ==============│



CLIENT                                      SERVER
  │                                            │
  │──────────── TCP connection ───────────────>│
  │                                            │
  │<────────── server certificate ─────────────│
  │                                            │
  │ Verify certificate using trusted CA        │
  │                                            │
  │ ✓ CA signature                             │
  │ ✓ validity period                          │
  │                                            │
  │──────── random 32-byte challenge ─────────>│
  │                                            │
  │                                  Sign(challenge)
  │                                  using server.key
  │                                            │
  │<──────────── signature ────────────────────│
  │                                            │
  │ Verify(signature, challenge,               │
  │           public key from certificate)     │
  │                                            │
  │ ✓ Proof of possession                      │
  │                                            │
  │──────────── DH public key ────────────────>│
  │<──────────── DH public key ────────────────│
  │                                            │
  │          Shared DH secret                  │
  │                                            │
  │          AES-256-GCM chat                  │
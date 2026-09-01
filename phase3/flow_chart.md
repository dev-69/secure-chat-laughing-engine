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


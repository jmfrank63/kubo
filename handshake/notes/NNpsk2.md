# NNpsk2

1. **Initiator**:

    - Use `generate_keypair()` to generate the initiator's ephemeral key pair (`e`).
    - The generated `Keypair` struct will contain both the public and private components
      of the ephemeral key.
    - Send the public component (contained in `Keypair.public`) to the Responder.

2. **Responder**:

    - Upon receiving the initiator's ephemeral public key, the Responder will also use
      `generate_keypair()` to generate its own ephemeral key pair (`e`).
    - Perform the DH operation using its ephemeral private key and the received
      initiator's ephemeral public key to get the shared secret.
    - Mix in the PSK (if you're using a pattern with a PSK).
    - Send its own ephemeral public key (from its `Keypair.public`) back to the initiator.

3. **Initiator**:
    - Upon receiving the responder's ephemeral public key, it will also perform the DH operation
      using its ephemeral private key and the received responder's ephemeral public key to get
      the shared secret.
    - Mix in the PSK (again, if a PSK pattern is used).

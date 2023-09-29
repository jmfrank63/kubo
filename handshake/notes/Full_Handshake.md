# Handshake

To implement the `Noise_NNpsk2_ChaChaPoly_Blake2s` handshake pattern using the
Noise protocol, we need to ensure that all components are in place. Based on the name of the pattern:

1. `NN`: This represents the handshake pattern where two parties, both initiating and responding,
   do not authenticate each other.
2. `psk2`: This denotes that a pre-shared key is being used during the second message flow.
3. `ChaChaPoly`: Specifies that ChaCha20Poly1305 will be used as the symmetric cipher for encryption
   and decryption.
4. `Blake2s`: This signifies the use of the Blake2s hash function in the protocol.

Given the information you've provided, and from our previous discussions:

- You have functions for encryption and decryption using `ChaCha20Poly1305`.
- You have a way to decode the shared secret.

What might still be needed:

1. **Handshake Logic**: The actual handshake steps according to the `NNpsk2` pattern. This typically
    involves:

        - Initiator sends a message (often public key or some initial data).
        - Responder replies with its message (often public key), and both sides compute a shared secret
        (possibly with DH or some other method, or using a pre-shared key as indicated by `psk2`).

2. **Blake2s Hashing**: Integration of the Blake2s hash function wherever required by the Noise
    specification for this pattern.

3. **Key Derivation and State Management**: Noise protocol often involves managing state, deriving
    various keys (e.g., chaining keys), and updating state as the handshake progresses.

4. **Error Handling and Logging**: It's always a good idea to have robust error handling and
    optionally logging for debugging.

5. **Testing**: Once the handshake logic is implemented, it will be essential to test the handshake
    to ensure it works as expected.

6. **Integration with Actual Transport**: The handshake is just the initial step. Once it's complete,
    you'll probably want to integrate with whatever transport layer you're using (e.g., TCP, UDP, etc.)
    to send and receive encrypted messages.

7. **Documentation**: Documenting the steps, expected inputs/outputs, and any assumptions will be
    crucial for anyone using or maintaining the code in the future.

If you've addressed all these points or they are not applicable to your use-case, then you might be
set! Otherwise, you might want to consider the points above.

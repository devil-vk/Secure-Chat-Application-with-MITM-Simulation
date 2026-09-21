// crypto.hpp — Application-layer cryptography primitives.
//
// This module provides the building blocks used for END-TO-END confidentiality,
// independent of the TLS transport layer:
//
//   * DiffieHellman  — ephemeral DH key exchange (RFC 3526 2048-bit MODP group)
//                      producing a shared secret known only to the two endpoints.
//   * derive_key     — HKDF-SHA256 that turns the raw DH secret into a 256-bit
//                      AES key.
//   * aes_gcm_encrypt / aes_gcm_decrypt — authenticated encryption (AES-256-GCM)
//                      giving both confidentiality and integrity in one step.
//
// The point of the layered design: even if the TLS layer were stripped or
// downgraded by a man-in-the-middle, the payload is still sealed under a key the
// attacker never sees. See docs/ATTACKS.md for how this is demonstrated.

#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace sca {

using Bytes = std::vector<uint8_t>;

// Ephemeral Diffie-Hellman over the 2048-bit MODP group (RFC 3526, group 14).
// Each side creates one object, exchanges public_key(), and both arrive at the
// same compute_shared() value without the secret ever crossing the wire.
class DiffieHellman {
public:
    DiffieHellman();
    ~DiffieHellman();

    DiffieHellman(const DiffieHellman&) = delete;
    DiffieHellman& operator=(const DiffieHellman&) = delete;

    // This side's public value, to be sent to the peer.
    Bytes public_key() const;

    // Combine our private key with the peer's public value to get the shared
    // secret. Throws std::runtime_error on malformed peer input.
    Bytes compute_shared(const Bytes& peer_public) const;

private:
    struct Impl;
    Impl* impl_;
};

// HKDF-SHA256: turn an arbitrary-length shared secret into a fixed 32-byte key.
// `info` binds the key to a purpose (e.g. "sca chat v1") so the same secret can
// derive independent keys for different uses.
Bytes derive_key(const Bytes& shared_secret,
                 const std::string& info,
                 size_t out_len = 32);

// AES-256-GCM authenticated encryption.
// Output layout: [12-byte IV][16-byte tag][ciphertext].
Bytes aes_gcm_encrypt(const Bytes& key, const Bytes& plaintext);

// Reverse of aes_gcm_encrypt. Throws std::runtime_error if the authentication
// tag does not verify (i.e. the ciphertext was tampered with or the key wrong).
Bytes aes_gcm_decrypt(const Bytes& key, const Bytes& sealed);

// Convenience helpers.
Bytes to_bytes(const std::string& s);
std::string to_string(const Bytes& b);
std::string hex(const Bytes& b);

} // namespace sca

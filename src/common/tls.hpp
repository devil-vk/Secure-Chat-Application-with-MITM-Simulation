// tls.hpp — OpenSSL context/session helpers.
//
// Centralises how the SSL_CTX is built so the same rules apply everywhere:
//   * The server presents a certificate chain signed by our project CA.
//   * The client verifies that chain against the CA bundle (the "chain of
//     trust"). A certificate not signed by the trusted CA is rejected — this is
//     exactly what defeats the MITM proxy in the demo.
//   * A minimum protocol version can be pinned to block SSL/TLS downgrade.

#pragma once

#include <string>

typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;

namespace sca {

struct TlsConfig {
    // Server side: certificate chain + private key.
    std::string cert_file;   // PEM: server cert (optionally followed by chain)
    std::string key_file;    // PEM: server private key

    // Client side: CA bundle used to verify the peer's chain.
    std::string ca_file;

    // Verify the peer certificate against ca_file. Turning this OFF on the
    // client is what makes a MITM possible — the demo toggles it to show the
    // difference.
    bool verify_peer = true;

    // Minimum negotiated protocol. "1.2" pins TLS 1.2+ and blocks downgrade to
    // TLS 1.0/1.1. "1.0" deliberately allows legacy versions for the downgrade
    // demonstration.
    std::string min_version = "1.2";

    // Optional maximum protocol. Empty means "no cap" (negotiate the highest
    // both sides support). The MITM tool sets this to "1.0" to *simulate* an
    // attacker that strips modern versions from the handshake — a real
    // downgrade attempt that a server with min_version 1.2 will refuse.
    std::string max_version = "";
};

// Build a server-side context (loads cert + key). Returns nullptr on error and
// prints the reason.
SSL_CTX* make_server_ctx(const TlsConfig& cfg);

// Build a client-side context (loads CA bundle, sets verify mode).
SSL_CTX* make_client_ctx(const TlsConfig& cfg);

void free_ctx(SSL_CTX* ctx);

// Perform the TLS handshake over an already-connected fd.
// `expected_hostname` (client side) enables certificate hostname checking when
// non-empty. Returns the SSL* on success, nullptr on failure (reason printed).
SSL* server_handshake(SSL_CTX* ctx, int fd);
SSL* client_handshake(SSL_CTX* ctx, int fd, const std::string& expected_hostname);

void shutdown_ssl(SSL* ssl);

// Human-readable summary of the negotiated session (protocol + cipher).
std::string describe_session(SSL* ssl);

} // namespace sca

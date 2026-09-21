// net.hpp — thin TCP socket helpers plus length-prefixed message framing.
//
// TCP is a byte stream with no message boundaries, so every logical message is
// framed as a 4-byte big-endian length followed by that many payload bytes.
// The read/write helpers work on a plain fd (used by the P2P and MITM tools) or
// on an OpenSSL SSL* (used once a TLS session is established).

#pragma once

#include <string>
#include <vector>
#include <cstdint>

typedef struct ssl_st SSL; // forward-declare to avoid pulling <openssl/ssl.h> here

namespace sca {

using Bytes = std::vector<uint8_t>;

// ---- Connection setup ------------------------------------------------------

// Create a listening TCP socket bound to host:port. Returns the listen fd or -1.
int tcp_listen(const std::string& host, uint16_t port, int backlog = 16);

// Accept one client. Returns the connection fd or -1.
int tcp_accept(int listen_fd);

// Connect to host:port. Returns the connection fd or -1.
int tcp_connect(const std::string& host, uint16_t port);

void tcp_close(int fd);

// ---- Framed I/O over a raw fd ----------------------------------------------

// Returns false on connection close / error.
bool send_frame(int fd, const Bytes& payload);
bool recv_frame(int fd, Bytes& out);

// ---- Framed I/O over an established TLS session -----------------------------

bool ssl_send_frame(SSL* ssl, const Bytes& payload);
bool ssl_recv_frame(SSL* ssl, Bytes& out);

} // namespace sca

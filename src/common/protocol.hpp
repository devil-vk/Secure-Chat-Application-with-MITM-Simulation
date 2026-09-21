// protocol.hpp — shared constants describing the application handshake.
//
// Once the TLS session is up, both sides run this small application protocol:
//
//   1. DH exchange:  each side sends one framed message containing its raw DH
//      public value; both derive the same AES-256 key via HKDF.
//   2. Identity:     the client sends one AES-GCM-sealed frame with its username.
//   3. Chat:         every subsequent frame is an AES-GCM-sealed UTF-8 message.
//
// Keeping the info string and version in one place ensures client, server, P2P
// and the MITM tool all agree on the key-derivation binding.

#pragma once

namespace sca {

// HKDF `info` label — binds derived keys to this application + version so a
// secret reused elsewhere cannot produce the same chat key.
constexpr const char* kKdfInfo = "sca chat v1";

// Default endpoints used across the tools and demo scripts.
constexpr const char* kDefaultHost = "127.0.0.1";
constexpr unsigned short kDefaultServerPort = 8443;
constexpr unsigned short kDefaultP2PPort = 9443;

} // namespace sca

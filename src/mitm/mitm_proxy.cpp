// mitm_proxy.cpp — man-in-the-middle demonstration proxy (EDUCATIONAL).
//
// This tool exists to show, on your own machine, WHY the defences in this
// project matter. It is a lab instrument, not an attack tool: it only works
// against the loopback client/server you run yourself.
//
// It sits between the client and the real server and attempts a two-layer
// interception:
//
//   Layer 1 (TLS): it terminates the client's TLS using a FORGED certificate
//   (self-signed, NOT issued by the project CA) and opens its own TLS session
//   to the real server.
//     * If the client verifies certificates (chain of trust), the client
//       rejects the forged cert and the handshake fails here — the attack is
//       stopped cold. This is the defence being demonstrated.
//     * Only if the client is run with --insecure does Layer 1 succeed.
//
//   Layer 2 (application DH): if Layer 1 succeeds, the proxy also runs a
//   separate Diffie-Hellman exchange with each side. Because plain DH is
//   unauthenticated, the proxy ends up holding one key with the client and a
//   different key with the server, letting it decrypt, print, and re-encrypt
//   every message. This is exactly the attack that TLS's authenticated
//   handshake is designed to prevent — hence Layer 1 is what actually keeps
//   you safe.
//
// It can also illustrate an SSL-downgrade attempt with --downgrade, which
// forces its TLS legs down to TLS 1.0; a server started with --min-version 1.2
// refuses, showing why a protocol floor matters.
//
// Usage:
//   mitm_proxy [--listen-port 8444] [--server-host H] [--server-port 8443]
//              [--cert certs/mitm.crt] [--key certs/mitm.key]
//              [--ca certs/ca.crt] [--downgrade]

#include "../common/crypto.hpp"
#include "../common/net.hpp"
#include "../common/tls.hpp"
#include "../common/protocol.hpp"

#include <openssl/ssl.h>

#include <atomic>
#include <cstdio>
#include <string>
#include <thread>

using namespace sca;

namespace {

void relay(SSL* from, const Bytes& from_key,
           SSL* to, const Bytes& to_key,
           const char* label, std::atomic<bool>& running) {
    while (running) {
        Bytes sealed;
        if (!ssl_recv_frame(from, sealed)) { running = false; break; }
        try {
            Bytes plain = aes_gcm_decrypt(from_key, sealed);
            printf("[mitm] intercepted %s: \"%s\"\n", label, to_string(plain).c_str());
            fflush(stdout);
            // Re-seal under the other leg's key and forward, so neither side
            // notices anything is wrong.
            if (!ssl_send_frame(to, aes_gcm_encrypt(to_key, plain))) { running = false; break; }
        } catch (const std::exception& e) {
            fprintf(stderr, "[mitm] %s frame failed to decrypt: %s\n", label, e.what());
            running = false;
            break;
        }
    }
}

} // namespace

int main(int argc, char** argv) {
    uint16_t listen_port = 8444;
    std::string server_host = kDefaultHost;
    uint16_t server_port = kDefaultServerPort;
    bool downgrade = false;

    TlsConfig forged;               // what we present to the victim client
    forged.cert_file = "certs/mitm.crt";
    forged.key_file  = "certs/mitm.key";
    forged.min_version = "1.2";

    TlsConfig upstream;             // how we talk to the real server
    upstream.ca_file = "certs/ca.crt";
    upstream.verify_peer = true;
    upstream.min_version = "1.2";

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() { return (i + 1 < argc) ? argv[++i] : ""; };
        if (a == "--listen-port") listen_port = static_cast<uint16_t>(std::stoi(next()));
        else if (a == "--server-host") server_host = next();
        else if (a == "--server-port") server_port = static_cast<uint16_t>(std::stoi(next()));
        else if (a == "--cert") forged.cert_file = next();
        else if (a == "--key") forged.key_file = next();
        else if (a == "--ca") upstream.ca_file = next();
        else if (a == "--downgrade") downgrade = true;
        else if (a == "--help") {
            printf("usage: mitm_proxy [--listen-port N] [--server-host H] [--server-port N]\n"
                   "                  [--cert F] [--key F] [--ca F] [--downgrade]\n");
            return 0;
        }
    }

    setvbuf(stdout, nullptr, _IOLBF, 0); // line-buffer logs so they appear promptly

    if (downgrade) {
        // Simulate an attacker stripping the strongest protocol: cap both legs
        // at TLS 1.2 (i.e. refuse to speak TLS 1.3). A server that requires a
        // minimum of TLS 1.3 will refuse to negotiate, defeating the downgrade;
        // a server that still permits 1.2 gets downgraded to the weaker version.
        //
        // Note: TLS 1.0/1.1 would be the classic downgrade target, but modern
        // OpenSSL disables them outright ("no protocols available"), which is an
        // even stronger defence — see docs/ATTACKS.md.
        forged.max_version = "1.2";
        upstream.max_version = "1.2";
        printf("[mitm] downgrade mode: stripping TLS 1.3, offering only up to TLS 1.2\n");
    }

    SSL_library_init();
    SSL_load_error_strings();

    SSL_CTX* client_facing = make_server_ctx(forged);   // presents forged cert
    SSL_CTX* server_facing = make_client_ctx(upstream); // connects to real server
    if (!client_facing || !server_facing) return 1;

    int listen_fd = tcp_listen(kDefaultHost, listen_port);
    if (listen_fd < 0) { fprintf(stderr, "[mitm] bind failed on port %u\n", listen_port); return 1; }

    printf("[mitm] proxy listening on %s:%u, forwarding to real server %s:%u\n",
           kDefaultHost, listen_port, server_host.c_str(), server_port);
    printf("[mitm] presenting FORGED certificate: %s\n", forged.cert_file.c_str());
    printf("[mitm] point the victim client at --port %u to run the demo.\n", listen_port);

    while (true) {
        int cfd = tcp_accept(listen_fd);
        if (cfd < 0) continue;
        printf("\n[mitm] victim connected — starting interception\n");

        // Layer 1a: TLS handshake with the victim using the forged certificate.
        SSL* victim = server_handshake(client_facing, cfd);
        if (!victim) {
            printf("[mitm] victim REJECTED the forged certificate — chain of trust held. "
                   "Interception blocked.\n");
            tcp_close(cfd);
            continue;
        }
        printf("[mitm] victim accepted forged cert (insecure client). session=%s\n",
               describe_session(victim).c_str());

        // Layer 1b: our own TLS session to the real server.
        int sfd = tcp_connect(server_host, server_port);
        if (sfd < 0) { printf("[mitm] cannot reach real server\n"); shutdown_ssl(victim); tcp_close(cfd); continue; }
        SSL* upstream_ssl = client_handshake(server_facing, sfd, "localhost");
        if (!upstream_ssl) {
            printf("[mitm] could not establish TLS to real server (min-version floor?). Aborting.\n");
            shutdown_ssl(victim); tcp_close(cfd); tcp_close(sfd);
            continue;
        }
        printf("[mitm] upstream session to real server=%s\n", describe_session(upstream_ssl).c_str());

        // Layer 2: actively man-in-the-middle the application DH exchange.
        // Protocol: client sends its DH public first; server replies with its.
        Bytes client_pub;
        if (!ssl_recv_frame(victim, client_pub)) { shutdown_ssl(victim); shutdown_ssl(upstream_ssl); tcp_close(cfd); tcp_close(sfd); continue; }

        DiffieHellman dh_to_client;   // our identity toward the client
        DiffieHellman dh_to_server;   // our identity toward the server

        // Reply to the client as if we were the server.
        ssl_send_frame(victim, dh_to_client.public_key());
        // Start the DH with the real server as if we were the client.
        ssl_send_frame(upstream_ssl, dh_to_server.public_key());
        Bytes server_pub;
        if (!ssl_recv_frame(upstream_ssl, server_pub)) { shutdown_ssl(victim); shutdown_ssl(upstream_ssl); tcp_close(cfd); tcp_close(sfd); continue; }

        Bytes key_client, key_server;
        try {
            key_client = derive_key(dh_to_client.compute_shared(client_pub), kKdfInfo);
            key_server = derive_key(dh_to_server.compute_shared(server_pub), kKdfInfo);
        } catch (const std::exception& e) {
            fprintf(stderr, "[mitm] DH MITM failed: %s\n", e.what());
            shutdown_ssl(victim); shutdown_ssl(upstream_ssl); tcp_close(cfd); tcp_close(sfd);
            continue;
        }
        printf("[mitm] two-key DH MITM established — messages are now readable in the clear.\n");

        std::atomic<bool> running{true};
        std::thread c2s(relay, victim, std::cref(key_client), upstream_ssl, std::cref(key_server),
                        "client->server", std::ref(running));
        std::thread s2c(relay, upstream_ssl, std::cref(key_server), victim, std::cref(key_client),
                        "server->client", std::ref(running));
        c2s.join();
        s2c.join();

        shutdown_ssl(victim);
        shutdown_ssl(upstream_ssl);
        tcp_close(cfd);
        tcp_close(sfd);
        printf("[mitm] session closed\n");
    }

    free_ctx(client_facing);
    free_ctx(server_facing);
    return 0;
}

// chat_client.cpp — secure chat client.
//
// Connects to the server, verifies the server's certificate against the project
// CA (chain of trust), runs the DH exchange, then sends/receives AES-GCM-sealed
// messages. A background thread prints incoming messages while the main thread
// reads the user's input.
//
// Usage:
//   chat_client [--host H] [--port N] [--ca F] [--name NAME]
//               [--insecure] [--min-version 1.0|1.2|1.3] [--sni HOST]
//
//   --insecure   disable certificate verification. This is the vulnerable mode
//                a MITM needs; with verification ON, the MITM's forged
//                certificate is rejected and the connection aborts.

#include "../common/crypto.hpp"
#include "../common/net.hpp"
#include "../common/tls.hpp"
#include "../common/protocol.hpp"

#include <openssl/ssl.h>

#include <atomic>
#include <cstdio>
#include <iostream>
#include <string>
#include <thread>

using namespace sca;

int main(int argc, char** argv) {
    std::string host = kDefaultHost;
    uint16_t port = kDefaultServerPort;
    std::string name = "anon";
    std::string sni = "localhost"; // must match the server cert's subject/SAN
    TlsConfig cfg;
    cfg.ca_file = "certs/ca.crt";
    cfg.verify_peer = true;
    cfg.min_version = "1.2";

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() { return (i + 1 < argc) ? argv[++i] : ""; };
        if (a == "--host") host = next();
        else if (a == "--port") port = static_cast<uint16_t>(std::stoi(next()));
        else if (a == "--ca") cfg.ca_file = next();
        else if (a == "--name") name = next();
        else if (a == "--sni") sni = next();
        else if (a == "--insecure") cfg.verify_peer = false;
        else if (a == "--min-version") cfg.min_version = next();
        else if (a == "--help") {
            printf("usage: chat_client [--host H] [--port N] [--ca F] [--name NAME] "
                   "[--insecure] [--min-version V] [--sni HOST]\n");
            return 0;
        }
    }

    setvbuf(stdout, nullptr, _IOLBF, 0); // line-buffer logs so they appear promptly

    SSL_library_init();
    SSL_load_error_strings();

    SSL_CTX* ctx = make_client_ctx(cfg);
    if (!ctx) return 1;

    int fd = tcp_connect(host, port);
    if (fd < 0) { fprintf(stderr, "[client] connect to %s:%u failed\n", host.c_str(), port); free_ctx(ctx); return 1; }

    // With verify_peer on, an empty SNI still verifies the chain; passing the
    // hostname additionally checks the cert was issued for this host.
    std::string check_host = cfg.verify_peer ? sni : "";
    SSL* ssl = client_handshake(ctx, fd, check_host);
    if (!ssl) {
        fprintf(stderr, "[client] TLS handshake failed — refusing to continue.\n");
        if (cfg.verify_peer)
            fprintf(stderr, "[client] (the server's certificate is not trusted by %s)\n",
                    cfg.ca_file.c_str());
        tcp_close(fd); free_ctx(ctx); return 1;
    }

    printf("[client] connected securely: %s\n", describe_session(ssl).c_str());
    if (!cfg.verify_peer)
        printf("[client] WARNING: certificate verification is DISABLED (insecure mode)\n");

    // --- Application-layer DH ---
    DiffieHellman dh;
    if (!ssl_send_frame(ssl, dh.public_key())) { shutdown_ssl(ssl); tcp_close(fd); return 1; }
    Bytes server_pub;
    if (!ssl_recv_frame(ssl, server_pub)) { shutdown_ssl(ssl); tcp_close(fd); return 1; }

    Bytes key;
    try {
        key = derive_key(dh.compute_shared(server_pub), kKdfInfo);
    } catch (const std::exception& e) {
        fprintf(stderr, "[client] DH failed: %s\n", e.what());
        shutdown_ssl(ssl); tcp_close(fd); return 1;
    }

    // --- Identity ---
    ssl_send_frame(ssl, aes_gcm_encrypt(key, to_bytes(name)));

    std::atomic<bool> running{true};

    // Reader thread: print incoming sealed messages.
    std::thread reader([&]() {
        while (running) {
            Bytes sealed;
            if (!ssl_recv_frame(ssl, sealed)) { running = false; break; }
            try {
                std::string msg = to_string(aes_gcm_decrypt(key, sealed));
                printf("\r%s\n> ", msg.c_str());
                fflush(stdout);
            } catch (const std::exception& e) {
                fprintf(stderr, "[client] dropped a message failing integrity: %s\n", e.what());
            }
        }
    });

    printf("[client] type messages and press enter. /quit to leave.\n> ");
    fflush(stdout);

    std::string line;
    while (running && std::getline(std::cin, line)) {
        if (!ssl_send_frame(ssl, aes_gcm_encrypt(key, to_bytes(line)))) break;
        if (line == "/quit") break;
        printf("> ");
        fflush(stdout);
    }

    // Shut down in an order that avoids a use-after-free: the reader thread is
    // blocked in SSL_read, so close the socket first to unblock it, join it, and
    // only then free the SSL object (which the reader was still using).
    running = false;
    tcp_close(fd);
    if (reader.joinable()) reader.join();
    shutdown_ssl(ssl);
    free_ctx(ctx);
    return 0;
}

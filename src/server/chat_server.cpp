// chat_server.cpp — multi-client secure chat server.
//
// Per client the server:
//   1. Completes a TLS handshake, presenting a CA-signed certificate chain.
//   2. Runs an application-layer Diffie-Hellman exchange and derives a
//      per-session AES-256 key (defence in depth on top of TLS).
//   3. Relays AES-GCM-sealed chat messages to every other connected client,
//      re-sealing under each recipient's own session key.
//
// Usage:
//   chat_server [--port N] [--cert F] [--key F] [--min-version 1.0|1.2|1.3]
//
// The --min-version flag exists so the SSL-downgrade demo can start a server
// that (mis)allows legacy TLS versions.

#include "../common/crypto.hpp"
#include "../common/net.hpp"
#include "../common/tls.hpp"
#include "../common/protocol.hpp"

#include <openssl/ssl.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <thread>

using namespace sca;

namespace {

struct Client {
    SSL* ssl = nullptr;
    Bytes key;            // per-session AES-256 key
    std::string name;
};

std::mutex g_mutex;
std::map<int, Client> g_clients;   // id -> client
std::atomic<int> g_next_id{1};

void broadcast(int from_id, const std::string& text) {
    std::lock_guard<std::mutex> lock(g_mutex);
    for (auto& [id, c] : g_clients) {
        if (id == from_id) continue;
        Bytes sealed = aes_gcm_encrypt(c.key, to_bytes(text));
        ssl_send_frame(c.ssl, sealed);
    }
}

void handle_client(int fd, SSL* ssl) {
    int id = g_next_id.fetch_add(1);

    // --- Application-layer DH: server responds with its public value ---
    Bytes client_pub;
    if (!ssl_recv_frame(ssl, client_pub)) { shutdown_ssl(ssl); tcp_close(fd); return; }

    DiffieHellman dh;
    if (!ssl_send_frame(ssl, dh.public_key())) { shutdown_ssl(ssl); tcp_close(fd); return; }

    Bytes shared;
    try {
        shared = dh.compute_shared(client_pub);
    } catch (const std::exception& e) {
        fprintf(stderr, "[server] DH failed for client %d: %s\n", id, e.what());
        shutdown_ssl(ssl); tcp_close(fd); return;
    }
    Bytes key = derive_key(shared, kKdfInfo);

    // --- Identity ---
    Bytes sealed_name;
    if (!ssl_recv_frame(ssl, sealed_name)) { shutdown_ssl(ssl); tcp_close(fd); return; }
    std::string name;
    try {
        name = to_string(aes_gcm_decrypt(key, sealed_name));
    } catch (const std::exception& e) {
        fprintf(stderr, "[server] identity decrypt failed: %s\n", e.what());
        shutdown_ssl(ssl); tcp_close(fd); return;
    }

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_clients[id] = Client{ssl, key, name};
    }
    printf("[server] '%s' joined (id=%d, session=%s)\n",
           name.c_str(), id, describe_session(ssl).c_str());
    broadcast(id, "* " + name + " joined the chat *");

    // --- Chat loop ---
    while (true) {
        Bytes sealed;
        if (!ssl_recv_frame(ssl, sealed)) break;
        std::string msg;
        try {
            msg = to_string(aes_gcm_decrypt(key, sealed));
        } catch (const std::exception& e) {
            fprintf(stderr, "[server] '%s' message failed integrity check: %s\n",
                    name.c_str(), e.what());
            break;
        }
        if (msg == "/quit") break;
        printf("[%s] %s\n", name.c_str(), msg.c_str());
        broadcast(id, name + ": " + msg);
    }

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_clients.erase(id);
    }
    printf("[server] '%s' left (id=%d)\n", name.c_str(), id);
    broadcast(id, "* " + name + " left the chat *");
    shutdown_ssl(ssl);
    tcp_close(fd);
}

} // namespace

int main(int argc, char** argv) {
    uint16_t port = kDefaultServerPort;
    TlsConfig cfg;
    cfg.cert_file = "certs/server.crt";
    cfg.key_file  = "certs/server.key";
    cfg.min_version = "1.2";

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() { return (i + 1 < argc) ? argv[++i] : ""; };
        if (a == "--port") port = static_cast<uint16_t>(std::stoi(next()));
        else if (a == "--cert") cfg.cert_file = next();
        else if (a == "--key") cfg.key_file = next();
        else if (a == "--min-version") cfg.min_version = next();
        else if (a == "--help") {
            printf("usage: chat_server [--port N] [--cert F] [--key F] [--min-version 1.0|1.2|1.3]\n");
            return 0;
        }
    }

    setvbuf(stdout, nullptr, _IOLBF, 0); // line-buffer logs so they appear promptly

    SSL_library_init();
    SSL_load_error_strings();

    SSL_CTX* ctx = make_server_ctx(cfg);
    if (!ctx) return 1;

    int listen_fd = tcp_listen(kDefaultHost, port);
    if (listen_fd < 0) { fprintf(stderr, "[server] bind failed on port %u\n", port); free_ctx(ctx); return 1; }

    printf("[server] secure chat server listening on %s:%u (min TLS %s)\n",
           kDefaultHost, port, cfg.min_version.c_str());
    printf("[server] presenting certificate chain: %s\n", cfg.cert_file.c_str());

    while (true) {
        int fd = tcp_accept(listen_fd);
        if (fd < 0) continue;
        SSL* ssl = server_handshake(ctx, fd);
        if (!ssl) { tcp_close(fd); continue; }
        std::thread(handle_client, fd, ssl).detach();
    }

    free_ctx(ctx);
    tcp_close(listen_fd);
    return 0;
}

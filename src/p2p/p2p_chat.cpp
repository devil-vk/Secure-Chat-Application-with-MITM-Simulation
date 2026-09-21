// p2p_chat.cpp — peer-to-peer end-to-end encrypted chat (no central server).
//
// Two peers connect directly. One listens, the other dials in. They perform a
// Diffie-Hellman exchange over the raw socket and derive a shared AES-256 key,
// then exchange AES-GCM-sealed messages. Because there is no relay, the key is
// held only by the two endpoints: this is genuine end-to-end confidentiality —
// anyone in the middle (including the MITM proxy) sees only ciphertext.
//
// Usage:
//   p2p_chat --listen [--port N] [--name NAME]
//   p2p_chat --connect HOST [--port N] [--name NAME]

#include "../common/crypto.hpp"
#include "../common/net.hpp"
#include "../common/protocol.hpp"

#include <atomic>
#include <cstdio>
#include <iostream>
#include <string>
#include <thread>

using namespace sca;

int main(int argc, char** argv) {
    bool listen_mode = false;
    std::string peer_host = kDefaultHost;
    uint16_t port = kDefaultP2PPort;
    std::string name = "peer";

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() { return (i + 1 < argc) ? argv[++i] : ""; };
        if (a == "--listen") listen_mode = true;
        else if (a == "--connect") { listen_mode = false; peer_host = next(); }
        else if (a == "--port") port = static_cast<uint16_t>(std::stoi(next()));
        else if (a == "--name") name = next();
        else if (a == "--help") {
            printf("usage: p2p_chat --listen [--port N] [--name NAME]\n");
            printf("       p2p_chat --connect HOST [--port N] [--name NAME]\n");
            return 0;
        }
    }

    setvbuf(stdout, nullptr, _IOLBF, 0); // line-buffer logs so they appear promptly

    int fd = -1;
    if (listen_mode) {
        int listen_fd = tcp_listen(kDefaultHost, port);
        if (listen_fd < 0) { fprintf(stderr, "[p2p] bind failed on port %u\n", port); return 1; }
        printf("[p2p] listening on %s:%u — waiting for a peer...\n", kDefaultHost, port);
        fd = tcp_accept(listen_fd);
        tcp_close(listen_fd);
        if (fd < 0) { fprintf(stderr, "[p2p] accept failed\n"); return 1; }
        printf("[p2p] peer connected.\n");
    } else {
        fd = tcp_connect(peer_host, port);
        if (fd < 0) { fprintf(stderr, "[p2p] connect to %s:%u failed\n", peer_host.c_str(), port); return 1; }
        printf("[p2p] connected to %s:%u\n", peer_host.c_str(), port);
    }

    // --- Diffie-Hellman directly between the two peers ---
    DiffieHellman dh;
    Bytes peer_pub;
    if (listen_mode) {
        // Listener sends first, then receives — the dialer does the reverse, so
        // the two never block on each other.
        send_frame(fd, dh.public_key());
        if (!recv_frame(fd, peer_pub)) { tcp_close(fd); return 1; }
    } else {
        if (!recv_frame(fd, peer_pub)) { tcp_close(fd); return 1; }
        send_frame(fd, dh.public_key());
    }

    Bytes key;
    try {
        key = derive_key(dh.compute_shared(peer_pub), kKdfInfo);
    } catch (const std::exception& e) {
        fprintf(stderr, "[p2p] DH failed: %s\n", e.what());
        tcp_close(fd); return 1;
    }
    printf("[p2p] end-to-end key established (fingerprint %s...)\n",
           hex(key).substr(0, 16).c_str());

    std::atomic<bool> running{true};

    std::thread reader([&]() {
        while (running) {
            Bytes sealed;
            if (!recv_frame(fd, sealed)) { running = false; break; }
            try {
                std::string msg = to_string(aes_gcm_decrypt(key, sealed));
                if (msg == "/quit") { running = false; break; }
                printf("\r%s\n> ", msg.c_str());
                fflush(stdout);
            } catch (const std::exception& e) {
                fprintf(stderr, "[p2p] dropped a tampered message: %s\n", e.what());
            }
        }
    });

    printf("[p2p] chat ready. type messages, /quit to leave.\n> ");
    fflush(stdout);

    std::string line;
    while (running && std::getline(std::cin, line)) {
        std::string wire = line.empty() ? std::string(" ") : line;
        std::string labeled = (line == "/quit") ? "/quit" : (name + ": " + line);
        if (!send_frame(fd, aes_gcm_encrypt(key, to_bytes(labeled)))) break;
        if (line == "/quit") break;
        printf("> ");
        fflush(stdout);
    }

    running = false;
    tcp_close(fd);
    if (reader.joinable()) reader.join();
    return 0;
}

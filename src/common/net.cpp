#include "net.hpp"

#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <cstdio>

namespace sca {

namespace {
constexpr uint32_t kMaxFrame = 16u * 1024u * 1024u; // 16 MiB sanity cap
} // namespace

int tcp_listen(const std::string& host, uint16_t port, int backlog) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int yes = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) { ::close(fd); return -1; }

    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) { ::close(fd); return -1; }
    if (::listen(fd, backlog) < 0) { ::close(fd); return -1; }
    return fd;
}

int tcp_accept(int listen_fd) {
    sockaddr_in peer{};
    socklen_t len = sizeof(peer);
    return ::accept(listen_fd, reinterpret_cast<sockaddr*>(&peer), &len);
}

int tcp_connect(const std::string& host, uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) { ::close(fd); return -1; }
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) { ::close(fd); return -1; }
    int yes = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
    return fd;
}

void tcp_close(int fd) { if (fd >= 0) ::close(fd); }

// ---- raw fd helpers --------------------------------------------------------

static bool write_all(int fd, const uint8_t* buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t k = ::send(fd, buf + sent, n - sent, 0);
        if (k <= 0) return false;
        sent += static_cast<size_t>(k);
    }
    return true;
}

static bool read_all(int fd, uint8_t* buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t k = ::recv(fd, buf + got, n - got, 0);
        if (k <= 0) return false;
        got += static_cast<size_t>(k);
    }
    return true;
}

bool send_frame(int fd, const Bytes& payload) {
    uint32_t len = htonl(static_cast<uint32_t>(payload.size()));
    if (!write_all(fd, reinterpret_cast<uint8_t*>(&len), 4)) return false;
    return write_all(fd, payload.data(), payload.size());
}

bool recv_frame(int fd, Bytes& out) {
    uint32_t len_be = 0;
    if (!read_all(fd, reinterpret_cast<uint8_t*>(&len_be), 4)) return false;
    uint32_t len = ntohl(len_be);
    if (len > kMaxFrame) return false;
    out.resize(len);
    if (len == 0) return true;
    return read_all(fd, out.data(), len);
}

// ---- SSL helpers -----------------------------------------------------------

static bool ssl_write_all(SSL* ssl, const uint8_t* buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        int k = SSL_write(ssl, buf + sent, static_cast<int>(n - sent));
        if (k <= 0) return false;
        sent += static_cast<size_t>(k);
    }
    return true;
}

static bool ssl_read_all(SSL* ssl, uint8_t* buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        int k = SSL_read(ssl, buf + got, static_cast<int>(n - got));
        if (k <= 0) return false;
        got += static_cast<size_t>(k);
    }
    return true;
}

bool ssl_send_frame(SSL* ssl, const Bytes& payload) {
    uint32_t len = htonl(static_cast<uint32_t>(payload.size()));
    if (!ssl_write_all(ssl, reinterpret_cast<uint8_t*>(&len), 4)) return false;
    return ssl_write_all(ssl, payload.data(), payload.size());
}

bool ssl_recv_frame(SSL* ssl, Bytes& out) {
    uint32_t len_be = 0;
    if (!ssl_read_all(ssl, reinterpret_cast<uint8_t*>(&len_be), 4)) return false;
    uint32_t len = ntohl(len_be);
    if (len > kMaxFrame) return false;
    out.resize(len);
    if (len == 0) return true;
    return ssl_read_all(ssl, out.data(), len);
}

} // namespace sca

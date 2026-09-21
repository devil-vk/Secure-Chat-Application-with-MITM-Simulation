#include "tls.hpp"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include <cstdio>

namespace sca {

namespace {

void print_ssl_errors(const char* where) {
    fprintf(stderr, "[tls] %s failed:\n", where);
    unsigned long e;
    while ((e = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(e, buf, sizeof(buf));
        fprintf(stderr, "      %s\n", buf);
    }
}

int version_from_string(const std::string& v) {
    if (v == "1.0") return TLS1_VERSION;
    if (v == "1.1") return TLS1_1_VERSION;
    if (v == "1.2") return TLS1_2_VERSION;
    if (v == "1.3") return TLS1_3_VERSION;
    return TLS1_2_VERSION;
}

} // namespace

SSL_CTX* make_server_ctx(const TlsConfig& cfg) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { print_ssl_errors("SSL_CTX_new(server)"); return nullptr; }

    SSL_CTX_set_min_proto_version(ctx, version_from_string(cfg.min_version));
    if (!cfg.max_version.empty())
        SSL_CTX_set_max_proto_version(ctx, version_from_string(cfg.max_version));

    if (SSL_CTX_use_certificate_chain_file(ctx, cfg.cert_file.c_str()) != 1) {
        print_ssl_errors("use_certificate_chain_file");
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, cfg.key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
        print_ssl_errors("use_PrivateKey_file");
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        print_ssl_errors("check_private_key");
        SSL_CTX_free(ctx);
        return nullptr;
    }
    return ctx;
}

SSL_CTX* make_client_ctx(const TlsConfig& cfg) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { print_ssl_errors("SSL_CTX_new(client)"); return nullptr; }

    SSL_CTX_set_min_proto_version(ctx, version_from_string(cfg.min_version));
    if (!cfg.max_version.empty())
        SSL_CTX_set_max_proto_version(ctx, version_from_string(cfg.max_version));

    if (cfg.verify_peer) {
        if (SSL_CTX_load_verify_locations(ctx, cfg.ca_file.c_str(), nullptr) != 1) {
            print_ssl_errors("load_verify_locations");
            SSL_CTX_free(ctx);
            return nullptr;
        }
        // Fail the handshake automatically if the chain does not verify.
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    } else {
        // Intentionally insecure mode for the MITM demonstration.
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    }
    return ctx;
}

void free_ctx(SSL_CTX* ctx) { if (ctx) SSL_CTX_free(ctx); }

SSL* server_handshake(SSL_CTX* ctx, int fd) {
    SSL* ssl = SSL_new(ctx);
    if (!ssl) { print_ssl_errors("SSL_new(server)"); return nullptr; }
    SSL_set_fd(ssl, fd);
    if (SSL_accept(ssl) != 1) {
        print_ssl_errors("SSL_accept");
        SSL_free(ssl);
        return nullptr;
    }
    return ssl;
}

SSL* client_handshake(SSL_CTX* ctx, int fd, const std::string& expected_hostname) {
    SSL* ssl = SSL_new(ctx);
    if (!ssl) { print_ssl_errors("SSL_new(client)"); return nullptr; }
    SSL_set_fd(ssl, fd);

    if (!expected_hostname.empty()) {
        // SNI + certificate hostname verification: the cert must actually be
        // issued for the host we intended to reach.
        SSL_set_tlsext_host_name(ssl, expected_hostname.c_str());
        SSL_set1_host(ssl, expected_hostname.c_str());
    }

    if (SSL_connect(ssl) != 1) {
        print_ssl_errors("SSL_connect");
        long vr = SSL_get_verify_result(ssl);
        if (vr != X509_V_OK) {
            fprintf(stderr, "[tls] certificate verification result: %s\n",
                    X509_verify_cert_error_string(vr));
        }
        SSL_free(ssl);
        return nullptr;
    }
    return ssl;
}

void shutdown_ssl(SSL* ssl) {
    if (!ssl) return;
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

std::string describe_session(SSL* ssl) {
    if (!ssl) return "(no session)";
    std::string s = SSL_get_version(ssl);
    s += " / ";
    s += SSL_get_cipher(ssl);
    return s;
}

} // namespace sca

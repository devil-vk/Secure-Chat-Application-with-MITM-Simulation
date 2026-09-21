#include "crypto.hpp"

#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <stdexcept>
#include <memory>

// We use the classic low-level DH API deliberately: it makes the key exchange
// explicit and readable for a teaching project. OpenSSL 3 marks it deprecated
// in favour of the EVP_PKEY interface, so we silence that specific warning here.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

namespace sca {

namespace {

[[noreturn]] void throw_ssl(const std::string& where) {
    unsigned long e = ERR_get_error();
    char buf[256] = {0};
    if (e) ERR_error_string_n(e, buf, sizeof(buf));
    throw std::runtime_error(where + ": " + (e ? buf : "unknown error"));
}

// RFC 3526, 2048-bit MODP group (group 14). Standard, widely-vetted parameters,
// so we don't have to generate (slow) or trust (risky) our own.
const char* kPrimeHex =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

} // namespace

struct DiffieHellman::Impl {
    DH* dh = nullptr;
};

DiffieHellman::DiffieHellman() : impl_(new Impl) {
    impl_->dh = DH_new();
    if (!impl_->dh) throw_ssl("DH_new");

    BIGNUM* p = nullptr;
    if (BN_hex2bn(&p, kPrimeHex) == 0) throw_ssl("BN_hex2bn(p)");
    BIGNUM* g = BN_new();
    BN_set_word(g, 2); // generator g = 2 for this group

    if (DH_set0_pqg(impl_->dh, p, nullptr, g) != 1) {
        BN_free(p);
        BN_free(g);
        throw_ssl("DH_set0_pqg");
    }
    if (DH_generate_key(impl_->dh) != 1) throw_ssl("DH_generate_key");
}

DiffieHellman::~DiffieHellman() {
    if (impl_) {
        if (impl_->dh) DH_free(impl_->dh);
        delete impl_;
    }
}

Bytes DiffieHellman::public_key() const {
    const BIGNUM* pub = nullptr;
    DH_get0_key(impl_->dh, &pub, nullptr);
    Bytes out(BN_num_bytes(pub));
    BN_bn2bin(pub, out.data());
    return out;
}

Bytes DiffieHellman::compute_shared(const Bytes& peer_public) const {
    BIGNUM* peer = BN_bin2bn(peer_public.data(),
                             static_cast<int>(peer_public.size()), nullptr);
    if (!peer) throw_ssl("BN_bin2bn(peer)");

    Bytes secret(DH_size(impl_->dh));
    int len = DH_compute_key(secret.data(), peer, impl_->dh);
    BN_free(peer);
    if (len < 0) throw_ssl("DH_compute_key");
    secret.resize(len);
    return secret;
}

Bytes derive_key(const Bytes& shared_secret, const std::string& info, size_t out_len) {
    Bytes out(out_len);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) throw_ssl("EVP_PKEY_CTX_new_id(HKDF)");

    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>
        guard(ctx, EVP_PKEY_CTX_free);

    if (EVP_PKEY_derive_init(ctx) != 1) throw_ssl("HKDF derive_init");
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) != 1) throw_ssl("HKDF set_md");
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, shared_secret.data(),
                                   static_cast<int>(shared_secret.size())) != 1)
        throw_ssl("HKDF set_key");
    if (EVP_PKEY_CTX_add1_hkdf_info(
            ctx, reinterpret_cast<const unsigned char*>(info.data()),
            static_cast<int>(info.size())) != 1)
        throw_ssl("HKDF set_info");

    size_t len = out_len;
    if (EVP_PKEY_derive(ctx, out.data(), &len) != 1) throw_ssl("HKDF derive");
    out.resize(len);
    return out;
}

Bytes aes_gcm_encrypt(const Bytes& key, const Bytes& plaintext) {
    if (key.size() != 32) throw std::runtime_error("aes_gcm_encrypt: key must be 32 bytes");

    Bytes iv(12);
    if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1) throw_ssl("RAND_bytes(iv)");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw_ssl("EVP_CIPHER_CTX_new");
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>
        guard(ctx, EVP_CIPHER_CTX_free);

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw_ssl("EncryptInit(gcm)");
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1)
        throw_ssl("set ivlen");
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1)
        throw_ssl("EncryptInit(key/iv)");

    Bytes ciphertext(plaintext.size());
    int outl = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outl, plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1)
        throw_ssl("EncryptUpdate");
    int total = outl;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outl, &outl) != 1)
        throw_ssl("EncryptFinal");
    total += outl;
    ciphertext.resize(total);

    Bytes tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1)
        throw_ssl("get tag");

    // Sealed layout: IV || TAG || CIPHERTEXT
    Bytes sealed;
    sealed.reserve(iv.size() + tag.size() + ciphertext.size());
    sealed.insert(sealed.end(), iv.begin(), iv.end());
    sealed.insert(sealed.end(), tag.begin(), tag.end());
    sealed.insert(sealed.end(), ciphertext.begin(), ciphertext.end());
    return sealed;
}

Bytes aes_gcm_decrypt(const Bytes& key, const Bytes& sealed) {
    if (key.size() != 32) throw std::runtime_error("aes_gcm_decrypt: key must be 32 bytes");
    if (sealed.size() < 28) throw std::runtime_error("aes_gcm_decrypt: sealed data too short");

    Bytes iv(sealed.begin(), sealed.begin() + 12);
    Bytes tag(sealed.begin() + 12, sealed.begin() + 28);
    Bytes ciphertext(sealed.begin() + 28, sealed.end());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw_ssl("EVP_CIPHER_CTX_new");
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>
        guard(ctx, EVP_CIPHER_CTX_free);

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw_ssl("DecryptInit(gcm)");
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1)
        throw_ssl("set ivlen");
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1)
        throw_ssl("DecryptInit(key/iv)");

    Bytes plaintext(ciphertext.size());
    int outl = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &outl, ciphertext.data(),
                          static_cast<int>(ciphertext.size())) != 1)
        throw_ssl("DecryptUpdate");
    int total = outl;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data()) != 1)
        throw_ssl("set tag");

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outl, &outl) != 1)
        throw std::runtime_error("aes_gcm_decrypt: authentication failed (tampered or wrong key)");
    total += outl;
    plaintext.resize(total);
    return plaintext;
}

Bytes to_bytes(const std::string& s) { return Bytes(s.begin(), s.end()); }
std::string to_string(const Bytes& b) { return std::string(b.begin(), b.end()); }

std::string hex(const Bytes& b) {
    static const char* d = "0123456789abcdef";
    std::string out;
    out.reserve(b.size() * 2);
    for (uint8_t c : b) { out.push_back(d[c >> 4]); out.push_back(d[c & 0xf]); }
    return out;
}

} // namespace sca

#pragma GCC diagnostic pop

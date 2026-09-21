# Design & Cryptographic Details

This document explains the protocol and the cryptographic choices behind the
Secure Chat Application.

## 1. Threat model

We assume an active network attacker (a *man-in-the-middle*) who can:

- observe every byte on the wire,
- modify, drop, replay, or inject packets, and
- present their own certificate to the client.

We want to guarantee, against that attacker:

- **Confidentiality** — the attacker cannot read message contents.
- **Integrity** — the attacker cannot alter a message without detection.
- **Authentication** — the client can be sure it is talking to the real server,
  not an impostor.

## 2. Two-layer protection

### Layer 1 — TLS transport (authentication + confidentiality)

The server holds a certificate issued (signed) by the project Certificate
Authority. During the TLS handshake:

1. The server sends its certificate chain.
2. The client checks that the chain terminates in a CA it trusts
   (`certs/ca.crt`) and that the certificate was issued for the host it intended
   to reach (`--sni`, default `localhost`).
3. If either check fails, the client aborts (`SSL_VERIFY_PEER`).

This is the **chain of trust**. It is what authenticates the server: an attacker
can copy the server's public certificate, but cannot obtain the CA's signature
on their own key, so their forged certificate fails verification.

A **minimum protocol version** (`--min-version`, default TLS 1.2) is pinned to
prevent an attacker from negotiating a weak, broken protocol (a *downgrade
attack*).

### Layer 2 — Application-layer Diffie–Hellman + AES-256-GCM

Even after TLS is established, the endpoints derive their *own* key that the
transport never sees:

1. **Diffie–Hellman.** Each side generates an ephemeral DH key pair over the
   RFC 3526 2048-bit MODP group (generator `g = 2`) and exchanges public values.
   Both compute the same shared secret; the secret itself never crosses the
   wire. See `DiffieHellman` in `src/common/crypto.cpp`.
2. **Key derivation.** The raw DH secret is run through HKDF-SHA256 with the info
   label `"sca chat v1"` to produce a uniformly random 256-bit key. Binding the
   key to a purpose label means the same secret can't accidentally produce the
   same key for a different use.
3. **Authenticated encryption.** Every message is sealed with AES-256-GCM. The
   sealed blob is laid out as `IV(12) || TAG(16) || ciphertext`. GCM's
   authentication tag gives integrity for free — decryption fails loudly if a
   single byte is tampered with.

This layered design is *defence in depth*: if TLS were somehow stripped or
downgraded, the payload is still AES-GCM-sealed under a key the attacker doesn't
hold. (The `mitm_proxy` shows that to actually read messages, an attacker must
break *both* layers — which requires the client to have disabled certificate
verification.)

## 3. Message framing

TCP is a byte stream with no message boundaries, so each logical message is
framed as:

```
[ 4-byte big-endian length ][ payload bytes ]
```

`send_frame`/`recv_frame` (raw sockets, used by P2P and the proxy) and
`ssl_send_frame`/`ssl_recv_frame` (over an established TLS session) implement
this. A 16 MiB cap rejects absurd lengths.

## 4. Application protocol

Once the secure channel exists, both sides run:

```
1. DH exchange   client → server : client DH public value   (one frame)
                 server → client : server DH public value   (one frame)
                 → both derive the AES-256 session key
2. Identity      client → server : AES-GCM{ username }
3. Chat          either side     : AES-GCM{ UTF-8 message }  (repeated)
                 "/quit" ends the session
```

The multi-client server keeps a per-client session key and re-seals each
broadcast under the recipient's key.

## 5. Cryptographic choices, and why

| Choice | Reason |
|--------|--------|
| RFC 3526 2048-bit MODP DH group | Standard, widely reviewed parameters — no home-grown primes. |
| Ephemeral DH keys per session | Forward secrecy: a compromised session key doesn't expose past/future sessions. |
| HKDF-SHA256 | Proper KDF turns a raw DH secret into a full-entropy symmetric key. |
| AES-256-GCM | Authenticated encryption — confidentiality and integrity in one primitive, no separate MAC to get wrong. |
| Random 96-bit IV per message | GCM requires a unique IV per key; a fresh random IV per message satisfies this. |
| TLS min-version floor | Blocks protocol-downgrade attacks. |

## 6. Relationship to the original course assignment

The course assignment (Python) established the concepts:

- nonce + SHA-256 challenge–response authentication with account lockout,
- Diffie–Hellman for a session key,
- HMAC-SHA256 for chunked file-transfer integrity,
- AES-128-CBC for encrypted commands, verified with Wireshark.

This project keeps those ideas and hardens them for a chat setting: real TLS with
a certificate chain of trust, a stronger DH group, AES-256-**GCM** (authenticated
encryption instead of CBC + separate HMAC), a P2P mode, and an explicit
attack/defence demonstration.

## 7. Known simplifications

This is a teaching project, not a production messaging system. Notably:

- The application-layer DH is unauthenticated on its own; it relies on the TLS
  layer for authentication (which is exactly the point the MITM demo makes).
- The server relays messages, so client–server mode is hop-by-hop at the
  application layer; true end-to-end is shown in P2P mode.
- No persistent identity, message history, or replay window across sessions.

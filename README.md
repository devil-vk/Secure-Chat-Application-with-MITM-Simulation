# Secure Chat Application with MITM Simulation

A C++ client–server **and** peer-to-peer chat application secured with SSL/TLS,
Diffie–Hellman key exchange, and AES, together with an educational
man-in-the-middle (MITM) / SSL-downgrade lab that shows *why* those defences
matter. The MITM tools are lab instruments that operate only against the local
client and server you run yourself.

> Built as an extension of a Network Security course assignment (client–server
> secure file/communication with nonce authentication, Diffie–Hellman session
> keys, HMAC integrity and AES-CBC). This project re-implements and expands the
> ideas in modern C++ with OpenSSL, adds a P2P mode, and adds an attack
> simulation validated by a certificate chain of trust.

---

## What it demonstrates

| Claim | Where it lives |
|-------|----------------|
| C++ client–server chat over SSL/TLS | [`src/server`](src/server), [`src/client`](src/client) |
| C++ peer-to-peer (P2P) chat | [`src/p2p`](src/p2p) |
| Diffie–Hellman key exchange | [`src/common/crypto.cpp`](src/common/crypto.cpp) (`DiffieHellman`) |
| AES for end-to-end confidentiality | [`src/common/crypto.cpp`](src/common/crypto.cpp) (AES-256-GCM) |
| Simulated MITM attack | [`src/mitm/mitm_proxy.cpp`](src/mitm/mitm_proxy.cpp) |
| Simulated SSL downgrade attack | `mitm_proxy --downgrade` |
| Validated with Chain of Trust certificates | [`certs/generate_certs.sh`](certs/generate_certs.sh) |

## Security architecture (defence in depth)

Every message is protected by **two independent layers**, so a weakness in one
does not expose the payload:

```
  ┌─────────────┐   TLS 1.2/1.3 (authenticated, CA-verified)   ┌─────────────┐
  │   client    │  ═══════════════════════════════════════════ │   server    │
  │             │  ── inside: AES-256-GCM over DH session key ─│             │
  └─────────────┘                                              └─────────────┘
```

1. **Transport layer — SSL/TLS.** The server presents an X.509 certificate
   chain signed by the project's Certificate Authority. The client verifies that
   chain (the *chain of trust*) before trusting the connection. This is what
   authenticates the server and stops an impostor.
2. **Application layer — Diffie–Hellman + AES-256-GCM.** After the TLS session is
   up, the two endpoints run an ephemeral Diffie–Hellman exchange (RFC 3526
   2048-bit MODP group), derive a 256-bit key with HKDF-SHA256, and seal every
   message with AES-256-GCM (which provides confidentiality *and* integrity).

In **P2P mode** the two peers run the Diffie–Hellman exchange and AES-256-GCM
directly with each other — no relay ever holds the key, so it is genuine
end-to-end encryption.

## Build

Requirements: a C++17 compiler and OpenSSL 3.x.

```bash
# macOS (Homebrew OpenSSL is auto-detected)
brew install openssl@3

# Build all four binaries into ./build/bin
make            # or: cmake -B build && cmake --build build

# Generate the certificate chain of trust (CA + server + attacker certs)
make certs      # or: ./certs/generate_certs.sh
```

Binaries produced: `chat_server`, `chat_client`, `p2p_chat`, `mitm_proxy`.

## Run

### Client–server chat

```bash
# terminal 1
./build/bin/chat_server

# terminal 2 and 3 (two chatting clients)
./build/bin/chat_client --name alice
./build/bin/chat_client --name bob
```

Type messages and press enter; `/quit` to leave. The client verifies the
server's certificate against `certs/ca.crt` by default and refuses to connect if
verification fails.

### Peer-to-peer chat

```bash
# terminal 1 — listener
./build/bin/p2p_chat --listen --name alice

# terminal 2 — dialer
./build/bin/p2p_chat --connect 127.0.0.1 --name bob
```

### MITM / downgrade demonstration

Run the guided, automated walkthrough:

```bash
./scripts/demo_mitm.sh
```

or drive it manually — see [`docs/ATTACKS.md`](docs/ATTACKS.md).

## Results (from `scripts/demo_mitm.sh`)

```
SCENARIO 2 — MITM vs a VERIFYING client (chain of trust defends)
    [tls] certificate verification result: self-signed certificate
    [client] TLS handshake failed — refusing to continue.
    [mitm] victim REJECTED the forged certificate — chain of trust held. Interception blocked.

SCENARIO 3 — MITM vs an INSECURE client (interception succeeds)
    [mitm] intercepted client->server: "my password is hunter2"

SCENARIO 4a — server requires TLS 1.3, attacker strips it
    downgrade blocked — no messages intercepted
SCENARIO 4b — server allows TLS 1.2, attacker strips 1.3
    [mitm] upstream session to real server=TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384
```

The takeaway: **certificate verification and a TLS-version floor are what defeat
the man-in-the-middle.** Disable verification (`--insecure`) and the same proxy
reads every message in cleartext.

## Project layout

```
.
├── src/
│   ├── common/     crypto (DH, HKDF, AES-GCM), TLS context, sockets, framing
│   ├── server/     multi-client secure chat server
│   ├── client/     secure chat client
│   ├── p2p/        peer-to-peer end-to-end chat
│   └── mitm/       man-in-the-middle demonstration proxy
├── certs/          chain-of-trust generation script
├── scripts/        automated demo
├── docs/           DESIGN.md and ATTACKS.md
├── CMakeLists.txt  / Makefile
```

## Documentation

- [`docs/DESIGN.md`](docs/DESIGN.md) — cryptographic design and protocol details.
- [`docs/ATTACKS.md`](docs/ATTACKS.md) — how each attack works and how it is defeated.

## Scope and ethics

The `mitm_proxy` tool is provided for **education on the developer's own
machine**. It only intercepts traffic between a client and server you run
yourself on loopback, and its purpose is to demonstrate the value of certificate
validation. Do not point it at systems you do not own or have permission to test.

## License

MIT — see [`LICENSE`](LICENSE).

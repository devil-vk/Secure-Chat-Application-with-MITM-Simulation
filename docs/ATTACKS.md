# Attack & Defence Walkthrough

This project includes a man-in-the-middle proxy (`mitm_proxy`) used **only
against the client and server you run yourself on loopback**, to demonstrate why
certificate verification and a TLS-version floor matter. Everything below is run
on `127.0.0.1`.

Build and generate certificates first:

```bash
make && make certs
```

You can run all of this automatically with `./scripts/demo_mitm.sh`; the manual
steps are below so you can see each piece.

---

## Attack 1 — Man-in-the-middle interception

### How the proxy attacks

`mitm_proxy` sits between the client and the real server and tries to break both
protection layers:

1. **TLS layer:** it terminates the client's TLS connection using a **forged
   certificate** (`certs/mitm.crt`, self-signed — *not* signed by the project
   CA) and opens its own TLS session to the real server.
2. **Application layer:** if the client accepts the forged certificate, the proxy
   also runs a *separate* Diffie–Hellman exchange with each side. Because plain
   DH is unauthenticated, the proxy ends up sharing one key with the client and a
   different key with the server — so it can decrypt every message, read it, and
   re-encrypt it for the other side. Neither end notices.

### The defence: chain of trust

Start the pieces:

```bash
./build/bin/chat_server                                  # real server, port 8443
./build/bin/mitm_proxy --listen-port 8444 --server-port 8443
```

Now connect a **normal (verifying)** client to the proxy's port:

```bash
./build/bin/chat_client --port 8444 --name victim
```

Result:

```
[tls] certificate verification result: self-signed certificate
[client] TLS handshake failed — refusing to continue.
[mitm] victim REJECTED the forged certificate — chain of trust held. Interception blocked.
```

The client checked the proxy's certificate against `certs/ca.crt`, found it was
not signed by the trusted CA, and aborted. **The MITM is stopped at layer 1.**

### Showing what happens without the defence

Re-run the client with certificate verification **disabled** (the mistake that
makes real-world MITM possible):

```bash
./build/bin/chat_client --port 8444 --name victim --insecure
```

Type `my password is hunter2`. On the proxy you will see:

```
[mitm] victim accepted forged cert (insecure client).
[mitm] two-key DH MITM established — messages are now readable in the clear.
[mitm] intercepted client->server: "my password is hunter2"
```

Same proxy, same server — the only difference is the client skipped verification.
**Certificate validation is the control that matters.**

---

## Attack 2 — SSL/TLS downgrade

### How the proxy attacks

With `--downgrade`, the proxy simulates an attacker that strips the strongest
protocol from the handshake — here it refuses TLS 1.3 and offers only up to
TLS 1.2 on both legs. The goal is to push the connection onto a weaker protocol.

### The defence: a minimum-version floor

Start a **hardened** server that requires TLS 1.3, and the downgrading proxy:

```bash
./build/bin/chat_server --port 8443 --min-version 1.3
./build/bin/mitm_proxy  --listen-port 8444 --server-port 8443 --downgrade
./build/bin/chat_client --port 8444 --name victim --insecure
```

Result — the proxy cannot complete its upstream handshake, so no message is ever
intercepted:

```
[tls] SSL_connect failed: tlsv1 alert protocol version
[mitm] could not establish TLS to real server (min-version floor?). Aborting.
```

The server's version floor refused the downgraded handshake.

### Showing what happens without the floor

Point the same downgrading proxy at a server that still permits TLS 1.2:

```bash
./build/bin/chat_server --port 8445 --min-version 1.2
./build/bin/mitm_proxy  --listen-port 8446 --server-port 8445 --downgrade
./build/bin/chat_client --port 8446 --name victim --insecure
```

```
[mitm] upstream session to real server=TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384
[mitm] intercepted client->server: "weak-tls secret"
```

The session was downgraded from TLS 1.3 to TLS 1.2. **Pinning a minimum version
removes the attacker's room to negotiate down.**

> Note on TLS 1.0/1.1: the classic downgrade target is TLS 1.0, but modern
> OpenSSL refuses it outright (`no protocols available`). That refusal is itself
> a defence — legacy, broken protocols simply can't be spoken anymore — so this
> demo uses the still-negotiable 1.3 → 1.2 downgrade to illustrate the concept.

---

## Summary

| Attack | Defence in this project | Control |
|--------|-------------------------|---------|
| MITM with forged certificate | Client verifies chain against the CA | `certs/ca.crt` + `SSL_VERIFY_PEER` |
| MITM of the key exchange | TLS authenticates the endpoint before DH runs | Chain of trust |
| SSL/TLS downgrade | Minimum protocol version pinned | `--min-version` floor |
| Message tampering | AES-256-GCM authentication tag | `aes_gcm_decrypt` fails on tamper |

The single most important lesson the demo makes concrete: **an encrypted channel
is only as trustworthy as the identity check that precedes it.** Encryption
without authentication is encryption to *someone* — possibly the attacker.

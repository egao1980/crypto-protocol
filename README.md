# crypto-protocol

Lispy **CLOS** crypto for [cl-stack](https://github.com/egao1980/cl-stack) — recipes first, hazmat second.

| System | Role | Repo |
|--------|------|------|
| `crypto-protocol` (`stack-crypto`) | Digests, HMAC, AEAD, `seal`/`unseal`, **sign/verify** | this repo |
| `crypto-backend-ironclad` | Default backend | [`egao1980/crypto-backend-ironclad`](https://github.com/egao1980/crypto-backend-ironclad) |

Shape targets: **PyCA cryptography** (Fernet/AEAD), **Java JCA**, **OpenSSL EVP**.

```lisp
(asdf:load-system "crypto-backend-ironclad")  ; pulls crypto-protocol

(let ((key (stack-crypto:generate-key))
      (pt …))
  (stack-crypto:unseal (stack-crypto:seal pt :key key) :key key))
```

Signatures (wave-1): `:ed25519`, `:rsa-pss-sha256`, `:ecdsa-p256-sha256`, and
explicit `:rsa-pkcs1-sha256` (JWT RS256 — not the recipe default).

```lisp
(multiple-value-bind (sk pk) (stack-crypto:generate-key-pair :ed25519)
  (let ((sig (stack-crypto:sign #(1 2 3) :algorithm :ed25519 :key sk)))
    (stack-crypto:verify #(1 2 3) sig :algorithm :ed25519 :key pk)))
```

`verify` fails closed (`crypto-authentication-error`).

OCI: `ghcr.io/egao1980/cl-systems/crypto-protocol:0.2.0`

Companion: [`secrets-protocol`](https://github.com/egao1980/secrets-protocol).

## License

MIT

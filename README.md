# crypto-protocol

Lispy **CLOS** crypto for [cl-stack](https://github.com/egao1980/cl-stack) — recipes first, hazmat second.

| System | Role | Repo |
|--------|------|------|
| `crypto-protocol` (`stack-crypto`) | Digests, HMAC, AEAD, `seal`/`unseal` | this repo |
| `crypto-backend-ironclad` | Default backend | [`egao1980/crypto-backend-ironclad`](https://github.com/egao1980/crypto-backend-ironclad) |

Shape targets: **PyCA cryptography** (Fernet/AEAD), **Java JCA**, **OpenSSL EVP**.

```lisp
(asdf:load-system "crypto-backend-ironclad")  ; pulls crypto-protocol

(let ((key (stack-crypto:generate-key))
      (pt …))
  (stack-crypto:unseal (stack-crypto:seal pt :key key) :key key))
```

OCI: `ghcr.io/egao1980/cl-systems/crypto-protocol:0.1.1`

Companion: [`secrets-protocol`](https://github.com/egao1980/secrets-protocol).

## License

MIT

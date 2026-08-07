# crypto-protocol

Lispy **CLOS** crypto for [cl-stack](https://github.com/egao1980/cl-stack) — recipes first, hazmat second.

| System | Role |
|--------|------|
| `crypto-protocol` (`stack-crypto`) | Digests, HMAC, AEAD, `seal`/`unseal` |
| `crypto-backend-ironclad` | Default backend (auto-select) |

Shape targets: **PyCA cryptography** (Fernet/AEAD), **Java JCA** (MessageDigest/Mac/Cipher), **OpenSSL EVP**. Not a thin Ironclad re-export — Ironclad is the backend.

```lisp
(asdf:load-system "crypto-backend-ironclad")

;; Recipes — prefer these
(let ((key (stack-crypto:generate-key))
      (pt (ironclad:ascii-string-to-byte-array "secret")))
  (stack-crypto:unseal (stack-crypto:seal pt :key key) :key key))

(stack-crypto:digest data :algorithm :sha256)
(stack-crypto:hmac key data :algorithm :sha256)

;; Hazmat AEAD (explicit)
(multiple-value-bind (ct nonce tag)
    (stack-crypto:aead-encrypt pt :key key :algorithm :aes-gcm :aad aad)
  (stack-crypto:aead-decrypt ct :key key :nonce nonce :tag tag :aad aad))
```

`seal` wire format: `CLSEAL1` || 12-byte nonce || ciphertext || 16-byte GCM tag.

Companion: [`secrets-protocol`](https://github.com/egao1980/secrets-protocol) for CSPRNG / tokens / password hashes.

## License

MIT

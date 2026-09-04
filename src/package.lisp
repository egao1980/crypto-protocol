(defpackage #:crypto-protocol
  (:use #:cl)
  (:nicknames #:stack-crypto)
  (:export #:crypto-error
           #:crypto-authentication-error
           #:crypto-key-error
           #:crypto-unsupported
           #:crypto-error-message

           #:crypto-backend
           #:*crypto-backend*

           #:backend-digest
           #:backend-hmac
           #:backend-aead-encrypt
           #:backend-aead-decrypt
           #:backend-sign
           #:backend-verify
           #:backend-generate-key-pair
           #:make-hasher
           #:make-mac-ctx
           #:update!
           #:finalize

           #:digest
           #:hmac
           #:aead-encrypt
           #:aead-decrypt
           #:seal
           #:unseal
           #:generate-key
           #:sign
           #:verify
           #:generate-key-pair

           #:+seal-magic+
           #:+seal-nonce-length+
           #:+seal-tag-length+
           #:+seal-key-length+))

(in-package #:crypto-protocol)

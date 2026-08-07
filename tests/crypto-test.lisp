(in-package #:crypto-protocol/tests)

(deftest digest-sha256-abc
  (let* ((data (ironclad:ascii-string-to-byte-array "abc"))
         (d (crypto-protocol:digest data :algorithm :sha256)))
    (ok (string-equal
         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
         (ironclad:byte-array-to-hex-string d)))))

(deftest hmac-sha256
  (let* ((key (ironclad:ascii-string-to-byte-array "key"))
         (msg (ironclad:ascii-string-to-byte-array "msg"))
         (h (crypto-protocol:hmac key msg :algorithm :sha256)))
    (ok (string-equal
         "2d93cbc1be167bcb1637a4a23cbff01a7878f0c50ee833954ea5221bb1b8c628"
         (ironclad:byte-array-to-hex-string h)))))

(deftest incremental-digest
  (let ((ctx (crypto-protocol:make-hasher crypto-protocol:*crypto-backend* :sha256)))
    (crypto-protocol:update! ctx (ironclad:ascii-string-to-byte-array "ab"))
    (crypto-protocol:update! ctx (ironclad:ascii-string-to-byte-array "c"))
    (ok (equalp (crypto-protocol:finalize ctx)
                (crypto-protocol:digest (ironclad:ascii-string-to-byte-array "abc"))))))

(deftest seal-unseal-roundtrip
  (let* ((key (ironclad:random-data 32))
         (pt (ironclad:ascii-string-to-byte-array "hello sealed world"))
         (aad (ironclad:ascii-string-to-byte-array "meta"))
         (blob (crypto-protocol:seal pt :key key :aad aad)))
    (ok (equalp pt (crypto-protocol:unseal blob :key key :aad aad)))
    (ok (signals (crypto-protocol:unseal blob :key key)
                 'crypto-protocol:crypto-authentication-error))
    (let ((bad (copy-seq blob)))
      (setf (aref bad (1- (length bad))) (logxor (aref bad (1- (length bad))) 1))
      (ok (signals (crypto-protocol:unseal bad :key key :aad aad)
                   'crypto-protocol:crypto-authentication-error)))))

(deftest aead-wrong-key
  (let* ((key1 (ironclad:random-data 32))
         (key2 (ironclad:random-data 32))
         (pt (ironclad:ascii-string-to-byte-array "x"))
         (blob (crypto-protocol:seal pt :key key1)))
    (ok (signals (crypto-protocol:unseal blob :key key2)
                 'crypto-protocol:crypto-authentication-error))))

(deftest generate-key-length
  (ok (= 32 (length (crypto-protocol:generate-key)))))

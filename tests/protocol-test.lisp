(in-package #:crypto-protocol/tests)

;;; Protocol-only tests (no backend). Backend conformance lives in
;;; egao1980/crypto-backend-ironclad.

(deftest no-backend-signals
  (let ((crypto-protocol:*crypto-backend* nil))
    (ok (signals (crypto-protocol:digest #(1 2 3))
                 'crypto-protocol:crypto-error))))

(deftest seal-key-length
  (let ((crypto-protocol:*crypto-backend* nil)
        (pt (make-array 4 :element-type '(unsigned-byte 8) :initial-element 0))
        (short (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (ok (signals (crypto-protocol:seal pt :key short)
                 'crypto-protocol:crypto-key-error))))

(deftest unpack-bad-magic
  (let ((bad (make-array 40 :element-type '(unsigned-byte 8) :initial-element 0)))
    (ok (signals (crypto-protocol::%unpack-sealed bad)
                 'crypto-protocol:crypto-authentication-error))))

(deftest pack-roundtrip-shape
  (let* ((nonce (make-array 12 :element-type '(unsigned-byte 8) :initial-element 1))
         (ct (make-array 5 :element-type '(unsigned-byte 8) :initial-element 2))
         (tag (make-array 16 :element-type '(unsigned-byte 8) :initial-element 3))
         (blob (crypto-protocol::%pack-sealed nonce ct tag)))
    (ok (equalp (subseq blob 0 7) crypto-protocol:+seal-magic+))
    (multiple-value-bind (n c t*) (crypto-protocol::%unpack-sealed blob)
      (ok (equalp n nonce))
      (ok (equalp c ct))
      (ok (equalp t* tag)))))

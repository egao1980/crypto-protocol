(in-package #:crypto-backend-ironclad)

(defclass ironclad-crypto-backend (crypto-protocol:crypto-backend) ())

(defun make-ironclad-crypto-backend ()
  (make-instance 'ironclad-crypto-backend))

(defun use-ironclad-crypto-backend ()
  (setf crypto-protocol:*crypto-backend* (make-ironclad-crypto-backend)))

(defun %simple (v)
  (coerce v '(simple-array (unsigned-byte 8) (*))))

(defun %digest-name (algorithm)
  (or (find algorithm (ironclad:list-all-digests) :test #'string-equal)
      (error 'crypto-protocol:crypto-unsupported
             :message (format nil "unsupported digest ~s" algorithm))))

(defun %aead-name (algorithm)
  (ecase algorithm
    ((:aes-gcm :gcm) :gcm)
    ((:eax) :eax)))

(defmethod crypto-protocol:backend-digest ((backend ironclad-crypto-backend) algorithm data
                                           &key (start 0) end)
  (declare (ignore backend))
  (ironclad:digest-sequence (%digest-name algorithm) data
                            :start start :end (or end (length data))))

(defmethod crypto-protocol:backend-hmac ((backend ironclad-crypto-backend) algorithm key data
                                         &key (start 0) end)
  (declare (ignore backend))
  (let ((mac (ironclad:make-hmac (%simple key) (%digest-name algorithm)))
        (end (or end (length data))))
    (ironclad:update-hmac mac data :start start :end end)
    (ironclad:hmac-digest mac)))

(defmethod crypto-protocol:make-hasher ((backend ironclad-crypto-backend) algorithm)
  (declare (ignore backend))
  (ironclad:make-digest (%digest-name algorithm)))

(defmethod crypto-protocol:make-mac-ctx ((backend ironclad-crypto-backend) algorithm key)
  (declare (ignore backend))
  (ironclad:make-hmac (%simple key) (%digest-name algorithm)))

(defmethod crypto-protocol:update! (ctx data &key (start 0) end)
  (let ((end (or end (length data))))
    (if (typep ctx 'ironclad:hmac)
        (ironclad:update-hmac ctx data :start start :end end)
        (ironclad:update-digest ctx data :start start :end end)))
  ctx)

(defmethod crypto-protocol:finalize (ctx)
  (if (typep ctx 'ironclad:hmac)
      (ironclad:hmac-digest ctx)
      (ironclad:produce-digest ctx)))

(defun %fresh-nonce (nbytes)
  (let* ((sp (find-package :secrets-protocol))
         (sym (and sp (find-symbol "RANDOM-BYTES" sp))))
    (if (and sym (fboundp sym))
        (funcall sym nbytes)
        (ironclad:random-data nbytes))))

(defmethod crypto-protocol:backend-aead-encrypt
    ((backend ironclad-crypto-backend) algorithm key plaintext &key nonce aad)
  (declare (ignore backend))
  (let* ((aead (%aead-name algorithm))
         (key (%simple key))
         (nonce (%simple (or nonce (%fresh-nonce crypto-protocol:+seal-nonce-length+))))
         (pt (%simple plaintext))
         (mode (ironclad:make-authenticated-encryption-mode
                aead :cipher-name :aes :key key :initialization-vector nonce))
         (ct (if aad
                 (ironclad:encrypt-message mode pt :associated-data (%simple aad))
                 (ironclad:encrypt-message mode pt)))
         (tag (ironclad:produce-tag mode)))
    (values ct nonce tag)))

(defmethod crypto-protocol:backend-aead-decrypt
    ((backend ironclad-crypto-backend) algorithm key ciphertext &key nonce tag aad)
  (declare (ignore backend))
  (unless (and nonce tag)
    (error 'crypto-protocol:crypto-key-error
           :message "aead-decrypt requires :nonce and :tag"))
  (let* ((aead (%aead-name algorithm))
         (key (%simple key))
         (nonce (%simple nonce))
         (tag (%simple tag))
         (ct (%simple ciphertext))
         (mode (ironclad:make-authenticated-encryption-mode
                aead :cipher-name :aes :key key
                :initialization-vector nonce :tag tag)))
    (handler-case
        (if aad
            (ironclad:decrypt-message mode ct :associated-data (%simple aad))
            (ironclad:decrypt-message mode ct))
      (ironclad:bad-authentication-tag ()
        (error 'crypto-protocol:crypto-authentication-error
               :message "AEAD authentication tag mismatch")))))

(use-ironclad-crypto-backend)

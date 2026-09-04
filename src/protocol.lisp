(in-package #:crypto-protocol)

;;; Recipes (safe defaults) + hazmat GFs. Backends implement the generics.
;;; Shape: PyCA recipes/hazmat · JCA MessageDigest/Mac/Cipher · OpenSSL EVP.

(defclass crypto-backend () ()
  (:documentation "Base class for crypto-protocol backends."))

(defvar *crypto-backend* nil
  "Current crypto backend. Set by loading crypto-backend-* .")

(defconstant +seal-key-length+ 32)
(defconstant +seal-nonce-length+ 12)
(defconstant +seal-tag-length+ 16)

(defparameter +seal-magic+
  (make-array 7 :element-type '(unsigned-byte 8)
              :initial-contents (map 'list #'char-code "CLSEAL1"))
  "Magic prefix for seal/unseal blobs.")

(defun %octets (x)
  (etypecase x
    ((simple-array (unsigned-byte 8) (*)) x)
    ((vector (unsigned-byte 8))
     (coerce x '(simple-array (unsigned-byte 8) (*))))
    ((and vector (not string))
     (coerce x '(simple-array (unsigned-byte 8) (*))))
    (string
     (error 'crypto-key-error
            :message "expected octets; encode strings before calling crypto APIs"))))

(defun %ensure-backend (&optional (backend *crypto-backend*))
  (or backend
      (error 'crypto-error :message "*crypto-backend* is nil — load a crypto-backend-* system")))

;;; ---------------------------------------------------------------------------
;;; Hazmat generics
;;; ---------------------------------------------------------------------------

(defgeneric backend-digest (backend algorithm data &key start end)
  (:documentation "One-shot digest. ALGORITHM e.g. :sha256 :sha512 :blake2."))

(defgeneric backend-hmac (backend algorithm key data &key start end)
  (:documentation "One-shot HMAC. ALGORITHM is the hash, e.g. :sha256."))

(defgeneric backend-aead-encrypt (backend algorithm key plaintext &key nonce aad)
  (:documentation "→ (values ciphertext nonce tag). Nonce generated if NIL."))

(defgeneric backend-aead-decrypt (backend algorithm key ciphertext &key nonce tag aad)
  (:documentation "→ plaintext octets, or signal crypto-authentication-error."))

(defgeneric backend-sign (backend algorithm key message &key)
  (:documentation "Sign MESSAGE with KEY. ALGORITHM is :ed25519, :rsa-pss-sha256,
:ecdsa-p256-sha256, or :rsa-pkcs1-sha256. → signature octets."))

(defgeneric backend-verify (backend algorithm key message signature &key)
  (:documentation "Verify SIGNATURE. T on success; signal crypto-authentication-error
on a bad signature (fail closed)."))

(defgeneric backend-generate-key-pair (backend algorithm &key)
  (:documentation "→ (values private-key public-key) for ALGORITHM."))

(defgeneric make-hasher (backend algorithm)
  (:documentation "Incremental digest context."))

(defgeneric make-mac-ctx (backend algorithm key)
  (:documentation "Incremental MAC context."))

(defgeneric update! (ctx data &key start end)
  (:documentation "Feed DATA into hasher/MAC context. Returns CTX."))

(defgeneric finalize (ctx)
  (:documentation "Finish hasher/MAC; return digest octets."))

(defmethod backend-sign ((backend crypto-backend) algorithm key message &key)
  (declare (ignore algorithm key message))
  (error 'crypto-unsupported
         :message "backend-sign not implemented — load crypto-backend-ironclad"))

(defmethod backend-verify ((backend crypto-backend) algorithm key message signature &key)
  (declare (ignore algorithm key message signature))
  (error 'crypto-unsupported
         :message "backend-verify not implemented — load crypto-backend-ironclad"))

(defmethod backend-generate-key-pair ((backend crypto-backend) algorithm &key)
  (declare (ignore algorithm))
  (error 'crypto-unsupported
         :message "backend-generate-key-pair not implemented"))

;;; ---------------------------------------------------------------------------
;;; Facade (hazmat + recipes)
;;; ---------------------------------------------------------------------------

(defun digest (data &key (algorithm :sha256) (backend *crypto-backend*)
                      (start 0) end)
  "One-shot digest. Default ALGORITHM :sha256."
  (backend-digest (%ensure-backend backend) algorithm (%octets data)
                  :start start :end end))

(defun hmac (key data &key (algorithm :sha256) (backend *crypto-backend*)
                    (start 0) end)
  "One-shot HMAC. Default ALGORITHM :sha256 (HMAC-SHA256)."
  (backend-hmac (%ensure-backend backend) algorithm (%octets key) (%octets data)
                :start start :end end))

(defun aead-encrypt (plaintext &key key (algorithm :aes-gcm) nonce aad
                                 (backend *crypto-backend*))
  "Hazmat AEAD encrypt. → (values ciphertext nonce tag).
Prefer SEAL for application data."
  (backend-aead-encrypt (%ensure-backend backend) algorithm (%octets key)
                        (%octets plaintext) :nonce nonce :aad aad))

(defun aead-decrypt (ciphertext &key key (algorithm :aes-gcm) nonce tag aad
                                 (backend *crypto-backend*))
  "Hazmat AEAD decrypt. Signals CRYPTO-AUTHENTICATION-ERROR on bad tag."
  (backend-aead-decrypt (%ensure-backend backend) algorithm (%octets key)
                        (%octets ciphertext) :nonce nonce :tag tag :aad aad))

(defun sign (message &key algorithm key (backend *crypto-backend*))
  "Hazmat sign. ALGORITHM required. KEY is a backend key object or raw octets
(Ed25519 seed / public)."
  (unless algorithm
    (error 'crypto-key-error :message "sign requires :algorithm"))
  (unless key
    (error 'crypto-key-error :message "sign requires :key"))
  (backend-sign (%ensure-backend backend) algorithm key
                (if (stringp message)
                    (error 'crypto-key-error
                           :message "expected octets; encode strings before calling crypto APIs")
                    (%octets message))))

(defun verify (message signature &key algorithm key (backend *crypto-backend*))
  "Hazmat verify. Signals CRYPTO-AUTHENTICATION-ERROR on a bad signature."
  (unless algorithm
    (error 'crypto-key-error :message "verify requires :algorithm"))
  (unless key
    (error 'crypto-key-error :message "verify requires :key"))
  (backend-verify (%ensure-backend backend) algorithm key
                  (if (stringp message)
                      (error 'crypto-key-error
                             :message "expected octets; encode strings before calling crypto APIs")
                      (%octets message))
                  (%octets signature)))

(defun generate-key-pair (algorithm &key (backend *crypto-backend*))
  "→ (values private public) for ALGORITHM."
  (backend-generate-key-pair (%ensure-backend backend) algorithm))

(defun generate-key (&key (nbytes +seal-key-length+))
  "CSPRNG key material. Prefers secrets-protocol; falls back to Ironclad OS PRNG."
  (let* ((sp (find-package :secrets-protocol))
         (secrets (and sp (find-symbol "RANDOM-BYTES" sp)))
         (ip (find-package :ironclad))
         (iron (and ip (find-symbol "RANDOM-DATA" ip))))
    (cond
      ((and secrets (fboundp secrets)) (funcall secrets nbytes))
      ((and iron (fboundp iron)) (funcall iron nbytes))
      (t (error 'crypto-error
                :message "no CSPRNG — load crypto-backend-ironclad")))))

(defun %pack-sealed (nonce ciphertext tag)
  (let* ((magic +seal-magic+)
         (out (make-array (+ (length magic) (length nonce)
                             (length ciphertext) (length tag))
                          :element-type '(unsigned-byte 8))))
    (replace out magic)
    (replace out nonce :start1 (length magic))
    (replace out ciphertext :start1 (+ (length magic) (length nonce)))
    (replace out tag :start1 (+ (length magic) (length nonce) (length ciphertext)))
    out))

(defun %unpack-sealed (sealed)
  (let* ((sealed (%octets sealed))
         (magic-len (length +seal-magic+))
         (min-len (+ magic-len +seal-nonce-length+ +seal-tag-length+)))
    (unless (>= (length sealed) min-len)
      (error 'crypto-authentication-error :message "sealed blob too short"))
    (unless (equalp (subseq sealed 0 magic-len) +seal-magic+)
      (error 'crypto-authentication-error :message "bad sealed magic"))
    (let* ((nonce-end (+ magic-len +seal-nonce-length+))
           (tag-start (- (length sealed) +seal-tag-length+)))
      (when (< tag-start nonce-end)
        (error 'crypto-authentication-error :message "sealed blob truncated"))
      (values (subseq sealed magic-len nonce-end)
              (subseq sealed nonce-end tag-start)
              (subseq sealed tag-start)))))

(defun seal (plaintext &key key aad (backend *crypto-backend*))
  "Recipe: AES-256-GCM sealed blob (magic||nonce||ct||tag). KEY must be 32 octets.
Nonce is generated fresh. Prefer this over raw AEAD-ENCRYPT."
  (let ((key (%octets (or key (generate-key)))))
    (unless (= (length key) +seal-key-length+)
      (error 'crypto-key-error
             :message (format nil "seal key must be ~d octets, got ~d"
                              +seal-key-length+ (length key))))
    (multiple-value-bind (ct nonce tag)
        (aead-encrypt plaintext :key key :algorithm :aes-gcm :aad aad
                      :backend backend)
      (%pack-sealed nonce ct tag))))

(defun unseal (sealed &key key aad (backend *crypto-backend*))
  "Recipe inverse of SEAL. Signals CRYPTO-AUTHENTICATION-ERROR on tamper/wrong key."
  (unless key
    (error 'crypto-key-error :message "unseal requires :key"))
  (let ((key (%octets key)))
    (unless (= (length key) +seal-key-length+)
      (error 'crypto-key-error
             :message (format nil "unseal key must be ~d octets, got ~d"
                              +seal-key-length+ (length key))))
    (multiple-value-bind (nonce ct tag) (%unpack-sealed sealed)
      (aead-decrypt ct :key key :algorithm :aes-gcm :nonce nonce :tag tag
                    :aad aad :backend backend))))

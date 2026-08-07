(in-package #:crypto-protocol)

(define-condition crypto-error (error)
  ((message :initarg :message :reader crypto-error-message :initform nil))
  (:report (lambda (c s)
             (format s "crypto error~@[: ~a~]" (crypto-error-message c)))))

(define-condition crypto-authentication-error (crypto-error) ()
  (:report (lambda (c s)
             (format s "crypto authentication failed~@[: ~a~]"
                     (crypto-error-message c)))))

(define-condition crypto-key-error (crypto-error) ())

(define-condition crypto-unsupported (crypto-error) ())

(defsystem "crypto-protocol"
  :version "0.1.1"
  :description "CLOS crypto protocol for cl-stack (recipes + hazmat AEAD/digest/HMAC)"
  :author "egao1980"
  :license "MIT"
  :depends-on ()
  :serial t
  :pathname "src"
  :components ((:file "package")
               (:file "conditions")
               (:file "protocol"))
  :in-order-to ((test-op (test-op "crypto-protocol/tests"))))

(defsystem "crypto-protocol/tests"
  :depends-on ("crypto-protocol" "rove")
  :pathname "tests"
  :serial t
  :components ((:file "package")
               (:file "protocol-test"))
  :perform (test-op (o c)
             (unless (symbol-call :rove :run c)
               (error "tests failed for ~A" (component-name c)))))

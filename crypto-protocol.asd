(defsystem "crypto-protocol"
  :version "0.1.0"
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

(defsystem "crypto-backend-ironclad"
  :version "0.1.0"
  :description "Ironclad backend for crypto-protocol"
  :author "egao1980"
  :license "MIT"
  :depends-on ("crypto-protocol" "ironclad")
  :serial t
  :pathname "src/backend-ironclad"
  :components ((:file "package")
               (:file "backend"))
  :in-order-to ((test-op (test-op "crypto-protocol/tests"))))

(defsystem "crypto-protocol/tests"
  :depends-on ("crypto-backend-ironclad" "ironclad" "rove")
  :pathname "tests"
  :serial t
  :components ((:file "package")
               (:file "crypto-test"))
  :perform (test-op (o c)
             (unless (symbol-call :rove :run c)
               (error "tests failed for ~A" (component-name c)))))

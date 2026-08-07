(defsystem "crypto-backend-ironclad"
  :version "0.1.0"
  :description "Ironclad backend for crypto-protocol"
  :author "egao1980"
  :license "MIT"
  :depends-on ("crypto-protocol" "ironclad")
  :serial t
  :pathname "src/backend-ironclad"
  :components ((:file "package")
               (:file "backend")))

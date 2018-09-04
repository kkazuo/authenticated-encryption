#|
  This file is a part of authenticated-encryption project.
|#

(defsystem "authenticated-encryption"
  :version "0.1.0"
  :author "Koga Kazuo"
  :license "MIT"
  :depends-on (ironclad)
  :components ((:module "src"
                :components
                ((:file "authenticated-encryption"))))
  :description "Authenticated-Encryption functions"
  :long-description
  #.(read-file-string
     (subpathname *load-pathname* "README.markdown"))
  :in-order-to ((test-op (test-op "authenticated-encryption-test"))))

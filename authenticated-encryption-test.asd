#|
  This file is a part of authenticated-encryption project.
|#

(defsystem "authenticated-encryption-test"
  :author "Koga Kazuo"
  :license "MIT"
  :depends-on (:authenticated-encryption
               :1am)
  :components ((:module "tests"
                :components
                ((:file "authenticated-encryption"))))
  :description "Test system for authenticated-encryption"
  :perform (test-op (op c) (symbol-call :1am :run)))

#|
  This file is a part of authenticated-encryption project.
|#

(defsystem "authenticated-encryption-test"
  :defsystem-depends-on ("prove-asdf")
  :author ""
  :license ""
  :depends-on ("authenticated-encryption"
               "prove")
  :components ((:module "tests"
                :components
                ((:test-file "authenticated-encryption"))))
  :description "Test system for authenticated-encryption"

  :perform (test-op (op c) (symbol-call :prove-asdf :run-test-system c)))

(defpackage authenticated-encryption-test
  (:use :cl
        :authenticated-encryption
        :ironclad
        :1am))
(in-package :authenticated-encryption-test)

;; NOTE: To run this test file, execute `(asdf:test-system :authenticated-encryption)' in your Lisp.

(test encrypt-decrypt
  (let ((secret (ironclad:ascii-string-to-byte-array "01234567890abcde"))
        (nonce (make-array 16
                           :element-type '(unsigned-byte 8)
                           :initial-contents #(254 105 255 23 133 125 163 190 72 25 186 247 13 73 5 185)))
        (plain1 (ironclad:ascii-string-to-byte-array "ab00000000000009"))
        (enc1 (make-array 66
                          :element-type '(unsigned-byte 8)
                          :initial-contents #(0 16 254 105 255 23 133 125 163 190 72 25 186 247
                                              13 73 5 185 229 167 95 55 239 235 243 131 125 125
                                              147 244 45 77 34 229 111 145 189 134 176 175 46 6 126
                                              50 193 244 61 204 101 166 219 179 94 228 114 225 94 21
                                              194 126 47 22 149 27 80 199)))
        (plain2 (ironclad:ascii-string-to-byte-array "ab0000000000000"))
        (enc2 (make-array 50
                          :element-type '(unsigned-byte 8)
                          :initial-contents #(0 16 254 105 255 23 133 125 163 190 72 25 186 247
                                              13 73 5 185 229 167 95 55 239 235 243 131 125 125
                                              147 244 45 77 34 221 231 96 10 121 199 183 67 196 55
                                              246 98 234 23 230 43 40))))
    (is (equalp
         (authenticated-encrypt plain1 :secret secret :nonce nonce)
         enc1))
    (is (equalp
         (authenticated-decrypt enc1 :secret secret)
         plain1))
    (is (equalp
         (authenticated-encrypt plain2 :secret secret :nonce nonce)
         enc2))
    (is (equalp
         (authenticated-decrypt enc2 :secret secret)
         plain2))))

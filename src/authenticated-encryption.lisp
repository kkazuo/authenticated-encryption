;;; A implementation of Authenticated Encryption
;;; https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/proposed-modes/eax/eax-spec.pdf

(defpackage authenticated-encryption
  (:use :cl)
  (:nicknames :aead)
  (:export
   #:authenticated-encrypt
   #:authenticated-decrypt

   #:authenticated-decrypt-error
   #:invalid-header-error
   #:invalid-cipher-error
   #:invalid-block-length-error
   #:invalid-data-length-error
   #:invalid-signature-error))
(in-package :authenticated-encryption)

(defun make-nonce (n-bytes)
  (crypto:random-data n-bytes))

(defun make-header (cipher block-length)
  (ecase cipher
    ((:aes)
     (make-array 2
                 :element-type '(unsigned-byte 8)
                 :initial-contents (list 0 block-length)))))

(defun pkcs7-padding (data-length block-size)
  (declare (type (unsigned-byte 8) block-size))
  (let* ((n-padding-bytes (- block-size (rem data-length block-size)))
         (pad-byte (if (zerop n-padding-bytes) block-size n-padding-bytes)))
    (make-array pad-byte
                :element-type '(unsigned-byte 8)
                :initial-element pad-byte)))

(defun authenticated-encrypt (message &key secret nonce (cipher-name :aes))
  "Encrypt the message with secret key

MESSAGE and SECRET must be array of (unsigned-byte 8).
NONCE will generate per evaluate if nil (default).
CIPHER-NAME accepts only :AES (default) for now.

Returns the encrypted bytes.

Encrypted Bytes Format are:
  Header (2 byte) +
  Nonce  (16 byte) +
  Encrypted Message (with PKCS#7 padding) +
  Tag    (16 byte)
  (16 = AES block size)"
  (let* ((cmac (crypto:make-cmac secret cipher-name))
         (block-length (crypto:block-length cipher-name))
         (nonce (or nonce (make-nonce block-length))))
    (crypto:update-cmac cmac nonce)
    (let* ((N (crypto:cmac-digest cmac))
           (cipher (crypto:make-cipher cipher-name
                                       :mode :ctr
                                       :key secret
                                       :padding nil
                                       :initialization-vector N))
           (header (make-header cipher-name block-length)))
      (crypto:update-cmac cmac header)
      (let* ((H (crypto:cmac-digest cmac))
             (buffer (make-array (* 2 block-length)
                                 :element-type '(unsigned-byte 8))))
        (with-open-stream (s (crypto:make-octet-output-stream))
          (write-sequence header s)
          (write-sequence nonce s)

          (loop with length = (length message)
                with start = 0
                with end = (min length block-length)
                while (< start end)
                do (multiple-value-bind (n-bytes-consumed n-bytes-produced)
                       (crypto:encrypt cipher message buffer
                                       :plaintext-start start
                                       :plaintext-end end)
                     (crypto:update-cmac cmac buffer :end n-bytes-produced)
                     (write-sequence buffer s :end n-bytes-produced)
                     (incf start n-bytes-consumed)
                     (setf end (min length (+ end n-bytes-consumed)))))

          (multiple-value-bind (n-bytes-consumed n-bytes-produced)
              (crypto:encrypt cipher
                              (pkcs7-padding (length message) block-length)
                              buffer)
            (declare (ignore n-bytes-consumed))
            (crypto:update-cmac cmac buffer :end n-bytes-produced)
            (write-sequence buffer s :end n-bytes-produced))

          (let ((C (crypto:cmac-digest cmac)))
            (map-into buffer #'logxor N C H)
            (write-sequence buffer s :end block-length)
            (crypto:get-output-stream-octets s)))))))

(define-condition authenticated-decrypt-error (simple-error)
  ())

(define-condition invalid-header-error (authenticated-decrypt-error)
  ())

(define-condition invalid-cipher-error (authenticated-decrypt-error)
  ())

(define-condition invalid-block-length-error (authenticated-decrypt-error)
  ())

(define-condition invalid-data-length-error (authenticated-decrypt-error)
  ())

(define-condition invalid-signature-error (authenticated-decrypt-error)
  ())

(defun authenticated-decrypt (encrypted &key secret)
  "Decrypt message with secret key

ENCRYPTED and SECRET must be array of (unsigned-byte 8).

Returns the decrypted bytes.

Conditions:
  authenticated-decrypt-error when invalid encrypted bytes"
  (let ((length (length encrypted)))
    (unless (< 2 length)
      (error (make-condition 'invalid-header-error)))
    (unless (= 0 (aref encrypted 0))
      (error (make-condition 'invalid-cipher-error)))
    (let ((block-length (aref encrypted 1)))
      (unless (< 0 block-length)
        (error (make-condition 'invalid-block-length-error)))
      (unless (<= (+ 2 (* 3 block-length)) length)
        (error (make-condition 'invalid-data-length-error)))

      (let* ((cipher-name :aes)
             (cmac (crypto:make-cmac secret cipher-name)))
        (crypto:update-cmac cmac encrypted :start 2 :end (+ 2 block-length))
        (let ((N (crypto:cmac-digest cmac)))
          (crypto:update-cmac cmac encrypted :start 0 :end 2)
          (let ((H (crypto:cmac-digest cmac))
                (buffer (make-array (* 2 block-length) :element-type '(unsigned-byte 8))))
            (crypto:update-cmac cmac encrypted :start (+ 2 block-length) :end (- length block-length))
            (let ((C (crypto:cmac-digest cmac)))
              (map-into buffer #'logxor N C H)
              (unless (= 0 (loop for i from (- length block-length) to (- length 1)
                                 for v across buffer
                                 sum (logxor v (aref encrypted i))))
                (error (make-condition 'invalid-signature-error)))

              (let ((cipher (crypto:make-cipher cipher-name
                                                :mode :ctr
                                                :key secret
                                                :padding nil
                                                :initialization-vector N)))
                (with-open-stream (s (crypto:make-octet-output-stream))
                  (loop with length = (- length block-length)
                        with start = (+ 2 block-length)
                        with end = (min length (+ start block-length))
                        while (< start end)
                        do (multiple-value-bind (n-bytes-consumed n-bytes-produced)
                               (crypto:decrypt cipher encrypted buffer
                                               :ciphertext-start start
                                               :ciphertext-end end)
                             (incf start n-bytes-consumed)
                             (setf end (min length (+ end n-bytes-consumed)))
                             (cond
                               ((< start end)
                                (write-sequence buffer s :end n-bytes-produced))
                               (t
                                (let ((n-pad (aref buffer (- n-bytes-produced 1))))
                                  (write-sequence buffer s :end (- n-bytes-produced n-pad)))))))
                  (crypto:get-output-stream-octets s))))))))))

# Authenticated-Encryption

A implementation of Authenticated Encryption

## Usage

Encrypt

```
(aead::authenticated-encrypt plain-text-as-bytes :secret secret-bytes)
;=> encrypted-bytes
```

Decrypt

```
(aead::authenticated-decrypt encrypted-bytes :secret secret-bytes)
;=> plain-text-as-bytes
; or raise authenticated-decrypt-error condition
```

## Installation


## Cite

* https://en.wikipedia.org/wiki/Authenticated_encryption
* https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/proposed-modes/eax/eax-spec.pdf

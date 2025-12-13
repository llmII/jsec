(import jsec/crypto :as crypto)

(print "Generating Ed25519 key...")
(let [key (crypto/generate-key :ed25519)]
  (print "Key generated (PEM length: " (length key) ")")

  (let [data "Important message to sign"]
    (print "Signing data: " data)

    (let [sig (crypto/sign key data)]
      (print "Signature generated (length: " (length sig) ")")

      (print "Verifying signature...")
      (let [valid (crypto/verify key data sig)]
        (if valid
          (print "Signature verified successfully!")
          (error "Signature verification failed!"))
        (print "Crypto Signing example successful!")))))

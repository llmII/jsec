# Discarded OpenSSL failure signals regression test
# Ticket cf6c570109bab116f53a5e15af4651176910f094
#
# "Check OpenSSL return values and drain error queue across jutils
# cert/context helpers, jbio I/O, and jtls server/SNI setup"
#
# Mechanism (this tree): several helpers detect a failure - or have it
# available from OpenSSL - and hand the caller a default instead of the
# failure itself:
#   - src/jutils/cert_loading.c:54-85 (load_cert_chain_mem) and
#     :113-134 (load_ca_mem) loop on PEM_read_bio_X509 and treat any
#     termination as end of input (:73, :127), so a corrupt block in the
#     middle of a PEM bundle silently truncates the chain or the trust
#     anchors and the function still reports success (:85, :134);
#     load_ca_mem also discards every X509_STORE_add_cert return (:128);
#   - src/jutils/cert_loading.c:144-180 (add_trusted_cert) folds a wrong
#     Janet type, a BIO allocation failure, a PEM parse failure, a store
#     lookup failure, and a store add failure into one bare 0, and the
#     callers raise one generic "failed to add trusted certificate"
#     whose cause text is empty for the type case;
#   - src/jtls/context/sni.c:24-34 discards the SSL_set_SSL_CTX return
#     (:26) and always reports success to the handshake (:34), and
#     src/jtls/api/context.c:183-196 panics "failed to create SNI
#     context for %s" without the OpenSSL reason that made the per-name
#     context build fail (:195-196);
#   - src/jbio.c:68-96 (read) folds every non-positive BIO_read into one
#     nil (:86, :96) - a hard failure, end of data, and a zero-length
#     request are one and the same answer - and src/jbio.c:52-60 (write)
#     hands any BIO_write return, negative counts included, straight to
#     the caller with no cause text (:59-60);
#   - src/jutils/error.c:19-24 (the string behind every SSL raise) pops
#     exactly one error from the thread queue and drops the rest, so an
#     operation that queued several failures reports only the earliest.
#
# This test demonstrates:
#   (a) a PEM certificate chain whose second block is corrupt raises
#       naming that block and the parse failure instead of loading a
#       silently truncated chain,
#   (b) a PEM CA bundle whose second block is corrupt raises the same
#       way instead of installing silently truncated trust anchors,
#   (c) a wrong-type trusted certificate raises a message naming the
#       type problem instead of "failed to add trusted certificate: No
#       SSL error",
#   (d) a per-name SNI context whose material cannot be loaded raises a
#       message carrying the OpenSSL cause in addition to the name,
#   (e) a zero-length BIO read does not report the documented no-data
#       nil while the BIO still holds bytes,
#   (f) an operation whose probes queued several OpenSSL errors raises a
#       message carrying all of them, not only the earliest,
#   (g) tls/trust-cert is idempotent on the same CA certificate and
#       leaves the OpenSSL error queue clean (matching cfun_dtls_trust_cert).
#
# Proof contract: under the defect each proof test (a)-(f) fails with
# exactly the predicted symptom named in its final assertion - the
# silently truncated chain and trust anchors, the empty "No SSL error"
# text, the cause-less SNI panic, the conflated no-data nil, and the
# dropped multi-error context - and nothing else: no crash, no hang, no
# unrelated error. Guard (g) pins the duplicate-cert idempotency contract
# and PASSES
# under the defect on this OpenSSL (X509_STORE_add_cert already reports
# success for an already-present certificate); it must keep passing when
# add_trusted_cert is hardened. Under fixed code every test passes.

(use assay)
(import jsec/crypto :as crypto)
(import jsec/cert :as cert)
(import jsec/tls :as tls)
(import jsec/tls-stream :as tls-stream)
(import jsec/bio :as bio)
(import ../helpers :prefix "")

(def certs (cert/generate-self-signed-cert
             {:common-name "discarded-signals.example"
              :key-type :ec-p256}))

# A PEM block that PEM_read_bio_X509 fails to PARSE (not end-of-input):
# the header and footer are well formed and the body is not base64.
(def corrupt-cert-block
  "-----BEGIN CERTIFICATE-----\nnot base64 garbage!!!\n-----END CERTIFICATE-----\n")

(defn- capture
  "Run thunk; return [:raised message] or [:returned value]."
  [thunk]
  (try
    [:returned (thunk)]
    ([e] [:raised (string e)])))

(defn- short-q
  "Describe x with %q, truncated to 200 chars for failure messages."
  [x]
  (def s (string/format "%q" x))
  (string/slice s 0 (min 200 (length s))))

(defn- drain-queue
  ``Leave the thread OpenSSL error queue empty so an observation reads its
   own cause text instead of a leftover from an earlier failure: a failing
   key load raises through the error-string helper, which pops the first
   queued error and clears the rest.``
  []
  (try (crypto/load-key "not a key") ([_] nil)))

(def-suite :name "Discarded Error Signals Regression"
  :description "Ticket cf6c570109: discarded OpenSSL and BIO failure signals must raise with their cause instead of returning silent defaults"

  (def-test "cert-chain-corrupt-middle-cert-must-raise-not-truncate"
    :timeout 60

    (def outcome
      (capture
        (fn []
          (tls/new-context {:cert (string (certs :cert) corrupt-cert-block)
                            :key (certs :key)}))))
    (assert (and (= :raised (get outcome 0))
                 (string/find "certificate 2" (get outcome 1))
                 (string/find "parse" (get outcome 1)))
            (string/format
              (string "loading a certificate chain whose second PEM block is "
                      "corrupt must raise naming certificate 2 and the parse "
                      "failure, but it %s - load_cert_chain_mem "
                      "(src/jutils/cert_loading.c:54-85) treats any PEM_read_bio_X509 "
                      "termination as end of input (:73) and reports success "
                      "(:85), so the chain is silently truncated to the "
                      "certificates parsed before the bad block")
              (short-q outcome))))

  (def-test "ca-bundle-corrupt-middle-cert-must-raise-not-truncate"
    :timeout 60

    (def outcome
      (capture
        (fn []
          (tls/new-context {:verify false
                            :ca (string (certs :cert) corrupt-cert-block)}))))
    (assert (and (= :raised (get outcome 0))
                 (string/find "certificate 2" (get outcome 1))
                 (string/find "parse" (get outcome 1)))
            (string/format
              (string "loading a CA bundle whose second PEM block is corrupt "
                      "must raise naming certificate 2 and the parse failure, "
                      "but it %s - load_ca_mem (src/jutils/cert_loading.c:113-134) "
                      "treats any PEM_read_bio_X509 termination as end of "
                      "input (:127), discards every X509_STORE_add_cert "
                      "return (:128), and reports success (:134), so the "
                      "trust anchors are silently truncated and later "
                      "handshakes fail against the wrong cause")
              (short-q outcome))))

  (def-test "trusted-cert-wrong-type-must-raise-a-type-error-not-no-ssl-error"
    :timeout 60

    (drain-queue)
    (def outcome
      (capture
        (fn []
          (def ctx (tls/new-context {:verify false}))
          (tls-stream/trust-cert ctx 42))))
    (assert (and (= :raised (get outcome 0))
                 (not (string/find "No SSL error" (get outcome 1)))
                 (or (string/find "string" (get outcome 1))
                     (string/find "buffer" (get outcome 1))
                     (string/find "type" (get outcome 1))))
            (string/format
              (string "trusting a wrong-type certificate (the integer 42) "
                      "must raise a message naming the type problem, but it "
                      "%s - add_trusted_cert (src/jutils/cert_loading.c:144-180) "
                      "folds the wrong Janet type (:149-158), BIO, PEM parse, "
                      "store lookup, and store add failures into one bare 0, "
                      "and the generic caller message then reports the "
                      "empty \"No SSL error\" cause text instead of the "
                      "type problem")
              (short-q outcome))))

  (def-test "trusted-cert-twice-is-idempotent-and-leaves-queue-clean"
    :timeout 60

    # A second tls/trust-cert with the same CA certificate is idempotent
    # success and leaves the OpenSSL error queue clean (add_trusted_cert
    # must treat X509_R_CERT_ALREADY_IN_HASH_TABLE as success and drain the
    # queue, matching cfun_dtls_trust_cert). On this OpenSSL
    # X509_STORE_add_cert already reports success for an already-present
    # certificate, so this guard passes under the defect too and exists
    # to keep the add_trusted_cert hardening honest.
    (drain-queue)
    (def ctx (tls/new-context {:verify false}))
    (def first-outcome
      (capture (fn [] (tls-stream/trust-cert ctx (certs :cert)))))
    (def second-outcome
      (capture (fn [] (tls-stream/trust-cert ctx (certs :cert)))))
    (assert (and (= :returned (get first-outcome 0))
                 (nil? (get first-outcome 1))
                 (= :returned (get second-outcome 0))
                 (nil? (get second-outcome 1)))
            (string/format
              (string "calling tls/trust-cert twice with the same CA "
                      "certificate must return nil both times "
                      "(X509_R_CERT_ALREADY_IN_HASH_TABLE is idempotent "
                      "success), but the second call %s - add_trusted_cert "
                      "(src/jutils/cert_loading.c:144-180) folds a store "
                      "add refusal into one bare 0 and the caller "
                      "(src/jtls/api/context.c:334-344) raises the generic "
                      "message; add_trusted_cert must match the idempotent "
                      "treatment cfun_dtls_trust_cert already implements "
                      "(src/jdtls/api/info.c:260-283)")
              (short-q second-outcome)))

    # The queue must stay clean: the error-string helper pops the OLDEST
    # queued error (src/jutils/error.c:19-24), so a stale duplicate-add
    # error would show up as the earliest cause of an unrelated failure.
    (def probe
      (capture (fn [] (crypto/convert-key "not a key at all" :pem))))
    (assert (and (= :raised (get probe 0))
                 (not (string/find "hash table" (get probe 1)))
                 (not (string/find "already" (get probe 1))))
            (string/format
              (string "after two tls/trust-cert calls with the same CA "
                      "certificate the OpenSSL error queue must be clean, "
                      "but the next unrelated failure reported %s - the "
                      "duplicate store add left its error queued, and the "
                      "error-string helper (src/jutils/error.c:19-24) pops "
                      "the oldest queued error first, so a stale "
                      "duplicate-add error contaminates every later raise")
              (short-q probe))))

  (def-test "sni-context-failure-must-raise-with-the-openssl-cause"
    :timeout 60

    (def outcome
      (capture
        (fn []
          (tls/new-context
            {:cert (certs :cert) :key (certs :key)
             :sni {"a.example" {:cert corrupt-cert-block
                                :key (certs :key)}}}))))
    (assert (and (= :raised (get outcome 0))
                 (string/find "a.example" (get outcome 1))
                 (or (string/find "routines" (get outcome 1))
                     (string/find "error:" (get outcome 1))))
            (string/format
              (string "when a per-name SNI context cannot be built the raise "
                      "must carry the OpenSSL cause along with the name, but "
                      "it %s - the per-name builder panics with only the name "
                      "(src/jtls/api/context.c:183-196) and drops the reason "
                      "that made the context build fail; the same "
                      "cause-dropping callback also discards the "
                      "SSL_set_SSL_CTX return and reports success to the "
                      "handshake (src/jtls/context/sni.c:24-34), which is the "
                      "wrong certificate served silently")
              (short-q outcome))))

  (def-test "bio-read-nil-means-no-data-not-an-empty-read"
    :timeout 30

    # Controls: the documented no-data nil is only for "nothing to read".
    (let [b (bio/new-mem)]
      (bio/write b "hello")
      (assert (= "hello" (string (bio/read b 10)))
              "control: a read with data available returns the data")
      (assert (nil? (bio/read b 5))
              "control: after the data is consumed the read returns the documented no-data nil"))

    (let [b (bio/new-mem)]
      (bio/write b "hello")
      (def outcome (capture (fn [] (bio/read b 0))))
      (def conflated (and (= :returned (get outcome 0))
                          (nil? (get outcome 1))))
      (assert (not conflated)
              (string/format
                (string "a zero-length BIO read must return an empty result "
                        "(or reject the request), not the documented no-data "
                        "nil, but it %s while \"hello\" was still pending in "
                        "the BIO - cfun_bio_read (src/jbio.c:68-96) folds a "
                        "hard failure, end of data, and a zero-length request "
                        "into one nil (:86, :96); nil must mean no data is "
                        "available and nothing else (a zero-length tls/read "
                        "returns the empty buffer, src/jtls/api/io.c:117-124)")
                (short-q outcome)))))

  (def-test "ssl-error-string-must-carry-every-queued-error"
    :timeout 60

    # crypto/convert-key probes PEM private, PEM public, DER private, and
    # DER public in turn (src/jcrypto/convert.c:56-73); on this input every
    # probe fails and queues an error, and the panic then consults the
    # error-string helper (:78).
    (drain-queue)
    (def outcome
      (capture (fn [] (crypto/convert-key "not a key at all" :pem))))
    (def err (if (= :raised (get outcome 0)) (get outcome 1) ""))
    (def reported (length (string/find-all "routines::" err)))
    (assert (and (= :raised (get outcome 0)) (>= reported 2))
            (string/format
              (string "an operation whose failed probes queued several "
                      "OpenSSL errors must raise a message carrying all of "
                      "them (each queued error, separated), but the raise "
                      "reported %d error string(s): %s - the error-string "
                      "helper (src/jutils/error.c:19-24) pops exactly one "
                      "error and drops the rest, so a multi-failure reports "
                      "only its earliest cause and the newer causes vanish "
                      "from the message")
              reported
              (short-q outcome)))))

# dtls/connect string port parsed with unchecked atoi regression test
# Ticket b9f70a23a27cbf5ea62c6b499fd362e658b6be1d
#
# "dtls/connect string port parsed with unchecked atoi"
#
# Mechanism (this tree, ticket branch off 0.2.0): in the dtls/connect
# entry a string port is converted with plain atoi on the raw string
# (src/jdtls/api/connect.c:43) with no validation, while only
# non-string ports go the checked integer path
# (src/jdtls/api/connect.c:45, janet_getinteger). atoi accepts
# trailing junk ("80x" parses as 80) and yields 0 for empty or
# non-numeric strings; the result flows to htons((uint16_t)port) at
# src/jdtls/api/connect.c:120 and the UDP connect at
# src/jdtls/api/connect.c:127-132, so a garbage port string is
# silently accepted and the connection proceeds. A bad host at the
# same entry raises the established parameter error
# dtls_panic_param("invalid address: %s") at
# src/jdtls/api/connect.c:123-124 - the string port is the one bad
# parameter that gets no check.
#
# This test demonstrates:
#   (a) dtls/connect with a garbage string port - the live test
#       server's port carrying the ticket's trailing-junk shape,
#       "PORTx" - must raise a parameter error before any socket
#       work, in the same established shape as the invalid-address
#       error at src/jdtls/api/connect.c:123-124,
#   (b) under the defect the call instead connects: atoi strips the
#       trailing junk, the DTLS handshake completes with the live
#       test server on the parsed port, and the call returns a client
#       whose peer port is the server port - proof that the junk
#       string was accepted and used to connect.
#
# Predicted symptom: the garbage string port raises a parameter error
# rather than connecting. Under the defect nothing raises - the call
# connects to the numeric prefix of the junk string.
#
# Proof contract: under the defect the test fails with exactly that
# symptom and nothing else (no crash, no hang, no unrelated error);
# under fixed code the whole test passes. The guard pins the
# parameter-error fix shape matching the invalid-address precedent at
# src/jdtls/api/connect.c:123-124; the error message wording is free.

(use assay)
(import jsec/dtls-stream :as dtls)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

(def-suite :name "DTLS Connect String Port Regression"
  :description "Ticket b9f70a23a2: dtls/connect with a garbage string port must raise a parameter error rather than connecting"

  (def-test "garbage-string-port-raises-parameter-error-instead-of-connecting"
    :timeout 15

    (let [server (dtls/listen "127.0.0.1" 0 {:cert (certs :cert)
                                             :key (certs :key)})
          [_ port] (dtls/localname server)]

      (defer (:close server)

        # Server fiber: two echo rounds - one for the clean control
        # connection, one to serve the proof call's handshake under
        # the defect (under the fix the proof call raises before any
        # datagram and the second round simply stays pending).
        (ev/go (fn []
                 (try
                   (repeat 2
                     (def buf (buffer/new 1024))
                     (def addr (dtls/recv-from server 1024 buf))
                     (when addr
                       (dtls/send-to server addr
                                     (string "echo:" (string buf)))))
                   ([_] nil))))

        (ev/sleep 0.2)

        # Control: the clean string form of the same port works and
        # round-trips, isolating the missing parse check as the sole
        # cause of the proof failure below.
        (let [c (dtls/connect "127.0.0.1" (string port) {:verify false})]
          (defer (:close c true)
            (dtls/write c "Ping")
            (def reply (dtls/read c 1024))
            (assert reply "control: clean string port should complete the handshake")
            (assert (= "echo:Ping" (string reply))
                    (string/format
                      (string "control: clean string port should round-trip, "
                              "got %q")
                      (string reply)))))

        # The proof call: a garbage string port (the ticket's "80x"
        # trailing-junk shape, pointed at the live server port so the
        # acceptance is observable as a completed connection). Under
        # the defect this raises nothing and connects to the parsed
        # port; the raise propagates only under the fix.
        (def outcome
          (try
            (do
              (def c (dtls/connect "127.0.0.1" (string port "x")
                                   {:verify false}))
              [:returned
               (string "connected to peer port "
                       (dtls/address-port (dtls/peername c)))])
            ([e] [:raised (string e)])))

        # (a) The garbage port must raise a parameter error rather
        # than connecting. Under the defect this fails with exactly
        # the predicted symptom: the call connected to the numeric
        # prefix of the junk string.
        (assert (= :raised (get outcome 0))
                (string/format
                  (string "dtls/connect with a garbage string port (trailing "
                          "junk, \"PORTx\" per the ticket's \"80x\" shape) must "
                          "raise a parameter error rather than connecting "
                          "(plain atoi at src/jdtls/api/connect.c:43 accepts "
                          "trailing junk and parses it as the numeric prefix); "
                          "got %q")
                  outcome))))))

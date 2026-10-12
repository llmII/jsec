# dtls/listen and dtls/connect port validation regression test
#
# Mechanism (this tree): the dtls/listen port parse reads a string port
# with strtol (src/jdtls/server.c:234) and validates it
# (src/jdtls/server.c:235) without ever checking that any digits were
# parsed, so an empty string is accepted as port 0 and binds an ephemeral
# port; dtls/connect rejects that shape (src/jdtls/api/connect.c:61). The
# integer port paths on both entry points perform no range check at all
# (src/jdtls/server.c:240 and src/jdtls/api/connect.c:67) and each
# formats the port through a 16-bit truncation (src/jdtls/server.c:247
# and src/jdtls/api/connect.c:135), so an out-of-range integer silently
# wraps modulo 65536 and is used as a real port.
#
# This test demonstrates:
#   (a) dtls/listen with an empty string port must raise a parameter
#       error before any socket work, in the same established shape as
#       the bad string port error at src/jdtls/server.c:236,
#   (b) out-of-range integer ports must raise a parameter error on both
#       entry points - dtls/listen accepts 0 through 65535 and
#       dtls/connect accepts 1 through 65535 - rather than being wrapped
#       modulo 65536 and used as a real port.
#
# Predicted symptom: the empty string port and the out-of-range integer
# ports raise parameter errors rather than producing a bound server or a
# connection. Under the defect nothing raises at the parameter level -
# dtls/listen returns a server bound to the wrapped port and
# dtls/connect connects to the wrapped port.
#
# Proof contract: under the defect the tests fail with exactly these
# symptoms and nothing else (no crash, no hang, no unrelated error);
# under fixed code the whole suite passes. The guards pin the
# parameter-error fix shape matching the invalid-port precedent at
# src/jdtls/server.c:236 and src/jdtls/api/connect.c:63; the error
# message wording is free.

(use assay)
(import jsec/dtls-stream :as dtls)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

(def-suite :name "DTLS Port Validation Regression"
  :description "dtls/listen and dtls/connect must reject an empty string port and out-of-range integer ports with a parameter error"

  (def-test "empty-string-port-in-listen-must-raise-parameter-error"
    :timeout 15

    (def outcome
      (try
        (do
          (def server
            (dtls/listen "127.0.0.1" ""
                         {:cert (certs :cert) :key (certs :key)}))
          (def [_ bound-port] (dtls/localname server))
          (:close server)
          [:returned (string "server bound to port " bound-port)])
        ([e] [:raised (string e)])))

    (assert (and (= :raised (get outcome 0))
                 (string/find "[DTLS:PARAM]" (get outcome 1)))
            (string/format
              (string
                "dtls/listen with an empty string port must raise a "
                "parameter error before any socket work (an empty string "
                "is not a port: strtol at src/jdtls/server.c:234 parses "
                "zero digits there and the validation at "
                "src/jdtls/server.c:235 does not check for that, unlike "
                "the dtls/connect check at src/jdtls/api/connect.c:61, "
                "so the empty string is taken as port 0); instead of "
                "being rejected as a parameter the empty string port was "
                "accepted and used as a real port; observed: %q")
              outcome)))

  (def-test "out-of-range-integer-port-must-raise-parameter-error"
    :timeout 30

    # A live echo server so the dtls/connect probe can observe the
    # wrapped port being accepted as a destination: its port is below the
    # 16-bit range edge, so port + 65536 is out of range and wraps back
    # to the live port.
    (def server
      (dtls/listen "127.0.0.1" 0
                   {:cert (certs :cert) :key (certs :key)}))
    (def [_ port] (dtls/localname server))
    (ev/go (fn []
             (try
               (repeat 8
                 (def buf (buffer/new 1024))
                 (def addr (dtls/recv-from server 1024 buf))
                 (when addr
                   (dtls/send-to server addr
                                 (string "echo:" (string buf)))))
               ([_] nil))))
    (ev/sleep 0.2)

    (defn attempt [thunk]
      (try
        [:returned (thunk)]
        ([e] [:raised (string e)])))

    (defer (:close server)
      (def listen-hi
        (attempt
          (fn []
            (def s (dtls/listen "127.0.0.1" 65536
                                {:cert (certs :cert) :key (certs :key)}))
            (def [_ p] (dtls/localname s))
            (:close s)
            (string "server bound to port " p))))

      (def listen-neg
        (attempt
          (fn []
            (def s (dtls/listen "127.0.0.1" -1
                                {:cert (certs :cert) :key (certs :key)}))
            (def [_ p] (dtls/localname s))
            (:close s)
            (string "server bound to port " p))))

      (def connect-wrap
        (attempt
          (fn []
            (def c (dtls/connect "127.0.0.1" (+ 65536 port)
                                 {:verify false}))
            (def p (dtls/address-port (dtls/peername c)))
            (:close c true)
            (string "client connected to peer port " p))))

      (def connect-zero
        (attempt
          (fn []
            (def c (ev/with-deadline 2
                     (dtls/connect "127.0.0.1" 0 {:verify false})))
            (def p (dtls/address-port (dtls/peername c)))
            (:close c true)
            (string "client connected to peer port " p))))

      (def outcomes {:listen-65536 listen-hi
                     :listen-minus-one listen-neg
                     :connect-wrap connect-wrap
                     :connect-zero connect-zero})

      (assert (and (= :raised (get listen-hi 0))
                   (string/find "[DTLS:PARAM]" (get listen-hi 1)))
              (string/format
                (string
                  "dtls/listen with the integer port 65536 must raise a "
                  "parameter error before any socket work (the integer "
                  "path at src/jdtls/server.c:240 performs no range "
                  "check and the port is formatted through a 16-bit "
                  "truncation at src/jdtls/server.c:247, so the value "
                  "silently wraps modulo 65536); instead of being "
                  "rejected as a parameter the out-of-range port was "
                  "accepted and used as a real bind port (65536 wraps "
                  "to 0, an ephemeral port); observed: %q")
                outcomes))

      (assert (and (= :raised (get listen-neg 0))
                   (string/find "[DTLS:PARAM]" (get listen-neg 1)))
              (string/format
                (string
                  "dtls/listen with the integer port -1 must raise a "
                  "parameter error before any socket work (no range "
                  "check at src/jdtls/server.c:240 and a 16-bit "
                  "truncation at src/jdtls/server.c:247); instead of "
                  "being rejected as a parameter the negative port was "
                  "accepted and used as a real bind port (-1 wraps to "
                  "65535); observed: %q")
                outcomes))

      (assert (and (= :raised (get connect-wrap 0))
                   (string/find "[DTLS:PARAM]" (get connect-wrap 1)))
              (string/format
                (string
                  "dtls/connect with the out-of-range integer port %d "
                  "(65536 past the live server port %d) must raise a "
                  "parameter error before any socket work (the integer "
                  "path at src/jdtls/api/connect.c:67 performs no range "
                  "check and the port is truncated at "
                  "src/jdtls/api/connect.c:135); instead of being "
                  "rejected as a parameter the out-of-range port was "
                  "silently wrapped modulo 65536 and used as the "
                  "destination port, connecting to the live server at "
                  "the wrapped port %d; observed: %q")
                (+ 65536 port) port port outcomes))

      (assert (and (= :raised (get connect-zero 0))
                   (string/find "[DTLS:PARAM]" (get connect-zero 1)))
              (string/format
                (string
                  "dtls/connect with the integer port 0 must raise a "
                  "parameter error before any socket work (the accepted "
                  "range starts at 1; the integer path at "
                  "src/jdtls/api/connect.c:67 performs no range "
                  "check); instead of being rejected as a parameter the "
                  "zero port was accepted and the call proceeded toward "
                  "connecting to port 0; observed: %q")
                outcomes)))))

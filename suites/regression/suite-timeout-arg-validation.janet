# Timeout argument validation regression test
# Ticket b85747a9f2780c4cdf2cd6d7bf276e4c9cb0ef1e
#
# "parse_timeout_opt and I/O timeout arguments silently accept NaN and
# non-numeric/non-dictionary values"
#
# Mechanism (this tree, branch ticket-b85747a9f2780c4cdf2cd6d7bf276e4c9cb0ef1e
# off 0.2.0 at 2eef29afaf): parse_timeout_opt (src/jtls/api/io.c:52-81)
# - and its jdtls twin (src/jdtls/api/io.c:33-59) - validate only
# `if (timeout < 0)` (:75-77, :55-57). Three holes fall through that
# single check: (1) NaN compares false with everything, so
# (math/sqrt -1) passes the negative check and reaches
# state->timeout/has_timeout and the janet_addtimeout arming; (2) a
# non-number, non-table/struct argument (a string, a keyword, a boolean)
# matches neither unwrap branch and leaves the INFINITY default - the
# call proceeds as "no timeout" instead of raising; (3) a table/struct
# whose :timeout key is non-nil but not a number (e.g. {:timeout "fast"})
# is silently ignored for the same reason. cfun_read, cfun_chunk and
# cfun_write route their timeout arguments through this helper
# (src/jtls/api/io.c:109, :154, :197); the jdtls twins do the same
# (src/jdtls/api/io.c:127, :175, and cfun_dtls_chunk), and
# cfun_dtls_recv_from carries an unchecked inline copy
# (src/jdtls/server.c:778-796). Only negative numbers are rejected
# today (src/jtls/api/io.c:77-78).
#
# This test demonstrates: every timeout argument - NaN, non-numeric
# values, and a non-number :timeout in an options table/struct - must
# raise a [TLS:PARAM] parameter error at the API boundary, the way a
# negative timeout already does. The calls run against a live TLS
# stream with plaintext already pending in the kernel buffer, so each
# one completes synchronously and an accepted argument is observable as
# a plain return value rather than a hang. Under the defect the test
# fails with exactly the predicted symptom - the invalid arguments are
# accepted (or, for {:timeout nan}, mis-handled as an instant deadline)
# and no parameter error is raised; under fixed code the whole test
# passes.

(use assay)
(import jsec/tls :as tls)
(import ../helpers :prefix "")

# Generate certs at suite load time (shared by tests in this module)
(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

(defn- looks-like-timeout-param-error?
  "True when err is the timeout parameter rejection the contract calls
   for: a [*:PARAM] tagged error mentioning timeout."
  [err]
  (and (string? err)
       (string/find ":PARAM]" err)
       (string/find "timeout" err)))

(defn- probe-timeout-arg
  "Run one timed TLS call and classify the outcome:
   [:param]    - raised the timeout parameter error (the contract),
   [:wrong e]  - raised some other error,
   [:accepted v] - returned normally, the invalid argument was accepted."
  [thunk]
  (try
    (do (def r (thunk)) [:accepted r])
    ([e]
      (if (looks-like-timeout-param-error? e)
        [:param]
        [:wrong (string e)]))))

(def-suite :name "Timeout Argument Validation Regression"
  :description "Ticket b85747a9f2: NaN and non-numeric I/O timeout arguments must raise a parameter error instead of being silently accepted"

  (def-test "timeout-arguments-must-reject-nan-and-non-numeric-values"
    :timeout 30

    (let [[server socket-path] [(net/listen "127.0.0.1" "0") nil]
          [_ port] (net/localname server)
          ready (ev/chan 1)]

      (defer (:close server)

        # Client fiber: complete the TLS handshake, queue twelve
        # plaintext bytes (one record per :write), then stay silent so
        # the server-side probe calls each find data already pending and
        # complete synchronously - an accepted invalid argument returns
        # its bytes instead of parking on the network.
        (ev/go
          (fn []
            (try
              (do
                (def conn (net/connect "127.0.0.1" (string port)))
                (def c (tls/wrap conn "127.0.0.1" {:verify false}))
                (:write c "aaaaaaaaaaaa")
                (ev/give ready true)
                (ev/sleep 4)
                (:close c true))
              ([e] (ev/give ready (string "client error: " e))))))

        (with [conn (:accept server)]
          (with [s (tls/wrap conn {:cert (certs :cert) :key (certs :key)})]

            (def ready-val (ev/take ready))
            (assert (= true ready-val)
                    (string/format "client setup failed: %v" ready-val))
            (ev/sleep 0.2)

            # Control: the narrow validation that already exists - a
            # negative timeout raises [TLS:PARAM] - so a missing raise
            # below cannot be an environment failure in disguise.
            (def control (probe-timeout-arg |(:read s 1 nil -5)))
            (assert (= :param (get control 0))
                    (string/format
                      (string "control: a negative timeout must raise the "
                              "[TLS:PARAM] timeout error (src/jtls/api/io.c:"
                              "77-78), got %q - the probe cannot distinguish "
                              "acceptance from a broken raise path")
                      control))

            # The invalid arguments of ticket b85747a9f2. Each is a
            # timeout argument shape parse_timeout_opt
            # (src/jtls/api/io.c:52-81) must reject with [*:PARAM] "timeout
            # must be a non-negative number": NaN bypasses `timeout < 0`,
            # non-numbers fall through both unwrap branches to the silent
            # INFINITY default, and a non-number :timeout is skipped by
            # the JANET_NUMBER check inside the table/struct branch.
            (def cases
              [["(:read s 1 nil nan) - NaN number"
                |(:read s 1 nil (math/sqrt -1))]
               ["(:read s 1 nil \"5\") - non-numeric string"
                |(:read s 1 nil "5")]
               ["(:read s 1 nil true) - non-numeric boolean"
                |(:read s 1 nil true)]
               ["(:read s 1 nil {:timeout \"fast\"}) - non-number :timeout"
                |(:read s 1 nil {:timeout "fast"})]
               ["(:read s 1 nil {:timeout nan}) - NaN :timeout"
                |(:read s 1 nil {:timeout (math/sqrt -1)})]
               ["(:write s \"x\" nan) - write entry point, NaN"
                |(:write s "x" (math/sqrt -1))]
               ["(:chunk s 1 nil \"5\") - chunk entry point, string"
                |(:chunk s 1 nil "5")]])

            (def violations @[])
            (each [label thunk] cases
              (def outcome (probe-timeout-arg thunk))
              (unless (= :param (get outcome 0))
                (array/push violations
                            (string label " -> " (string/format "%q" outcome)))))

            # Every timeout argument above must raise the parameter
            # error. Under the defect parse_timeout_opt accepts them all:
            # the reads and the write complete with the pending data and
            # the chunk returns its byte, with no error at all.
            (assert (empty? violations)
                    (string/format
                      (string "I/O timeout arguments that parse_timeout_opt "
                              "(src/jtls/api/io.c:52-81) must reject with a "
                              "[TLS:PARAM] timeout parameter error were "
                              "accepted or mis-handled instead (%d "
                              "violations): %s. Only `timeout < 0` is "
                              "checked (:75-77), so NaN, non-numeric values "
                              "and a non-number :timeout silently become \"no "
                              "timeout\" (or an instant deadline for {:timeout "
                              "nan})")
                      (length violations)
                      (string/join violations "; ")))))))))

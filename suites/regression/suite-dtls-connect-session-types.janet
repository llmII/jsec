# dtls/connect :session type parity regression test
# Ticket fbf4f8f37c216f26d6f8a12fccc444c3ace20330
#
# ":session accepts a string on tls/connect but not on dtls/connect"
#
# Mechanism (this tree, ticket branch off 0.2.0): the jdtls connect
# session handling reads :session only when it is a buffer and ignores
# every other type - src/jdtls/api/connect.c:250-257 (the
# janet_checktype(session_data, JANET_BUFFER) gate at :251 has no else
# branch, so a non-buffer is silently dropped). The jtls connect path
# also accepts a string first - src/jtls/api/connect.c:340-343 (string)
# before :344-347 (buffer) - so the same session blob works for TLS and
# is silently dropped for DTLS. Both connect docstrings promise
# ":session - Session data for resumption" with no type restriction
# (src/jtls/module.c:105 for tls/connect, src/jdtls/api/module.c:27 for
# dtls/connect); docs/API.org:102 documents tls/connect's :session as
# "Byte string. Session data for resumption (from get-session)."
# while docs/API.org:190 documents wrap's as "Buffer", and
# docs/API.org:426-441 (dtls/connect) does not list :session at all.
# The producers differ by side: tls-stream/get-session returns a byte
# string (src/jtls/api/session.c:73) while dtls-stream/session returns
# a buffer (src/jdtls/api/info.c:127-146), so a TLS-produced blob fed
# to dtls/connect is exactly the silently dropped string case.
#
# This test demonstrates:
#   (a) the same session blob fed as a STRING to dtls/connect must be
#       applied exactly as the buffer form is - the resumed connection
#       reports (:session-reused? client) true,
#   (b) the same blob fed as a BUFFER is applied (control: this half
#       already works and must keep working),
#   (c) :session values of any other type (integer, keyword) must raise
#       a parameter error rather than being silently ignored - today
#       both connect without complaint.
#
# Predicted symptom: the string-fed connection silently drops the blob
# at src/jdtls/api/connect.c:251 and completes a FULL handshake
# (session-reused? is false), and :session with an integer or keyword
# connects fine with no error at all.
#
# Proof contract: under the defect the test fails with exactly that
# symptom and nothing else (no crash, no hang, no unrelated error);
# under fixed code the whole test passes. The guard pins the ticket's
# stated contract: both string and buffer applied, other types raise.

(use assay)
(import jsec/dtls-stream :as dtls)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

(defn- serve-pong
  ``Server fiber body: answer up to n client datagrams with Pong.``
  [server n done]
  (ev/go (fn []
           (try
             (repeat n
               (def buf (buffer/new 1024))
               (def addr (dtls/recv-from server 1024 buf))
               (when addr
                 (dtls/send-to server addr "Pong")))
             ([_] nil))
           (ev/give done true))))

(defn- capture-session-blob
  ``Full first connection against a live server; returns the session blob.``
  [port]
  (def client (dtls/connect "127.0.0.1" port {:verify false}))
  (defer (:close client true)
    (dtls/write client "Ping")
    (def reply (dtls/read client 1024))
    (assert reply "capture connection should receive Pong")
    (assert (= "Pong" (string reply))
            "capture connection should receive the Pong payload")
    (def blob (:session client))
    (assert (bytes? blob)
            "(:session client) should return the session blob as bytes")
    (assert (pos? (length blob))
            "session blob should be non-empty")
    blob))

(defn- try-session-connect
  ``Attempt dtls/connect with the given :session value.
   Returns [:connected true] when the call connects (handshake done),
   [:connected false] when it returns without raising but without a
   completed handshake, or [:raised err] when it raises.``
  [port session-val]
  (try
    (do
      (def client (dtls/connect "127.0.0.1" port
                                {:verify false :session session-val}))
      (def connected (not (nil? client)))
      (when client (:close client true))
      [:connected connected])
    ([err] [:raised err])))

(def-suite :name "DTLS Connect Session Types Regression"
  :description "Ticket fbf4f8f37c: :session on dtls/connect must accept string and buffer alike, raise on other types, and (:session client) must return an immutable string"

  (def-test "dtls-session-returns-immutable-string"
    :timeout 15

    (let [server (dtls/listen "127.0.0.1" 0 {:cert (certs :cert)
                                             :key (certs :key)})
          [_ port] (dtls/localname server)
          done (ev/chan 1)]
      (defer (:close server)
        (serve-pong server 1 done)
        (ev/sleep 0.2)

        (def blob (capture-session-blob port))
        (assert (string? blob)
                (string/format
                  (string "(:session client) must return an immutable byte "
                          "string (matching tls-stream/get-session), got "
                          "%q (%s) from src/jdtls/api/info.c:147-153")
                  (type blob) (describe blob)))

        (ev/take done))))

  (def-test "session-blob-as-string-is-applied"
    :timeout 15

    (let [server (dtls/listen "127.0.0.1" 0 {:cert (certs :cert)
                                             :key (certs :key)})
          [_ port] (dtls/localname server)
          done (ev/chan 1)]
      (defer (:close server)
        (serve-pong server 2 done)
        (ev/sleep 0.2)

        (def blob (capture-session-blob port))

        (def client (dtls/connect "127.0.0.1" port
                                  {:verify false :session (string blob)}))
        (defer (:close client true)
          # (a) The same bytes as a string must be APPLIED: the second
          # connection resumes the captured session. Under the defect
          # the string is silently dropped at
          # src/jdtls/api/connect.c:251 and this connection completes a
          # full handshake instead - the predicted symptom.
          (assert (:session-reused? client)
                  (string "the session blob fed as a string must be "
                          "applied (session resumed): the string form is "
                          "silently dropped at src/jdtls/api/connect.c:251 "
                          "and a full handshake ran instead"))
          # Keep the server handler progressing so shutdown is clean
          # under fixed code.
          (dtls/write client "Ping")
          (def reply (dtls/read client 1024))
          (assert (= "Pong" (string reply))
                  "resumed connection (string form) should still round-trip"))

        (ev/take done))))

  (def-test "session-blob-as-buffer-is-applied"
    :timeout 15

    (let [server (dtls/listen "127.0.0.1" 0 {:cert (certs :cert)
                                             :key (certs :key)})
          [_ port] (dtls/localname server)
          done (ev/chan 1)]
      (defer (:close server)
        (serve-pong server 2 done)
        (ev/sleep 0.2)

        (def blob (capture-session-blob port))

        (def client (dtls/connect "127.0.0.1" port
                                  {:verify false :session (buffer blob)}))
        (defer (:close client true)
          # (b) Control half: the buffer form is applied today and must
          # keep working under the fix.
          (assert (:session-reused? client)
                  (string/format
                    (string "the session blob fed as a buffer must be "
                            "applied (session resumed), got session-reused? "
                            "%q")
                    (:session-reused? client)))
          # Keep the server handler progressing so shutdown is clean.
          (dtls/write client "Ping")
          (def reply (dtls/read client 1024))
          (assert (= "Pong" (string reply))
                  "resumed connection (buffer form) should still round-trip"))

        (ev/take done))))

  (def-test "session-option-with-other-types-raises"
    :timeout 15

    (let [server (dtls/listen "127.0.0.1" 0 {:cert (certs :cert)
                                             :key (certs :key)})
          [_ port] (dtls/localname server)
          done (ev/chan 1)]
      (defer (:close server)
        (serve-pong server 2 done)
        (ev/sleep 0.2)

        # (c) Types other than string/buffer/nil must raise a parameter
        # error, not be silently ignored. Under the defect both calls
        # below connect without complaint (the value is dropped) and
        # the assertions fail naming the silent drop.
        (defn- must-raise [session-val kind]
          (def result (try-session-connect port session-val))
          (assert (= :raised (first result))
                  (string/format
                    (string "dtls/connect with :session %s must raise a "
                            "parameter error instead of silently ignoring "
                            "the value and connecting (src/jdtls/api/"
                            "connect.c:250-257 has no rejection path); "
                            "got %q")
                    kind result)))

        (must-raise 42 "an integer")
        (must-raise :not-a-session "a keyword")
        # No wait on the server fiber: under fixed code both calls raise
        # at option parse and the server sees no datagrams at all; the
        # deferred server close reaps it.

        ))))

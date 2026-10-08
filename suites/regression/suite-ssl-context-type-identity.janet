# SSLContext type identity regression test
# Ticket a8cd5f34163f3cd0aa60485baad0088aa3dbe8a0
#
# "SSLContext is not actually one type (per-.so duplication)"
#
# Mechanism (this tree, ticket branch off 0.2.0 at 599e82e288):
#   - src/jutils/context.c is compiled into EVERY native module.
#     project.janet:185-187 defines jutils-shared-sources (all
#     src/jutils/*.c except module.c) and splices it into the source lists
#     of jsec/tls-stream (project.janet:204), jsec/dtls-stream
#     (project.janet:211), jsec/cert (project.janet:222), jsec/bio
#     (project.janet:229), jsec/crypto (project.janet:237) and jsec/ca
#     (project.janet:244); jsec/utils builds the same files again
#     (project.janet:198-201). The unified type
#     `const JanetAbstractType ssl_context_type` at
#     src/jutils/context.c:42-53 is therefore a DISTINCT object per .so -
#     nm shows ssl_context_type as a defined data symbol at 0x14c80 in
#     jsec/tls-stream.so, 0x11cc0 in jsec/dtls-stream.so and 0x5d80 in
#     jsec/utils.so - and with it a private copy of the
#     ssl_context_methods table (src/jutils/context.c:18-20) and of the
#     ssl_context_type_registered guard (src/jutils/context.c:55-62).
#   - janet_getabstract compares the expected type by POINTER, so an
#     abstract created against one .so's copy is rejected by another .so's
#     copy with the self-contradicting message "bad slot #0, expected
#     jsec/ssl-context, got <jsec/ssl-context 0x...>" - the ticket's
#     "expected jsec/ssl-context, got jsec/ssl-context". Both contexts
#     come from the SAME shared jutils_create_context
#     (src/jutils/context.c:127) and carry the same type NAME
#     (src/jutils/context.c:42); only the type OBJECT address differs.
#   - Observable rejection sites in THIS tree: tls/trust-cert
#     (cfun_trust_cert, src/jtls/api/context.c:202-204) and
#     tls/set-ocsp-response (cfun_set_ocsp_response,
#     src/jtls/api/context.c:156-158) pass &tls_context_type - a macro for
#     the jtls copy (src/jtls/internal.h:273) - to janet_getabstract;
#     dtls/connect's :context option (src/jdtls/api/connect.c:84-86) passes
#     &dtls_context_type, the jdtls copy (src/jdtls/internal.h:370). A
#     dtls/new-context result is therefore refused by the tls/ APIs and a
#     tls/new-context result by the dtls/ API.
#   - Same class, not asserted here: tls/wrap and tls/accept/accept-loop
#     probe with janet_checkabstract (src/jtls/api/connect.c:63,
#     src/jtls/api/server.c:265, src/jtls/api/server.c:753), which returns
#     false across modules, so a foreign context falls through and is
#     silently ignored instead of raising. Related per-module state:
#     error_buf (src/jutils/error.c:18-21) and the ssl_context_methods
#     table are duplicated the same way.
#   - Related build issue, noted and NOT asserted here:
#     src/jutils/error.c:20 uses the C11 _Thread_local keyword while
#     project.janet:98 compiles with -std=c99. It builds on this GCC as an
#     accepted extension but is a portability hazard on strict C99
#     compilers.
#
# This test demonstrates:
#   (a) a context created by dtls/new-context is accepted by a tls/ API:
#       (tls/trust-cert dctx cert-pem) returns nil, exactly as the
#       same-module control (tls/trust-cert tctx cert-pem) does,
#   (b) the reverse direction - a context created by tls/new-context is
#       accepted by the dtls/ API's abstract type check. dtls/connect's
#       :context option must reach its intentional protocol guard and
#       reject the TLS context with "cannot use TLS context for DTLS
#       connection" (src/jdtls/api/connect.c:88-90) - one abstract type
#       identity across modules means the type check passes and only the
#       protocol guard speaks, never the identity error.
#
# Proof contract: under the defect each def-test fails with exactly the
# predicted symptom - the self-contradicting janet_getabstract rejection
# "bad slot #0, expected jsec/ssl-context, got <jsec/ssl-context ...>"
# ("expected jsec/ssl-context, got jsec/ssl-context") - and nothing else:
# no crash, no hang, no unrelated error. Under fixed code both def-tests
# pass.

(use assay)
(import jsec/tls-stream :as tls)
(import jsec/dtls-stream :as dtls)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

(def-suite :name "SSL Context Type Identity Regression"
  :description "Ticket a8cd5f3416: SSLContext is duplicated per .so so cross-module contexts are rejected as not jsec/ssl-context"

  (def-test "dtls new-context is accepted by tls trust-cert"

    (def tctx (tls/new-context {}))
    (def dctx (dtls/new-context {}))

    # Control: a tls/new-context context is accepted by tls/trust-cert
    # (same .so, same type object) and the call returns nil.
    (assert (nil? (tls/trust-cert tctx (certs :cert)))
            (string "control: tls/trust-cert must accept a tls/new-context "
                    "context and return nil"))

    # (a) The cross-module call. Under the defect janet_getabstract's
    # pointer-compare rejects this dtls/new-context context against the
    # jtls copy of ssl_context_type and raises "bad slot #0, expected
    # jsec/ssl-context, got <jsec/ssl-context 0x...>" - the same type
    # name on both sides of a check that just refused it. The raise is
    # the proof; let it propagate so the test fails with that exact
    # message. Under fixed code this returns nil like the control.
    (assert (nil? (tls/trust-cert dctx (certs :cert)))
            (string "tls/trust-cert must accept a dtls/new-context context "
                    "(one abstract type identity across modules) and return "
                    "nil")))

  (def-test "tls new-context is accepted by the dtls context type check"

    (def tctx (tls/new-context {}))

    # (b) The reverse direction, through dtls/connect's :context option
    # (src/jdtls/api/connect.c:84-86). Under the defect janet_getabstract
    # rejects the tls/new-context context against the jdtls copy of
    # ssl_context_type with "bad slot #0, expected jsec/ssl-context, got
    # <jsec/ssl-context 0x...>". Under fixed code the type check passes
    # and the intentional protocol guard (src/jdtls/api/connect.c:88-90)
    # rejects the TLS context with "cannot use TLS context for DTLS
    # connection" - the designed outcome, reached before any socket is
    # created.
    (var outcome :no-error)
    (try
      (do (dtls/connect "127.0.0.1" "9" {:context tctx :verify false})
          (set outcome :no-error))
      ([err] (set outcome err)))
    (assert (string/find "cannot use TLS context for DTLS connection"
                         (string outcome))
            (string/format
              (string "a tls/new-context context must be accepted by the "
                      "dtls abstract type check and rejected only by the "
                      "intentional protocol guard (\"cannot use TLS context "
                      "for DTLS connection\", src/jdtls/api/connect.c:88-90); "
                      "got %q")
              outcome))))

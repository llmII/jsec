# dtls/localname client registration shadowed by the server registration regression test
# Ticket 419dae6ce42ff7b24baa8d09f2565788477f87e8
#
# "dtls/localname client registration shadowed by the server registration"
#
# Mechanism (this tree, ticket branch off 0.2.0): dtls/localname is
# registered twice into the same jsec/dtls-stream module environment.
# The client group registers it at src/jdtls/api/module.c:104-107
# ("localname", cfun_dtls_localname, "(dtls/localname client)"); the
# server group registers it at src/jdtls/server.c:941-944
# ("localname", cfun_dtls_server_localname, "(dtls/localname server)").
# JANET_MODULE_ENTRY runs jdtls_register_client and then
# jdtls_register_server (src/jdtls/module.c:37-38), and janet_cfuns
# writes both into the same env table (src/jdtls/api/module.c:114,
# src/jdtls/server.c:949), so the second registration of the same name
# REPLACES the first: after full module init only the server function
# remains bound. cfun_dtls_localname (src/jdtls/api/info.c:161-183)
# takes a DTLSClient and returns its local address as a DTLSAddress;
# cfun_dtls_server_localname (src/jdtls/server.c:867-896) takes a
# DTLSServer via janet_getabstract (src/jdtls/server.c:870) and panics
# on any other abstract type. Both entries carry their own docstring
# promising their own argument, so the client promise at
# src/jdtls/api/module.c:105 is broken at all times. The abstract
# method table is unaffected: (:localname client) still dispatches to
# cfun_dtls_localname through dtls_client_methods
# (src/jdtls/api/types.c:54).
#
# This test demonstrates:
#   (a) after full module init, (dtls/localname client) must return
#       the client's local address - a [host port] tuple with the same
#       host and port as the (:localname client) method result and with
#       host 127.0.0.1 and port above 0 on this loopback connection,
#   (b) under the defect the module-level name is bound to the server
#       function, so (dtls/localname client) raises a type error on a
#       DTLSClient argument instead of returning the address - the
#       documented client call shape is unreachable.
#
# Predicted symptom: the call raises the janet_getabstract type error
# naming the DTLSServer expectation (bad slot #0, expected ... got
# ...DTLSClient...) instead of returning the client local address.
#
# Proof contract: under the defect the test fails with exactly that
# symptom and nothing else (no crash, no hang, no unrelated error);
# under fixed code the whole test passes. The guard pins one module
# entry that dispatches on the abstract type of its argument (the
# ticket's stated fix shape), keeping both docstring promises.

(use assay)
(import jsec/dtls-stream :as dtls)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

(def-suite :name "DTLS Localname Shadowing Regression"
  :description "Ticket 419dae6ce4: (dtls/localname client) must return the client local address after full module init"

  (def-test "dtls-localname-client-returns-local-address-after-module-init"
    :timeout 15

    (let [server (dtls/listen "127.0.0.1" 0 {:cert (certs :cert)
                                             :key (certs :key)})
          [_ port] (dtls/localname server)
          done (ev/chan 1)]

      (defer (:close server)

        (ev/go (fn []
                 (try
                   (do
                     (def buf (buffer/new 1024))
                     (def addr (dtls/recv-from server 1024 buf))
                     (when addr
                       (dtls/send-to server addr "Pong")))
                   ([_] nil))
                 (ev/give done true)))

        (ev/sleep 0.2)

        (let [client (dtls/connect "127.0.0.1" port {:verify false})]
          (defer (:close client true)

            # Establish the connection fully first.
            (dtls/write client "Ping")
            (def reply (dtls/read client 1024))
            (assert reply "client should receive the Pong reply")
            (assert (= "Pong" (string reply))
                    "client should receive the Pong payload")

            # Reference truth: the abstract METHOD path is bound to
            # cfun_dtls_localname and is not shadowed. Both the method
            # and the module entry return a [host port] tuple
            # (net/localname parity, ticket c135d5659d).
            (def via-method (:localname client))
            (assert (tuple? via-method)
                    "method :localname should return a [host port] tuple")

            # (a) The proof call: the module-level name must reach the
            # client implementation after full module init. Under the
            # original defect this raises the server function's type
            # error - the predicted symptom - and the raise propagates
            # so the test fails with exactly that message.
            (def via-module (dtls/localname client))

            (assert (tuple? via-module)
                    (string/format
                      (string "(dtls/localname client) must return the "
                              "client local address as a [host port] "
                              "tuple, got %q")
                      via-module))
            (let [[module-host module-port] via-module
                  [method-host method-port] via-method]
              (assert (= "127.0.0.1" module-host)
                      (string/format
                        "client local address host must be 127.0.0.1, got %q"
                        module-host))
              (assert (pos? module-port)
                      (string/format
                        "client local address port must be above 0, got %q"
                        module-port))
              (assert (= method-host module-host)
                      (string/format
                        (string "module-level (dtls/localname client) must "
                                "match the (:localname client) method: %q vs %q")
                        method-host module-host))
              (assert (= method-port module-port)
                      (string/format
                        (string "module-level (dtls/localname client) must "
                                "match the (:localname client) method: %q vs %q")
                        method-port module-port)))))

        (ev/take done)))))

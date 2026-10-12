# DTLS address equality and hash cover socket padding bytes regression test
# Ticket 0e9e80e7bd05b58860db9ab8828fdce93c85045f
#
# "DTLS address equality and hash cover socket padding bytes"
#
# Mechanism (this tree, ticket branch off 0.2.0): dtls_address_equal
# (src/jdtls/address.c:52-55) memcmp's the raw stored socket-address
# bytes over the stored addrlen after comparing lengths (the compare
# at src/jdtls/address.c:54), and dtls_address_hash_fn
# (src/jdtls/address.c:70-79) FNV-hashes the same raw range (the loop
# at :74). The Janet abstract type's own compare and hash repeat the
# shape - src/jdtls/address.c:39-50 memcmp's raw bytes at :49 and
# src/jdtls/address.c:64-68 delegates to the same hash at :67 - and
# they back Janet =, (hash ...), and table keys for these values. The
# DTLS server session table keys on the same pair: session_bucket at
# src/jdtls/session.c:18-22 calls dtls_address_hash_fn at :19, and
# dtls_server_get_session (src/jdtls/session.c:111) and
# dtls_server_remove_session (:155) call dtls_address_equal. Those
# ranges include padding - sin_zero for AF_INET, sin6_flowinfo for
# AF_INET6 - which is not part of address identity and is commonly
# left uninitialized by callers, so identical addresses can compare
# unequal and hash differently.
#
# This test demonstrates:
#   (a) the same socket address obtained twice - via the recv-from
#       kernel fill path, via the dtls/address constructor, and via
#       the client localname (getsockname) path - compares equal and
#       hashes identically through both paths (the Janet
#       compare/hash path and the DTLS server session-table path),
#   (b) address-keyed lookups hold across acquisition paths: a Janet
#       table keyed by one acquisition finds the others, and
#       dtls/send-to with a constructed address finds the session the
#       recv-from address created (dtls_address_equal +
#       dtls_address_hash_fn at src/jdtls/session.c:19,:111).
#
# Predicted symptom under the defect: the same socket address obtained
# twice compares unequal and hashes differently - the memcmp and FNV
# ranges cover sin_zero / sin6_flowinfo, which differ whenever the
# filler left the padding uninitialized - and the session-table lookup
# misses ("no session for peer address", src/jdtls/server.c:793).
#
# PLATFORM NOTE (ledger Blocker has the measurements): on this host
# (Linux 7.0.14_1 x86_64) every socket-address fill path normalizes
# the padding - the kernel zero-fills sin_zero / sin6_flowinfo on
# recvfrom, getsockname, and getpeername, and every jsec constructor
# memsets before filling - so these assertions PASS here under the
# defect as well as under the fix. They fail with the predicted
# symptom on platforms whose kernel leaves the padding live. On this
# host this suite is therefore a CONTRACT ASSERTION and not an
# exhibitable proof-of-defect; the ledger gate is BLOCKED on that
# limit (S5: a non-failing test is not a proof).
#
# Proof contract: on a padding-live platform the test fails with
# exactly that symptom and nothing else (no crash, no hang, no
# unrelated error); under fixed code the whole test passes on every
# platform. The guard pins the padding-agnostic equality invariant
# regardless of which fix shape the ledger's option table picks.

(use assay)
(import jsec/dtls-stream :as dtls)
(import ../helpers :prefix "")

(def certs (generate-temp-certs {:common-name "127.0.0.1"}))

(defn- addr-desc
  "Compact host/port description of a DTLS address for failure text."
  [a]
  (string (dtls/address-host a) ":" (dtls/address-port a)))

# NB: the module-level dtls/localname name is shadowed by the server
# registration (ticket 419dae6ce4); the client local address is taken
# through the :localname method, which dispatches to the client
# implementation (src/jdtls/api/types.c:54).

(def-suite :name "DTLS Address Equality And Hash Regression"
  :description "Ticket 0e9e80e7bd: the same socket address obtained twice must compare equal and hash identically through both paths"

  (def-test "same-address-obtained-twice-compares-equal-and-hashes-identically"
    :timeout 15

    (let [server (dtls/listen "127.0.0.1" 0 {:cert (certs :cert)
                                             :key (certs :key)})
          [_ port] (dtls/localname server)
          recv-addrs @[]]

      (defer (:close server)

        (ev/go (fn []
                 (try
                   (do
                     (def buf (buffer/new 1024))
                     (def addr (dtls/recv-from server 1024 buf))
                     (when addr
                       (array/push recv-addrs addr)
                       (dtls/send-to server addr
                                     (string "echo:" (string buf)))))
                   ([_] nil))))

        (ev/sleep 0.2)

        (let [client (dtls/connect "127.0.0.1" port {:verify false})]
          (defer (:close client true)
            (dtls/write client "Ping")
            (def reply (dtls/read client 1024))
            (assert reply "setup: client should receive the echo reply")
            (assert (= "echo:Ping" (string reply))
                    "setup: client should receive the echo payload")

            # The same socket address (the client's source endpoint),
            # obtained three times: recv-from kernel fill, constructor,
            # getsockname.
            (def via-recv (get recv-addrs 0))
            (def via-method (:localname client))
            (def via-ctor (dtls/address "127.0.0.1"
                                        (dtls/address-port via-method)))
            (assert (dtls/address? via-recv)
                    "setup: recv-from should return a DTLS address")

            # (a) Equality and hash stability across every acquisition
            # pair - the Janet compare/hash path (dtls_address_compare
            # src/jdtls/address.c:39-50, dtls_address_hash :64-68).
            (assert (= via-recv via-method)
                    (string/format
                      (string "the same socket address obtained twice must "
                              "compare equal (dtls_address_equal memcmp's "
                              "sin_zero / sin6_flowinfo padding over addrlen "
                              "at src/jdtls/address.c:54): recv-from %s vs "
                              "localname %s came out unequal")
                      (addr-desc via-recv) (addr-desc via-method)))
            (assert (= (hash via-recv) (hash via-method))
                    (string/format
                      (string "the same socket address obtained twice must "
                              "hash identically (dtls_address_hash_fn FNV's "
                              "the padding-inclusive range at "
                              "src/jdtls/address.c:70-79): recv-from hash %d "
                              "vs localname hash %d")
                      (hash via-recv) (hash via-method)))
            (assert (= via-recv via-ctor)
                    (string/format
                      (string "the same socket address obtained twice must "
                              "compare equal (padding-covered memcmp at "
                              "src/jdtls/address.c:54): recv-from %s vs "
                              "constructed %s came out unequal")
                      (addr-desc via-recv) (addr-desc via-ctor)))
            (assert (= (hash via-recv) (hash via-ctor))
                    (string/format
                      (string "the same socket address obtained twice must "
                              "hash identically (padding-covered FNV at "
                              "src/jdtls/address.c:70-79): recv-from hash %d "
                              "vs constructed hash %d")
                      (hash via-recv) (hash via-ctor)))
            (assert (= via-method via-ctor)
                    (string/format
                      (string "the same socket address obtained twice must "
                              "compare equal (src/jdtls/address.c:54): "
                              "localname %s vs constructed %s came out "
                              "unequal")
                      (addr-desc via-method) (addr-desc via-ctor)))
            (assert (= (hash via-method) (hash via-ctor))
                    (string/format
                      (string "the same socket address obtained twice must "
                              "hash identically (src/jdtls/address.c:70-79): "
                              "localname hash %d vs constructed hash %d")
                      (hash via-method) (hash via-ctor)))

            # (b) Table-key path: one acquisition keys the table, the
            # others must find it.
            (def t @{})
            (put t via-recv :hit)
            (assert (= :hit (get t via-method))
                    (string/format
                      (string "a table keyed by the recv-from address must "
                              "find the same address obtained via localname "
                              "(hash bucket + compare over the "
                              "padding-inclusive range); got %q")
                      (get t via-method)))
            (assert (= :hit (get t via-ctor))
                    (string/format
                      (string "a table keyed by the recv-from address must "
                              "find the same address obtained via the "
                              "constructor; got %q")
                      (get t via-ctor))))))))

  (def-test "session-table-lookup-matches-same-peer-across-acquisition-paths"
    :timeout 15

    (let [server (dtls/listen "127.0.0.1" 0 {:cert (certs :cert)
                                             :key (certs :key)})
          [_ port] (dtls/localname server)
          recv-addrs @[]]

      (defer (:close server)

        (ev/go (fn []
                 (try
                   (do
                     (def buf (buffer/new 1024))
                     (def addr (dtls/recv-from server 1024 buf))
                     (when addr
                       (array/push recv-addrs addr)
                       (dtls/send-to server addr
                                     (string "echo:" (string buf)))))
                   ([_] nil))))

        (ev/sleep 0.2)

        (let [client (dtls/connect "127.0.0.1" port {:verify false})]
          (defer (:close client true)
            (dtls/write client "Ping")
            (def reply (dtls/read client 1024))
            (assert reply "setup: client should receive the echo reply")

            # The session was created from the recv-from kernel-filled
            # peer address. A constructed address for the same peer
            # must find it through the session-table path -
            # session_bucket's dtls_address_hash_fn (src/jdtls/session.c:19)
            # and dtls_server_get_session's dtls_address_equal
            # (src/jdtls/session.c:111).
            (def via-ctor (dtls/address "127.0.0.1"
                                        (dtls/address-port
                                          (:localname client))))

            # Under the defect on a padding-live platform this raises
            # "no session for peer address" (src/jdtls/server.c:793) -
            # the session-table miss is the predicted symptom on the
            # equal+hash_fn path.
            (dtls/send-to server via-ctor "via-ctor")

            (def got (dtls/read client 1024))
            (assert got "send-to with the constructed address must reach the session")
            (assert (= "via-ctor" (string got))
                    (string/format
                      (string "the session created for the recv-from peer "
                              "must be found by dtls/send-to with a "
                              "constructed address for the same socket "
                              "(dtls_address_equal + dtls_address_hash_fn, "
                              "src/jdtls/session.c:19,:111); got %q")
                      (string got)))))))))

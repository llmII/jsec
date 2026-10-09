# unlink of arbitrary paths in tls/listen :unix regression test
# Ticket c88a2496c0d89e73b8b2ec4090393231384f8778
#
# "unlink() of arbitrary paths in tls/listen :unix"
#
# cfun_listen's unix-socket path (src/jtls/api/server.c:425-460 in this
# tree) unconditionally removes whatever exists at the socket path before
# bind: the comment "Remove existing socket file (if not abstract)" at
# src/jtls/api/server.c:446 guards only the abstract-namespace case
# (:447), and the unlink at :448 deletes ANY filesystem object the
# process has permission to remove - a regular file, a symlink, a
# directory entry - before bind() runs at :456-460 and puts a socket at
# the same path. Janet's net/listen never unlinks: core/net.c:651-662
# only sets SO_REUSEADDR/SO_REUSEPORT in serverify_socket, so bind fails
# with EADDRINUSE and the pre-existing file is left untouched.
#
# The predicted symptom, verbatim (forge ticket):
#
# : (tls/listen :unix path) deletes whatever exists at path. Janet's
# : net/listen fails EADDRINUSE instead.
#
# This test demonstrates:
#   (a) given a pre-existing regular file at the path,
#       (tls/listen :unix path) must FAIL - the way net/listen fails
#       EADDRINUSE - instead of silently succeeding; under the defect the
#       call returns a listener,
#   (b) the pre-existing regular file must be left untouched; under the
#       defect the unconditional unlink at src/jtls/api/server.c:448
#       deletes it and bind() replaces it with a socket inode, so the
#       caller's data at that path is destroyed.
#
# Proof contract: under the defect the test fails with exactly the
# predicted symptom (tls/listen :unix silently succeeds and the
# pre-existing file is deleted/replaced); under fixed code the whole test
# passes and becomes the regression guard after the fix lands.

(use assay)
(import jsec/tls :as tls)
(import ../helpers :prefix "")

(def- file-content
  "PRECIOUS DATA - a tls/listen :unix typo must not destroy this")

(defn- make-preexisting-file
  ``Create a regular file with known content at a unique path.``
  []
  (def path (make-socket-path))
  (spit path file-content)
  path)

(defn- cleanup-file
  [path]
  (when path
    (try (os/rm path) ([_] nil))))

(defn- describe-path
  ``Human-readable state of path after a tls/listen :unix attempt.``
  [path]
  (def st (os/stat path))
  (cond
    (nil? st) "was deleted"
    (= :file (st :mode))
    (if (= file-content (try (slurp path) ([_] nil)))
      "is still the original regular file"
      "is still a regular file but its content changed")
    (string "is now a " (string (st :mode)) ", not the original regular file")))

(def-suite :name "Unix Listen Unlink Regression"
  :description "Ticket c88a2496c0: tls/listen :unix must refuse a pre-existing regular file, not unlink it"

  (def-test "unix listen on a pre-existing regular file must fail"
    :timeout 10

    (def path (make-preexisting-file))
    (defer (cleanup-file path)
      (var outcome :none)
      (try
        (do
          (def srv (tls/listen :unix path))
          (set outcome [:returned-listener srv])
          (try (:close srv) ([_] nil)))
        ([e] (set outcome [:raised (string e)])))
      (assert (= :raised (first outcome))
              (string/format
                (string "tls/listen :unix must fail when the path is "
                        "occupied by a regular file (net/listen refuses "
                        "with EADDRINUSE and never unlinks: Janet "
                        "core/net.c:651-662); got %q - the pre-existing "
                        "file at %s %s (unlink at "
                        "src/jtls/api/server.c:448)")
                outcome path (describe-path path)))))

  (def-test "unix listen must leave a pre-existing regular file untouched"
    :timeout 10

    (def path (make-preexisting-file))
    (defer (cleanup-file path)
      (try
        (do
          (def srv (tls/listen :unix path))
          (try (:close srv) ([_] nil)))
        ([_] nil))
      (def st (os/stat path))
      (assert (and st (= :file (st :mode)))
              (string/format
                (string "the pre-existing regular file at %s must "
                        "survive a tls/listen :unix attempt as a "
                        "regular file (Janet net/listen leaves it "
                        "untouched and fails EADDRINUSE); it %s "
                        "(unlink at src/jtls/api/server.c:448)")
                path (describe-path path)))
      (assert (= file-content (slurp path))
              (string/format
                (string "the pre-existing regular file at %s must keep "
                        "its original content (Janet net/listen leaves "
                        "it untouched); the unlink at "
                        "src/jtls/api/server.c:448 destroys it")
                path)))))

###
### JSEC Test Runner (janet-assay version)
###
### Run tests for the jsec library using the janet-assay testing framework.
###
### Usage:
###   janet test/runner.janet [OPTIONS]
###
### See `janet test/runner.janet --help` for full option list.
###

(import assay/worker)

# Ensure assay subprocess workers (both suite workers and nested combo/participant
# subprocess workers) are waited on via os/proc-wait during :shutdown/:close so
# Janet's proc GC does not send SIGKILL while a child worker is still running
# its exit/atexit handlers (e.g. LeakSanitizer heap scanning).
(def- reap-hook-code
  ```
  (let [wm (require "assay/worker")
        se (get wm 'spawn)
        orig-spawn (se :value)]
    (unless (get wm :jsec-reap-installed)
      (put wm :jsec-reap-installed true)
      (put se :value
           (fn [worker-type & args]
             (def h (orig-spawn worker-type ;args))
             (when (= worker-type :subprocess)
               (def orig-shutdown (h :shutdown))
               (def orig-close (h :close))
               (defn reap [self]
                 (when-let [proc (self :_process)]
                   (put self :_process nil)
                   (try
                     (ev/with-deadline 10 (os/proc-wait proc))
                     ([_]
                       (try (os/proc-kill proc true) ([_] nil))))))
               (put h :shutdown
                    (fn [self &opt timeout]
                      (def r (orig-shutdown self timeout))
                      (orig-close self)
                      (reap self)
                      r))
               (put h :close
                    (fn [self]
                      (orig-close self)
                      (reap self))))
             h)))
      nil)
  ```)

(eval-string reap-hook-code)
(let [wm (require "assay/worker")
      se (get wm 'spawn)
      reap-spawn (se :value)]
  (put se :value
       (fn [worker-type & args]
         (def h (reap-spawn worker-type ;args))
         (when (= worker-type :subprocess)
           (try (:exec h "eval-string" [reap-hook-code]) ([_] nil)))
         h)))

(import assay)

# Use def-runner macro from janet-assay
# When using explicit category paths (struct format), paths are prefixed with
# base-dir (runner location) NOT suites-dir. So we use full relative paths.
(assay/def-runner
  :name "JSEC Test Runner"
  :env-prefix "JSEC"
  :categories {:unit "../suites/unit"
               :coverage "../suites/coverage"
               :regression "../suites/regression"
               :integration "../suites/integration"
               :performance "../suites/performance"})

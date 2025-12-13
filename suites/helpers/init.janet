# JSEC Test Helpers
#
# Re-exports all helper modules for test suites.
# Usage: (import ../helpers :prefix "")

(import ./certs :prefix "" :export true)
(import ./matrix-config :prefix "" :export true)
(import ./sockets :prefix "" :export true)

# Additional assertion helpers that janet-assay doesn't provide

(defmacro assert-error
  ``Assert that the given form throws an error.
   Fails if form completes without error.``
  [form &opt msg]
  (with-syms [err-caught result]
    ~(do
       (var ,err-caught false)
       (try
         (do ,form)
         ([_] (set ,err-caught true)))
       (if ,err-caught
         true
         (error (or ,msg (string "Expected error from: " ',form)))))))

(defmacro assert-no-error
  ``Assert that the given form does NOT throw an error.
   Fails if form throws.``
  [form &opt msg]
  ~(try
     (do ,form true)
     ([err]
       (error (or ,msg (string "Unexpected error: " err " from: " ',form))))))

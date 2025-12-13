# Session Resumption Example
# Demonstrates saving and restoring TLS sessions for faster handshakes.

(import jsec/tls :as jtls)

(defn main [& args]
  (let [host "example.com"
        port "443"]

    # 1. First Connection (Full Handshake)
    (print "--- Connection 1 (Full Handshake) ---")
    (let [s1 (jtls/connect host port)]
      (print "Connected!")
      (print "Resumed? " (jtls/session-reused? s1))

      # Save the session
      (let [session-data (jtls/get-session s1)]
        (print "Session data size: " (length session-data) " bytes")
        (:close s1)

        # 2. Second Connection (Resumed)
        (print "\n--- Connection 2 (Resumed) ---")
        # Pass the session data in options
        (let [s2 (jtls/connect host port {:session session-data})]
          (print "Connected!")
          (print "Resumed? " (jtls/session-reused? s2))

          (if (jtls/session-reused? s2)
            (print "SUCCESS: Session was resumed!")
            (print "NOTE: Session was NOT resumed (server might not support it or rejected it)."))

          (:close s2))))))

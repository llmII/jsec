# Socket helpers for jsec tests
#
# Helpers for creating and managing test sockets.

(defn make-socket-path
  ``Generate a unique socket path for unix socket tests.
   Uses cryptographically random bytes for uniqueness.``
  []
  (let [rand-bytes (os/cryptorand 8)
        rand-hex (string/join (map |(string/format "%02x" $) rand-bytes) "")]
    (string "/tmp/jsec-test-" rand-hex ".sock")))

(defn cleanup-socket
  ``Remove socket file if it exists.``
  [path]
  (when path
    (try (os/rm path) ([_] nil))))

(defn make-server
  ``Create a server listener for the given socket type.
   
   For TCP, creates listener on 127.0.0.1 with random port.
   For Unix, creates listener with unique socket path.
   
   Returns [server socket-path-or-nil]``
  [socket-type &opt host port]
  (default host "127.0.0.1")
  (default port "0")
  (case socket-type
    :tcp [(net/listen host port) nil]
    :unix (let [socket-path (make-socket-path)]
            # Remove any stale socket file
            (cleanup-socket socket-path)
            [(net/listen :unix socket-path) socket-path])
    (error (string "Unknown socket type: " socket-type))))

(defn get-server-addr
  ``Get the address to connect to for this server.``
  [server socket-type &opt socket-path]
  (case socket-type
    :tcp (let [[host port] (net/localname server)]
           {:host host :port (string port)})
    :unix {:path socket-path}
    (error (string "Unknown socket type: " socket-type))))

(defn make-client-conn
  ``Create a raw client connection to the server.``
  [socket-type addr]
  (case socket-type
    :tcp (net/connect (addr :host) (addr :port))
    :unix (net/connect :unix (addr :path))
    (error (string "Unknown socket type: " socket-type))))

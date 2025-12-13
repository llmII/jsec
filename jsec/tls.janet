###
### jsec/tls - Unified TLS/DTLS API for Janet
###
### This module provides a unified API for both TLS (TCP/Unix) and DTLS (UDP).
### - Use :datagram option for DTLS connections
### - Without :datagram, defaults to TLS over TCP/Unix
###
### This module ONLY exports: connect, listen, wrap, server, upgrade, new-context
### For stream-specific functions, import jsec/tls-stream or jsec/dtls-stream
###

# Import utils first to register shared types (SSLContext)
(import jsec/utils)
(import jsec/tls-stream)
(import jsec/dtls-stream)

(defn- opts-want-datagram?
  "Check if any of the provided args want datagram mode"
  [& args]
  (some |(and $ (or (table? $) (struct? $)) ($ :datagram)) args))

(defn- strip-datagram-opt
  "Clone opts and remove :datagram key"
  [opts]
  (-> (if (struct? opts) (table ;(kvs opts)) opts)
      table/clone
      (put :datagram nil)))

(defn new-context
  ``
  Create a reusable TLS or DTLS context.
  
  For TLS: (new-context &opt opts)
  For DTLS: (new-context {:datagram true ...})
  
  Options:
    :cert - Certificate (PEM string or file path)
    :key - Private key (PEM string or file path)
    :verify - Verify peer certificates (default: true for client, false for server)
    :ca - CA certificate path
    :trusted-cert - Trust specific certificate (for self-signed)
    :ciphers - Cipher suite string
    :security - Security options table
    :datagram - If true, creates DTLS context instead of TLS
  
  If :cert and :key are provided, creates a server-capable context.
  Otherwise creates a client-only context.
  
  The returned context can be passed to connect/listen/wrap via :context option.
  ``
  [&opt opts]
  (default opts {})
  (if (opts :datagram)
    (dtls-stream/new-context (strip-datagram-opt opts))
    (tls-stream/new-context opts)))

(defn connect
  ``
  Create a TLS or DTLS client connection.
  
  For TLS (TCP): (connect host port &opt opts)
  For TLS (Unix): (connect :unix path &opt opts)
  For DTLS (UDP): (connect host port {:datagram true ...})
  
  Unix socket options may include :hostname for SNI.
  
  Returns a stream/connection that supports standard Janet stream methods.
  ``
  [host port &opt opts]
  (default opts {})
  (if (opts :datagram)
    (dtls-stream/connect host port (strip-datagram-opt opts))
    (tls-stream/connect host port opts)))

(defn listen
  ``
  Create a TLS or DTLS server listener.
  
  For TLS (TCP): (listen host port &opt opts)
  For TLS (Unix): (listen :unix path &opt opts)
  For DTLS (UDP): (listen host port {:datagram true ...})
  
  Returns a listener that supports :accept for TLS, or recv-from/send-to for DTLS.
  ``
  [host port &opt opts]
  (default opts {})
  (if (opts :datagram)
    (dtls-stream/listen host port (strip-datagram-opt opts))
    (tls-stream/listen host port opts)))

(defn accept
  ``
  Accept a TLS connection from a listener.
  
  (accept listener opts &opt timeout)
  
  Accepts a TCP connection and wraps it with TLS.
  Options must include :cert and :key for server-side TLS.
  Options may include :handshake-timing, :buffer-size, :tcp-nodelay.
  
  Returns a TLSStream ready for I/O.
  
  Note: For DTLS (UDP), use recv-from/send-to instead.
  ``
  [listener opts &opt timeout]
  (tls-stream/accept listener opts timeout))

(defn wrap
  ``
  Wrap an existing socket with TLS or DTLS.
  
  Signatures:
    (wrap stream opts)                - Server mode (opts has :cert and :key)
    (wrap stream hostname opts)       - Client mode (hostname for SNI/verification)
    (wrap stream context)             - Server mode with pre-created context
    (wrap stream context hostname)    - Client mode with pre-created context
    (wrap stream context hostname opts) - Client mode with context and options
  
  For TLS (TCP/Unix sockets): wraps with TLS
  For DTLS (UDP sockets): wraps with DTLS (auto-detected from socket type)
  
  Note: For DTLS, pass :datagram true in opts to force DTLS mode, or the socket
  type will be auto-detected if possible.
  ``
  [stream &opt arg1 arg2 arg3]
  (if (opts-want-datagram? arg1 arg2 arg3)
    # DTLS upgrade - find and strip :datagram from opts
    (let [opts (or arg1 arg2 arg3 {})]
      (dtls-stream/upgrade stream (strip-datagram-opt opts)))
    # TLS - pass through
    (cond
      (nil? arg1) (tls-stream/wrap stream)
      (nil? arg2) (tls-stream/wrap stream arg1)
      (nil? arg3) (tls-stream/wrap stream arg1 arg2)
      (tls-stream/wrap stream arg1 arg2 arg3))))

(defn upgrade
  ``
  Upgrade an existing plaintext connection to TLS (STARTTLS pattern).
  
  This is an alias for wrap, used for STARTTLS-style upgrades.
  Signatures same as wrap:
    (upgrade stream opts)                - Server mode
    (upgrade stream hostname opts)       - Client mode
  
  This is for TLS only (TCP/Unix). DTLS doesn't support STARTTLS.
  ``
  [stream &opt arg1 arg2 arg3]
  (cond
    (nil? arg1) (tls-stream/upgrade stream)
    (nil? arg2) (tls-stream/upgrade stream arg1)
    (nil? arg3) (tls-stream/upgrade stream arg1 arg2)
    (tls-stream/upgrade stream arg1 arg2 arg3)))

(defn server
  ``
  Start a TLS server. Returns the listener stream immediately.
  If handler is provided, spawns a fiber to accept connections.
  
  This follows the net/server API pattern:
  - (server host port) - just creates listener, returns it
  - (server host port handler opts) - creates listener, spawns accept loop
  - (server :unix path handler opts) - unix socket server
  
  Options must include :cert and :key when handler is provided.
  Options may include :handshake-timing, :buffer-size, :tcp-nodelay.
  Note: This is for TLS (TCP/Unix) only. DTLS servers use a different paradigm.
  ``
  [host port &opt handler opts]
  # Pass opts to listen for backlog and other socket options
  (let [s (tls-stream/listen host port opts)]
    (when handler
      (assert (or (table? opts) (struct? opts))
              "server with handler requires {:cert ... :key ...} options")
      (assert (opts :cert) "server requires :cert option")
      (assert (opts :key) "server requires :key option")
      # Pass opts (not just ctx) to accept-loop so it gets handshake-timing, buffer-size, tcp-nodelay
      (ev/go (fn [] (tls-stream/accept-loop s opts handler))))
    s))

# =============================================================================
# DTLS Address Utilities (re-exported for convenience)
# =============================================================================

(def address-host
  ``
  Get the host string from a DTLS peer address.
  Peer addresses are returned by :recv-from on DTLS servers.
  ``
  dtls-stream/address-host)

(def address-port
  ``
  Get the port number from a DTLS peer address.
  Peer addresses are returned by :recv-from on DTLS servers.
  ``
  dtls-stream/address-port)

(def address?
  ``
  Check if a value is a DTLS address.
  ``
  dtls-stream/address?)

(def address
  ``
  Create a DTLS address from host and port.
  ``
  dtls-stream/address)

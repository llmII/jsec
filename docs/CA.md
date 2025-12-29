

# Overview

The `jsec/ca` module provides a complete Certificate Authority (CA) implementation
for managing X.509 certificates. It supports:

-   Root CA generation
-   Intermediate CA generation
-   Certificate issuance (from CSRs or direct generation)
-   Certificate revocation and CRL generation
-   OCSP response creation (mechanics only - you provide HTTP server)

For API reference, see [API.org - jsec/ca section](API.md).


## Design Philosophy

-   **Simple API for common cases** - `:issue` generates key + cert in one call
-   **Powerful API for complex cases** - `:sign-csr` gives full control
-   **Methods AND functions** - Every operation works both ways
-   **Stateless by default** - Tracking is opt-in for memory efficiency
-   **Crypto only** - We handle certificates, you handle networking


# Quick Start

    (import jsec/ca)
    
    # Generate a root CA
    (def root-ca (ca/generate {:common-name "My Root CA"
                               :days-valid 3650}))
    
    # Issue a server certificate
    (def server (ca/issue root-ca {:common-name "server.example.com"
                                   :san ["DNS:server.example.com"
                                         "DNS:localhost"
                                         "IP:127.0.0.1"]
                                   :extended-key-usage "serverAuth"}))
    
    # Use the certificate
    (print (server :cert))  # PEM certificate
    (print (server :key))   # PEM private key
    
    # Get CA cert for trust stores
    (print (:get-cert root-ca))


# OCSP Responder Example

You implement the HTTP server; the CA module provides the OCSP mechanics:

    (import jsec/ca)
    
    # Your CA
    (def ca (ca/create (slurp "ca.crt") (slurp "ca.key")))
    
    # Your certificate status lookup (implement based on your storage)
    (defn lookup-status [serial]
      (if (revoked? serial)
        :revoked
        :good))
    
    # OCSP handler for your HTTP server
    (defn handle-ocsp [request]
      (def parsed (ca/parse-ocsp-request (request :body)))
      (def status (lookup-status (parsed :serial)))
      (def response (:create-ocsp-response ca parsed status))
    
      {:status 200
       :headers {"Content-Type" "application/ocsp-response"}
       :body response})


# Key Types

Supported key types for CA and certificate generation:

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />

<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left">Keyword</th>
<th scope="col" class="org-left">Algorithm</th>
<th scope="col" class="org-left">Size/Curve</th>
<th scope="col" class="org-left">Notes</th>
</tr>
</thead>
<tbody>
<tr>
<td class="org-left"><code>:ec-p256</code></td>
<td class="org-left">EC</td>
<td class="org-left">P-256</td>
<td class="org-left">Default, fast</td>
</tr>

<tr>
<td class="org-left"><code>:ec</code></td>
<td class="org-left">EC</td>
<td class="org-left">P-256</td>
<td class="org-left">Alias</td>
</tr>

<tr>
<td class="org-left"><code>:ec-p384</code></td>
<td class="org-left">EC</td>
<td class="org-left">P-384</td>
<td class="org-left">Higher security</td>
</tr>

<tr>
<td class="org-left"><code>:ec-p521</code></td>
<td class="org-left">EC</td>
<td class="org-left">P-521</td>
<td class="org-left">Maximum security</td>
</tr>

<tr>
<td class="org-left"><code>:rsa-2048</code></td>
<td class="org-left">RSA</td>
<td class="org-left">2048 bits</td>
<td class="org-left">Compatibility</td>
</tr>

<tr>
<td class="org-left"><code>:rsa</code></td>
<td class="org-left">RSA</td>
<td class="org-left">2048 bits</td>
<td class="org-left">Alias</td>
</tr>

<tr>
<td class="org-left"><code>:rsa-4096</code></td>
<td class="org-left">RSA</td>
<td class="org-left">4096 bits</td>
<td class="org-left">Higher security</td>
</tr>
</tbody>
</table>

EC keys are recommended for new deployments. RSA keys are available for
compatibility with legacy systems.


# Serial Number Persistence

For production CAs, serial numbers must be persisted to avoid reuse:

    (import jsec/ca)
    
    # Save before shutdown
    (defn save-ca-state [ca path]
      (spit path (string (:get-serial ca))))
    
    # Restore on startup
    (defn load-ca [cert-path key-path serial-path]
      (def cert (slurp cert-path))
      (def key (slurp key-path))
      (def serial (scan-number (slurp serial-path)))
      (ca/create cert key {:serial serial}))


# Certificate Tracking

By default, CAs don't track issued certificates (memory efficient). Enable
tracking when you need to:

-   List all issued certificates
-   Implement revocation by certificate (not just serial)
-   Audit certificate issuance

    # Enable tracking
    (def ca (ca/generate {:track-issued true}))
    
    # Issue some certificates
    (:issue ca {:common-name "cert1"})
    (:issue ca {:common-name "cert2"})
    
    # Get all issued certs
    (def issued (:get-issued ca))
    (print (length issued))  # => 2


# Subject Alternative Names (SAN)

The `:san` option accepts an array of SAN entries:

    :san ["DNS:example.com"
          "DNS:www.example.com"
          "DNS:*.example.com"
          "IP:192.168.1.1"
          "IP:10.0.0.1"
          "email:admin@example.com"]

Prefix types:

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left">Prefix</th>
<th scope="col" class="org-left">Description</th>
</tr>
</thead>
<tbody>
<tr>
<td class="org-left"><code>DNS:</code></td>
<td class="org-left">DNS name (most common)</td>
</tr>

<tr>
<td class="org-left"><code>IP:</code></td>
<td class="org-left">IP address</td>
</tr>

<tr>
<td class="org-left"><code>email:</code></td>
<td class="org-left">Email address</td>
</tr>

<tr>
<td class="org-left"><code>URI:</code></td>
<td class="org-left">Uniform Resource ID</td>
</tr>
</tbody>
</table>


# PKI Hierarchy Example

    (import jsec/ca)
    
    # Root CA (offline, long-lived)
    (def root (ca/generate {:common-name "Root CA"
                            :days-valid 7300     # 20 years
                            :organization "My Org"
                            :country "US"}))
    
    # Intermediate CA (online, medium-lived)
    (def intermediate (ca/generate-intermediate root
                        {:common-name "Intermediate CA"
                         :days-valid 1825        # 5 years
                         :path-length 0}))       # No sub-CAs
    
    # Issue end-entity certificates from intermediate
    (def server (:issue intermediate
                  {:common-name "server.example.com"
                   :san ["DNS:server.example.com"]
                   :extended-key-usage "serverAuth"
                   :days-valid 365}))
    
    # Chain for server: server cert + intermediate cert
    (def chain (string (server :cert) (:get-cert intermediate)))


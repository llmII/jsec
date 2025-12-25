
# Table of Contents

1.  [Overview](#orge8524d9)
    1.  [Design Philosophy](#org2ff6dac)
2.  [Quick Start](#org913834a)
3.  [API Reference](#org120d1c0)
    1.  [Constructors](#orgad4246a)
    2.  [Certificate Issuance](#org762becf)
    3.  [Accessor Methods](#orgbc8f8ad)
    4.  [Revocation and CRL](#org3469f8e)
    5.  [OCSP Support](#org6cf7491)
    6.  [OCSP Responder Example](#org7313835)
4.  [Key Types](#org4cc258e)
5.  [Serial Number Persistence](#orga96c420)
6.  [Certificate Tracking](#orgc5206c0)
7.  [Subject Alternative Names (SAN)](#org46c291b)
8.  [PKI Hierarchy Example](#orgdfcd2db)



<a id="orge8524d9"></a>

# Overview

The `jsec/ca` module provides a complete Certificate Authority (CA) implementation
for managing X.509 certificates. It supports:

-   Root CA generation
-   Intermediate CA generation
-   Certificate issuance (from CSRs or direct generation)
-   Certificate revocation and CRL generation
-   OCSP response creation (mechanics only - you provide HTTP server)


<a id="org2ff6dac"></a>

## Design Philosophy

-   **Simple API for common cases** - `:issue` generates key + cert in one call
-   **Powerful API for complex cases** - `:sign-csr` gives full control
-   **Methods AND functions** - Every operation works both ways
-   **Stateless by default** - Tracking is opt-in for memory efficiency
-   **Crypto only** - We handle certificates, you handle networking


<a id="org913834a"></a>

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


<a id="org120d1c0"></a>

# API Reference


<a id="orgad4246a"></a>

## Constructors


### `ca/generate`

Generate a new self-signed root CA.

    (ca/generate &opt opts)

Options:

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left">Option</th>
<th scope="col" class="org-left">Default</th>
<th scope="col" class="org-left">Description</th>
</tr>
</thead>
<tbody>
<tr>
<td class="org-left"><code>:common-name</code></td>
<td class="org-left">"Root CA"</td>
<td class="org-left">CA common name</td>
</tr>

<tr>
<td class="org-left"><code>:days-valid</code></td>
<td class="org-left">3650</td>
<td class="org-left">Validity period in days</td>
</tr>

<tr>
<td class="org-left"><code>:key-type</code></td>
<td class="org-left"><code>:ec-p256</code></td>
<td class="org-left">Key type (see Key Types below)</td>
</tr>

<tr>
<td class="org-left"><code>:serial</code></td>
<td class="org-left">1</td>
<td class="org-left">Starting serial number for issued certs</td>
</tr>

<tr>
<td class="org-left"><code>:track-issued</code></td>
<td class="org-left">false</td>
<td class="org-left">Track issued certificates in memory</td>
</tr>

<tr>
<td class="org-left"><code>:organization</code></td>
<td class="org-left">nil</td>
<td class="org-left">Organization name</td>
</tr>

<tr>
<td class="org-left"><code>:country</code></td>
<td class="org-left">nil</td>
<td class="org-left">Two-letter country code</td>
</tr>
</tbody>
</table>


### `ca/generate-intermediate`

Generate an intermediate CA signed by a parent CA.

    (ca/generate-intermediate parent-ca &opt opts)

Options are the same as `ca/generate` plus:

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-right" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left">Option</th>
<th scope="col" class="org-right">Default</th>
<th scope="col" class="org-left">Description</th>
</tr>
</thead>
<tbody>
<tr>
<td class="org-left"><code>:path-length</code></td>
<td class="org-right">0</td>
<td class="org-left">Maximum sub-CAs allowed</td>
</tr>

<tr>
<td class="org-left"><code>:common-name</code></td>
<td class="org-right">"Intermediate CA"</td>
<td class="org-left">(different default)</td>
</tr>

<tr>
<td class="org-left"><code>:days-valid</code></td>
<td class="org-right">1825</td>
<td class="org-left">(different default - 5 years)</td>
</tr>
</tbody>
</table>


### `ca/create`

Create a CA from existing certificate and private key.

    (ca/create cert-pem key-pem &opt opts)

This is useful for:

-   Loading a CA from files
-   Restoring CA state from persistence

Options:

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left">Option</th>
<th scope="col" class="org-left">Default</th>
<th scope="col" class="org-left">Description</th>
</tr>
</thead>
<tbody>
<tr>
<td class="org-left"><code>:serial</code></td>
<td class="org-left">1</td>
<td class="org-left">Current serial number (restore this)</td>
</tr>

<tr>
<td class="org-left"><code>:track-issued</code></td>
<td class="org-left">false</td>
<td class="org-left">Track issued certificates</td>
</tr>
</tbody>
</table>


<a id="org762becf"></a>

## Certificate Issuance


### `:issue` / `ca/issue`

Generate a new certificate (key + cert in one step). This is the recommended
method for most use cases.

    (:issue ca &opt opts)
    (ca/issue ca &opt opts)

Options:

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left">Option</th>
<th scope="col" class="org-left">Required</th>
<th scope="col" class="org-left">Description</th>
</tr>
</thead>
<tbody>
<tr>
<td class="org-left"><code>:common-name</code></td>
<td class="org-left">YES</td>
<td class="org-left">Certificate common name</td>
</tr>

<tr>
<td class="org-left"><code>:san</code></td>
<td class="org-left">no</td>
<td class="org-left">Subject Alternative Names (array)</td>
</tr>

<tr>
<td class="org-left"><code>:days-valid</code></td>
<td class="org-left">no</td>
<td class="org-left">Validity period (default: 365)</td>
</tr>

<tr>
<td class="org-left"><code>:key-type</code></td>
<td class="org-left">no</td>
<td class="org-left">Key type (default: <code>:ec-p256</code>)</td>
</tr>

<tr>
<td class="org-left"><code>:key-usage</code></td>
<td class="org-left">no</td>
<td class="org-left">Override key usage extension</td>
</tr>

<tr>
<td class="org-left"><code>:extended-key-usage</code></td>
<td class="org-left">no</td>
<td class="org-left">e.g., "serverAuth", "clientAuth"</td>
</tr>

<tr>
<td class="org-left"><code>:organization</code></td>
<td class="org-left">no</td>
<td class="org-left">Organization name</td>
</tr>

<tr>
<td class="org-left"><code>:country</code></td>
<td class="org-left">no</td>
<td class="org-left">Country code</td>
</tr>
</tbody>
</table>

Returns: `{:cert <pem> :key <pem>}`


### `:sign-csr` / `ca/sign`

Sign a Certificate Signing Request (CSR). Use this when you need full control
over the certificate request process.

    (:sign-csr ca csr-pem &opt opts)
    (ca/sign ca csr-pem &opt opts)

Options:

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left">Option</th>
<th scope="col" class="org-left">Default</th>
<th scope="col" class="org-left">Description</th>
</tr>
</thead>
<tbody>
<tr>
<td class="org-left"><code>:days-valid</code></td>
<td class="org-left">365</td>
<td class="org-left">Validity period</td>
</tr>

<tr>
<td class="org-left"><code>:serial</code></td>
<td class="org-left">auto</td>
<td class="org-left">Override serial number</td>
</tr>

<tr>
<td class="org-left"><code>:copy-extensions</code></td>
<td class="org-left">false</td>
<td class="org-left">Copy extensions from CSR</td>
</tr>

<tr>
<td class="org-left"><code>:key-usage</code></td>
<td class="org-left">digitalSignature,</td>
<td class="org-left">Key usage extension</td>
</tr>

<tr>
<td class="org-left">&#xa0;</td>
<td class="org-left">keyEncipherment</td>
<td class="org-left">&#xa0;</td>
</tr>

<tr>
<td class="org-left"><code>:extended-key-usage</code></td>
<td class="org-left">nil</td>
<td class="org-left">Extended key usage</td>
</tr>

<tr>
<td class="org-left"><code>:san</code></td>
<td class="org-left">nil</td>
<td class="org-left">Subject Alternative Names</td>
</tr>

<tr>
<td class="org-left"><code>:basic-constraints</code></td>
<td class="org-left">"CA:FALSE"</td>
<td class="org-left">Basic constraints extension</td>
</tr>
</tbody>
</table>

Returns: Certificate in PEM format.


<a id="orgbc8f8ad"></a>

## Accessor Methods


### `:get-cert` / `ca/get-cert`

Get the CA's certificate in PEM format.

    (:get-cert ca)
    (ca/get-cert ca)


### `:get-serial` / `ca/get-serial`

Get the CA's current serial number. Use for persistence.

    (:get-serial ca)
    (ca/get-serial ca)


### `:set-serial` / `ca/set-serial`

Set the CA's serial number. Use to restore from persistence.

    (:set-serial ca serial)
    (ca/set-serial ca serial)


### `:is-tracking` / `ca/is-tracking`

Check if the CA is tracking issued certificates.

    (:is-tracking ca)
    (ca/is-tracking ca)


### `:get-issued` / `ca/get-issued`

Get list of issued certificates (only if tracking enabled).

    (:get-issued ca)
    (ca/get-issued ca)

Returns: Array of PEM certificates, or nil if tracking disabled.


<a id="org3469f8e"></a>

## Revocation and CRL


### `:revoke` / `ca/revoke`

Revoke a certificate by serial number.

    (:revoke ca serial &opt reason)
    (ca/revoke ca serial &opt reason)

Revocation reasons:

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left">Keyword</th>
<th scope="col" class="org-left">Description</th>
</tr>
</thead>
<tbody>
<tr>
<td class="org-left"><code>:unspecified</code></td>
<td class="org-left">Default</td>
</tr>

<tr>
<td class="org-left"><code>:key-compromise</code></td>
<td class="org-left">Private key compromised</td>
</tr>

<tr>
<td class="org-left"><code>:ca-compromise</code></td>
<td class="org-left">CA key compromised</td>
</tr>

<tr>
<td class="org-left"><code>:affiliation-changed</code></td>
<td class="org-left">Subject affiliation changed</td>
</tr>

<tr>
<td class="org-left"><code>:superseded</code></td>
<td class="org-left">Replaced by new certificate</td>
</tr>

<tr>
<td class="org-left"><code>:cessation-of-operation</code></td>
<td class="org-left">No longer in use</td>
</tr>

<tr>
<td class="org-left"><code>:certificate-hold</code></td>
<td class="org-left">Temporarily suspended</td>
</tr>

<tr>
<td class="org-left"><code>:remove-from-crl</code></td>
<td class="org-left">Remove from CRL (unrevoke)</td>
</tr>

<tr>
<td class="org-left"><code>:privilege-withdrawn</code></td>
<td class="org-left">Privileges revoked</td>
</tr>

<tr>
<td class="org-left"><code>:aa-compromise</code></td>
<td class="org-left">AA key compromised</td>
</tr>
</tbody>
</table>


### `:generate-crl` / `ca/crl`

Generate a Certificate Revocation List.

    (:generate-crl ca &opt opts)
    (ca/crl ca &opt opts)

Options:

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left">Option</th>
<th scope="col" class="org-left">Default</th>
<th scope="col" class="org-left">Description</th>
</tr>
</thead>
<tbody>
<tr>
<td class="org-left"><code>:days-valid</code></td>
<td class="org-left">30</td>
<td class="org-left">CRL validity period</td>
</tr>

<tr>
<td class="org-left"><code>:revoked</code></td>
<td class="org-left">nil</td>
<td class="org-left">Additional revocations (array of tables)</td>
</tr>
</tbody>
</table>

Returns: CRL in PEM format.


### `:get-revoked` / `ca/get-revoked`

Get list of revoked certificate serials.

    (:get-revoked ca)
    (ca/get-revoked ca)

Returns: Array of `{:serial N :reason <kw>}` tables.


<a id="org6cf7491"></a>

## OCSP Support

The CA module provides OCSP **mechanics** only. You implement the HTTP server
yourself using Janet's networking or a web framework.


### `ca/parse-ocsp-request`

Parse an OCSP request (DER-encoded bytes).

    (ca/parse-ocsp-request request-bytes)
    (:parse-ocsp-request ca request-bytes)  ; method form also works

Returns:

    {:issuer-name-hash <buffer>
     :issuer-key-hash <buffer>
     :serial <number>
     :nonce <buffer|nil>}


### `:create-ocsp-response` / `ca/create-ocsp-response`

Create an OCSP response for a certificate status query.

    (:create-ocsp-response ca request-info status &opt opts)
    (ca/create-ocsp-response ca request-info status &opt opts)

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left">Argument</th>
<th scope="col" class="org-left">Description</th>
</tr>
</thead>
<tbody>
<tr>
<td class="org-left"><code>ca</code></td>
<td class="org-left">The CA that issued the certificate</td>
</tr>

<tr>
<td class="org-left"><code>request-info</code></td>
<td class="org-left">Parsed request from <code>ca/parse-ocsp-request</code></td>
</tr>

<tr>
<td class="org-left"><code>status</code></td>
<td class="org-left"><code>:good</code>, <code>:revoked</code>, or <code>:unknown</code></td>
</tr>
</tbody>
</table>

Options:

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left">Option</th>
<th scope="col" class="org-left">Description</th>
</tr>
</thead>
<tbody>
<tr>
<td class="org-left"><code>:revocation-time</code></td>
<td class="org-left">When revoked (required if status :revoked)</td>
</tr>

<tr>
<td class="org-left"><code>:revocation-reason</code></td>
<td class="org-left">Why revoked (see revocation reasons)</td>
</tr>

<tr>
<td class="org-left"><code>:this-update</code></td>
<td class="org-left">Response validity start (default: now)</td>
</tr>

<tr>
<td class="org-left"><code>:next-update</code></td>
<td class="org-left">Response validity end (default: +1 day)</td>
</tr>

<tr>
<td class="org-left"><code>:include-nonce</code></td>
<td class="org-left">Echo nonce from request (default: true)</td>
</tr>
</tbody>
</table>

Returns: DER-encoded OCSP response bytes.


<a id="org7313835"></a>

## OCSP Responder Example

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


<a id="org4cc258e"></a>

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


<a id="orga96c420"></a>

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


<a id="orgc5206c0"></a>

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


<a id="org46c291b"></a>

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


<a id="orgdfcd2db"></a>

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


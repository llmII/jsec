/*
 * jcrypto/module.c - Cryptographic functions module registration
 *
 * Author: llmII <dev@amlegion.org>
 * License: ISC
 */

#include "internal.h"

static const JanetReg cfuns[] = {
    {
        "digest", cfun_digest,
        "(jsec/crypto/digest alg data)\n\n"
        "Compute hash digest. Supported algorithms include :sha256, :sha384, :sha512, :sha1, :md5."
    },
    {
        "generate-key", cfun_generate_key,
        "(jsec/crypto/generate-key alg &opt bits)\n\n"
        "Generate private key. Returns PEM format.\n"
        "Supported algorithms:\n"
        "  :rsa - RSA key (optional bits param, default 2048)\n"
        "  :ed25519 - Ed25519 key (signing)\n"
        "  :x25519 - X25519 key (key exchange/ECDH)\n"
        "  :ec-p256 or :p256 - EC P-256 curve\n"
        "  :ec-p384 or :p384 - EC P-384 curve\n"
        "  :ec-p521 or :p521 - EC P-521 curve"
    },
    {
        "sign", cfun_sign,
        "(jsec/crypto/sign key data)\n\n"
        "Sign data with private key (PEM format)."
    },
    {
        "verify", cfun_verify,
        "(jsec/crypto/verify key data sig)\n\n"
        "Verify signature with key (PEM format). Returns boolean."
    },
    {
        "hmac", cfun_hmac,
        "(jsec/crypto/hmac alg key data)\n\n"
        "Compute HMAC. Algorithm examples: :sha256, :sha384, :sha512."
    },
    {
        "random-bytes", cfun_random_bytes,
        "(jsec/crypto/random-bytes n)\n\n"
        "Generate n cryptographically secure random bytes (1-65536)."
    },
    {
        "base64-encode", cfun_base64_encode,
        "(jsec/crypto/base64-encode data)\n\n"
        "Encode data as base64."
    },
    {
        "base64-decode", cfun_base64_decode,
        "(jsec/crypto/base64-decode data)\n\n"
        "Decode base64 data."
    },
    {
        "base64url-encode", cfun_base64url_encode,
        "(jsec/crypto/base64url-encode data)\n\n"
        "Encode data as URL-safe base64 (no padding). Used for JWT/ACME."
    },
    {
        "base64url-decode", cfun_base64url_decode,
        "(jsec/crypto/base64url-decode data)\n\n"
        "Decode URL-safe base64 data."
    },
    {
        "export-public-key", cfun_export_public_key,
        "(jsec/crypto/export-public-key private-key-pem)\n\n"
        "Extract public key from private key. Returns PEM format."
    },
    {
        "hkdf", cfun_hkdf,
        "(jsec/crypto/hkdf alg ikm salt info length)\n\n"
        "HMAC-based Key Derivation Function (RFC 5869).\n"
        "  alg - hash algorithm (:sha256, :sha384, etc.)\n"
        "  ikm - input keying material\n"
        "  salt - salt value (can be empty string)\n"
        "  info - context/application-specific info\n"
        "  length - desired output length in bytes"
    },
    {
        "pbkdf2", cfun_pbkdf2,
        "(jsec/crypto/pbkdf2 alg password salt iterations length)\n\n"
        "Password-Based Key Derivation Function 2 (RFC 2898).\n"
        "  alg - hash algorithm (:sha256, :sha384, etc.)\n"
        "  password - password bytes\n"
        "  salt - salt bytes\n"
        "  iterations - iteration count (higher = slower but more secure)\n"
        "  length - desired output length in bytes (1-1024)"
    },
    {
        "ecdh-derive", cfun_ecdh_derive,
        "(jsec/crypto/ecdh-derive private-key-pem peer-public-key-pem)\n\n"
        "Derive a shared secret using ECDH key agreement.\n"
        "Works with X25519, EC P-256, P-384, P-521 keys.\n"
        "Returns the raw shared secret bytes."
    },
    {
        "generate-csr", cfun_generate_csr,
        "(jsec/crypto/generate-csr private-key-pem options)\n\n"
        "Generate a Certificate Signing Request (CSR).\n"
        "Options table keys:\n"
        "  :common-name - CN field (required for most CAs)\n"
        "  :country - C field (2-letter code)\n"
        "  :state - ST field\n"
        "  :locality - L field\n"
        "  :organization - O field\n"
        "  :organizational-unit - OU field\n"
        "  :email - emailAddress field\n"
        "  :san - array of Subject Alt Names (e.g. [\"DNS:example.com\" \"IP:1.2.3.4\"])\n"
        "  :digest - signing digest (:sha256 default)\n"
        "Returns CSR in PEM format."
    },
    {
        "parse-csr", cfun_parse_csr,
        "(jsec/crypto/parse-csr csr-pem)\n\n"
        "Parse a CSR and return its contents as a table:\n"
        "  :subject - table of subject fields\n"
        "  :key-type - :rsa, :ec, :ed25519, or :unknown\n"
        "  :key-bits - key size in bits\n"
        "  :signature-valid - boolean"
    },
    /* CMS/PKCS#7 functions for SCEP support */
    {
        "cms-sign", cfun_cms_sign,
        "(jsec/crypto/cms-sign cert-pem key-pem data &opt opts)\n\n"
        "Create CMS signed data structure.\n"
        "Options:\n"
        "  :detached - if true, creates detached signature (content not included)\n"
        "Returns DER-encoded CMS structure."
    },
    {
        "cms-verify", cfun_cms_verify,
        "(jsec/crypto/cms-verify cms-der &opt trusted-certs-pem detached-data)\n\n"
        "Verify CMS signed data.\n"
        "Returns table with:\n"
        "  :valid - boolean indicating signature validity\n"
        "  :content - decrypted content (if not detached)\n"
        "  :signers - array of signer certificates in PEM format"
    },
    {
        "cms-encrypt", cfun_cms_encrypt,
        "(jsec/crypto/cms-encrypt data recipient-certs &opt opts)\n\n"
        "Create CMS enveloped (encrypted) data.\n"
        "recipient-certs can be a single PEM string or array of PEM strings.\n"
        "Options:\n"
        "  :cipher - encryption cipher (:aes-128-cbc, :aes-192-cbc, :aes-256-cbc, :3des)\n"
        "            Default is :aes-256-cbc\n"
        "Returns DER-encoded CMS structure."
    },
    {
        "cms-decrypt", cfun_cms_decrypt,
        "(jsec/crypto/cms-decrypt cms-der cert-pem key-pem)\n\n"
        "Decrypt CMS enveloped data using recipient's certificate and private key.\n"
        "Returns decrypted content."
    },
    {
        "cms-certs-only", cfun_cms_certs_only,
        "(jsec/crypto/cms-certs-only certs)\n\n"
        "Create degenerate signed-data structure containing only certificates.\n"
        "Used in SCEP for certificate distribution.\n"
        "certs can be a PEM string (possibly containing multiple certs) or array of PEM strings.\n"
        "Returns DER-encoded CMS structure."
    },
    {
        "cms-get-certs", cfun_cms_get_certs,
        "(jsec/crypto/cms-get-certs cms-der)\n\n"
        "Extract certificates from a CMS structure.\n"
        "Returns array of certificates in PEM format."
    },
    {
        "generate-challenge", cfun_generate_challenge,
        "(jsec/crypto/generate-challenge &opt length)\n\n"
        "Generate a random challenge/nonce for SCEP or similar protocols.\n"
        "length defaults to 16 bytes (128 bits), range 8-64.\n"
        "Returns raw bytes."
    },
    /* Symmetric encryption */
    {
        "encrypt", cfun_encrypt,
        "(jsec/crypto/encrypt algo key nonce plaintext &opt aad)\n\n"
        "Encrypt data using an AEAD or block cipher.\n\n"
        "Supported algorithms:\n"
        "  :aes-128-gcm - AES-128 in GCM mode (16-byte key, 12-byte nonce)\n"
        "  :aes-256-gcm - AES-256 in GCM mode (32-byte key, 12-byte nonce)\n"
        "  :chacha20-poly1305 - ChaCha20-Poly1305 (32-byte key, 12-byte nonce)\n"
        "  :aes-128-cbc - AES-128 in CBC mode (16-byte key, 16-byte IV)\n"
        "  :aes-256-cbc - AES-256 in CBC mode (32-byte key, 16-byte IV)\n\n"
        "For AEAD ciphers, optional aad is authenticated but not encrypted.\n"
        "Returns struct {:ciphertext <buffer> :tag <buffer>}\n"
        "IMPORTANT: Never reuse a nonce with the same key!"
    },
    {
        "decrypt", cfun_decrypt,
        "(jsec/crypto/decrypt algo key nonce ciphertext tag &opt aad)\n\n"
        "Decrypt data using an AEAD or block cipher.\n\n"
        "Parameters must match those used for encryption.\n"
        "tag is required for AEAD ciphers (nil for CBC).\n"
        "aad must match what was used during encryption.\n"
        "Returns plaintext buffer.\n"
        "Errors if authentication fails (tag mismatch)."
    },
    {
        "generate-nonce", cfun_generate_nonce,
        "(jsec/crypto/generate-nonce algo)\n\n"
        "Generate a random nonce suitable for the specified cipher algorithm.\n"
        "Returns buffer of appropriate length for the algorithm.\n"
        "IMPORTANT: Never reuse a nonce with the same key!"
    },
    {
        "cipher-info", cfun_cipher_info,
        "(jsec/crypto/cipher-info algo)\n\n"
        "Get information about a cipher algorithm.\n"
        "Returns struct:\n"
        "  {:name \"aes-256-gcm\"\n"
        "   :key-length 32\n"
        "   :nonce-length 12\n"
        "   :tag-length 16\n"
        "   :aead true}"
    },
    /* Password-protected keys */
    {
        "load-key", cfun_load_key,
        "(jsec/crypto/load-key key-pem &opt password)\n\n"
        "Load a private key from PEM format.\n"
        "If the key is encrypted, provide the password.\n"
        "Returns decrypted key in PEM format."
    },
    {
        "export-key", cfun_export_key,
        "(jsec/crypto/export-key key-pem &opt opts)\n\n"
        "Export a private key, optionally encrypted.\n"
        "Options:\n"
        "  :password - password for encryption (if not provided, key is unencrypted)\n"
        "  :cipher - encryption cipher (:aes-256-cbc, :aes-128-cbc, :des-ede3-cbc)\n"
        "            Default is :aes-256-cbc\n"
        "Returns PEM format key."
    },
    {
        "key-info", cfun_key_info,
        "(jsec/crypto/key-info key-pem)\n\n"
        "Get metadata about a key without needing the password for encrypted keys.\n"
        "Returns table with:\n"
        "  :type - :rsa, :ec, :ed25519, :x25519, etc.\n"
        "  :bits - key size in bits (RSA/EC)\n"
        "  :curve - EC curve name (:p-256, :p-384, :p-521) for EC keys\n"
        "  :encrypted - true if key is password-protected"
    },
    /* RSA encryption */
    {
        "rsa-encrypt", cfun_rsa_encrypt,
        "(jsec/crypto/rsa-encrypt key-pem plaintext &opt opts)\n\n"
        "Encrypt data with RSA public key.\n"
        "Options:\n"
        "  :padding - padding mode (default :oaep-sha256)\n"
        "             :oaep-sha256 (recommended)\n"
        "             :oaep-sha384\n"
        "             :oaep-sha512\n"
        "             :oaep-sha1 (legacy)\n"
        "             :pkcs1 (legacy, NOT recommended)\n\n"
        "NOTE: RSA encryption has size limits based on key size.\n"
        "Use crypto/rsa-max-plaintext to check maximum size.\n"
        "For larger data, use hybrid encryption (RSA + AES)."
    },
    {
        "rsa-decrypt", cfun_rsa_decrypt,
        "(jsec/crypto/rsa-decrypt key-pem ciphertext &opt opts)\n\n"
        "Decrypt data with RSA private key.\n"
        "Options:\n"
        "  :padding - must match encryption padding (default :oaep-sha256)\n"
        "Returns plaintext."
    },
    {
        "rsa-max-plaintext", cfun_rsa_max_plaintext,
        "(jsec/crypto/rsa-max-plaintext key-pem &opt opts)\n\n"
        "Get maximum plaintext size for RSA encryption with given key.\n"
        "Options:\n"
        "  :padding - padding mode (default :oaep-sha256)\n"
        "Returns maximum bytes that can be encrypted."
    },
    /* Key/cert format conversion */
    {
        "convert-key", cfun_convert_key,
        "(jsec/crypto/convert-key key-data target-format &opt opts)\n\n"
        "Convert a key between formats.\n"
        "target-format:\n"
        "  :pem - PEM format\n"
        "  :der - DER (binary) format\n"
        "  :pkcs8 - PKCS#8 PEM format\n"
        "  :pkcs8-der - PKCS#8 DER format\n"
        "Options:\n"
        "  :password - password for encrypted PKCS#8 output"
    },
    {
        "convert-cert", cfun_convert_cert,
        "(jsec/crypto/convert-cert cert-data target-format)\n\n"
        "Convert a certificate between PEM and DER formats.\n"
        "target-format: :pem or :der"
    },
    {
        "detect-format", cfun_detect_format,
        "(jsec/crypto/detect-format data)\n\n"
        "Detect if data is PEM or DER format.\n"
        "Returns :pem or :der."
    },
    /* PKCS#12 */
    {
        "parse-pkcs12", cfun_parse_pkcs12,
        "(jsec/crypto/parse-pkcs12 pfx-data password)\n\n"
        "Parse a PKCS#12 (PFX) bundle.\n"
        "Returns table with:\n"
        "  :cert - certificate PEM\n"
        "  :key - private key PEM\n"
        "  :chain - array of CA certificate PEMs\n"
        "  :friendly-name - friendly name if present"
    },
    {
        "create-pkcs12", cfun_create_pkcs12,
        "(jsec/crypto/create-pkcs12 cert-pem key-pem opts)\n\n"
        "Create a PKCS#12 bundle.\n"
        "Options:\n"
        "  :password - required password for bundle\n"
        "  :chain - array of CA certificate PEMs\n"
        "  :friendly-name - friendly name attribute\n"
        "Returns PKCS#12 bundle bytes (DER format)."
    },
    /* EC point operations */
    {
        "ec-point-mul", cfun_ec_point_mul,
        "(jsec/crypto/ec-point-mul curve scalar &opt point)\n\n"
        "Scalar multiplication on elliptic curve.\n"
        "If point is nil, multiplies the generator G.\n"
        "curve: :p-256, :p-384, :p-521, :secp256k1\n"
        "scalar: big-endian byte buffer\n"
        "point: {:x <buffer> :y <buffer>}\n"
        "Returns {:x <buffer> :y <buffer>}"
    },
    {
        "ec-point-add", cfun_ec_point_add,
        "(jsec/crypto/ec-point-add curve point1 point2)\n\n"
        "Point addition on elliptic curve.\n"
        "Returns {:x <buffer> :y <buffer>}"
    },
    {
        "ec-point-to-bytes", cfun_ec_point_to_bytes,
        "(jsec/crypto/ec-point-to-bytes curve point &opt opts)\n\n"
        "Serialize EC point to SEC1 format.\n"
        "Options:\n"
        "  :compressed - if true, use compressed format\n"
        "Returns bytes buffer."
    },
    {
        "ec-point-from-bytes", cfun_ec_point_from_bytes,
        "(jsec/crypto/ec-point-from-bytes curve bytes)\n\n"
        "Deserialize EC point from SEC1 format.\n"
        "Returns {:x <buffer> :y <buffer>}"
    },
    {
        "ec-generate-scalar", cfun_ec_generate_scalar,
        "(jsec/crypto/ec-generate-scalar curve)\n\n"
        "Generate a random scalar in [1, order-1] for the curve.\n"
        "Returns big-endian byte buffer."
    },
    {NULL, NULL, NULL}
};

JANET_MODULE_ENTRY(JanetTable *env) {
    const JanetReg *reg = cfuns;
    while (reg->name) {
        janet_def(env, reg->name, janet_wrap_cfunction(reg->cfun),
                  reg->documentation);
        reg++;
    }
}

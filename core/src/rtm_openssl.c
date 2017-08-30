#include <errno.h>
#include <fcntl.h>
#include <string.h>

#ifdef _WIN32
#include <Windows.h>
#endif

#include <openssl/bio.h>
#include <openssl/hmac.h>
#include <openssl/x509v3.h>
#include "rtm_internal.h"
#include "rtm_openssl_bio.h"

// Disable deprecation warnings on OSX /IOS
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#pragma comment(lib, "crypt32")

static unsigned is_openssl_initialized = NO;
static const SSL_METHOD *ssl_method = NULL;

/**
 * @return 0 - ok, -1 - fail
 */
static rtm_status openssl_initialize(rtm_client_t *rtm) {
  ASSERT_NOT_NULL(rtm);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  if (!OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL)) {
    _rtm_log_error(rtm, RTM_ERR_TLS, "OpenSSL initialization failed");
    return RTM_ERR_TLS;
  }
#else
  (void) OPENSSL_config(NULL);
#endif

  (void) OpenSSL_add_ssl_algorithms();
  ssl_method = SSLv23_client_method();
  (void) SSL_load_error_strings();


  if (NULL == ssl_method) {
    _rtm_log_error(rtm, RTM_ERR_TLS, "OpenSSL initialization failed");
    return RTM_ERR_TLS;
  }

#if !defined(NDEBUG) && defined (OPENSSL_THREADS)
#pragma warn "thread locking is not implemented"
  // fprintf(stdout, "Warning: thread locking is not implemented\n");
#endif

  return RTM_OK;
}

#if defined(_WIN32) && defined(_MSC_VER)
static rtm_status openssl_load_windows_certificates(rtm_client_t *rtm)
{
  SSL_CTX *ssl = rtm->ssl_context;

  DWORD flags
    = CERT_STORE_READONLY_FLAG
    | CERT_STORE_OPEN_EXISTING_FLAG
    | CERT_SYSTEM_STORE_CURRENT_USER;
  HCERTSTORE systemStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, flags, L"Root");

  if (!systemStore) {
    _rtm_log_error(rtm, RTM_ERR_TLS, "CertOpenStore failed with %d", GetLastError());
    return RTM_ERR_TLS;
  }

  PCCERT_CONTEXT certificateIterator = NULL;
  X509_STORE *opensslStore = SSL_CTX_get_cert_store(ssl);

  int certificateCount = 0;
  while (certificateIterator = CertEnumCertificatesInStore(systemStore, certificateIterator)) {
    X509 *x509 = d2i_X509(
      NULL,
      (const unsigned char **)&certificateIterator->pbCertEncoded,
      certificateIterator->cbCertEncoded);

    if (x509) {
      if (X509_STORE_add_cert(opensslStore, x509) == 1) {
        ++certificateCount;
      }

      X509_free(x509);
    }
  }

  CertFreeCertificateContext(certificateIterator);
  CertCloseStore(systemStore, 0);

  if (certificateCount == 0) {
      _rtm_log_error(rtm, RTM_ERR_TLS, "No certificates found");
      return RTM_ERR_TLS;
  }

  return RTM_OK;
}
#endif

static int openssl_verify_callback(int preverify, X509_STORE_CTX *x509_ctx) {
  return preverify;
}

static SSL_CTX *openssl_create_context() {
  SSL_CTX *ctx = SSL_CTX_new(ssl_method);
  if (ctx) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, openssl_verify_callback);
    SSL_CTX_set_verify_depth(ctx, 4);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
  }
  return ctx;
}

/* create new SSL connection state object */
static SSL *openssl_create_connection(SSL_CTX *ctx, int socket, const char *hostname) {
  ASSERT_NOT_NULL(ctx);
  ASSERT(socket > 0);
  SSL *ssl = SSL_new(ctx);
  BIO *bio = BIO_new(rtm_openssl_bio());
  if (!bio) {
    SSL_free(ssl);
    return NULL;
  }
  BIO_set_fd(bio, socket, BIO_NOCLOSE);
  SSL_set_bio(ssl, bio, bio);

  // SNI support
  SSL_set_tlsext_host_name(ssl, hostname);

  // Acceptable ciphers as of Aug 2017
  SSL_set_cipher_list(ssl,
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256"
    #if OPENSSL_VERSION_NUMBER < 0x10002000L
      // To be sure that everyting works, add some old ciphers for old OpenSSL versions
      ":HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4"
    #endif
  );

  #if OPENSSL_VERSION_NUMBER >= 0x10002000L
    // Support for server name verification
    // (The docs say that this should work from 1.0.2, and is the default from
    // 1.1.0, but it does not. To be on the safe side, the manual test below is
    // enabled for all versions prior to 1.1.0.)
    X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set1_host(param, hostname, 0);
  #endif


  return ssl;
}

#if OPENSSL_VERSION_NUMBER < 0x10010000L
/**
 * Check whether a hostname matches a pattern
 *
 * The pattern MUST contain at most a single, leading asterisk. This means that
 * this function cannot serve as a generic validation function, as that would
 * allow for partial wildcards, too. Also, this does not check whether the
 * wildcard covers multiple levels of labels. For RTM, this suffices, as we
 * are only interested in the main domain name.
 *
 * @param[in] hostname The hostname of the server
 * @param[in] pattern The hostname pattern from a SSL certificate
 * @return TRUE if the pattern matches, FALSE otherwise
 */
static int check_host(const char *hostname, const char *pattern) {
  if(pattern[0] == '*') {
    pattern++;
    hostname = hostname + strlen(hostname) - strlen(pattern);
  }
  int match = strcasecmp(hostname, pattern);

  return match == 0;
}
#endif

static rtm_status openssl_check_server_cert(rtm_client_t *rtm, SSL *ssl, const char *hostname) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(ssl);
  ASSERT_NOT_NULL(hostname);
  X509 *server_cert = SSL_get_peer_certificate(ssl);
  if (NULL == server_cert) {
    _rtm_log_error(rtm, RTM_ERR_TLS, "OpenSSL failed - peer didn't present a X509 certificate.");
    return RTM_ERR_TLS;
  }

  #if OPENSSL_VERSION_NUMBER < 0x10010000L
    // Check server name
    int hostname_verifies_ok = 0;
    STACK_OF(GENERAL_NAME) *san_names = X509_get_ext_d2i((X509 *)server_cert, NID_subject_alt_name, NULL, NULL);
    if (san_names) {
      for (int i=0; i<sk_GENERAL_NAME_num(san_names); i++) {
        const GENERAL_NAME *sk_name = sk_GENERAL_NAME_value(san_names, i);
        if (sk_name->type == GEN_DNS) {
          char *name = (char *)ASN1_STRING_data(sk_name->d.dNSName);
          if ((size_t)ASN1_STRING_length(sk_name->d.dNSName) == strlen(name) && check_host(hostname, name)) {
            hostname_verifies_ok = 1;
            break;
          }
        }
      }
    }
    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);

    if (!hostname_verifies_ok) {
      int cn_pos = X509_NAME_get_index_by_NID(X509_get_subject_name((X509 *)server_cert), NID_commonName, -1);
      if (cn_pos) {
        X509_NAME_ENTRY *cn_entry = X509_NAME_get_entry(X509_get_subject_name((X509 *)server_cert), cn_pos);
        if (cn_entry) {
          ASN1_STRING *cn_asn1 = X509_NAME_ENTRY_get_data(cn_entry);
          char *cn = (char *)ASN1_STRING_data(cn_asn1);

          if((size_t)ASN1_STRING_length(cn_asn1) == strlen(cn) && check_host(hostname, cn)) {
            hostname_verifies_ok = 1;
          }
        }
      }
    }

    if (!hostname_verifies_ok) {
      _rtm_log_error(rtm, RTM_ERR_TLS, "OpenSSL failed - certificate was issued for a different domain.");
      return RTM_ERR_TLS;
    }
  #else
    (void)hostname;
  #endif


  X509_free(server_cert);
  return RTM_OK;
}

static void print_ssl_error(rtm_client_t *rtm, int ret){
  unsigned long e;

  int err = SSL_get_error(rtm->ssl_connection, ret);

  switch (err) {
    case SSL_ERROR_WANT_CONNECT:
    case SSL_ERROR_WANT_ACCEPT:
      _rtm_log_error(rtm, RTM_ERR_TLS, "OpenSSL failed - connection failure");
      break;
    case SSL_ERROR_WANT_X509_LOOKUP:
      _rtm_log_error(rtm, RTM_ERR_TLS, "OpenSSL failed - x509 error");
      break;
    case SSL_ERROR_SYSCALL:
      e = ERR_get_error();
      if (e > 0) {
        _rtm_log_error(rtm, RTM_ERR_TLS, "OpenSSL failed - %s", ERR_error_string(e, NULL));
      } else if (e == 0 && ret == 0) {
        _rtm_log_error(rtm, RTM_ERR_TLS, "OpenSSL failed - received early EOF");
      } else {
        _rtm_log_error(rtm, RTM_ERR_TLS, "OpenSSL failed - underlying BIO reported an I/O error");
      }
      break;
    case SSL_ERROR_SSL:
      e = ERR_get_error();
      _rtm_log_error(rtm, RTM_ERR_TLS, "OpenSSL failed - %s", ERR_error_string(e, NULL));
      break;
    case SSL_ERROR_NONE:
    case SSL_ERROR_ZERO_RETURN:
    default:
      _rtm_log_error(rtm, RTM_ERR_TLS, "OpenSSL failed - unknown error");
      break;
  }
}
static rtm_status openssl_handshake(rtm_client_t *rtm, const char *hostname) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(hostname);

  while (TRUE) {
    int connect_result = SSL_connect(rtm->ssl_connection);
    if (connect_result == 1) {
      return openssl_check_server_cert(rtm, rtm->ssl_connection, hostname);
    }
    int reason = SSL_get_error(rtm->ssl_connection, connect_result);

    rtm_status rc;
    if (reason == SSL_ERROR_WANT_READ || reason == SSL_ERROR_WANT_WRITE) {
      rc = _rtm_io_wait(rtm, SSL_ERROR_WANT_READ == reason, SSL_ERROR_WANT_WRITE == reason, -1);
    } else {
      print_ssl_error(rtm, connect_result);
      rc = RTM_ERR_TLS;
    }

    if (RTM_OK != rc) {
      return rc;
    }
  }
}

rtm_status _rtm_io_open_tls_session(rtm_client_t *rtm, const char *hostname) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(hostname);

  rtm_status rc;

  if (!is_openssl_initialized) {
    rc = openssl_initialize(rtm);
    if (RTM_OK != rc)
      return rc;
    is_openssl_initialized = YES;
  }

  rtm->ssl_context = openssl_create_context();
  if (NULL == rtm->ssl_context) {
    _rtm_log_error(rtm, RTM_ERR_TLS, "OpenSSL failed to create context");
    return RTM_ERR_TLS;
  }

#if defined(_WIN32) && defined(_MSC_VER)
  rc = openssl_load_windows_certificates(rtm);
  if (rc != RTM_OK) {
      _rtm_log_error(
          rtm, rc,
          "Certificate loading failed\n");
  }
#else
  int cert_load_result = SSL_CTX_set_default_verify_paths(rtm->ssl_context);
  if (0 == cert_load_result) {
      unsigned long ssl_err = ERR_get_error();
      _rtm_log_error(
          rtm, RTM_ERR_TLS,
          "OpenSSL failed - SSL_CTX_default_verify_paths loading failed:  %s\n",
          ERR_reason_error_string(ssl_err));
  }
#endif

  rtm->ssl_connection = openssl_create_connection(rtm->ssl_context, rtm->fd, hostname);
  if (NULL == rtm->ssl_connection) {
    _rtm_log_error(rtm, RTM_ERR_TLS, "OpenSSL failed to connect");
    SSL_CTX_free(rtm->ssl_context);
    rtm->ssl_context = NULL;
    return RTM_ERR_TLS;
  }

  rc = openssl_handshake(rtm, hostname);

  if (RTM_OK != rc) {
    _rtm_io_close_tls_session(rtm);
    return rc;
  }

  return RTM_OK;
}

rtm_status _rtm_io_close_tls_session(rtm_client_t *rtm) {
  ASSERT_NOT_NULL(rtm);
  // assert rtm?
  if (rtm->ssl_connection) {
    SSL_free(rtm->ssl_connection);
    rtm->ssl_connection = NULL;
  }
  if (rtm->ssl_context) {
    SSL_CTX_free(rtm->ssl_context);
    rtm->ssl_context = NULL;
  }
  return RTM_OK;
}

ssize_t _rtm_io_read_tls(rtm_client_t *rtm, char *buf, size_t nbyte, int wait) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(buf);
  ASSERT(nbyte > 0);
  errno = 0;

  while (TRUE) {
    int read_result = SSL_read(rtm->ssl_connection, buf, (int) nbyte);

    if (read_result >= 0) {
      return read_result;
    }

    rtm_status rc = RTM_OK;
    int reason = SSL_get_error(rtm->ssl_connection, read_result);

    if (reason == SSL_ERROR_WANT_READ || reason == SSL_ERROR_WANT_WRITE) {
      if (!wait) {
        errno = EAGAIN;
        return -1;
      }
      rc = _rtm_io_wait(rtm, SSL_ERROR_WANT_READ == reason, SSL_ERROR_WANT_WRITE == reason, -1);
    } else {
      print_ssl_error(rtm, read_result);
      rc = RTM_ERR_TLS;
    }
    if (rc != RTM_OK) {
      return -1;
    }
  }
}

ssize_t _rtm_io_write_tls(rtm_client_t *rtm, const char *buf, size_t nbyte) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(buf);
  ASSERT(nbyte > 0);

  ssize_t sent = 0;

  while (nbyte > 0) {
    int write_result = SSL_write(rtm->ssl_connection, buf + sent, (int) nbyte);
    int reason = SSL_get_error(rtm->ssl_connection, write_result);
    rtm_status rc = RTM_OK;
    if (reason == SSL_ERROR_NONE) {
      nbyte -= write_result;
      sent += write_result;
    } else if (reason == SSL_ERROR_WANT_READ || reason == SSL_ERROR_WANT_WRITE) {
      rc = _rtm_io_wait(rtm, SSL_ERROR_WANT_READ == reason, SSL_ERROR_WANT_WRITE == reason, -1);
    } else {
      print_ssl_error(rtm, write_result);
      rc = RTM_ERR_TLS;
    }
    if (rc != RTM_OK) {
      return -1;
    }
  }
  return sent;
}

void _rtm_calculate_auth_hash(char const *role_secret, char const *nonce, char *output_25bytes) {
  unsigned char hash[16];
  HMAC(
    EVP_md5(),
    role_secret, strlen(role_secret),
    (unsigned char *)nonce, strlen(nonce),
    (unsigned char *)hash, NULL);
  _rtm_b64encode_16bytes((char const *)hash, output_25bytes);
}

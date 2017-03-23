#include <errno.h>
#include <fcntl.h>

#include <openssl/hmac.h>

#ifdef _WIN32
#include <Windows.h>
#endif

#include "rtm_internal.h"

// Disable deprecation warnings on OSX /IOS
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#pragma comment(lib, "crypt32")
#pragma comment(lib, "libeay32MD")
#pragma comment(lib, "ssleay32MD")

static unsigned is_openssl_initialized = NO;
static const SSL_METHOD *ssl_method = NULL;

/**
 * @return 0 - ok, -1 - fail
 */
static rtm_status openssl_initialize(rtm_client_t *rtm) {
  ASSERT_NOT_NULL(rtm);

  (void) OpenSSL_add_ssl_algorithms();
  ssl_method = SSLv23_client_method();
  (void) SSL_load_error_strings();
  (void) OPENSSL_config(NULL);

  if (NULL == ssl_method) {
    return _rtm_log_error(rtm, RTM_ERR_TLS, "OpenSSL initialization failed");
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
  /*
  ASSERT_NOT_NULL(x509_ctx);
  // where did the error occur ?
  int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
  int err = X509_STORE_CTX_get_error(x509_ctx);
  char message[16372];

  ERR_error_string((unsigned long) err, message);

  X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);
  X509_NAME *iname = cert ? X509_get_issuer_name(cert) : NULL;
  X509_NAME *sname = cert ? X509_get_subject_name(cert) : NULL;

  return preverify;
  */
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
static SSL *openssl_create_connection(SSL_CTX *ctx, int socket) {
  ASSERT_NOT_NULL(ctx);
  ASSERT(socket > 0);
  SSL *ssl = SSL_new(ctx);
  if (ssl)
    SSL_set_fd(ssl, socket);
  return ssl;
}

static rtm_status openssl_check_server_cert(rtm_client_t *rtm, SSL *ssl, const char *hostname) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(ssl);
  ASSERT_NOT_NULL(hostname);
  X509 *server_cert = SSL_get_peer_certificate(ssl);
  if (NULL == server_cert) {
    _rtm_log_error(rtm, RTM_ERR_TLS, "OpenSSL failed - peer didn't present a X509 certificate.");
    return RTM_ERR_TLS;
  }
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
    if (rc)
      return rc;
    is_openssl_initialized = YES;
  }

  rtm->ssl_context = openssl_create_context();
  if (NULL == rtm->ssl_context) {
    return _rtm_log_error(rtm, RTM_ERR_TLS, "OpenSSL failed to create context");
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

  rtm->ssl_connection = openssl_create_connection(rtm->ssl_context, rtm->fd);
  if (NULL == rtm->ssl_connection) {
    rc = _rtm_log_error(rtm, RTM_ERR_TLS, "OpenSSL failed to connect");
    SSL_CTX_free(rtm->ssl_context);
    rtm->ssl_context = NULL;
    return rc;
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

  while (TRUE) {
    int read_result = SSL_read(rtm->ssl_connection, buf, (int) nbyte);

    if (read_result > 0) {
      return read_result;
    }

    rtm_status rc = RTM_OK;
    int reason = SSL_get_error(rtm->ssl_connection, read_result);

    if (reason == SSL_ERROR_WANT_READ || reason == SSL_ERROR_WANT_WRITE) {
      if (!wait) {
        return 0;
      }
      rc = _rtm_io_wait(rtm, SSL_ERROR_WANT_READ == reason, SSL_ERROR_WANT_WRITE == reason, -1);
    } else {
      print_ssl_error(rtm, read_result);
      rc = RTM_ERR_TLS;
    }
    if (rc != RTM_OK) {
      return READ_FAILURE;
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
      return WRITE_FAILURE;
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

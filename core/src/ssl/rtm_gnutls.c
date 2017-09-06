#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "rtm_internal.h"

#include <gnutls/crypto.h>

static int is_gnutls_initialized = NO;
static gnutls_anon_client_credentials_t anoncred;
static gnutls_certificate_credentials_t xcred;

static rtm_status gtls_initialize(rtm_client_t *rtm) {
  ASSERT_NOT_NULL(rtm);

  gnutls_global_init(); /* supposedly not needed since 3.3.0 */
  gnutls_anon_allocate_client_credentials(&anoncred);
  gnutls_certificate_allocate_credentials(&xcred);
#if GNUTLS_VERSION_MAJOR >= 3
  {
    int certificate_store_found = 0;
    if (gnutls_certificate_set_x509_system_trust(xcred) > 0) {
      certificate_store_found = 1;
    }

    char *cert_file = getenv("SSL_CERT_FILE");
    if (cert_file && gnutls_certificate_set_x509_trust_file(xcred, cert_file, GNUTLS_X509_FMT_PEM)) {
      certificate_store_found = 1;
    }

    if (certificate_store_found != 1) {
      _rtm_log_error(rtm, RTM_ERR_TLS, "GnuTLS Unable to load TLS trusted root certificates, or no certs found");
      return RTM_ERR_TLS;
    }
  }
#else
  _rtm_log_message(rtm, RTM_OK, "GNUTLS version < 3 no system root certificates defined");
#endif
  return RTM_OK;
}

static rtm_status gtls_create_session(rtm_client_t *rtm, const char *hostname) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(hostname);
  rtm->priv.session = NULL;

  gnutls_init(&rtm->priv.session, GNUTLS_CLIENT);
  gnutls_priority_set_direct(rtm->priv.session, "NORMAL", 0);
  gnutls_credentials_set(rtm->priv.session, GNUTLS_CRD_ANON, anoncred);
  gnutls_credentials_set(rtm->priv.session, GNUTLS_CRD_CERTIFICATE, xcred);
  gnutls_server_name_set(rtm->priv.session, GNUTLS_NAME_DNS, hostname, strlen(hostname));
#if GNUTLS_VERSION_NUMBER >= 0x030406
  gnutls_session_set_verify_cert(rtm->priv.session, hostname, 0);
#else
  #warning GnuTLS certificate validation only supported from version 3.4.6 on
#endif

#if GNUTLS_VERSION_MAJOR >= 3
  gnutls_transport_set_int(rtm->priv.session, rtm->priv.fd);
  gnutls_handshake_set_timeout(rtm->priv.session, rtm->priv.connect_timeout * 1000);
#else
  gnutls_transport_set_ptr(rtm->priv.session, (void *) (long) rtm->priv.fd);
#endif
  return RTM_OK;
}

static rtm_status gtls_handshake(rtm_client_t *rtm) {
  ASSERT_NOT_NULL(rtm);
  int ret;
  do {
    ret = gnutls_handshake(rtm->priv.session);
    if (ret < 0 && ret == GNUTLS_E_AGAIN)
      _rtm_io_wait(rtm, 1, 1, -1);
  } while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

  if (ret < 0) {
    gnutls_deinit(rtm->priv.session);
    _rtm_log_error(rtm, RTM_ERR_TLS, "TLS handshake failed – reason %s – %s",
                   gnutls_strerror(ret),
                   gnutls_alert_get_name(gnutls_alert_get(rtm->priv.session)));
    return RTM_ERR_TLS;
  }
  return RTM_OK;
}

static rtm_status _rtm_gtls_wait_for_socket(rtm_client_t *rtm, rtm_status error_status, int error, int readable, int writable) {
  ASSERT_NOT_NULL(rtm);
  if (GNUTLS_E_INTERRUPTED == error) {
    return RTM_OK;
  } else if (GNUTLS_E_AGAIN == error) {
    return _rtm_io_wait(rtm, readable, writable, -1);
  } else {
    _rtm_log_error(rtm, error_status, "GnuTLS error – error=%d message=%s", error, gnutls_strerror(error));
    return RTM_ERR_TLS;
  }
  return RTM_OK;
}

rtm_status _rtm_io_open_tls_session(rtm_client_t *rtm, const char *hostname) {
  rtm_status rc;
  if (!is_gnutls_initialized) {
    rc = gtls_initialize(rtm);
    if (RTM_OK != rc)
      return rc;
    is_gnutls_initialized = YES;
  }

  rc = gtls_create_session(rtm, hostname);
  if (RTM_OK != rc)
    return rc;

  rc = gtls_handshake(rtm);
  return rc;

}

rtm_status _rtm_io_close_tls_session(rtm_client_t *rtm) {
  ASSERT_NOT_NULL(rtm);

  if (rtm->priv.session) {
    gnutls_deinit(rtm->priv.session);
    rtm->priv.session = NULL;
  }

  return RTM_OK;
}

ssize_t _rtm_io_read_tls(rtm_client_t *rtm, char *buf, size_t nbyte, int wait) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(buf);
  ASSERT(nbyte > 0);
  errno = 0;

  while (TRUE) {
    ssize_t read_result = gnutls_record_recv(rtm->priv.session, buf, nbyte);
    if (read_result >= 0) {
      return read_result;
    } else if (!wait && read_result == GNUTLS_E_AGAIN) {
      errno = EAGAIN;
      return -1;
    } else if (_rtm_gtls_wait_for_socket(rtm, RTM_ERR_READ, (int) read_result, wait, NO) != RTM_OK) {
      return -1;
    }
  }
}

ssize_t _rtm_io_write_tls(rtm_client_t *rtm, const char *buf, size_t nbyte) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(buf);
  ASSERT(nbyte > 0);
  ssize_t written = 0;

  while (nbyte > 0) {
    ssize_t write_result = gnutls_record_send(rtm->priv.session, buf + written, nbyte);
    if (write_result >= 0) {
      written += write_result;
      nbyte -= write_result;
    } else if (_rtm_gtls_wait_for_socket(rtm, RTM_ERR_WRITE, (int) write_result, NO, YES) != RTM_OK) {
      return -1;
    }
  }
  return written;
}

void _rtm_calculate_auth_hash(char const *role_secret, char const *nonce, char *output_25bytes) {
  unsigned char hash[16];
  gnutls_hmac_fast(
      GNUTLS_MAC_MD5,
      role_secret, strlen(role_secret),
      nonce, strlen(nonce),
      hash);
  _rtm_b64encode_16bytes((char const *)hash, output_25bytes);
}

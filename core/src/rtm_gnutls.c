#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
      return _rtm_log_error(rtm, RTM_ERR_TLS,
                           "GnuTLS Unable to load TLS trusted root certificates, or no certs found");
    }
  }
#else
  _rtm_log_message(RTM_OK, "GNUTLS version < 3 no system root certificates defined");
#endif
  return RTM_OK;
}

static rtm_status gtls_create_session(rtm_client_t *rtm, const char *hostname) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(hostname);
  rtm->session = NULL;

  gnutls_init(&rtm->session, GNUTLS_CLIENT);
  gnutls_priority_set_direct(rtm->session, "NORMAL", 0);
  gnutls_credentials_set(rtm->session, GNUTLS_CRD_ANON, anoncred);
  gnutls_credentials_set(rtm->session, GNUTLS_CRD_CERTIFICATE, xcred);
  gnutls_server_name_set(rtm->session, GNUTLS_NAME_DNS, hostname, strlen(hostname));

#if GNUTLS_VERSION_MAJOR >= 3
  gnutls_transport_set_int(rtm->session, rtm->fd);
  gnutls_handshake_set_timeout(rtm->session, (unsigned) rtm_connect_timeout * 1000);
#else
  gnutls_transport_set_ptr(rtm->session, (void *) (long) rtm->fd);
#endif
  return RTM_OK;
}

static rtm_status gtls_handshake(rtm_client_t *rtm) {
  ASSERT_NOT_NULL(rtm);
  int ret;
  do {
    ret = gnutls_handshake(rtm->session);
    if (ret < 0 && ret == GNUTLS_E_AGAIN)
      _rtm_io_wait(rtm, 1, 1, -1);
  } while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

  if (ret < 0) {
    rtm_status error = _rtm_log_error(rtm, RTM_ERR_TLS, "TLS handshake failed – reason %s – %s",
                                     gnutls_strerror(ret),
                                     gnutls_alert_get_name(gnutls_alert_get(rtm->session)));
    gnutls_deinit(rtm->session);
    return error;
  }
  return RTM_OK;
}

static rtm_status gtls_wait_for_socket(rtm_client_t *rtm, rtm_status error_status, int error, int readable, int writable) {
  ASSERT_NOT_NULL(rtm);
  if (GNUTLS_E_INTERRUPTED == error) {
    return RTM_OK;
  } else if (GNUTLS_E_AGAIN == error) {
    return _rtm_io_wait(rtm, readable, writable, -1);
  } else {
    _rtm_log_error(rtm, error_status, "GnuTLS error – error=%d message=%s", error, gnutls_strerror(error));
  }
  return RTM_OK;
}

rtm_status _rtm_io_open_tls_session(rtm_client_t *rtm, const char *hostname) {
  rtm_status rc;
  if (!is_gnutls_initialized) {
    rc = gtls_initialize(rtm);
    if (rc)
      return rc;
    is_gnutls_initialized = YES;
  }

  rc = gtls_create_session(rtm, hostname);
  if (rc)
    return rc;

  rc = gtls_handshake(rtm);
  if (rc)
    return rc;

  return gtls_handshake(rtm);

}

rtm_status _rtm_io_close_tls_session(rtm_client_t *rtm) {
  ASSERT_NOT_NULL(rtm);

  if (rtm->session) {
    gnutls_deinit(rtm->session);
    rtm->session = NULL;
  }

  return RTM_OK;
}

ssize_t _rtm_io_read_tls(rtm_client_t *rtm, char *buf, size_t nbyte, int wait) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(buf);
  ASSERT(nbyte > 0);

  while (TRUE) {
    ssize_t read_result = gnutls_record_recv(rtm->session, buf, nbyte);
    if (read_result >= 0) {
      return read_result; // FIXME: handle 0 correctly
    } else if (!wait && read_result == GNUTLS_E_AGAIN) {
      return 0;
    } else if (gtls_wait_for_socket(rtm, RTM_ERR_READ, (int) read_result, wait, NO) != RTM_OK) {
      return READ_FAILURE;
    }
  }
}

ssize_t _rtm_io_write_tls(rtm_client_t *rtm, const char *buf, size_t nbyte) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(buf);
  ASSERT(nbyte > 0);
  ssize_t written = 0;

  while (nbyte > 0) {
    ssize_t write_result = gnutls_record_send(rtm->session, buf + written, nbyte);
    if (write_result >= 0) {
      written += write_result;
      nbyte -= write_result;
    } else if (gtls_wait_for_socket(rtm, RTM_ERR_WRITE, (int) write_result, NO, YES) != RTM_OK) {
      return WRITE_FAILURE;
    }
  }
  return written;
}

void rtm_calculate_auth_hash(char const *role_secret, char const *nonce, char *output_25bytes) {
  unsigned char hash[16];
  gnutls_hmac_fast(
      GNUTLS_MAC_MD5,
      role_secret, strlen(role_secret),
      nonce, strlen(nonce),
      hash);
  _rtm_b64encode_16bytes((char const *)hash, output_25bytes);
}
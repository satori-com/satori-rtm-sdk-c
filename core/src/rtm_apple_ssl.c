#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "rtm_internal.h"
#include <Security/SecureTransport.h>
#include <CommonCrypto/CommonHMAC.h>

static OSStatus read_from_socket(SSLConnectionRef connection, void *data, size_t *len) {
  int fd = (int) (long) connection;
  ASSERT(fd > 0);
  ASSERT_NOT_NULL(data);
  ASSERT_NOT_NULL(len);

  size_t requested_sz = *len;

  ssize_t status = read(fd, data, requested_sz);

  if (status > 0) {
    *len = (size_t) status;
    if (requested_sz > *len)
      // sic! Apple SSL requires to return an error if fewer bytes have been
      // read than requested.
      return errSSLWouldBlock;
    else
      return noErr;
  } else if (0 == status) {
    *len = 0;
    return errSSLClosedGraceful;
  } else {
    *len = 0;
    switch (errno) {
      case ENOENT:
        return errSSLClosedGraceful;

      case EAGAIN:
        return errSSLWouldBlock;

      case ECONNRESET:
        return errSSLClosedAbort;

      default:
        return errSecIO;
    }
  }
}

static OSStatus write_to_socket(SSLConnectionRef connection, const void *data, size_t *len) {
  int fd = (int) (long) connection;
  ASSERT(fd > 0);
  ASSERT_NOT_NULL(data);
  ASSERT_NOT_NULL(len);

  size_t to_write_sz = *len;
  int status = write(fd, data, to_write_sz);

  if (status > 0) {
    *len = (size_t) status;
    // sic! Apple SSL requires to return an error if fewer bytes have been
    // written than requested.
    if (to_write_sz > *len)
      return errSSLWouldBlock;
    else
      return noErr;
  } else if (0 == status) {
    *len = 0;
    return errSSLClosedGraceful;
  } else {
    *len = 0;
    if (EAGAIN == errno) {
      return errSSLWouldBlock;
    } else {
      return errSecIO;
    }
  }
}

/*
static void rtm_log_status(OSStatus osStatus) {
  if (!rtm_error_logger) {
    return;
  } else {
    CFErrorRef error = CFErrorCreate(kCFAllocatorDefault, kCFErrorDomainOSStatus, osStatus, NULL);
    if (error) {
      CFStringRef message = CFErrorCopyDescription(error);
      if (message) {
        const char *error_message = CFStringGetCStringPtr(message, kCFStringEncodingASCII);
        rtm_error_logger(error_message);
        CFRelease(message);
      }
      CFRelease(error);
    }
  }
}
*/

rtm_status _rtm_io_open_tls_session(rtm_client_t *rtm, const char *host) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(host);

  OSStatus status;

  rtm->sslContext = SSLCreateContext(kCFAllocatorDefault, kSSLClientSide, kSSLStreamType);

  SSLSetIOFuncs(rtm->sslContext, read_from_socket, write_to_socket);
  SSLSetConnection(rtm->sslContext, (SSLConnectionRef) (long) rtm->fd);
  SSLSetProtocolVersionMin(rtm->sslContext, kTLSProtocol12);
  SSLSetPeerDomainName(rtm->sslContext, host, strlen(host));

  do {
    status = SSLHandshake(rtm->sslContext);

    if (errSSLWouldBlock == status)
      _rtm_io_wait(rtm, YES, YES, -1);

  } while (errSSLWouldBlock == status);

  if (noErr != status) {
    SSLClose(rtm->sslContext);
    CFRelease(rtm->sslContext);
    return _rtm_log_error(rtm, RTM_ERR_TLS, "TLS handshake failed. OSStatus=%d", status);
  }

  return RTM_OK;
}

rtm_status _rtm_io_close_tls_session(rtm_client_t *rtm) {
  ASSERT_NOT_NULL(rtm);

  SSLClose(rtm->sslContext);
  CFRelease(rtm->sslContext);

  return RTM_OK;
}

ssize_t _rtm_io_read_tls(rtm_client_t *rtm, char *buf, size_t nbyte, int wait) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(buf);
  ASSERT_NOT_NULL(buf);

  OSStatus status = errSSLWouldBlock;
  while (errSSLWouldBlock == status) {
    size_t processed = 0;
    status = SSLRead(rtm->sslContext, buf, nbyte, &processed);

    if (processed > 0)
      return (ssize_t) processed;

    if (errSSLWouldBlock == status) {
      if (wait)
        _rtm_io_wait(rtm, YES, NO, -1);
      else
        return 0;
    }
  }
  return -1;
}

ssize_t _rtm_io_write_tls(rtm_client_t *rtm, const char *buf, size_t nbyte) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(buf);
  ASSERT(nbyte > 0); // should have be caught earlier

  ssize_t ret = 0;
  OSStatus status;
  do {
    size_t processed = 0;
    status = SSLWrite(rtm->sslContext, buf, nbyte, &processed);
    ret += processed;
    buf += processed;
    nbyte -= processed;
  } while (nbyte > 0 && errSSLWouldBlock == status);

  if (ret == 0 && errSSLClosedAbort != status)
    ret = -1;
  return ret;
}

void _rtm_calculate_auth_hash(char const *role_secret, char const *nonce, char *output_25bytes) {
  unsigned char hash[16];
  CCHmac(
      kCCHmacAlgMD5,
      role_secret, strlen(role_secret),
      nonce, strlen(nonce),
      &hash);
  _rtm_b64encode_16bytes((char const *)hash, output_25bytes);
}

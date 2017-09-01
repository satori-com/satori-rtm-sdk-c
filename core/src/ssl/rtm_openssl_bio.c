// taken from https://github.com/alanxz/rabbitmq-c, revision 67264053434fa772bd082f9f5ce578fc1ddd9855

/*
 * Portions created by Alan Antonuk are Copyright (c) 2017 Alan Antonuk.
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */


#include "rtm_openssl_bio.h"

#include <string.h>

#include <errno.h>
#if ((defined(_WIN32)) || (defined(__MINGW32__)) || (defined(__MINGW64__)))
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <winsock2.h>
#else
# include <sys/types.h>
# include <sys/socket.h>
#endif

#ifdef ENABLE_THREAD_SAFETY
static pthread_once_t bio_init_once = PTHREAD_ONCE_INIT;
#endif

static int bio_initialized = 0;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static BIO_METHOD *rtm_bio_method;
#else
static BIO_METHOD _rtm_bio_method;
static BIO_METHOD *rtm_bio_method = &_rtm_bio_method;
#endif

static int rtm_openssl_bio_should_retry(int res) {
  if (res == -1) {
#ifdef _WIN32
    int err = WSAGetLastError();
#else
    int err = errno;
#endif
    if (
#ifdef EWOULDBLOCK
        err == EWOULDBLOCK ||
#endif
#ifdef WSAEWOULDBLOCK
        err == WSAEWOULDBLOCK ||
#endif
#ifdef ENOTCONN
        err == ENOTCONN ||
#endif
#ifdef EINTR
        err == EINTR ||
#endif
#ifdef EAGAIN
        err == EAGAIN ||
#endif
#ifdef EPROTO
        err == EPROTO ||
#endif
#ifdef EINPROGRESS
        err == EINPROGRESS ||
#endif
#ifdef EALREADY
        err == EALREADY ||
#endif
        0) {
      return 1;
    }
  }
  return 0;
}

static int rtm_openssl_bio_write(BIO* b, const char *in, int inl) {
  int flags = 0;
  int fd;
  int res;

#ifdef MSG_NOSIGNAL
  flags |= MSG_NOSIGNAL;
#endif

  BIO_get_fd(b, &fd);
  res = send(fd, in, inl, flags);

  BIO_clear_retry_flags(b);
  if (res <= 0 && rtm_openssl_bio_should_retry(res)) {
    BIO_set_retry_write(b);
  }

  return res;
}

static int rtm_openssl_bio_read(BIO* b, char* out, int outl) {
  int flags = 0;
  int fd;
  int res = 0;

  if(out != NULL) {
#ifdef MSG_NOSIGNAL
    flags |= MSG_NOSIGNAL;
#endif

    BIO_get_fd(b, &fd);
    res = recv(fd, out, outl, flags);

    BIO_clear_retry_flags(b);
    if (res <= 0 && rtm_openssl_bio_should_retry(res)) {
      BIO_set_retry_read(b);
    }
  }

  return res;
}

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
static int BIO_meth_set_write(BIO_METHOD *biom,
                              int (*wfn)(BIO *, const char *, int)) {
  biom->bwrite = wfn;
  return 0;
}

static int BIO_meth_set_read(BIO_METHOD *biom,
                              int (*rfn)(BIO *, char *, int)) {
  biom->bread = rfn;
  return 0;
}
#endif

static void rtm_openssl_bio_init(void) {
  #if OPENSSL_VERSION_NUMBER >= 0x10100000L
    // OpenSSL 1.1.0 made the BIO_METHOD structure opaque, so we cannot just
    // memcpy() here.
    rtm_bio_method = BIO_meth_new(BIO_TYPE_SOCKET, "");
    // BIO_s_socket() returns a const pointer, but BIO_meth_get_*() requires a
    // non-const pointer. It never changes the BIO_METHOD instance though.
    BIO_METHOD *sock_method = (BIO_METHOD *)BIO_s_socket();
    BIO_meth_set_puts(rtm_bio_method, BIO_meth_get_puts(sock_method));
    BIO_meth_set_gets(rtm_bio_method, BIO_meth_get_gets(sock_method));
    BIO_meth_set_ctrl(rtm_bio_method, BIO_meth_get_ctrl(sock_method));
    BIO_meth_set_create(rtm_bio_method, BIO_meth_get_create(sock_method));
    BIO_meth_set_callback_ctrl(rtm_bio_method, BIO_meth_get_callback_ctrl(sock_method));
  #else
    memcpy(rtm_bio_method, BIO_s_socket(), sizeof(*rtm_bio_method));
  #endif
  BIO_meth_set_write(rtm_bio_method, rtm_openssl_bio_write);
  BIO_meth_set_read(rtm_bio_method, rtm_openssl_bio_read);

  bio_initialized = 1;
}

BIO_METHOD* rtm_openssl_bio(void) {
  if (!bio_initialized) {
#ifdef ENABLE_THREAD_SAFETY
    pthread_once(&bio_init_once, rtm_openssl_bio_init);
#else
    rtm_openssl_bio_init();
#endif /* ifndef ENABLE_THREAD_SAFETY */
  }

  return rtm_bio_method;
}

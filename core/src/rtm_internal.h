#ifndef CORE_RTM_INTERNAL__INCLUDED
#define CORE_RTM_INTERNAL__INCLUDED

#include "rtm.h"

#include <stdint.h>

#ifdef _WIN32
#include <BaseTsd.h>

typedef SSIZE_T ssize_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if defined(USE_GNUTLS)

#include <gnutls/gnutls.h>

#elif defined(USE_OPENSSL)

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#elif defined(USE_APPLE_SSL)

#include <Security/Security.h>
#include <Security/SecureTransport.h>

#endif

#define _RTM_WS_PRE_BUFFER 16
#define _RTM_MAX_BUFFER (128*1024 - _RTM_WS_PRE_BUFFER)

#define _RTM_MAX_HOSTNAME_SIZE 255 // that's what POSIX says...
#define _RTM_MAX_PORT_SIZE 6       // 5 digits + 0
#define _RTM_MAX_PATH_SIZE (128)

// The scratch buffer can be dangerous when the following rule is not followed: never use the scratch buffer,
// then call another function and assume it is preserved. It's only valid in the scope, and as soon as you leave
// the scope it should be considered invalid.
#define _RTM_SCRATCH_BUFFER_SIZE (8 * 1024)

#define _RTM_BUFFER_TO_IO(base) (base + _RTM_WS_PRE_BUFFER)

#define _RTM_INBOUND_HEADER_SIZE_SMALL  (2)
#define _RTM_INBOUND_HEADER_SIZE_NORMAL (2 + 2)
#define _RTM_INBOUND_HEADER_SIZE_LARGE  (2 + 8)

#define _RTM_OUTBOUND_HEADER_SIZE_SMALL  (2 + 4)
#define _RTM_OUTBOUND_HEADER_SIZE_NORMAL (2 + 4 + 2)
#define _RTM_OUTBOUND_HEADER_SIZE_LARGE  (2 + 4 + 8)

#define _RTM_MAX_CONTROL_FRAME_SIZE (125)

// connect timeout in seconds
#define _RTM_CONNECT_TIMEOUT (5)

// value returned by c_{tls_,}{read,write}
#define READ_FAILURE (-1)
#define WRITE_FAILURE (-1)

struct _rtm_client {
    void *user;
    int fd;
    ssize_t input_length;
    unsigned is_closed: 1;
    unsigned is_used: 1;
    unsigned is_verbose: 1;
    unsigned last_request_id;

    unsigned is_secure: 1;
#if defined(USE_GNUTLS)
    gnutls_session_t session;
#elif defined(USE_OPENSSL)
    SSL_CTX *ssl_context;
    SSL *ssl_connection;
#elif defined(USE_APPLE_SSL)
    SSLContextRef sslContext;
#endif

    rtm_pdu_handler_t *handle_pdu;

    // The buffers are padded so we are always guaranteed to have
    // enough bytes to pre pad any buffer with websocket framing
    char input_buffer[_RTM_WS_PRE_BUFFER + _RTM_MAX_BUFFER + 1]; // add 1 to ALWAYS have a zero terminated buffer
    char output_buffer[_RTM_WS_PRE_BUFFER + _RTM_MAX_BUFFER + 1];
    char scratch_buffer[_RTM_SCRATCH_BUFFER_SIZE];
};

// json methods
RTM_API ssize_t _rtm_json_escape(char *dest, ssize_t n, const char *str);
char *_rtm_json_find_begin_obj(char *p);
char *_rtm_json_find_field_name(char* p, char **cursor, ssize_t *length);
char *_rtm_json_find_element(char* p, char **cursor, ssize_t *length);

// Network IO
rtm_status _rtm_io_connect(rtm_client_t *rtm, const char* hostname, const char* port,
    unsigned is_tls);
rtm_status _rtm_io_close(rtm_client_t *rtm);
rtm_status _rtm_io_wait(rtm_client_t *rtm, int readable, int writable, int timeout);
ssize_t    _rtm_io_write(rtm_client_t *rtm, const char *buf, size_t len);
ssize_t    _rtm_io_read(rtm_client_t *rtm, char *buf, size_t len, int wait);

void _rtm_calculate_auth_hash(char const *role_secret, char const *nonce, char *output);
rtm_status _rtm_io_open_tls_session(rtm_client_t *rtm, const char *host);
rtm_status _rtm_io_close_tls_session(rtm_client_t *rtm);
ssize_t    _rtm_io_read_tls(rtm_client_t *rtm, char *buf, size_t nbyte, int wait);
ssize_t    _rtm_io_write_tls(rtm_client_t *rtm, const char *buf, size_t nbyte);

void _rtm_b64encode_16bytes(char const *input, char *output);

// Logging
rtm_status _rtm_log_error(rtm_client_t *rtm, rtm_status error, const char *message, ...);
rtm_status _rtm_logv_error(rtm_client_t *rtm, rtm_status error, const char *message, va_list vl);
RTM_API rtm_status _rtm_log_message(rtm_status status, const char *message);

#define TRUE 1
#define YES 1
#define FALSE 0
#define NO 0

#define RTM_CLIENT_SIZE (sizeof(struct _rtm_client))

#if defined(RTM_TEST_ENV)
RTM_API rtm_status _rtm_test_parse_endpoint(rtm_client_t *rtm, const char *endpoint, char *hostname_out,
    char *port_out, char *path_out, unsigned *use_tls_out);
RTM_API rtm_status _rtm_test_prepare_path(rtm_client_t *rtm, char *path, const char *appkey);
#endif

// FIXME: add a ifdef and include only in debug builds

#if defined(NDEBUG)
#define ASSERT_NOT_NULL(expression)
#define ASSERT(expression)
#else
#include <assert.h>
#define ASSERT_NOT_NULL(expression) (assert(NULL != (expression)))
#define ASSERT(expression) (assert(expression))
#endif

#define CHECK_PARAM(param) \
  if (param == NULL) \
    return _rtm_log_message(RTM_ERR_PARAM, "param '"#param "' is required")

#define CHECK_MAX_SIZE(param, length)\
  CHECK_PARAM(param); \
  if (strlen(param) > (length) ) \
    return _rtm_log_message(RTM_ERR_PARAM, "param '"#param "' is too long. max=" #length)

#define CHECK_EXACT_SIZE(param, length)\
  CHECK_PARAM(param); \
  if (strlen(param) != (length) ) \
    return _rtm_log_message(RTM_ERR_PARAM, "param '"#param "' is not of expected length " #length)

enum WebSocketOpCode {
    WS_CONTINUATION = 0x00,
    WS_TEXT = 0x01,
    WS_BINARY = 0x02,
    WS_CONTROL_COMMANDS_START = 0x08,
    WS_CLOSE = 0x08,
    WS_PING = 0x09,
    WS_PONG = 0x0A,
    WS_CONTROL_COMMANDS_END = 0x0A,
    WS_OPCODE_LAST = 0x0A,
};

#ifdef __cplusplus
}
#endif
#endif //  CORE_RTM_INTERNAL__INCLUDED

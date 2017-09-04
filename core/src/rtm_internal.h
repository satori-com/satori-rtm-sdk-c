#ifndef CORE_RTM_INTERNAL__INCLUDED
#define CORE_RTM_INTERNAL__INCLUDED

#include "rtm.h"

#include <stdint.h>
#include <stdarg.h>
#include <string.h>

#ifdef _WIN32

#if !defined(__WINDOWS__)
  #define __WINDOWS__
#endif
#include <Winsock2.h>

#include <BaseTsd.h>

typedef SSIZE_T ssize_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define _RTM_MAX_HOSTNAME_SIZE 255 // that's what POSIX says...
#define _RTM_MAX_PORT_SIZE 6       // 5 digits + 0
#define _RTM_MAX_PATH_SIZE (128)

// The scratch buffer can be dangerous when the following rule is not followed: never use the scratch buffer,
// then call another function and assume it is preserved. It's only valid in the scope, and as soon as you leave
// the scope it should be considered invalid.
#define _RTM_SCRATCH_BUFFER_SIZE (256)

#define _RTM_BUFFER_TO_IO(base) (base + _RTM_WS_PRE_BUFFER)
#define _RTM_IO_TO_BUFFER(base) (base - _RTM_WS_PRE_BUFFER)

#define _RTM_INBOUND_HEADER_SIZE_SMALL  (2)
#define _RTM_INBOUND_HEADER_SIZE_NORMAL (2 + 2)
#define _RTM_INBOUND_HEADER_SIZE_LARGE  (2 + 8)

#define _RTM_OUTBOUND_HEADER_SIZE_SMALL  (2 + 4)
#define _RTM_OUTBOUND_HEADER_SIZE_NORMAL (2 + 4 + 2)
#define _RTM_OUTBOUND_HEADER_SIZE_LARGE  (2 + 4 + 8)

#define _RTM_MAX_CONTROL_FRAME_SIZE (125)

enum rtm_field_type_t {
  FIELD_JSON,
  FIELD_ITERATOR,
  FIELD_STRING
};

typedef struct {
  enum rtm_field_type_t type;
  char *name;
  void *dst;
} field_t;

// websocket frame processing
rtm_status _rtm_fill_input_buffer(rtm_client_t *rtm);
RTM_TEST_API rtm_status _rtm_handle_input(rtm_client_t *rtm);

// json methods
RTM_TEST_API char *_rtm_json_escape(char *dest, ssize_t n, const char *str);
char *_rtm_json_find_begin_obj(char *p);
char *_rtm_json_find_element(char* p, char **cursor, size_t *length);
RTM_TEST_API char *_rtm_json_find_kv_pair(char *p, char **key, size_t *key_length, char **value, size_t *value_length);

// Network IO
rtm_status _rtm_io_connect_to_host_and_port(rtm_client_t *rtm, const char *hostname, const char *port);
rtm_status _rtm_io_close(rtm_client_t *rtm);
rtm_status _rtm_io_wait(rtm_client_t *rtm, int readable, int writable, int timeout);
ssize_t    _rtm_io_write(rtm_client_t *rtm, const char *buf, size_t len);
ssize_t    _rtm_io_read(rtm_client_t *rtm, char *buf, size_t len, int wait);
rtm_status _rtm_check_interval_and_send_ws_ping(rtm_client_t *rtm);

void _rtm_calculate_auth_hash(char const *role_secret, char const *nonce, char *output);
rtm_status _rtm_io_open_tls_session(rtm_client_t *rtm, const char *host);
rtm_status _rtm_io_close_tls_session(rtm_client_t *rtm);
ssize_t    _rtm_io_read_tls(rtm_client_t *rtm, char *buf, size_t nbyte, int wait);
ssize_t    _rtm_io_write_tls(rtm_client_t *rtm, const char *buf, size_t nbyte);

void _rtm_b64encode_16bytes(char const *input, char *output);

// Logging
#ifdef RTM_LOGGING
  #define _rtm_log_error _rtm_log_error_impl
  #define _rtm_logv_error _rtm_logv_error_impl
  #define _rtm_log_message _rtm_log_message_impl
#else
  #define _rtm_log_error(...) (1)
  #define _rtm_logv_error(...) (1)
  #define _rtm_log_message(...) (1)
#endif

void _rtm_log_error_impl(rtm_client_t *rtm, rtm_status error, const char *message, ...);
void _rtm_logv_error_impl(rtm_client_t *rtm, rtm_status error, const char *message, va_list vl);
RTM_TEST_API void _rtm_log_message_impl(rtm_client_t *rtm, rtm_status status, const char *message);

#define TRUE 1
#define YES 1
#define FALSE 0
#define NO 0

enum rtm_url_scheme_t {
    SCHEME_WS = 1,
    SCHEME_WSS = 1 << 1,
    SCHEME_HTTP = 1 << 2
};
#if defined(RTM_TEST_ENV)
RTM_API rtm_status _rtm_test_parse_endpoint(
    rtm_client_t *rtm, const char *endpoint, enum rtm_url_scheme_t schemes, char *hostname_out,
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
  if (param == NULL) { \
    _rtm_log_message(rtm, RTM_ERR_PARAM, "param '"#param "' is required"); \
    return RTM_ERR_PARAM; \
  }

#define CHECK_MAX_SIZE(param, length)\
  CHECK_PARAM(param); \
  if (strlen(param) > (length) ) { \
    _rtm_log_message(rtm, RTM_ERR_PARAM, "param '"#param "' is too long. max=" #length); \
    return RTM_ERR_PARAM; \
  }

#define CHECK_EXACT_SIZE(param, length)\
  CHECK_PARAM(param); \
  if (strlen(param) != (length) ) { \
    _rtm_log_message(rtm, RTM_ERR_PARAM, "param '"#param "' is not of expected length " #length); \
    return RTM_ERR_PARAM; \
  }

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

// Byte order
uint16_t _rtm_ntohs(uint16_t in);
#define  _rtm_htons _rtm_ntohs
uint32_t _rtm_ntohl(uint32_t in);
#define  _rtm_htonl _rtm_ntohl
uint64_t _rtm_ntohll(uint64_t in);
#define  _rtm_htonll _rtm_ntohll

#ifdef __cplusplus
}
#endif
#endif //  CORE_RTM_INTERNAL__INCLUDED

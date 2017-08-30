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

/**
 * Internal representation of the RTM client's state
 */
struct _rtm_client {
    void *user; /*!< User specified context pointer. @see ::rtm_get_user_context. */
    int fd; /*!< File descriptor for the socket used by the SDK */

    /**
     * Total number of bytes in the current input buffer currently used for
     * storing a partial frame reconstructed from a number of
     * fragmented/continuation frames
     */
    size_t fragmented_message_length;

    /**
     * Total number of bytes in the current input buffer currently used for
     * storing unprocessed input
     */
    size_t input_length;

    /**
     * Number of bytes to be skipped when reading incoming data. Incoming bytes
     * are normaly stored in the input buffer. If this variable is non-zero, then
     * the next that-many bytes are instead discarded.
     */
    size_t skip_next_n_input_bytes;

    unsigned is_closed: 1; /*!< Whether the SDK is currently connected */
    unsigned is_used: 1; /*!< Whether there is a pending operation in the SDK */
    unsigned is_verbose: 1; /*!< Whether to verbosely log debug information */

    /**
     * Whether the current fragmented message should be skipped instead of
     * processing it.
     *
     * The SDK normally reassembles messages from fragments. If the user knows
     * that there isn't enough memory available to store the whole message,
     * then they can decide to skip a message completely.
     **/
    unsigned skip_current_fragmented_message: 1;

    unsigned last_request_id; /*!< The largest request ID used so far */
    unsigned last_ping_ts; /*!< Timestamp of the last websocket ping */
    time_t ws_ping_interval; /*!< How often to send websocket pings */

    unsigned is_secure: 1; /*!< Whether this connection uses TLS */
#if defined(USE_GNUTLS)
    gnutls_session_t session;
#elif defined(USE_OPENSSL)
    SSL_CTX *ssl_context;
    SSL *ssl_connection;
#elif defined(USE_APPLE_SSL)
    SSLContextRef sslContext;
#endif

    unsigned connect_timeout; /*!< Number of seconds to wait for connect() to succeed */
    rtm_pdu_handler_t *handle_pdu; /*!< PDU handler function pointer */
    rtm_raw_pdu_handler_t *handle_raw_pdu; /*!< Raw PDU handler function pointer */

    rtm_error_logger_t *error_logger; /*!< Error logger function pointer */
    rtm_malloc_fn_t *malloc_fn; /*!< malloc() function pointer */
    rtm_free_fn_t *free_fn; /*!< free() function pointer */

    /**
     * The scratch buffer is used for format error messages
     */
    char scratch_buffer[_RTM_SCRATCH_BUFFER_SIZE];

    // The buffers are padded so we are always guaranteed to have
    // enough bytes to pre pad any buffer with websocket framing

    /**
     * The input buffer is used to store incoming data until it is processed.
     *
     * It's memory layout is as follows:
     *
     * input_buffer + 0:
     *   The payload of a fragmented message which is yet to be received
     *   completely
     *
     * input_buffer + fragmented_message_length:
     *   Any (partially) received frames that have not been processed yet
     *
     * input_buffer + fragmented_message_length + input_length:
     *   Unused buffer space
     *
     * input_buffer + input_buffer_size:
     *   End of the input buffer
     *
     * If the memory in the input buffer does not suffice to store a message,
     * the SDK might use the dynamic_input_buffer instead. It will take care
     * of allocating memory & moving the data around.
     *
     * @see ::rtm_set_allocator
     *
     */
    char *input_buffer;
    size_t input_buffer_size; /*!< Input buffer size */

    /**
     * The output buffer is used to construct outgoing data
     *
     * Any messages constructed within this buffer must be offset by
     * _RTM_WS_PRE_BUFFER bytes, because the function used to send websocket
     * frames will prepend a websocket header to messages which can be up to
     * _RTM_WS_PRE_BUFFER bytes long.
     *
     * If the buffer size is not enough to store a message, the SDK might
     * dynamically allocate space instead.
     *
     * @see ::rtm_set_allocator
     */
    size_t output_buffer_size;
    char *output_buffer;

    size_t dynamic_input_buffer_size; /*!< Dynamic input buffer. @see input_buffer */
    char *dynamic_input_buffer; /*!< Size of the dynamic input buffer */
};

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
rtm_status _rtm_handle_input(rtm_client_t *rtm);

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
void _rtm_log_error(rtm_client_t *rtm, rtm_status error, const char *message, ...);
void _rtm_logv_error(rtm_client_t *rtm, rtm_status error, const char *message, va_list vl);
RTM_TEST_API void _rtm_log_message(rtm_client_t *rtm, rtm_status status, const char *message);

#define TRUE 1
#define YES 1
#define FALSE 0
#define NO 0

#define _RTM_MINIMAL_PDU_SIZE    256 /* Enough to store handshake and authentication PDUs */
#define _RTM_CLIENT_SIZE(buffer_size)  (sizeof(struct _rtm_client) + _RTM_WS_PRE_BUFFER + 2*(buffer_size + 1))
#define _RTM_CLIENT_MIN_SIZE     _RTM_CLIENT_SIZE(_RTM_MINIMAL_PDU_SIZE)
#define _RTM_CLIENT_DESIRED_SIZE _RTM_CLIENT_SIZE(_RTM_MAX_BUFFER)

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

#ifdef __cplusplus
}
#endif
#endif //  CORE_RTM_INTERNAL__INCLUDED

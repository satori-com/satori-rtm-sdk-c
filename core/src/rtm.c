#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <panzi/portable_endian.h>

#include "rtm_internal.h"

#define MAX_INTERESTING_FIELDS_IN_PDU 3
const size_t rtm_client_size = _RTM_CLIENT_DESIRED_SIZE;
const size_t rtm_client_min_size = _RTM_CLIENT_MIN_SIZE;

void rtm_default_text_frame_handler(rtm_client_t *rtm, char *message, size_t message_len);
void(*rtm_text_frame_handler)(rtm_client_t *rtm, char *message, size_t message_len) = rtm_default_text_frame_handler;

// Network
static enum rtm_url_scheme_t const websocket_schemes = SCHEME_WS | SCHEME_WSS;
static enum rtm_url_scheme_t const proxy_schemes = SCHEME_HTTP;
static rtm_status _rtm_parse_endpoint(rtm_client_t *rtm, const char *endpoint, enum rtm_url_scheme_t scheme,
    char *hostname_out, char *port_out, char *path_out, unsigned *use_tls_out);
static rtm_status _rtm_prepare_path(rtm_client_t *rtm, char *path, const char *appkey);
static rtm_status _rtm_send_http_upgrade_request(rtm_client_t *rtm,
    const char *hostname, const char *path);
static rtm_status _rtm_check_http_upgrade_response(rtm_client_t *rtm);
static ssize_t _rtm_ws_write(rtm_client_t *rtm, uint8_t op, char *io_buffer, size_t len);

// PDU formatting
static char *_rtm_prepare_pdu(rtm_client_t *rtm, char *buf, ssize_t size,
    const char *action, const char *body, unsigned *ack_id_out);
static char *_rtm_prepare_pdu_without_body(rtm_client_t *rtm, char *buf, ssize_t size,
    const char *action, unsigned *ack_id_out);

/**
 * Try to snprintf to dst
 *
 * @return A pointer pointing to the end of dst or NULL in case of insufficient
 *         memory.
 */
static char *_rtm_snprintf(char *dst, ssize_t max_size, char const *fmt, ...) {
  if (max_size <= 0 || dst == NULL) {
    return NULL;
  }

  va_list args;
  va_start(args, fmt);
  int result = vsnprintf(dst, max_size, fmt, args);
  va_end(args);

  if (result < 0 || result >= max_size) {
    return NULL;
  }

  dst += result;

  return dst;
}

RTM_API rtm_client_t * rtm_init(
  void *memory,
  rtm_pdu_handler_t *pdu_handler,
  void *user_context) {

  // FIXME The size of *memory should be passed by the client
  const size_t memory_size = _RTM_CLIENT_DESIRED_SIZE;

  if(memory_size < _RTM_CLIENT_MIN_SIZE) {
    return NULL;
  }

  if (memory == NULL) {
    return NULL;
  }

  memset(memory, 0, memory_size);

  rtm_client_t *rtm = (rtm_client_t *)memory;
  rtm->fd = -1;
  rtm->input_length = 0;
  rtm->last_request_id = 0;
  rtm->is_closed = NO;
  rtm->is_used = NO;
  rtm->handle_pdu = pdu_handler;
  rtm->user = user_context;
  rtm->scratch_buffer[0] = '\0';
  rtm->is_secure = NO;
  rtm->ws_ping_interval = 45;
  rtm->connect_timeout = 5;
  rtm->error_logger = rtm_default_error_logger;

  size_t available_memory_for_buffers = memory_size - sizeof(rtm_client_t) - _RTM_WS_PRE_BUFFER;
  size_t buffer_size = available_memory_for_buffers / 2;

  rtm->input_buffer = (char*)memory + sizeof(rtm_client_t);
  rtm->input_buffer_size = buffer_size;
  rtm->output_buffer = rtm->input_buffer + buffer_size;
  rtm->output_buffer_size = buffer_size + _RTM_WS_PRE_BUFFER;

  if (getenv("DEBUG_SATORI_SDK")) {
    rtm->is_verbose = YES;
  }

  return rtm;
}

/**
 * Perform handshake with an HTTP proxy using CONNECT. Blocks until the server
 * confirms.
 *
 * @return RTM_OK if the handshake was successfull, or an error.
 */
static rtm_status perform_proxy_handshake(rtm_client_t *rtm, char const *hostname, char const *port) {
  int len = snprintf(rtm->output_buffer, rtm->output_buffer_size, "CONNECT %s:%s HTTP/1.0\r\n\r\n", hostname, port);
  if(len < 0 || len >= rtm->output_buffer_size) {
    return RTM_ERR_OOM;
  }
  int written = _rtm_io_write(rtm, rtm->output_buffer, len);
  if (written < len) {
    return RTM_ERR_WRITE;
  }

  const size_t buffer_size = rtm->input_buffer_size;
  char *input_buffer = rtm->input_buffer;
  size_t input_length = 0;
  while (1) {
    char *end_of_header;
    if (buffer_size <= input_length) {
      _rtm_io_close(rtm);
      _rtm_log_error(rtm, RTM_ERR_OOM, "Insufficient memory to store HTTP CONNECT response.");
      return RTM_ERR_OOM;
    }

    ssize_t read = _rtm_io_read(rtm, input_buffer + input_length, buffer_size - input_length, YES);
    if (read <= 0) {
      _rtm_io_close(rtm);
      _rtm_log_error(rtm, RTM_ERR_READ, "Error reading from network while waiting for connection response");
      return RTM_ERR_READ;
    }
    input_length += read;

    input_buffer[input_length] = 0;
    end_of_header = strstr(input_buffer, "\r\n\r\n");
    if (end_of_header) {
      if (strncmp(input_buffer, "HTTP/1.1 200", 12) != 0 && strncmp(input_buffer, "HTTP/1.0 200", 12) != 0) {
        _rtm_log_error(rtm, RTM_ERR_PROTOCOL, "Received unexpected response from server:");
        _rtm_log_message(rtm, RTM_ERR_PROTOCOL, input_buffer);
        _rtm_io_close(rtm);
        return RTM_ERR_PROTOCOL;
      }

      return RTM_OK;
    }
  }

  return RTM_OK;
}

/**
 * Establish a RTM connection
 *
 * @return RTM_OK, or an error
 */
static rtm_status _rtm_io_connect(
    rtm_client_t *rtm,
    char const *endpoint,
    char const *appkey,
    char const *proxy_endpoint) {
  CHECK_PARAM(rtm);
  CHECK_MAX_SIZE(endpoint, RTM_MAX_ENDPOINT_SIZE);
  CHECK_MAX_SIZE(appkey, RTM_MAX_APPKEY_SIZE);

  char hostname[_RTM_MAX_HOSTNAME_SIZE + 1] = { 0 };
  char port[_RTM_MAX_PORT_SIZE + 1] = { 0 };
  char path[_RTM_MAX_PATH_SIZE + 1] = { 0 };

  unsigned use_tls = NO;

  if (strlen(endpoint) < 10) {
    // 10 is the minimum size of the endpoint string ws://api.satori.com/
    _rtm_log_error(rtm, RTM_ERR_PARAM_INVALID, "endpoint malformed – too short.");
    return RTM_ERR_PARAM_INVALID;
  }

  rtm_status rc;

  rc = _rtm_parse_endpoint(rtm, endpoint, websocket_schemes, hostname, port, path, &use_tls);
  if (RTM_OK != rc)
    return rc;

  rc = _rtm_prepare_path(rtm, path, appkey);
  if (RTM_OK != rc) {
    return rc;
  }

  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(hostname);
  ASSERT_NOT_NULL(port);

  rtm->fd = -1;
  if (proxy_endpoint) {
    char proxy_host[_RTM_MAX_HOSTNAME_SIZE + 1] = { 0 };
    char proxy_port[_RTM_MAX_PORT_SIZE + 1] = { 0 };
    char proxy_path[_RTM_MAX_PATH_SIZE + 1] = { 0 };
    unsigned proxy_tls = 0;
    rc = _rtm_parse_endpoint(rtm, proxy_endpoint, proxy_schemes, proxy_host, proxy_port, proxy_path, &proxy_tls);
    if (RTM_OK != rc) {
      return rc;
    }

    rc = _rtm_io_connect_to_host_and_port(rtm, proxy_host, proxy_port);
    if (RTM_OK != rc) {
      return rc;
    }

    rc = perform_proxy_handshake(rtm, hostname, port);
    if (RTM_OK != rc) {
      return rc;
    }
  } else {
    rc = _rtm_io_connect_to_host_and_port(rtm, hostname, port);
  }

  if (RTM_OK != rc) {
    return rc;
  }

  rtm->is_secure = NO;
  if (use_tls) {
    rc = _rtm_io_open_tls_session(rtm, hostname);
    if (RTM_OK != rc) {
      _rtm_io_close(rtm);
      return rc;
    }
    rtm->is_secure = YES;
  }

  // Connection established. Set current time as the last ping time.
  rtm->last_ping_ts = time(NULL);

  rc = _rtm_send_http_upgrade_request(rtm, hostname, path);
  if (RTM_OK != rc)
    return rc;

  rc = _rtm_check_http_upgrade_response(rtm);
  if (RTM_OK != rc)
    return rc;

  return RTM_OK;
}

rtm_status rtm_connect_via_https_proxy(
    rtm_client_t *rtm,
    char const *endpoint,
    char const *appkey,
    char const *proxy_endpoint) {
  CHECK_PARAM(proxy_endpoint);
  return _rtm_io_connect(rtm, endpoint, appkey, proxy_endpoint);
}

rtm_status rtm_connect(rtm_client_t *rtm, const char *endpoint, const char *appkey) {
  return _rtm_io_connect(rtm, endpoint, appkey, NULL);
}


void rtm_close(rtm_client_t *rtm) {
  if (!rtm) {
    return;
  }
  _rtm_io_close(rtm);
}

rtm_status rtm_handshake(rtm_client_t *rtm, const char *role_name, unsigned *ack_id) {
  CHECK_PARAM(rtm);
  CHECK_MAX_SIZE(role_name, RTM_MAX_ROLE_NAME_SIZE);

  char* const buf = _RTM_BUFFER_TO_IO(rtm->output_buffer);
  const size_t size = rtm->output_buffer_size - _RTM_WS_PRE_BUFFER;
  char *p = buf;

  p = _rtm_prepare_pdu_without_body(rtm, p, size, "auth/handshake", ack_id);
  p = _rtm_snprintf(p, size - (p - buf), "{\"method\":\"role_secret\",\"data\":{\"role\":\"");
  p = _rtm_json_escape(p, size - (p - buf), role_name);
  p = _rtm_snprintf(p, size - (p - buf), "\"}}}");

  if (!p) {
    return RTM_ERR_OOM;
  }

  ssize_t written = _rtm_ws_write(rtm, WS_TEXT, rtm->output_buffer, p - buf);
  return (written < 0) ? RTM_ERR_WRITE : RTM_OK;
}

rtm_status rtm_authenticate(rtm_client_t *rtm, const char *role_secret, const char *nonce, unsigned *ack_id) {
  CHECK_PARAM(rtm);

  char hash[RTM_AUTHENTICATION_HASH_SIZE + 1] = {0};
  _rtm_calculate_auth_hash(role_secret, nonce, hash);

  char* const buf = _RTM_BUFFER_TO_IO(rtm->output_buffer);
  const ssize_t size = rtm->output_buffer_size - _RTM_WS_PRE_BUFFER;
  char *p = buf;

  p = _rtm_prepare_pdu_without_body(rtm, p, size, "auth/authenticate", ack_id);
  p = _rtm_snprintf(p, size - (p - buf), "{\"method\":\"role_secret\",\"credentials\":{\"hash\":\"");
  p = _rtm_json_escape(p, size - (p - buf), hash);
  p = _rtm_snprintf(p, size - (p - buf), "\"}}}");

  if (!p) {
    return RTM_ERR_OOM;
  }

  ssize_t written = _rtm_ws_write(rtm, WS_TEXT, rtm->output_buffer, p - buf);
  return (written < 0) ? RTM_ERR_WRITE : RTM_OK;
}

rtm_status rtm_publish_string(rtm_client_t *rtm, const char *channel, const char *string, unsigned *ack_id) {
  CHECK_PARAM(rtm);
  CHECK_MAX_SIZE(channel, RTM_MAX_CHANNEL_SIZE);
  CHECK_MAX_SIZE(string, RTM_MAX_MESSAGE_SIZE);

  if (!ack_id) {
    rtm_status rc;
    rc = _rtm_check_interval_and_send_ws_ping(rtm);
    if (RTM_OK != rc) {
      return rc;
    }
  }

  char* const buf = _RTM_BUFFER_TO_IO(rtm->output_buffer);
  const ssize_t size = rtm->output_buffer_size - _RTM_WS_PRE_BUFFER;
  char *p = buf;

  p = _rtm_prepare_pdu_without_body(rtm, p, size, "rtm/publish", ack_id);
  p = _rtm_snprintf(p, size - (p - buf), "{\"channel\":\"");
  p = _rtm_json_escape(p, size - (p - buf), channel);
  p = _rtm_snprintf(p, size - (p - buf), "\",\"message\":\"");
  p = _rtm_json_escape(p, size - (p - buf), string);
  p = _rtm_snprintf(p, size - (p - buf), "\"}}");

  if (!p) {
    return RTM_ERR_OOM;
  }

  ssize_t written = _rtm_ws_write(rtm, WS_TEXT, rtm->output_buffer, p - buf);
  return (written < 0) ? RTM_ERR_WRITE : RTM_OK;
}

rtm_status rtm_publish_json(rtm_client_t *rtm, const char *channel, const char *json, unsigned *ack_id) {
  CHECK_PARAM(rtm);
  CHECK_MAX_SIZE(channel, RTM_MAX_CHANNEL_SIZE);
  CHECK_MAX_SIZE(json, RTM_MAX_MESSAGE_SIZE);

  if (!ack_id) {
    rtm_status rc;
    rc = _rtm_check_interval_and_send_ws_ping(rtm);
    if (RTM_OK != rc) {
      return rc;
    }
  }

  char* const buf = _RTM_BUFFER_TO_IO(rtm->output_buffer);
  const ssize_t size = rtm->output_buffer_size - _RTM_WS_PRE_BUFFER;
  char *p = buf;

  p = _rtm_prepare_pdu_without_body(rtm, p, size, "rtm/publish", ack_id);
  p = _rtm_snprintf(p, size - (p - buf), "{\"channel\":\"");
  p = _rtm_json_escape(p, size - (p - buf), channel);
  p = _rtm_snprintf(p, size - (p - buf), "\",\"message\":%s}}", json);

  if (!p) {
    return RTM_ERR_OOM;
  }

  ssize_t written = _rtm_ws_write(rtm, WS_TEXT, rtm->output_buffer, p - buf);
  return (written < 0) ? RTM_ERR_WRITE : RTM_OK;
}

rtm_status rtm_subscribe(rtm_client_t *rtm, const char *channel, unsigned *ack_id) {
  CHECK_PARAM(rtm);
  CHECK_MAX_SIZE(channel, RTM_MAX_CHANNEL_SIZE);

  char* const buf = _RTM_BUFFER_TO_IO(rtm->output_buffer);
  const ssize_t size = rtm->output_buffer_size - _RTM_WS_PRE_BUFFER;
  char *p = buf;

  p = _rtm_prepare_pdu_without_body(rtm, p, size, "rtm/subscribe", ack_id);
  p = _rtm_snprintf(p, size - (p - buf), "{\"channel\":\"");
  p = _rtm_json_escape(p, size - (p - buf), channel);
  p = _rtm_snprintf(p, size - (p - buf), "\"}}");

  if (!p) {
    return RTM_ERR_OOM;
  }

  ssize_t written = _rtm_ws_write(rtm, WS_TEXT, rtm->output_buffer, p - buf);
  return (written < 0) ? RTM_ERR_WRITE : RTM_OK;
}

rtm_status rtm_subscribe_with_body(rtm_client_t *rtm, const char *body, unsigned *ack_id) {
  CHECK_PARAM(rtm);

  char* const buf = _RTM_BUFFER_TO_IO(rtm->output_buffer);
  char *p = _rtm_prepare_pdu(rtm, buf, rtm->output_buffer_size - _RTM_WS_PRE_BUFFER, "rtm/subscribe", body, ack_id);

  if (!p) {
    return RTM_ERR_OOM;
  }

  ssize_t written = _rtm_ws_write(rtm, WS_TEXT, rtm->output_buffer, p - buf);
  return (written < 0) ? RTM_ERR_WRITE : RTM_OK;
}

rtm_status rtm_unsubscribe(rtm_client_t *rtm, const char *subscription_id, unsigned *ack_id) {
  CHECK_PARAM(rtm);
  CHECK_MAX_SIZE(subscription_id, RTM_MAX_CHANNEL_SIZE);

  char* const buf = _RTM_BUFFER_TO_IO(rtm->output_buffer);
  const ssize_t size = rtm->output_buffer_size - _RTM_WS_PRE_BUFFER;
  char *p = buf;

  p = _rtm_prepare_pdu_without_body(rtm, p, size, "rtm/unsubscribe", ack_id);
  p = _rtm_snprintf(p, size - (p - buf), "{\"subscription_id\":\"");
  p = _rtm_json_escape(p, size - (p - buf), subscription_id);
  p = _rtm_snprintf(p, size - (p - buf), "\"}}");

  if (!p) {
    return RTM_ERR_OOM;
  }

  ssize_t written = _rtm_ws_write(rtm, WS_TEXT, rtm->output_buffer, p - buf);
  return (written < 0) ? RTM_ERR_WRITE : RTM_OK;
}

int rtm_get_fd(rtm_client_t *rtm) {
  ASSERT_NOT_NULL(rtm);
  return rtm->fd; // OR: rtm ? rtm->fd : -1;
}

time_t rtm_get_ws_ping_interval(rtm_client_t *rtm) {
  ASSERT_NOT_NULL(rtm);
  return rtm->ws_ping_interval;
}

void rtm_set_connection_timeout(rtm_client_t *rtm, unsigned timeout_in_seconds) {
  ASSERT_NOT_NULL(rtm);
  rtm->connect_timeout = timeout_in_seconds;
}

void rtm_set_ws_ping_interval(rtm_client_t *rtm, time_t ws_ping_interval) {
  ASSERT_NOT_NULL(rtm);
  rtm->ws_ping_interval = ws_ping_interval;
}

rtm_status rtm_read(rtm_client_t *rtm, const char *channel, unsigned *ack_id) {
  CHECK_PARAM(rtm);
  CHECK_PARAM(channel);
  CHECK_PARAM(ack_id);

  char* const buf = _RTM_BUFFER_TO_IO(rtm->output_buffer);
  const ssize_t size = rtm->output_buffer_size - _RTM_WS_PRE_BUFFER;
  char *p = buf;

  p = _rtm_prepare_pdu_without_body(rtm, p, size, "rtm/read", ack_id);
  p = _rtm_snprintf(p, size - (p - buf), "{\"channel\":\"");
  p = _rtm_json_escape(p, size - (p - buf), channel);
  p = _rtm_snprintf(p, size - (p - buf), "\"}}");

  if (!p) {
    return RTM_ERR_OOM;
  }

  ssize_t written = _rtm_ws_write(rtm, WS_TEXT, rtm->output_buffer, p - buf);
  return (written < 0) ? RTM_ERR_WRITE : RTM_OK;
}

rtm_status rtm_read_with_body(rtm_client_t *rtm, const char *body, unsigned *ack_id) {
  CHECK_PARAM(rtm);

  char* const buf = _RTM_BUFFER_TO_IO(rtm->output_buffer);
  char *p = _rtm_prepare_pdu(rtm, buf, rtm->output_buffer_size - _RTM_WS_PRE_BUFFER, "rtm/read", body, ack_id);

  if (!p) {
    return RTM_ERR_OOM;
  }

  ssize_t written = _rtm_ws_write(rtm, WS_TEXT, rtm->output_buffer, p - buf);
  return (written < 0) ? RTM_ERR_WRITE : RTM_OK;
}

rtm_status rtm_write_string(rtm_client_t *rtm, const char *channel, const char *string, unsigned *ack_id) {
  CHECK_PARAM(rtm);
  CHECK_MAX_SIZE(channel, RTM_MAX_CHANNEL_SIZE);
  CHECK_MAX_SIZE(string, RTM_MAX_MESSAGE_SIZE);

  if (!ack_id) {
    rtm_status rc;
    rc = _rtm_check_interval_and_send_ws_ping(rtm);
    if (RTM_OK != rc) {
      return rc;
    }
  }

  char* const buf = _RTM_BUFFER_TO_IO(rtm->output_buffer);
  const ssize_t size = rtm->output_buffer_size - _RTM_WS_PRE_BUFFER;
  char *p = buf;

  p = _rtm_prepare_pdu_without_body(rtm, p, size, "rtm/write", ack_id);
  p = _rtm_snprintf(p, size - (p - buf), "{\"channel\":\"");
  p = _rtm_json_escape(p, size - (p - buf), channel);
  p = _rtm_snprintf(p, size - (p - buf), "\",\"message\":\"");
  p = _rtm_json_escape(p, size - (p - buf), string);
  p = _rtm_snprintf(p, size - (p - buf), "\"}}");

  if (!p) {
    return RTM_ERR_OOM;
  }

  ssize_t written = _rtm_ws_write(rtm, WS_TEXT, rtm->output_buffer, p - buf);
  return (written < 0) ? RTM_ERR_WRITE : RTM_OK;
}

rtm_status rtm_write_json(rtm_client_t *rtm, const char *channel, const char *json, unsigned *ack_id) {
  CHECK_PARAM(rtm);
  CHECK_MAX_SIZE(channel, RTM_MAX_CHANNEL_SIZE);
  CHECK_MAX_SIZE(json, RTM_MAX_MESSAGE_SIZE);

  if (!ack_id) {
    rtm_status rc;
    rc = _rtm_check_interval_and_send_ws_ping(rtm);
    if (RTM_OK != rc) {
      return rc;
    }
  }

  char* const buf = _RTM_BUFFER_TO_IO(rtm->output_buffer);
  const ssize_t size = rtm->output_buffer_size - _RTM_WS_PRE_BUFFER;
  char *p = buf;

  p = _rtm_prepare_pdu_without_body(rtm, p, size, "rtm/write", ack_id);
  p = _rtm_snprintf(p, size - (p - buf), "{\"channel\":\"");
  p = _rtm_json_escape(p, size - (p - buf), channel);
  p = _rtm_snprintf(p, size - (p - buf), "\",\"message\":%s}}", json);

  if (!p) {
    return RTM_ERR_OOM;
  }

  ssize_t written = _rtm_ws_write(rtm, WS_TEXT, rtm->output_buffer, p - buf);
  return (written < 0) ? RTM_ERR_WRITE : RTM_OK;
}

rtm_status rtm_delete(rtm_client_t *rtm, const char *channel, unsigned *ack_id) {
  CHECK_PARAM(rtm);

  char* const buf = _RTM_BUFFER_TO_IO(rtm->output_buffer);
  const ssize_t size = rtm->output_buffer_size - _RTM_WS_PRE_BUFFER;
  char *p = buf;

  p = _rtm_prepare_pdu_without_body(rtm, p, size, "rtm/delete", ack_id);
  p = _rtm_snprintf(p, size - (p - buf), "{\"channel\":\"");
  p = _rtm_json_escape(p, size - (p - buf), channel);
  p = _rtm_snprintf(p, size - (p - buf), "\"}}");

  if (!p) {
    return RTM_ERR_OOM;
  }

  ssize_t written = _rtm_ws_write(rtm, WS_TEXT, rtm->output_buffer, p - buf);
  return (written < 0) ? RTM_ERR_WRITE : RTM_OK;
}

rtm_status rtm_send_pdu(rtm_client_t *rtm, const char *json) {
  CHECK_PARAM(rtm);
  CHECK_MAX_SIZE(json, RTM_MAX_MESSAGE_SIZE);

  char* const buf = _RTM_BUFFER_TO_IO(rtm->output_buffer);
  char *p = _rtm_snprintf(buf, rtm->output_buffer_size - _RTM_WS_PRE_BUFFER, "%s", json);

  if (!p) {
    return RTM_ERR_OOM;
  }

  ssize_t written = _rtm_ws_write(rtm, WS_TEXT, rtm->output_buffer, p - buf);
  return (written < 0) ? RTM_ERR_WRITE : RTM_OK;
}

rtm_status rtm_send_ws_ping(rtm_client_t *rtm) {
  CHECK_PARAM(rtm);

  char* const buf = _RTM_BUFFER_TO_IO(rtm->output_buffer);

  // the contents of the body are arbitrary, but we "ping" to make a request obvious
  strcpy(buf, "ping");

  ssize_t written = _rtm_ws_write(rtm, WS_PING, rtm->output_buffer, 5);
  return (written < 0) ? RTM_ERR_WRITE : RTM_OK;
}

void *rtm_get_user_context(rtm_client_t *rtm) {
  ASSERT_NOT_NULL(rtm);
  return rtm->user; //OR: rtm ? rtm->user : NULL;
}

rtm_status rtm_wait(rtm_client_t *rtm) {
  CHECK_PARAM(rtm); // assert?
  rtm_status rc;
  while (TRUE) {
    rc = rtm_poll(rtm);
    if (rc != RTM_WOULD_BLOCK) {
      return rc;
    }
    rc = _rtm_io_wait(rtm, YES, NO, -1);
    if (RTM_OK != rc)
      return rc;
  };
}

rtm_status rtm_wait_timeout(rtm_client_t *rtm, int timeout_in_seconds) {
  CHECK_PARAM(rtm); // assert?
  rtm_status rc;
  time_t start = time(NULL);
  while (TRUE) {
    rc = rtm_poll(rtm);
    if (rc != RTM_WOULD_BLOCK) {
      return rc;
    }
    time_t now = time(NULL);
    if (now > start + timeout_in_seconds) {
      return RTM_ERR_TIMEOUT;
    }
    int poll_timeout = 1000 * (timeout_in_seconds - (int)(now - start));
    rc = _rtm_io_wait(rtm, YES, NO, poll_timeout);
    if (RTM_OK != rc)
      return rc;
  };
}

static const char *const action_table[] = {
    [RTM_ACTION_GENERAL_ERROR] = "/error",
    [RTM_ACTION_AUTHENTICATE_ERROR] = "auth/authenticate/error",
    [RTM_ACTION_AUTHENTICATE_OK] = "auth/authenticate/ok",
    [RTM_ACTION_DELETE_ERROR] = "rtm/delete/error",
    [RTM_ACTION_DELETE_OK] = "rtm/delete/ok",
    [RTM_ACTION_HANDSHAKE_ERROR] = "auth/handshake/error",
    [RTM_ACTION_HANDSHAKE_OK] = "auth/handshake/ok",
    [RTM_ACTION_PUBLISH_ERROR] = "rtm/publish/error",
    [RTM_ACTION_PUBLISH_OK] = "rtm/publish/ok",
    [RTM_ACTION_READ_ERROR] = "rtm/read/error",
    [RTM_ACTION_READ_OK] = "rtm/read/ok",
    [RTM_ACTION_SUBSCRIBE_ERROR] = "rtm/subscribe/error",
    [RTM_ACTION_SUBSCRIBE_OK] = "rtm/subscribe/ok",
    [RTM_ACTION_SUBSCRIPTION_DATA] = "rtm/subscription/data",
    [RTM_ACTION_SUBSCRIPTION_INFO] = "rtm/subscription/info",
    [RTM_ACTION_SUBSCRIPTION_ERROR] = "rtm/subscription/error",
    [RTM_ACTION_UNSUBSCRIBE_ERROR] = "rtm/unsubscribe/error",
    [RTM_ACTION_UNSUBSCRIBE_OK] = "rtm/unsubscribe/ok",
    [RTM_ACTION_WRITE_ERROR] = "rtm/write/error",
    [RTM_ACTION_WRITE_OK] = "rtm/write/ok"
};

void rtm_default_error_logger(const char *message) {
  // FIXME USE NSLog on Mac and iOS
  fprintf(stderr, "%s\n", message);
  fflush(stderr);
}

void rtm_default_pdu_handler(rtm_client_t *rtm, const rtm_pdu_t *pdu) {
  printf("received pdu: client=%p, action=%s, id=%u\n",
      (void*) rtm, action_table[pdu->action], pdu->request_id);
  switch (pdu->action) {
    case RTM_ACTION_SUBSCRIPTION_DATA: {
      char *message;
      while ((message = rtm_iterate(&pdu->message_iterator))) {
          printf("%s\n", message);
      }
      break;
    }
    case RTM_ACTION_GENERAL_ERROR:
    case RTM_ACTION_AUTHENTICATE_ERROR:
    case RTM_ACTION_DELETE_ERROR:
    case RTM_ACTION_HANDSHAKE_ERROR:
    case RTM_ACTION_PUBLISH_ERROR:
    case RTM_ACTION_READ_ERROR:
    case RTM_ACTION_SUBSCRIBE_ERROR:
    case RTM_ACTION_UNSUBSCRIBE_ERROR:
    case RTM_ACTION_WRITE_ERROR:
      printf("error: %s, reason: %s\n", pdu->error, pdu->reason);
      break;
    default:
      break;
  }
}

const char *rtm_error_string(rtm_status status) {
  switch (status) {
    case RTM_OK:
      return "RTM_OK: No error.";
    case RTM_WOULD_BLOCK:
      return "RTM_WOULD_BLOCK: The operation would be a blocking I/O operation.";
    case RTM_ERR_PARAM:
      return "RTM_ERR_PARAM: One of the parameters passed to the function is incorrect.";
    case RTM_ERR_CONNECT:
      return "RTM_ERR_CONNECT: The client could not connect to RTM.";
    case RTM_ERR_NETWORK:
      return "RTM_ERR_NETWORK: An unexpected network error occurred.";
    case RTM_ERR_CLOSED:
      return "RTM_ERR_CLOSED: The connection is closed.";
    case RTM_ERR_READ:
      return "RTM_ERR_READ: An error occurred while receiving data from RTM.";
    case RTM_ERR_WRITE:
      return "RTM_ERR_WRITE: An error occurred while sending data to RTM.";
    case RTM_ERR_PROTOCOL:
      return "RTM_ERR_PROTOCOL: An error occurred in the protocol layer.";
    case RTM_ERR_TLS:
      return "RTM_ERR_TLS: An unexpected error happened in the TLS layer.";
    case RTM_ERR_TIMEOUT:
      return "RTM_ERR_TIMEOUT: The operation timed out.";
    case RTM_ERR_OOM:
      return "RTM_ERR_OOM: Insufficient memory to complete the operation.";
    default:
      return "RTM_UNKNOWN: Unknown status of operation.";
  }
}

// Internal code

static rtm_status _rtm_check_http_upgrade_response(rtm_client_t *rtm) {
  const ssize_t buffer_size = rtm->input_buffer_size;
  char *input_buffer = rtm->input_buffer;
  // read HTTP response header
  size_t input_length = 0;
  while (TRUE) {
    const char *end_of_header;
    if (buffer_size <= input_length) {
      _rtm_io_close(rtm);
      _rtm_log_error(rtm, RTM_ERR_OOM, "Insufficient memory to store HTTP response.");
      return RTM_ERR_OOM;
    }

    ssize_t bytes_read = _rtm_io_read(rtm, input_buffer + input_length, buffer_size - input_length, YES);
    if (bytes_read <= 0) {
      _rtm_io_close(rtm);
      _rtm_log_error(rtm, RTM_ERR_READ, "Error reading from network while waiting for connection response");
      return RTM_ERR_READ;
    }

    input_length += bytes_read;
    input_buffer[input_length] = 0;

    end_of_header = strstr(input_buffer, "\r\n\r\n");
    if (end_of_header) {
      size_t header_len = end_of_header - input_buffer + 4; // include the blank line we just matched
      if (strncmp(input_buffer, "HTTP/1.1 101", 12) != 0) {
        _rtm_log_error(rtm, RTM_ERR_PROTOCOL, "Received unexpected response from server:");
        _rtm_log_message(rtm, RTM_ERR_PROTOCOL, input_buffer);
        _rtm_io_close(rtm);
        return RTM_ERR_PROTOCOL;
      }
      memmove(input_buffer, end_of_header, input_length - header_len);
      rtm->input_length = input_length - header_len;
      break;
    }
  }
  return RTM_OK;
}

static rtm_status _rtm_send_http_upgrade_request(rtm_client_t *rtm, const char *hostname, const char *path) {
  static const char sec_key[] = "cnRtLXNlY3VyaXR5LWtleQ==";

  char *request = rtm->output_buffer;

  char *p = _rtm_snprintf(request, rtm->output_buffer_size,
      "GET %s HTTP/1.1\r\n"
      "Host: %s\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Key: %s\r\n"
      "Sec-WebSocket-Version: 13\r\n\r\n",
      path, hostname, sec_key);

  if (!p) {
    return RTM_ERR_OOM;
  }

  if (_rtm_io_write(rtm, request, p - request) < 0) {
    _rtm_log_error(rtm, RTM_ERR_WRITE, "Error writing to network during connection handshake");
    _rtm_io_close(rtm);
    return RTM_ERR_PROTOCOL;
  }
  return RTM_OK;
}

#define WS_PREFIX "ws://"
#define WSS_PREFIX "wss://"
#define HTTP_PREFIX "http://"

static rtm_status _rtm_check_hostname_length(rtm_client_t *rtm, size_t length) {
  if (length < _RTM_MAX_HOSTNAME_SIZE) {
    return RTM_OK;
  } else {
    _rtm_log_error(rtm, RTM_ERR_PARAM, "param endpoint invalid:  hostname too long – size=%d expected<%d",
                         length, _RTM_MAX_HOSTNAME_SIZE);
    return RTM_ERR_PARAM;
  }
}

/**
 * Append API path and appkey to a path
 *
 * This function observes a maximal length of the path argument of
 * _RTM_MAX_PATH_SIZE.
 *
 * @return RTM_OK or an error
 */
static rtm_status _rtm_prepare_path(rtm_client_t *rtm, char *path, const char *appkey) {
  CHECK_MAX_SIZE(path, _RTM_MAX_PATH_SIZE);
  if (!*path) {
    _rtm_log_error(rtm, RTM_ERR_PARAM, "param endpoint invalid: path has incorrect format");
    return RTM_ERR_PARAM;
  }

  // Strip a tailing slash
  char *end_of_path = path + strlen(path) - 1;
  if (*end_of_path != '/') {
    ++end_of_path;
  }

  size_t size = _RTM_MAX_PATH_SIZE - (end_of_path - path);

  int w = snprintf(end_of_path, size, "%s?appkey=%s", RTM_PATH, appkey);
  if (w == 0 || w >= size) {
    _rtm_log_error(rtm, RTM_ERR_OOM, "Insufficient memory to build path - appkey malformed?");
    return RTM_ERR_OOM;
  }

  return RTM_OK;
}

/**
 * Parse an endpoint in URL form into hostname, port and path.
 *
 * @return RTM_OK or an error
 */
static rtm_status _rtm_parse_endpoint(
    rtm_client_t *rtm, const char *endpoint, enum rtm_url_scheme_t schemes, char *hostname_out,
    char *port_out, char *path_out, unsigned *use_tls_out) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(endpoint);

  ASSERT_NOT_NULL(hostname_out);
  ASSERT_NOT_NULL(port_out);
  ASSERT_NOT_NULL(path_out);
  ASSERT_NOT_NULL(use_tls_out);

  const char port80[] = "80";
  const char port443[] = "443";

  const char *auto_port = NULL;
  const char *hostname_start = NULL;

  if ((schemes & SCHEME_WS) && (strncmp(endpoint, WS_PREFIX, sizeof(WS_PREFIX) - 1) == 0)) {
    auto_port = port80;
    hostname_start = endpoint + sizeof(WS_PREFIX) - 1;
    *use_tls_out = NO;
  } else if ((schemes & SCHEME_WSS) && strncmp(endpoint, WSS_PREFIX, sizeof(WSS_PREFIX) - 1) == 0) {
    auto_port = port443;
    hostname_start = endpoint + sizeof(WSS_PREFIX) - 1;
    *use_tls_out = YES;
  } else if ((schemes & SCHEME_HTTP) && strncmp(endpoint, HTTP_PREFIX, sizeof(HTTP_PREFIX) - 1) == 0) {
    auto_port = port80;
    hostname_start = endpoint + sizeof(HTTP_PREFIX) - 1;
    *use_tls_out = NO;
  } else {
    _rtm_log_error(rtm, RTM_ERR_PROTOCOL, "Unsupported scheme in endpoint=%s", endpoint);
    return RTM_ERR_PROTOCOL;
  }

  if (!*hostname_start) {
    _rtm_log_error(rtm, RTM_ERR_PARAM, "param endpoint invalid: hostname should have non-zero length");
    return RTM_ERR_PARAM;
  }

  // try to find URI path
  const char *path = strchr(hostname_start, '/');
  const char *hostname_end = NULL;
  if (path) {
    hostname_end = path;
  } else {
    hostname_end = (endpoint + strlen(endpoint));
    path = "/";
  }

  int path_len = snprintf(path_out, _RTM_MAX_PATH_SIZE, "%s", path);
  if (path_len < 0 || path_len >= _RTM_MAX_PATH_SIZE) {
    return RTM_ERR_OOM;
  }

  // look for the port
  const char *port_delimiter = strchr(hostname_start, ':');
  if (port_delimiter) {
    const char *port_p = port_delimiter + 1;
    // calculate the length of port part
    while (port_p < hostname_end) {
      // end of port part
      if ((*port_p == '/') || (*port_p == '\0')) {
        break;
      }
      // not a number
      if (!(('0' <= *port_p) && (*port_p <= '9'))) {
        _rtm_log_error(rtm, RTM_ERR_PARAM, "param endpoint invalid: port must be an integer");
        return RTM_ERR_PARAM;
      }
      port_p++;
    }
    int port_length = port_p - port_delimiter - 1;
    if(port_length >= _RTM_MAX_PORT_SIZE - 1) {
      return RTM_ERR_OOM;
    }
    sprintf(port_out, "%.*s", port_length, port_delimiter + 1);
    hostname_end = port_delimiter;
  } else {
    strcpy(port_out, auto_port);
  }

  // check the hostname length
  int hostname_length = hostname_end - hostname_start;
  rtm_status rc = _rtm_check_hostname_length(rtm, hostname_length);
  if (RTM_OK != rc) {
    _rtm_log_error(rtm, RTM_ERR_PARAM, "param endpoint invalid: hostname has incorrect length");
    return RTM_ERR_PARAM;
  }
  // _rtm_check_hostname_length verifies that hostname_length is smaller than
  // the hostname buffer.
  sprintf(hostname_out, "%.*s", hostname_length, hostname_start);

  return RTM_OK;
}

// WebSocket IO functions and utilities

/**
 * Apply mask to buf following the WebSocket specification.
 */
static void _rtm_ws_mask(char *buf, size_t len, uint32_t mask) {
  ASSERT_NOT_NULL(buf);
  size_t i;
  for (i = 0; i < len; i++) {
    int offset = 8 * (i % 4);
    buf[i] ^= (mask >> offset) & 0xff;
  }
}

/**
 * Send a buffer as a WebSocket packet.
 *
 * @param op        A WebSocket opcode
 * @param io_buffer The buffer to be written. The data you want to write
 *                  must start _RTM_WS_PRE_BUFFER offset into this buffer.
 * @param len       The length of the data to be written, excluding the
 *                  padding at the start.
 * @return          The number of bytes actually written, including the padding
 *                  at the start.
 *
 * Developer note: The rationale for passing a pointer where the data starts
 * padded instead of passing a pointer to the start of the data is that this
 * way around, errors will be visible right away (wrong data will arrive at the
 * server) and no out-of-bounds writes will be performed in case of errorneous
 * use.
 */
static ssize_t _rtm_ws_write(rtm_client_t *rtm, uint8_t op, char *io_buffer, size_t len) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(io_buffer);
  ASSERT(op <= WS_OPCODE_LAST);

  io_buffer += _RTM_WS_PRE_BUFFER;

  if (rtm->is_verbose) {
    fprintf(stderr, "SEND: %.*s\n", (int)len, io_buffer);
  }

  // RFC 6455 asks for this mask to come from a strong entropy source, but we
  // cannot afford to block here. Since the application is to increase
  // unpredictability rather than crpytography, it should suffice to trust the
  // libc to have a sufficiently decent implementation. On IoT devices, there are
  // no good sources of entropy anyway.
  uint32_t mask = rand();
  #if RAND_MAX < UINT32_MAX
  if(mask == RAND_MAX) {
    mask += rand() * (UINT32_MAX - RAND_MAX) / RAND_MAX;
  }
  #endif

  /* we send single frame, text */
  _rtm_ws_mask(io_buffer, len, mask);
  if (len < 126) {
    io_buffer -= _RTM_OUTBOUND_HEADER_SIZE_SMALL;
    io_buffer[0] = (char) (0x80 | op);
    io_buffer[1] = (char) (len | 0x80);
    *(uint32_t *) (&io_buffer[2]) = mask;
    len += _RTM_OUTBOUND_HEADER_SIZE_SMALL;

  } else if (len < 65536) {
    io_buffer -= _RTM_OUTBOUND_HEADER_SIZE_NORMAL;
    io_buffer[0] = (char) (0x80 | op);
    io_buffer[1] = (char) (126 | 0x80);
    *(uint16_t *) (&io_buffer[2]) = htobe16(len);
    *(uint32_t *) (&io_buffer[4]) = mask;
    len += _RTM_OUTBOUND_HEADER_SIZE_NORMAL;

  } else {
    io_buffer -= _RTM_OUTBOUND_HEADER_SIZE_LARGE;
    io_buffer[0] = (char) (0x80 | op);
    io_buffer[1] = (char) (127 | 0x80);
    *(uint64_t *) (&io_buffer[2]) = htobe64(len);
    *(uint32_t *) (&io_buffer[10]) = mask;
    len += _RTM_OUTBOUND_HEADER_SIZE_LARGE;
  }
  return _rtm_io_write(rtm, io_buffer, len);
}

/**
 * Fill buf with a JSON PDU frame, including body and closing parenthesis
 *
 * @return A pointer to the end of buf, or NULL in case of insufficient memory.
 */
static char *_rtm_prepare_pdu(rtm_client_t *rtm, char *buf, ssize_t size,
    const char *action, const char *body, unsigned *ack_id_out) {
  if(!buf) {
    return NULL;
  }

  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(action);
  ASSERT_NOT_NULL(body);

  char *p = _rtm_prepare_pdu_without_body(rtm, buf, size, action, ack_id_out);
  p = _rtm_snprintf(p, size - (p - buf), "%s}", body);
  return p;
}

/**
 * Fill buf with a JSON PDU frame, excluding body and closing parenthesis "}".
 *
 * @return The number of bytes written, or -1 if OOM.
 */
static char *_rtm_prepare_pdu_without_body(rtm_client_t *rtm, char *buf, ssize_t size,
    const char *action, unsigned *ack_id_out) {
  if(!buf) {
    return NULL;
  }

  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(action);

  char *p = _rtm_snprintf(buf, size, "{\"action\":\"%s\",", action);

  if (ack_id_out) {
    *ack_id_out = ++rtm->last_request_id;
    p = _rtm_snprintf(p, size - (p - buf), "\"id\":%u,", *ack_id_out);
  }

  p = _rtm_snprintf(p, size - (p - buf), "\"body\":");

  return p;
}

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

rtm_status rtm_parse_pdu(char *message, rtm_pdu_t *pdu) {
  ASSERT_NOT_NULL(pdu);
  ASSERT_NOT_NULL(message);

  char *body = NULL;
  enum rtm_action_t action = RTM_ACTION_UNKNOWN;
  char *p = _rtm_json_find_begin_obj(message);
  int pdu_valid = TRUE;
  pdu->request_id = 0;

  while (pdu_valid && p) {
    char *key, *value;
    size_t key_length, value_length;

    p = _rtm_json_find_kv_pair(p, &key, &key_length, &value, &value_length);
    if (key_length < 2 || !value) {
      pdu_valid = FALSE;
      break;
    }

    if (!strncmp("\"action\"", key, key_length)) {
      if (value[0] != '"' || value[value_length-1] != '"' || action != RTM_ACTION_UNKNOWN) {
        pdu_valid = FALSE;
        break;
      }

      enum rtm_action_t o;
      for (o = 1; o < RTM_ACTION_SENTINEL; ++o) {
        if (!strncmp(action_table[o], value + 1, value_length - 2)) {
          action = o;
          break;
        }
      }
    } else if (!strncmp("\"id\"", key, key_length)) {
      char *id_end;

      pdu->request_id = strtoul(value, &id_end, 10);
      if (id_end == NULL || id_end != value + value_length) {
        pdu_valid = FALSE;
        break;
      }
    } else if (!strncmp("\"body\"", key, key_length)) {
      value[value_length] = 0;
      body = value;
    }
  }

  if (!pdu_valid) {
    return RTM_ERR_PROTOCOL;
  }

  field_t fields[MAX_INTERESTING_FIELDS_IN_PDU] = {{0}};

  pdu->action = action;
  switch (action) {
    case RTM_ACTION_SUBSCRIPTION_ERROR:
      fields[2].type = FIELD_STRING;
      fields[2].dst = &pdu->subscription_id;
      fields[2].name = "subscription_id";
    case RTM_ACTION_GENERAL_ERROR:
    case RTM_ACTION_AUTHENTICATE_ERROR:
    case RTM_ACTION_DELETE_ERROR:
    case RTM_ACTION_HANDSHAKE_ERROR:
    case RTM_ACTION_PUBLISH_ERROR:
    case RTM_ACTION_READ_ERROR:
    case RTM_ACTION_SUBSCRIBE_ERROR:
    case RTM_ACTION_UNSUBSCRIBE_ERROR:
    case RTM_ACTION_WRITE_ERROR:
      fields[0].type = FIELD_STRING;
      fields[0].dst = &pdu->error;
      fields[0].name = "error";

      fields[1].type = FIELD_STRING;
      fields[1].dst = &pdu->reason;
      fields[1].name = "reason";
      break;
    case RTM_ACTION_SUBSCRIPTION_INFO:
      fields[0].type = FIELD_STRING;
      fields[0].dst = &pdu->info;
      fields[0].name = "info";

      fields[1].type = FIELD_STRING;
      fields[1].dst = &pdu->reason;
      fields[1].name = "reason";

      fields[2].type = FIELD_STRING;
      fields[2].dst = &pdu->subscription_id;
      fields[2].name = "subscription_id";
      break;
    case RTM_ACTION_HANDSHAKE_OK:
      fields[0].type = FIELD_STRING;
      fields[0].dst = &pdu->nonce;
      fields[0].name = "nonce";
      break;
    case RTM_ACTION_PUBLISH_OK:
    case RTM_ACTION_DELETE_OK:
    case RTM_ACTION_WRITE_OK:
      fields[0].type = FIELD_STRING;
      fields[0].dst = &pdu->position;
      fields[0].name = "position";
      break;
    case RTM_ACTION_SUBSCRIBE_OK:
    case RTM_ACTION_UNSUBSCRIBE_OK:
      fields[0].type = FIELD_STRING;
      fields[0].dst = &pdu->position;
      fields[0].name = "position";

      fields[1].type = FIELD_STRING;
      fields[1].dst = &pdu->subscription_id;
      fields[1].name = "subscription_id";
      break;
    case RTM_ACTION_READ_OK:
      fields[0].type = FIELD_STRING;
      fields[0].dst = &pdu->position;
      fields[0].name = "position";

      fields[1].type = FIELD_JSON;
      fields[1].dst = &pdu->message;
      fields[1].name = "message";
      break;
    case RTM_ACTION_AUTHENTICATE_OK:
      break;
    case RTM_ACTION_SUBSCRIPTION_DATA: // messages are parsed elsewhere
      fields[0].type = FIELD_STRING;
      fields[0].dst = &pdu->position;
      fields[0].name = "position";

      fields[1].type = FIELD_ITERATOR;
      fields[1].dst = &pdu->message_iterator;
      fields[1].name = "messages";

      fields[2].type = FIELD_STRING;
      fields[2].dst = &pdu->subscription_id;
      fields[2].name = "subscription_id";
      break;
    case RTM_ACTION_UNKNOWN:
      pdu->body = body;
      return RTM_OK;
    case RTM_ACTION_SENTINEL:
      ASSERT_NOT_NULL(0); // never happens
  }

  if (!body) {
    return RTM_OK;
  }

  p = _rtm_json_find_begin_obj(body);

  while (p) {
    char *key, *value;
    size_t key_length, value_length;

    p = _rtm_json_find_kv_pair(p, &key, &key_length, &value, &value_length);
    if (!p && key && !*key) {
      // Valid, but empty object.
      break;
    }
    if (key_length < 2 || !value) {
      pdu_valid = FALSE;
      break;
    }

    // For handshakes, the answer is a nested JSON object {data:{nonce:xxx}}.
    // We only want the nonce.
    if (action == RTM_ACTION_HANDSHAKE_OK && !strncmp(key, "\"data\"", key_length)) {
      p = _rtm_json_find_begin_obj(value);
      continue;
    }

    int i;
    for (i = 0; i < MAX_INTERESTING_FIELDS_IN_PDU; ++i) {
      field_t field = fields[i];

      if (!field.name) {
        break;
      }

      // skip quotes when compare field name
      if (!strncmp(field.name, key + 1, key_length - 2)) {
        switch (field.type) {
          case FIELD_JSON:
            value[value_length] = 0;
            *((char **)field.dst) = value;
            break;
          case FIELD_STRING:
            value[value_length-1] = 0;
            *((char **)field.dst) = value + 1;
            break;
          case FIELD_ITERATOR:
            value[value_length] = 0;
            ((rtm_list_iterator_t *)field.dst)->position = value + 1;
            break;
        }
      }
    }
  }

  if (!pdu_valid) {
    return RTM_ERR_PROTOCOL;
  }

  return RTM_OK;
}

char *rtm_iterate(rtm_list_iterator_t const *iterator) {
  rtm_list_iterator_t *iter = (rtm_list_iterator_t *)iterator;
  if (!iter || !iter->position) {
    return NULL;
  }

  char *this_element_cursor;
  size_t this_element_length;

  char *next_element = _rtm_json_find_element(iter->position, &this_element_cursor, &this_element_length);

  if (next_element == NULL) {
    iter->position = NULL;
    return NULL;
  }
  else if (*next_element == ',') {
    iter->position = next_element + 1;
  }
  else if(!*next_element || *next_element == ']') {
    iter->position = NULL;
  }
  else {
    iter->position = NULL;
    return NULL;
  }

  this_element_cursor[this_element_length] = 0;
  return this_element_cursor;
}

void rtm_default_text_frame_handler(rtm_client_t *rtm, char *message, size_t message_len) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(message);
  ASSERT(message_len > 0);

  rtm->is_used = YES;
  if (rtm->handle_raw_pdu) {
      rtm->handle_raw_pdu(rtm, message);
  }

  if (rtm->handle_pdu) {
      rtm_pdu_t pdu = {0};
      rtm_status rc = rtm_parse_pdu(message, &pdu);
      if(rc != RTM_OK) {
        _rtm_log_error(rtm, rc, "Invalid PDU received");
        rtm_close(rtm);
        return;
      }

      rtm->handle_pdu(rtm, &pdu);
  }
  rtm->is_used = NO;
}

void rtm_set_error_logger(rtm_client_t *rtm, rtm_error_logger_t *error_logger) {
  rtm->error_logger = error_logger;
}

void rtm_set_raw_pdu_handler(rtm_client_t *rtm, rtm_raw_pdu_handler_t *handler) {
    rtm->handle_raw_pdu = handler;
}

void _rtm_log_error(rtm_client_t *rtm, rtm_status error, const char *message, ...) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(message);
  if (!rtm->error_logger)
    return;
  va_list vl;
  va_start(vl, message);
  _rtm_logv_error(rtm, error, message, vl);
  va_end(vl);
}

void _rtm_logv_error(rtm_client_t *rtm, rtm_status error, const char *message, va_list args) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(message);

  if (!rtm->error_logger)
    return;

  char *p = _rtm_snprintf(rtm->scratch_buffer, _RTM_SCRATCH_BUFFER_SIZE,
                        "%p (%d):", (void*) rtm, error);

  if(!p) {
    rtm->error_logger("message too long to print");
    return;
  }

  int written = vsnprintf(p, _RTM_SCRATCH_BUFFER_SIZE - (p - rtm->scratch_buffer), message, args);
  if (written >= _RTM_SCRATCH_BUFFER_SIZE - (p - rtm->scratch_buffer)) {
    rtm->error_logger("message too long to print");
  } else {
    rtm->error_logger(rtm->scratch_buffer);
  }
}

rtm_status _rtm_check_interval_and_send_ws_ping(rtm_client_t *rtm) {
  rtm_status rc = RTM_OK;

  if (labs(time(NULL) - rtm->last_ping_ts) > rtm->ws_ping_interval) {
    rc = rtm_send_ws_ping(rtm);
    if (RTM_OK != rc) {
      return rc;
    }
    rtm->last_ping_ts = time(NULL);
  }

  return rc;
}

void _rtm_log_message(rtm_client_t *rtm, rtm_status status, const char *message) {
  ASSERT_NOT_NULL(message);
  if (rtm->error_logger)
    rtm->error_logger(message);
}

void rtm_enable_verbose_logging(rtm_client_t *rtm) {
  rtm->is_verbose = YES;
}

void rtm_disable_verbose_logging(rtm_client_t *rtm) {
  rtm->is_verbose = NO;
}

void _rtm_b64encode_16bytes(char const *input, char *output) {
    static char const lut[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i;

    for (i = 0; i < 14; i += 3) {
        *output++ = lut[(input[i] >> 2) & 0x3F];
        *output++ = lut[((input[i] & 0x3) << 4) | ((int) (input[i + 1] & 0xF0) >> 4)];
        *output++ = lut[((input[i + 1] & 0xF) << 2) | ((int) (input[i + 2] & 0xC0) >> 6)];
        *output++ = lut[input[i + 2] & 0x3F];
    }

    *output++ = lut[(input[15] >> 2) & 0x3F];
    *output++ = lut[((input[15] & 0x3) << 4)];
    *output++ = '=';
    *output++ = '=';
}

rtm_status rtm_poll(rtm_client_t *rtm) {
  CHECK_PARAM(rtm);
  if (rtm->fd < 0) {
    _rtm_log_error(rtm, RTM_ERR_CLOSED, "connection closed");
    return RTM_ERR_CLOSED;
  }

  rtm_status return_code = RTM_OK;

  return_code = _rtm_check_interval_and_send_ws_ping(rtm);
  if (RTM_OK != return_code) {
    return return_code;
  }

  // Fill the buffer with data available in the socket

  // FIXME Allow to use a user-specified, dynamic larger buffer, too.
  char *base_input_buffer = rtm->input_buffer;
  size_t base_input_buffer_size = rtm->input_buffer_size;

  /*
   * The memory layout of the input buffer is as follows:
   *
   * First, it stores any partially reconstructed fragmented frame. The first
   * free byte is pointed to by rtm->fragment_end (if not NULL). Then come
   * possibly partial frames.
   */
  char *read_buffer;
  ssize_t to_read;
  if(rtm->fragment_end) {
    read_buffer = rtm->fragment_end;
    to_read = base_input_buffer_size - rtm->input_length - (read_buffer - base_input_buffer);
  }
  else {
    read_buffer = base_input_buffer;
    to_read = base_input_buffer_size - rtm->input_length;
  }

  if (to_read > 0) {
    ssize_t bytes_read = _rtm_io_read(rtm, read_buffer + rtm->input_length, (size_t) to_read, NO);
    if (bytes_read <= 0) {
      if (errno == EAGAIN) {
        // No data yet
        return RTM_WOULD_BLOCK;
      }

      return RTM_ERR_READ;
    }


    rtm->input_length += bytes_read;
  }

  char *ws_frame = read_buffer;

  if (rtm->huge_packet_bytes > 0) {
    // We are in the middle of processing a frame that is too large to handle
    // and the user decided to discard.
    if (rtm->huge_packet_bytes > rtm->input_length) {
      rtm->huge_packet_bytes -= rtm->input_length;
      rtm->input_length = 0;
      return RTM_WOULD_BLOCK;
    }
    else {
      ws_frame += rtm->huge_packet_bytes;
      rtm->input_length -= rtm->huge_packet_bytes;
      rtm->huge_packet_bytes = 0;
    }
  }

  // At this point we may have any number of full frames plus maybe one partial frame

  // Decode the WS frame.

  // RTM_OK is returned if any data frame presents and no protocol errors
  // RTM_WOULD_BLOCK is returned if there are no data frames and no protocol errors
  // RTM_ERR_PROTCOL is returned if parser detects protocol error
  // RTM_ERR_CLOSE is returned if socket is closed or CLOSE frame is received
  return_code = RTM_WOULD_BLOCK;
  while (rtm->input_length > 2) { // must be at least 4 bytes to read a ws frame
    // Decode frame header
    unsigned frame_fin = (0 != (ws_frame[0] & 0x80));
    unsigned frame_opcode = (unsigned) (ws_frame[0] & 0x0f);
    size_t frame_payload_length = (size_t) (ws_frame[1] & 0x7f);
    unsigned frame_masked = (0 != (ws_frame[1] & 0x80));

    if (frame_masked) { /* no mask from server */
      return_code = RTM_ERR_PROTOCOL;
      goto ws_error;
    }

    size_t header_length = 0; // two bytes already consumed.
    size_t payload_length = 0;

    if (frame_payload_length < 126) {
      payload_length = frame_payload_length;
      header_length = _RTM_INBOUND_HEADER_SIZE_SMALL;
    } else if (frame_payload_length == 126) { // 126 -> 16 bit size
      if (rtm->input_length < _RTM_INBOUND_HEADER_SIZE_NORMAL)
        return RTM_WOULD_BLOCK;
      payload_length = be16toh(*(uint16_t *) (&ws_frame[2]));
      header_length = _RTM_INBOUND_HEADER_SIZE_NORMAL;
    } else { // 127 -> 64 bit size
      if (rtm->input_length < _RTM_INBOUND_HEADER_SIZE_LARGE)
        return RTM_WOULD_BLOCK;
      payload_length = (size_t)be64toh(*(uint64_t *) (&ws_frame[2]));
      header_length = _RTM_INBOUND_HEADER_SIZE_LARGE;
    }

    if (payload_length >= ((read_buffer + to_read) - ws_frame)) {
      // Insufficient memory to ever read this frame.
      // FIXME pberndt Allow the user to allocate memory to store the frame away or fail hard,
      //               only skip the frame if the user chose to.

      if (rtm->is_in_huge_packet_skip && frame_opcode == WS_CONTINUATION) {
        // This is a huge packet within a series of huge packets that we want
        // to skip. If it has frame_fin set, skip it, but mark the series as
        // ended.
        rtm->is_in_huge_packet_skip = !frame_fin;
      }
      else if (rtm->is_in_huge_packet_skip && !frame_fin) {
        // This is the start of a fragmented packet, but we are already in the
        // process of skipping one.
        _rtm_log_error(rtm, RTM_ERR_PROTOCOL, "received out of sequence start of fragmented frame");
        return_code = RTM_ERR_PROTOCOL;
        goto ws_error;
      }

      if (!frame_fin) {
        // This packet is part of a series of fragmented packets. Discard them
        // all.
        rtm->is_in_huge_packet_skip = 1;
        rtm->fragment_end = NULL;
      }

      rtm->huge_packet_bytes = payload_length - (rtm->input_length - header_length);
      rtm->input_length = 0;

      return RTM_OK;
    }

    if (rtm->input_length < header_length + payload_length) {  // wait for more data to process the payload
      return_code = RTM_WOULD_BLOCK;
      break;
    }

    rtm->input_length -= header_length;
    ws_frame += header_length;

    // PING/PONG/CLOSE
    if (frame_opcode >= WS_CONTROL_COMMANDS_START && frame_opcode <= WS_CONTROL_COMMANDS_END) {
      if (!frame_fin || payload_length > _RTM_MAX_CONTROL_FRAME_SIZE) {
        // control frames must be single fragment, 125 bytes or less
        _rtm_log_error(rtm, RTM_ERR_PROTOCOL, "malformed control frame received – opcode=%d size=%d",
                                    frame_opcode, frame_payload_length);
        return_code = RTM_ERR_PROTOCOL;
        goto ws_error;
      }

      if (WS_CLOSE == frame_opcode) {
        _rtm_io_close(rtm);
        return RTM_ERR_CLOSED;
      } else if (WS_PING == frame_opcode || WS_PONG == frame_opcode) {
        // FIXME pberndt: Reply to PING
        const char* frame_type = (frame_opcode == WS_PONG) ? "pong" : "ping";
        if (rtm->is_verbose) {
          fprintf(stderr, "RECV: %s\n", frame_type);
        }
      }
    } else if (WS_TEXT == frame_opcode || WS_BINARY == frame_opcode || WS_CONTINUATION == frame_opcode) { /* data frame */
      if (frame_opcode == WS_CONTINUATION && !rtm->fragment_end) {
        _rtm_log_error(rtm, RTM_ERR_PROTOCOL, "received out of sequence continuation frame");
        return_code = RTM_ERR_PROTOCOL;
        goto ws_error;
      }

      if (!frame_fin) {
        // Fragmented frame

        if (frame_opcode != WS_CONTINUATION && rtm->fragment_end) {
          _rtm_log_error(rtm, RTM_ERR_PROTOCOL, "received out of sequence start of fragmented frame");
          return_code = RTM_ERR_PROTOCOL;
          goto ws_error;
        }

        if (rtm->is_in_huge_packet_skip) {
          // We discarded parts of this packet sequence. So discard this one,
          // too.
        }
        else {
          // Store body data away (essentially: remove WebSocket header)
          // We always have enough memory to do that, because the frame is in the
          // same buffer as are the fragments.
          char *fragment_target = rtm->fragment_end ? rtm->fragment_end : base_input_buffer;
          memmove(fragment_target, ws_frame, payload_length);
          rtm->fragment_end = fragment_target + payload_length;
        }
      }
      else if (rtm->fragment_end && frame_opcode == WS_CONTINUATION) {
        // Last in a series of fragmented frames.

        if (rtm->is_in_huge_packet_skip) {
          // We discarded parts of this packet sequence. So discard this one,
          // too. Then mark the sequence as ended.
          rtm->is_in_huge_packet_skip = 0;
        }
        else {
          // Reassemble the frame, then invoke handler.

          char *fragment_target = rtm->fragment_end ? rtm->fragment_end : base_input_buffer;
          memmove(fragment_target, ws_frame, payload_length);
          fragment_target[payload_length] = 0;

          size_t reassembled_payload_length = fragment_target + payload_length - base_input_buffer;

          if (rtm->is_verbose) {
            fprintf(stderr, "RECV: %.*s\n", (int)reassembled_payload_length, base_input_buffer);
          }

          rtm_text_frame_handler(rtm, base_input_buffer, reassembled_payload_length);
          return_code = RTM_OK;

          rtm->fragment_end = NULL;
        }
      }
      else {
        // Normal, non-fragmented frame.
        return_code = RTM_OK;

        char save = ws_frame[payload_length];
        ws_frame[payload_length] = 0; // be nice, null terminate

        if (rtm->is_verbose) {
          fprintf(stderr, "RECV: %.*s\n", (int)payload_length, ws_frame);
        }

        rtm_text_frame_handler(rtm, ws_frame, payload_length);
        ws_frame[payload_length] = save;
      }

      if (rtm->is_closed) {
        _rtm_io_close(rtm);
        return RTM_ERR_CLOSED;
      }
    } else {
      // unhandled opcode
      _rtm_log_error(rtm, RTM_ERR_PROTOCOL, "received unknown frame with opcode=%d", frame_opcode);
      return_code = RTM_ERR_PROTOCOL;
      goto ws_error;
    }
    rtm->input_length -= payload_length;
    ws_frame += payload_length;
  }

  /*
   * Move all remaining data to the start of the input buffer so that if we had a partial frame,
   * it will always be at the beginning of the buffer next time around, so we are guaranteed to have
   * memory space for a full frame
   */
  char *new_read_buffer = rtm->fragment_end ? rtm->fragment_end : read_buffer;
  if (rtm->input_length > 0 && ws_frame != new_read_buffer) {
    memmove(new_read_buffer, ws_frame, rtm->input_length);
  }
  return return_code;

  ws_error:
  // abort?
  _rtm_io_close(rtm);
  return return_code;
}

#if defined(RTM_TEST_ENV)
rtm_status _rtm_test_parse_endpoint(
    rtm_client_t *rtm, const char *endpoint, enum rtm_url_scheme_t schemes, char *hostname_out,
    char *port_out, char *path_out, unsigned *use_tls_out) {
  return _rtm_parse_endpoint(rtm, endpoint, schemes, hostname_out, port_out, path_out, use_tls_out);
}

rtm_status _rtm_test_prepare_path(rtm_client_t *rtm, char *path, const char *appkey) {
  return _rtm_prepare_path(rtm, path, appkey);
}
#endif

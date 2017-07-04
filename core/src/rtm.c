#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <panzi/portable_endian.h>

#include "rtm_internal.h"

#define MAX_INTERESTING_FIELDS_IN_PDU 3
const size_t rtm_client_size = RTM_CLIENT_SIZE;

void(*rtm_error_logger)(const char *message) = rtm_default_error_logger;

void rtm_default_text_frame_handler(rtm_client_t *rtm, char *message, size_t message_len);
void(*rtm_text_frame_handler)(rtm_client_t *rtm, char *message, size_t message_len) = rtm_default_text_frame_handler;

// Network
static rtm_status parse_endpoint(rtm_client_t *rtm, const char *endpoint,
    char *hostname_out, char *port_out, char *path_out, unsigned *use_tls_out);
static rtm_status prepare_path(rtm_client_t *rtm, char *path, const char *appkey);
static rtm_status send_http_upgrade_request(rtm_client_t *rtm,
    const char *hostname, const char *path);
static rtm_status check_http_upgrade_response(rtm_client_t *rtm);
static ssize_t ws_write(rtm_client_t *rtm, uint8_t op, char *io_buffer, size_t len);

// PDU formatting
static ssize_t prepare_pdu(rtm_client_t *rtm, char *buf, ssize_t size,
    const char *action, const char *body, unsigned *ack_id_out);
static ssize_t prepare_pdu_without_body(rtm_client_t *rtm, char *buf, ssize_t size,
    const char *action, unsigned *ack_id_out);

RTM_API rtm_client_t * rtm_init(
  void *memory,
  rtm_pdu_handler_t *pdu_handler,
  void *user_context) {

  if (memory == NULL) {
    _rtm_log_message(RTM_ERR_PARAM, "param memory is required");
    return NULL;
  }

  memset(memory, 0, RTM_CLIENT_SIZE);

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

  if (getenv("DEBUG_SATORI_SDK")) {
    rtm->is_verbose = YES;
  }

  return rtm;
}

rtm_status rtm_connect(rtm_client_t *rtm,
                       const char *endpoint,
                       const char *appkey) {
  CHECK_PARAM(rtm);
  CHECK_MAX_SIZE(endpoint, RTM_MAX_ENDPOINT_SIZE);
  CHECK_MAX_SIZE(appkey, RTM_MAX_APPKEY_SIZE);

  char hostname[_RTM_MAX_HOSTNAME_SIZE + 1] = { 0 };
  char port[_RTM_MAX_PORT_SIZE + 1] = { 0 };
  char path[_RTM_MAX_PATH_SIZE + 1] = { 0 };

  unsigned use_tls = NO;

  if (strlen(endpoint) < 10) {
    // 10 is the minimum size of the endpoint string ws://api.satori.com/
    return _rtm_log_error(rtm, RTM_ERR_PARAM_INVALID, "endpoint malformed – too short.");
  }

  rtm_status rc;

  rc = parse_endpoint(rtm, endpoint, hostname, port, path, &use_tls);
  if (rc)
    return rc;

  rc = prepare_path(rtm, path, appkey);
  if (rc) {
    return rc;
  }

  rc = _rtm_io_connect(rtm, hostname, port, use_tls);
  if (rc)
    return rc;

  // Connection established. Set current time as the last ping time.
  rtm->last_ping_ts = time(NULL);

  rc = send_http_upgrade_request(rtm, hostname, path);
  if (rc)
    return rc;

  rc = check_http_upgrade_response(rtm);
  if (rc)
    return rc;

  return RTM_OK;
}

void rtm_close(rtm_client_t *rtm) {
  if (!rtm) {
    return;
  }
  _rtm_io_close(rtm);
}

static ssize_t safer_snprintf(char *dst, ssize_t max_size, char const *fmt, ...) {
  if (max_size <= 0) {
      return 0;
  }

  va_list args;
  va_start(args, fmt);
  int result = vsnprintf(dst, max_size, fmt, args);
  va_end(args);

  if (result < 0) {
      return 0;
  }

  if (result < max_size) {
      return result;
  }

  return max_size;
}

rtm_status rtm_handshake(rtm_client_t *rtm, const char *role_name, unsigned *ack_id) {
  CHECK_PARAM(rtm);
  CHECK_MAX_SIZE(role_name, RTM_MAX_ROLE_NAME_SIZE);

  char* const buf = _RTM_BUFFER_TO_IO(rtm->output_buffer);
  const ssize_t size = _RTM_MAX_BUFFER;
  char *p = buf;

  p += prepare_pdu_without_body(rtm, p, size, "auth/handshake", ack_id);
  p += safer_snprintf(p, size - (p - buf), "{\"method\":\"role_secret\",\"data\":{\"role\":\"");
  p += _rtm_json_escape(p, size - (p - buf), role_name);
  p += safer_snprintf(p, size - (p - buf), "\"}}}");

  ssize_t written = ws_write(rtm, WS_TEXT, buf, p - buf);
  return (written < 0) ? RTM_ERR_WRITE : RTM_OK;
}

rtm_status rtm_authenticate(rtm_client_t *rtm, const char *role_secret, const char *nonce, unsigned *ack_id) {
  CHECK_PARAM(rtm);

  char hash[RTM_AUTHENTICATION_HASH_SIZE + 1] = {0};
  _rtm_calculate_auth_hash(role_secret, nonce, hash);

  char* const buf = _RTM_BUFFER_TO_IO(rtm->output_buffer);
  const ssize_t size = _RTM_MAX_BUFFER;
  char *p = buf;

  p += prepare_pdu_without_body(rtm, p, size, "auth/authenticate", ack_id);
  p += safer_snprintf(p, size - (p - buf), "{\"method\":\"role_secret\",\"credentials\":{\"hash\":\"");
  p += _rtm_json_escape(p, size - (p - buf), hash);
  p += safer_snprintf(p, size - (p - buf), "\"}}}");

  ssize_t written = ws_write(rtm, WS_TEXT, buf, p - buf);
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
  const ssize_t size = _RTM_MAX_BUFFER;
  char *p = buf;

  p += prepare_pdu_without_body(rtm, p, size, "rtm/publish", ack_id);
  p += safer_snprintf(p, size - (p - buf), "{\"channel\":\"");
  p += _rtm_json_escape(p, size - (p - buf), channel);
  p += safer_snprintf(p, size - (p - buf), "\",\"message\":\"");
  p += _rtm_json_escape(p, size - (p - buf), string);
  p += safer_snprintf(p, size - (p - buf), "\"}}");

  ssize_t written = ws_write(rtm, WS_TEXT, buf, p - buf);
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
  const ssize_t size = _RTM_MAX_BUFFER;
  char *p = buf;

  p += prepare_pdu_without_body(rtm, p, size, "rtm/publish", ack_id);
  p += safer_snprintf(p, size - (p - buf), "{\"channel\":\"");
  p += _rtm_json_escape(p, size - (p - buf), channel);
  p += safer_snprintf(p, size - (p - buf), "\",\"message\":%s}}", json);

  ssize_t written = ws_write(rtm, WS_TEXT, buf, p - buf);
  return (written < 0) ? RTM_ERR_WRITE : RTM_OK;
}

rtm_status rtm_subscribe(rtm_client_t *rtm, const char *channel, unsigned *ack_id) {
  CHECK_PARAM(rtm);
  CHECK_MAX_SIZE(channel, RTM_MAX_CHANNEL_SIZE);

  char* const buf = _RTM_BUFFER_TO_IO(rtm->output_buffer);
  const ssize_t size = _RTM_MAX_BUFFER;
  char *p = buf;

  p += prepare_pdu_without_body(rtm, p, size, "rtm/subscribe", ack_id);
  p += safer_snprintf(p, size - (p - buf), "{\"channel\":\"");
  p += _rtm_json_escape(p, size - (p - buf), channel);
  p += safer_snprintf(p, size - (p - buf), "\"}}");

  ssize_t written = ws_write(rtm, WS_TEXT, buf, p - buf);
  return (written < 0) ? RTM_ERR_WRITE : RTM_OK;
}

rtm_status rtm_subscribe_with_body(rtm_client_t *rtm, const char *body, unsigned *ack_id) {
  CHECK_PARAM(rtm);

  char* const buf = _RTM_BUFFER_TO_IO(rtm->output_buffer);
  ssize_t len = prepare_pdu(rtm, buf, _RTM_MAX_BUFFER,
      "rtm/subscribe", body, ack_id);

  ssize_t written = ws_write(rtm, WS_TEXT, buf, len);
  return (written < 0) ? RTM_ERR_WRITE : RTM_OK;
}

rtm_status rtm_unsubscribe(rtm_client_t *rtm, const char *subscription_id, unsigned *ack_id) {
  CHECK_PARAM(rtm);
  CHECK_MAX_SIZE(subscription_id, RTM_MAX_CHANNEL_SIZE);

  char* const buf = _RTM_BUFFER_TO_IO(rtm->output_buffer);
  const ssize_t size = _RTM_MAX_BUFFER;
  char *p = buf;

  p += prepare_pdu_without_body(rtm, p, size, "rtm/unsubscribe", ack_id);
  p += safer_snprintf(p, size - (p - buf), "{\"subscription_id\":\"");
  p += _rtm_json_escape(p, size - (p - buf), subscription_id);
  p += safer_snprintf(p, size - (p - buf), "\"}}");

  ssize_t written = ws_write(rtm, WS_TEXT, buf, p - buf);
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
  const ssize_t size = _RTM_MAX_BUFFER;
  char *p = buf;

  p += prepare_pdu_without_body(rtm, p, size, "rtm/read", ack_id);
  p += safer_snprintf(p, size - (p - buf), "{\"channel\":\"");
  p += _rtm_json_escape(p, size - (p - buf), channel);
  p += safer_snprintf(p, size - (p - buf), "\"}}");

  ssize_t written = ws_write(rtm, WS_TEXT, buf, p - buf);
  return (written < 0) ? RTM_ERR_WRITE : RTM_OK;
}

rtm_status rtm_read_with_body(rtm_client_t *rtm, const char *body, unsigned *ack_id) {
  CHECK_PARAM(rtm);

  char* const buf = _RTM_BUFFER_TO_IO(rtm->output_buffer);
  ssize_t len = prepare_pdu(rtm, buf, _RTM_MAX_BUFFER,
      "rtm/read", body, ack_id);

  ssize_t written = ws_write(rtm, WS_TEXT, buf, len);
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
  const ssize_t size = _RTM_MAX_BUFFER;
  char *p = buf;

  p += prepare_pdu_without_body(rtm, p, size, "rtm/write", ack_id);
  p += safer_snprintf(p, size - (p - buf), "{\"channel\":\"");
  p += _rtm_json_escape(p, size - (p - buf), channel);
  p += safer_snprintf(p, size - (p - buf), "\",\"message\":\"");
  p += _rtm_json_escape(p, size - (p - buf), string);
  p += safer_snprintf(p, size - (p - buf), "\"}}");

  ssize_t written = ws_write(rtm, WS_TEXT, buf, p - buf);
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
  const ssize_t size = _RTM_MAX_BUFFER;
  char *p = buf;

  p += prepare_pdu_without_body(rtm, p, size, "rtm/write", ack_id);
  p += safer_snprintf(p, size - (p - buf), "{\"channel\":\"");
  p += _rtm_json_escape(p, size - (p - buf), channel);
  p += safer_snprintf(p, size - (p - buf), "\",\"message\":%s}}", json);

  ssize_t written = ws_write(rtm, WS_TEXT, buf, p - buf);
  return (written < 0) ? RTM_ERR_WRITE : RTM_OK;
}

rtm_status rtm_delete(rtm_client_t *rtm, const char *channel, unsigned *ack_id) {
  CHECK_PARAM(rtm);

  char* const buf = _RTM_BUFFER_TO_IO(rtm->output_buffer);
  const ssize_t size = _RTM_MAX_BUFFER;
  char *p = buf;

  p += prepare_pdu_without_body(rtm, p, size, "rtm/delete", ack_id);
  p += safer_snprintf(p, size - (p - buf), "{\"channel\":\"");
  p += _rtm_json_escape(p, size - (p - buf), channel);
  p += safer_snprintf(p, size - (p - buf), "\"}}");

  ssize_t written = ws_write(rtm, WS_TEXT, buf, p - buf);
  return (written < 0) ? RTM_ERR_WRITE : RTM_OK;
}

rtm_status rtm_search(rtm_client_t *rtm, const char *prefix, unsigned *ack_id) {
  CHECK_PARAM(rtm);

  char* const buf = _RTM_BUFFER_TO_IO(rtm->output_buffer);
  const ssize_t size = _RTM_MAX_BUFFER;
  char *p = buf;

  p += prepare_pdu_without_body(rtm, p, size, "rtm/search", ack_id);
  p += safer_snprintf(p, size - (p - buf), "{\"prefix\":\"");
  p += _rtm_json_escape(p, size - (p - buf), prefix);
  p += safer_snprintf(p, size - (p - buf), "\"}}");

  ssize_t written = ws_write(rtm, WS_TEXT, buf, p - buf);
  return (written < 0) ? RTM_ERR_WRITE : RTM_OK;
}

rtm_status rtm_send_pdu(rtm_client_t *rtm, const char *json) {
  CHECK_PARAM(rtm);
  CHECK_MAX_SIZE(json, RTM_MAX_MESSAGE_SIZE);

  char* const buf = _RTM_BUFFER_TO_IO(rtm->output_buffer);
  strncpy(buf, json, _RTM_MAX_BUFFER);

  ssize_t written = ws_write(rtm, WS_TEXT, buf, strlen(buf));
  return (written < 0) ? RTM_ERR_WRITE : RTM_OK;
}

rtm_status rtm_send_ws_ping(rtm_client_t *rtm) {
  CHECK_PARAM(rtm);

  char* const buf = _RTM_BUFFER_TO_IO(rtm->output_buffer);
  const ssize_t size = _RTM_MAX_BUFFER;
  char *p = buf;

  // the contents of the body are arbitrary, but we "ping" to make a request obvious
  p += safer_snprintf(p, size - (p - buf), "ping");

  ssize_t written = ws_write(rtm, WS_PING, buf, p - buf);
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
    if (rc)
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
    if (rc)
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
    [RTM_ACTION_SEARCH_DATA] = "rtm/search/data",
    [RTM_ACTION_SEARCH_ERROR] = "rtm/search/error",
    [RTM_ACTION_SEARCH_OK] = "rtm/search/ok",
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
    case RTM_ACTION_SEARCH_ERROR:
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
    default:
      return "RTM_UNKNOWN: Unknown status of operation.";
  }
}

// Internal code

static rtm_status check_http_upgrade_response(rtm_client_t *rtm) {
  ssize_t buffer_size = _RTM_MAX_BUFFER;
  char *input_buffer = rtm->input_buffer;
  // read HTTP response header
  memset(input_buffer, 0, _RTM_MAX_BUFFER); // FIXME why? the data will be overwritten
  while (TRUE) {
    int input_length = 0;
    const char *end_of_header;
    if (buffer_size <= 0) {
      _rtm_io_close(rtm); /* unable to parse http headers */
      return _rtm_log_error(rtm, RTM_ERR_PROTOCOL, "Unable to parse HTTP response.");
    }

    ssize_t read = _rtm_io_read(rtm, input_buffer + input_length, (size_t) buffer_size, YES);
    if (read < 0) {
      _rtm_io_close(rtm);
      return _rtm_log_error(rtm, RTM_ERR_READ, "Error reading from network while waiting for connection response");
    }

    input_length += read;
    buffer_size -= input_length;

    end_of_header = strstr(input_buffer, "\r\n\r\n");
    if (end_of_header) {
      size_t header_len = end_of_header - input_buffer + 4; // include the blank line we just matched
      if (strncmp(input_buffer, "HTTP/1.1 101", 12) != 0) {
        rtm_status rc = _rtm_log_error(rtm, RTM_ERR_PROTOCOL, "Received unexpected response from server:");
        _rtm_log_message(RTM_ERR_PROTOCOL, input_buffer);
        _rtm_io_close(rtm);
        return rc;
      }
      memmove(input_buffer, end_of_header, input_length - header_len);
      rtm->input_length = input_length - header_len;
      break;
    }
  }
  return RTM_OK;
}

static rtm_status send_http_upgrade_request(rtm_client_t *rtm, const char *hostname, const char *path) {
  static const char sec_key[] = "cnRtLXNlY3VyaXR5LWtleQ==";

  char *request = rtm->output_buffer;

  ssize_t len = safer_snprintf(request, _RTM_MAX_BUFFER,
      "GET %s HTTP/1.1\r\n"
      "Host: %s\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Key: %s\r\n"
      "Sec-WebSocket-Version: 13\r\n\r\n",
      path, hostname, sec_key);

  ASSERT(len <= _RTM_MAX_BUFFER);

  if (_rtm_io_write(rtm, request, len) < 0) {
    rtm_status rc = _rtm_log_error(rtm, RTM_ERR_WRITE, "Error writing to network during connection handshake");
    _rtm_io_close(rtm);
    return rc;
  }
  return RTM_OK;
}



#define WS_PREFIX "ws://"
#define WSS_PREFIX "wss://"

static rtm_status check_hostname_length(rtm_client_t *rtm, size_t length) {
  if (length < _RTM_MAX_HOSTNAME_SIZE) {
    return RTM_OK;
  } else {
    return _rtm_log_error(rtm, RTM_ERR_PARAM, "param endpoint invalid:  hostname too long – size=%d expected<%d",
                         length, _RTM_MAX_HOSTNAME_SIZE);
  }
}

static rtm_status prepare_path(rtm_client_t *rtm, char *path, const char *appkey) {
  CHECK_MAX_SIZE(path, _RTM_MAX_PATH_SIZE);
  if (strlen(path) == 0) {
    return _rtm_log_error(rtm, RTM_ERR_PARAM, "param endpoint invalid: path has incorrect format");
  }

  char *end_of_path = path + strlen(path) - 1;
  if (*end_of_path != '/') {
    ++end_of_path;
  }

  ssize_t size = _RTM_MAX_PATH_SIZE - (end_of_path - path);
  ssize_t w = safer_snprintf(end_of_path, size, "%s?appkey=%s", RTM_PATH, appkey);
  if (w == 0 || _RTM_MAX_PATH_SIZE <= w) {
    return _rtm_log_error(rtm, RTM_ERR_PARAM_INVALID, "appkey malformed - can't build path.");
  }

  return RTM_OK;
}

static rtm_status parse_endpoint(rtm_client_t *rtm, const char *endpoint, char *hostname_out,
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

  if (strncmp(endpoint, WS_PREFIX, sizeof(WS_PREFIX) - 1) == 0) {
    auto_port = port80;
    hostname_start = endpoint + sizeof(WS_PREFIX) - 1;
    *use_tls_out = NO;
  } else if (strncmp(endpoint, WSS_PREFIX, sizeof(WSS_PREFIX) - 1) == 0) {
    auto_port = port443;
    hostname_start = endpoint + sizeof(WSS_PREFIX) - 1;
    *use_tls_out = YES;
  } else {
    _rtm_log_error(rtm, RTM_ERR_PROTOCOL, "Unsupported protocol endpoint=%s", endpoint);
    return RTM_ERR_PROTOCOL;
  }

  if (strlen(hostname_start) == 0) {
    return _rtm_log_error(rtm, RTM_ERR_PARAM, "param endpoint invalid: hostname should have non-zero length");
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
  safer_snprintf(path_out, _RTM_MAX_PATH_SIZE, "%s", path);

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
        return _rtm_log_error(rtm, RTM_ERR_PARAM, "param endpoint invalid: port must be an integer");
      }
      port_p++;
    }
    ssize_t port_length = port_p - port_delimiter - 1;
    safer_snprintf(port_out, _RTM_MAX_PORT_SIZE, "%.*s", port_length, port_delimiter + 1);
    hostname_end = port_delimiter;
  } else {
    safer_snprintf(port_out, _RTM_MAX_PORT_SIZE, "%s", auto_port);
  }

  // check the hostname length
  size_t hostname_length = hostname_end - hostname_start;
  rtm_status rc = check_hostname_length(rtm, hostname_length);
  if (RTM_OK != rc) {
    return _rtm_log_error(rtm, RTM_ERR_PARAM, "param endpoint invalid: hostname has incorrect length");
  }
  safer_snprintf(hostname_out, _RTM_MAX_HOSTNAME_SIZE, "%.*s", hostname_length, hostname_start);

  return RTM_OK;
}

// WebSocket IO functions and utilities

static void ws_mask(char *buf, size_t len, uint32_t mask) {
  ASSERT_NOT_NULL(buf);
  size_t i;
  for (i = 0; i < len; i++) {
    int offset = 8 * (i % 4);
    buf[i] ^= (mask >> offset) & 0xff;
  }
}

// WARNING: the buffer must have at least 14 bytes padding before the start for web socket framing!
static ssize_t ws_write(rtm_client_t *rtm, uint8_t op, char *io_buffer, size_t len) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(io_buffer);
  ASSERT(op <= WS_OPCODE_LAST);

  if (len >= _RTM_MAX_BUFFER) {
      _rtm_log_error(rtm, RTM_ERR_PARAM, "Write overflow");
      return -1;
  }

  if (rtm->is_verbose) {
    fprintf(stderr, "SEND: %.*s\n", (int)len, io_buffer);
  }

  static const uint32_t mask = 0xb0a21974;

  /* we send single frame, text */
  ws_mask(io_buffer, len, mask);
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

static ssize_t prepare_pdu(rtm_client_t *rtm, char *buf, ssize_t size,
    const char *action, const char *body, unsigned *ack_id_out) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(buf);
  ASSERT_NOT_NULL(action);
  ASSERT_NOT_NULL(body);

  char *p = buf;
  p += prepare_pdu_without_body(rtm, p, size - (p - buf), action, ack_id_out);
  p += safer_snprintf(p, size - (p - buf), "%s}", body);
  return p - buf;
}

static ssize_t prepare_pdu_without_body(rtm_client_t *rtm, char *buf, ssize_t size,
    const char *action, unsigned *ack_id_out) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(buf);
  ASSERT_NOT_NULL(action);

  char *p = buf;
  p += safer_snprintf(p, size, "{\"action\":\"%s\",", action);
  if (ack_id_out) {
    *ack_id_out = ++rtm->last_request_id;
    p += safer_snprintf(p, size - (p - buf), "\"id\":%u,", *ack_id_out);
  }
  p += safer_snprintf(p, size - (p - buf), "\"body\":");
  return p - buf;
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

void rtm_parse_pdu(char *message, rtm_pdu_t *pdu) {
  ASSERT_NOT_NULL(pdu);
  ASSERT_NOT_NULL(message);

  char *el;
  ssize_t el_len;
  char *body = NULL;
  enum rtm_action_t action = RTM_ACTION_UNKNOWN;
  char *p = _rtm_json_find_begin_obj(message);

  while (TRUE) {
    p = _rtm_json_find_field_name(p, &el, &el_len);

    if (el_len <= 0) {
      break;
    }

    if (!strncmp("\"action\"", el, el_len)) {
      p = _rtm_json_find_element(p, &el, &el_len);
      ASSERT(el_len);
      if (0 != el_len) {
        // skip quotes
        el[el_len - 1] = '\0';
        ++el;

        enum rtm_action_t o;
        for (o = 1; o < RTM_ACTION_SENTINEL; ++o) {
            if (!strncmp(action_table[o] , el, el_len)) {
                action = o;
                break;
            }
        }
      }
    } else if (!strncmp("\"id\"", el, el_len)) {
      p = _rtm_json_find_element(p, &el, &el_len);
      char *id_end;
      pdu->request_id = (unsigned) strtol(el, &id_end, 10); // unsafe
      if (id_end - el != el_len) {
        pdu->request_id = 0;
      }
    } else if (!strncmp("\"body\"", el, el_len)) {
      p = _rtm_json_find_element(p, &el, &el_len);
      if (0 != el_len) {
        el[el_len] = '\0';
        body = el;
      }
    } else {
      // skip json element
      p = _rtm_json_find_element(p, &el, &el_len);
    }
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
    case RTM_ACTION_SEARCH_ERROR:
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
      return;
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
    case RTM_ACTION_SEARCH_DATA: // search results are parsed elsewhere
    case RTM_ACTION_SEARCH_OK:
      fields[0].type = FIELD_ITERATOR;
      fields[0].dst = &pdu->channel_iterator;
      fields[0].name = "channels";
      break;
    case RTM_ACTION_UNKNOWN:
      pdu->body = body;
      return;
    case RTM_ACTION_SENTINEL:
      ASSERT_NOT_NULL(0); // never happens
  }

  if (!body) {
    return;
  }

  p = _rtm_json_find_begin_obj(body);

  while (TRUE) {
    p = _rtm_json_find_field_name(p, &el, &el_len);

    if (el_len <= 0) {
      break;
    }

    // special case for auth/handshake/ok
    if (0 == strncmp("data", el + 1, el_len - 2)) {
      p = _rtm_json_find_begin_obj(p);
      continue;
    }

    int i;
    for (i = 0; i < MAX_INTERESTING_FIELDS_IN_PDU; ++i) {
      field_t field = fields[i];

      if (!field.name) {
        break;
      }
      // skip quotes when compare field name
      if (0 == strncmp(field.name, el + 1, el_len - 2)) {
        p = _rtm_json_find_element(p, &el, &el_len);
        if (el_len <= 0) {
          continue;
        }
        switch (field.type) {
          case FIELD_JSON:
            el[el_len] = 0;
            *((char **)field.dst) = el;
            break;
          case FIELD_STRING:
            el[el_len - 1] = 0;
            *((char **)field.dst) = el + 1;
            break;
          case FIELD_ITERATOR:
            el[el_len - 1] = 0;
            ASSERT(*el == '[');
            // TODO: skip whitespace
            ((rtm_list_iterator_t *)field.dst)->position = el + 1;
            break;
        }
      }
    }
  }
}

// FIXME: extra element of array comes out as '}'
char *rtm_iterate(rtm_list_iterator_t const *iterator) {
  rtm_list_iterator_t *iter = (rtm_list_iterator_t *)iterator;
  if (!iter || !iter->position) {
    return NULL;
  }

  char *result = iter->position;

  char *el;
  ssize_t el_len;

  _rtm_json_find_element(iter->position, &el, &el_len);

  if (el_len <= 0) {
    iter->position = NULL;
    return NULL;
  } else {
    el[el_len] = 0;
    if (el[el_len] == ']') {
      iter->position = NULL;
    } else {
      // TODO: skip whitespace
      iter->position = el + el_len + 1;
    }
  }

  return result;
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
      rtm_parse_pdu(message, &pdu);

      rtm->handle_pdu(rtm, &pdu);
  }
  rtm->is_used = NO;
}

void rtm_set_raw_pdu_handler(rtm_client_t *rtm, rtm_raw_pdu_handler_t *handler) {
    rtm->handle_raw_pdu = handler;
}

rtm_status _rtm_log_error(rtm_client_t *rtm, rtm_status error, const char *message, ...) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(message);
  if (!rtm_error_logger)
    return error;
  va_list vl;
  va_start(vl, message);
  rtm_status rc = _rtm_logv_error(rtm, error, message, vl);
  va_end(vl);
  return rc;
}

rtm_status _rtm_logv_error(rtm_client_t *rtm, rtm_status error, const char *message, va_list args) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(message);

  if (!rtm_error_logger)
    return error;

  ssize_t prefix = safer_snprintf(rtm->scratch_buffer, _RTM_SCRATCH_BUFFER_SIZE,
                        "%p (%d):", (void*) rtm, error);
  int written = vsnprintf(rtm->scratch_buffer + prefix, _RTM_SCRATCH_BUFFER_SIZE - prefix, message, args);

  if (written > _RTM_SCRATCH_BUFFER_SIZE) {
    rtm_error_logger("message too long to print");
  } else {
    rtm_error_logger(rtm->scratch_buffer);
  }
  return error;
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

rtm_status _rtm_log_message(rtm_status status, const char *message) {
  ASSERT_NOT_NULL(message);
  if (rtm_error_logger)
    rtm_error_logger(message);
  return status;
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
  if (rtm->fd < 0)
    return _rtm_log_error(rtm, RTM_ERR_CLOSED, "connection closed");

  rtm_status return_code = RTM_OK;

  return_code = _rtm_check_interval_and_send_ws_ping(rtm);
  if (RTM_OK != return_code) {
    return return_code;
  }

  // will need space for a header if we want to respond to a ping
  // for instance, the header size will differ...
  char *const input_buffer = _RTM_BUFFER_TO_IO(rtm->input_buffer);

  // Fill the buffer with data available in the socket
  ssize_t to_read = _RTM_MAX_BUFFER - rtm->input_length;
  if (to_read > 0) {
    ssize_t bytes_read = _rtm_io_read(rtm, input_buffer + rtm->input_length, (size_t) to_read, NO);
    if (bytes_read < 0)
      return RTM_ERR_READ;

    if (bytes_read == 0) {
      // No data yet
      return RTM_WOULD_BLOCK;
    }

    rtm->input_length += bytes_read;
  }

  // At this point we may have any number of full frames plus maybe one partial frame

  // Decode the WS frame.
  char *ws_frame = input_buffer;
  ssize_t input_length = rtm->input_length;

  // RTM_OK is returned if any data frame presents and no protocol errors
  // RTM_WOULD_BLOCK is returned if there are no data frames and no protocol errors
  // RTM_ERR_PROTCOL is returned if parser detects protocol error
  // RTM_ERR_CLOSE is returned if socket is closed or CLOSE frame is received
  return_code = RTM_WOULD_BLOCK;
  while (input_length > 2) { // must be at least 4 bytes to read a ws frame

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
      if (input_length < _RTM_INBOUND_HEADER_SIZE_NORMAL)
        return RTM_WOULD_BLOCK;
      payload_length = be16toh(*(uint16_t *) (&ws_frame[2]));
      header_length = _RTM_INBOUND_HEADER_SIZE_NORMAL;

    } else { // 127 -> 64 bit size
      if (input_length < _RTM_INBOUND_HEADER_SIZE_LARGE)
        return RTM_WOULD_BLOCK;
      payload_length = (size_t)be64toh(*(uint64_t *) (&ws_frame[2]));
      header_length = _RTM_INBOUND_HEADER_SIZE_LARGE;
    }

    if (payload_length >= RTM_MAX_MESSAGE_SIZE) {
      // if the frame is bigger than the internal buffer, it will never be decoded.
      return_code = _rtm_log_error(rtm, RTM_ERR_PROTOCOL, "message size beyond RTM limit – size=%d", payload_length);
      goto ws_error;
    }

    if (input_length < header_length + payload_length) {  // wait for more data to process the payload
      return_code = RTM_WOULD_BLOCK;
      break;
    }

    input_length -= header_length;
    ws_frame += header_length;

    // PING/PONG/CLOSE
    if (frame_opcode >= WS_CONTROL_COMMANDS_START && frame_opcode <= WS_CONTROL_COMMANDS_END) {

      if (!frame_fin || payload_length > _RTM_MAX_CONTROL_FRAME_SIZE) {
        // control frames must be single fragment, 125 bytes or less
        return_code = _rtm_log_error(rtm, RTM_ERR_PROTOCOL, "malformed control frame received – opcode=%d size=%d",
                                    frame_opcode, frame_payload_length);
        goto ws_error;
      }

      if (WS_CLOSE == frame_opcode) {
        _rtm_io_close(rtm);
        return RTM_ERR_CLOSED;
      } else if (WS_PING == frame_opcode || WS_PONG == frame_opcode) {
        const char* frame_type = (frame_opcode == WS_PONG) ? "pong" : "ping";
        if (rtm->is_verbose) {
          fprintf(stderr, "RECV: %s\n", frame_type);
        }
      }
    } else if (WS_TEXT == frame_opcode || WS_BINARY == frame_opcode) { /* data frame */
      if (!frame_fin) {
        // TODO: add split frame support?
        return_code = _rtm_log_error(rtm, RTM_ERR_PROTOCOL, "received unhandled split frame.");
        goto ws_error;
      }

      return_code = RTM_OK;

      char save = ws_frame[payload_length];
      ws_frame[payload_length] = 0;  // be nice, null terminate

      if (rtm->is_verbose) {
        fprintf(stderr, "RECV: %.*s\n", (int)payload_length, ws_frame);
      }

      rtm_text_frame_handler(rtm, ws_frame, payload_length);
      ws_frame[payload_length] = save;

      if (rtm->is_closed) {
        _rtm_io_close(rtm);
        return RTM_ERR_CLOSED;
      }
    } else {
      // unhandled opcode
      return_code = _rtm_log_error(rtm, RTM_ERR_PROTOCOL, "received unknown frame with opcode=%d", frame_opcode);
      goto ws_error;
    }
    input_length -= payload_length;
    ws_frame += payload_length;
  }

  /*
   * Move all remaining data to the start of the input buffer so that if we had a partial frame,
   * it will always be at the beginning of the buffer next time around, so we are guaranteed to have
   * memory space for a full frame
   */
  rtm->input_length -= ws_frame - input_buffer;
  if (rtm->input_length > 0) {
    memmove(input_buffer, ws_frame, rtm->input_length);
  }
  return return_code;

  ws_error:
  // abort?
  _rtm_io_close(rtm);
  return return_code;
}

#if defined(RTM_TEST_ENV)
rtm_status _rtm_test_parse_endpoint(rtm_client_t *rtm, const char *endpoint, char *hostname_out,
    char *port_out, char *path_out, unsigned *use_tls_out) {
  return parse_endpoint(rtm, endpoint, hostname_out, port_out, path_out, use_tls_out);
}

rtm_status _rtm_test_prepare_path(rtm_client_t *rtm, char *path, const char *appkey) {
  return prepare_path(rtm, path, appkey);
}
#endif

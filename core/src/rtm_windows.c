#include <basetsd.h>
#include <WinSock2.h>
#include <ws2def.h>
#include <WS2tcpip.h>
#include <io.h>
#include <string.h>
#include <stdio.h>

#include <panzi/portable_endian.h>

#include "rtm.h"
#include "rtm_internal.h"

static rtm_status connect_to_address(rtm_client_t *rtm, const struct addrinfo *address) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(address);

  rtm->fd = -1;

  int fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
  if (fd < 0) {
    _rtm_log_error(rtm, RTM_ERR_CONNECT, "Cannot create a socket");
    return RTM_ERR_CONNECT;
  }

  unsigned long nonblocking = 1;
  ioctlsocket(fd, FIONBIO, &nonblocking);

  time_t start_time = time(NULL);

try_again:
  (void)0; // because declaration cannot have a label

  int connect_rc = connect(fd, address->ai_addr, address->ai_addrlen);
  int last_error = WSAGetLastError();

  if (connect_rc != -1) {
    rtm->fd = fd;
    return RTM_OK;
  }

  if (WSAEINTR == last_error)   // interrupted, try again!
    goto try_again;

  if (WSAEINPROGRESS == last_error || WSAEWOULDBLOCK == last_error) {  // async connect in progress. poll the socket until we are good to go.
    int poll_result = 0;
    while (poll_result == 0) {
      struct pollfd pfd;
      pfd.fd = fd;
      pfd.events = POLLOUT;
      pfd.revents = 0;  // get ready to receive the events

      time_t dt = (time(NULL) - start_time);
      if (dt > rtm->connect_timeout) {
        break;
      }

      poll_result = WSAPoll(&pfd, 1, (int)(rtm->connect_timeout - dt) * 1000);
      if (poll_result < 0 && (WSAEWOULDBLOCK == last_error || WSAEINTR == last_error)) {
        poll_result = 0;
      }
      else if (poll_result == 1) {
        if (!(pfd.revents & POLLOUT)) {
          poll_result = -1;
        }
        break;
      }
    }

    if (poll_result == 1) {
      // connection established!
      rtm->fd = fd;
      return RTM_OK;
    }
    else {
      _close(fd);
      _rtm_log_error(rtm, RTM_ERR_CONNECT,
        "strange connection error - errno=%d message=%s", last_error,
        strerror(last_error));
      return RTM_ERR_CONNECT;
    }
  }
  // should never come here.
  _rtm_log_error(rtm, RTM_ERR_CONNECT,
    "weird connection error - errno=%d message=%s", last_error,
    strerror(last_error));
  return RTM_ERR_CONNECT;
}

rtm_status _rtm_io_connect_to_host_and_port(rtm_client_t *rtm, const char *hostname, const char *port) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(hostname);
  ASSERT_NOT_NULL(port);

  rtm->fd = -1;

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  struct addrinfo *res = NULL;
  int getaddrinfo_result = getaddrinfo(hostname, port, &hints, &res);
  if (getaddrinfo_result) {
    _rtm_log_error(rtm, RTM_ERR_CONNECT, "Cannot find hostname=%s - reason=%s", hostname,
      gai_strerror(getaddrinfo_result));
    return RTM_ERR_CONNECT;
  }

  // iterate through the records to find a working peer
  struct addrinfo *address;
  rtm_status rc = RTM_ERR_CONNECT;
  for (address = res; NULL != address; address = address->ai_next) {
    rc = connect_to_address(rtm, address);
    if (RTM_OK == rc) {
      break;
    }
  }
  freeaddrinfo(res);
  return rc;
}


rtm_status _rtm_io_wait(rtm_client_t *rtm, int readable, int writable, int timeout) {
  struct pollfd pfd;
  pfd.fd = rtm->fd;
  pfd.events = (short)(((writable != 0) ? POLLOUT : 0) | ((readable != 0) ? POLLIN : 0));
  pfd.revents = 0;

  int poll_result, effective_timeout;
  int const ping_interval_ms = rtm->ws_ping_interval * 1000;
  int last_error;
  unsigned ping_repeat;
  do {
    ping_repeat = FALSE;
    effective_timeout = timeout > ping_interval_ms || timeout < 0 ? ping_interval_ms : timeout;
    poll_result = WSAPoll(&pfd, 1, effective_timeout);
    last_error = WSAGetLastError();
    if (poll_result == 0) {
      if (effective_timeout == timeout) {
        return RTM_ERR_TIMEOUT;

      } else if (timeout > 0) {
        timeout -= effective_timeout;
      }
      rtm_status rc = _rtm_check_interval_and_send_ws_ping(rtm);
      if (rc != RTM_OK) {
        return rc;
      }
      ping_repeat = TRUE;
    }
  } while (ping_repeat || (poll_result < 0 && (WSAEWOULDBLOCK == last_error || WSAEINTR == last_error)));

  if (poll_result < 0) {
    _rtm_log_error(rtm, RTM_ERR_NETWORK, "error while waiting for socket - errno=%d error=%s",
      last_error,
      strerror(last_error));
    return RTM_ERR_NETWORK;
  }
  return RTM_OK;

}

ssize_t _rtm_io_write(rtm_client_t *rtm, const char *output_buffer, size_t output_size) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(output_buffer);

  if (output_size == 0)
    return 0;

  if (rtm->is_secure) {
    return _rtm_io_write_tls(rtm, output_buffer, output_size);
  }

  ssize_t write_result;
  ssize_t written = 0;

  while (output_size > 0) {
    write_result = send(rtm->fd, (char*)output_buffer + written, output_size, 0);
    int last_error = WSAGetLastError();
    if (write_result >= 0) {
      written += write_result;
      output_size -= write_result;
    }
    else if (WSAEINTR == last_error) {
      continue;
    }
    else if (WSAEWOULDBLOCK == last_error) {
      if (_rtm_io_wait(rtm, NO, YES, -1) != RTM_OK)
        return -1;
    }
    else {
      _rtm_log_error(rtm, RTM_ERR_WRITE, "Error writing to the socket - errno=%d message=%s", last_error, strerror(last_error));
      return -1;
    }
  }
  return written;
}

ssize_t _rtm_io_read(rtm_client_t *rtm, char *input_buffer, size_t input_size, int wait) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(input_buffer);
  if (input_size == 0)
    return 0;

  if (rtm->is_secure) {
    return _rtm_io_read_tls(rtm, input_buffer, input_size, wait);
  }

  ssize_t read_result;
  while (TRUE) {
    read_result = recv(rtm->fd, input_buffer, input_size, 0);
    int last_error = WSAGetLastError();
    if (read_result >= 0) {
      return read_result;
    }
    else if (WSAEINTR == last_error) {
      continue;
    }
    else if (WSAEWOULDBLOCK == last_error) {
      if (wait && _rtm_io_wait(rtm, YES, NO, -1) != RTM_OK)
        return -1;
      if (!wait)
        return 0;
    }
    else {
      _rtm_log_error(rtm, RTM_ERR_READ, "Error reading from the socket - errno=%d message=%s", last_error, strerror(last_error));
      return -1;
    }
  }
}

rtm_status _rtm_io_close(rtm_client_t *rtm) {
  ASSERT_NOT_NULL(rtm);

  if (rtm->is_secure) {
    _rtm_io_close_tls_session(rtm);
    rtm->is_secure = NO;
  }

  if (rtm->fd >= 0) {
    closesocket(rtm->fd);
    rtm->fd = -1;
  }

  if (rtm->is_used) {
    rtm->is_closed = YES;
  }
}


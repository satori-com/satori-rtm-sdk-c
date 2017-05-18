#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/poll.h>

#include <panzi/portable_endian.h>

#include "rtm.h"
#include "rtm_internal.h"

static rtm_status connect_to_address(rtm_client_t *rtm, const struct addrinfo *address) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(address);

  rtm->fd = -1;

  int fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
  if (fd < 0)
    return _rtm_log_error(rtm, RTM_ERR_CONNECT, "Cannot create a socket");

  fcntl(fd, F_SETFL, O_NONBLOCK); // non blocking socket.

  time_t start_time = time(NULL);

  try_again:

  if (connect(fd, address->ai_addr, address->ai_addrlen) != -1) {
    rtm->fd = fd;
    return RTM_OK;
  }

  if (EINTR == errno)   // interrupted, try again!
    goto try_again;

  if (EINPROGRESS == errno) {  // async connect in progress. poll the socket until we are good to go.
    int poll_result = 0;
    while (poll_result == 0) {
      struct pollfd pfd;
      pfd.fd = fd;
      pfd.events = POLLOUT;
      pfd.revents = 0;  // get ready to receive the events

      time_t dt = (time(NULL) - start_time);
      if (dt > rtm_connect_timeout) {
        break;
      }

      poll_result = poll(&pfd, 1, (int) (rtm_connect_timeout - dt) * 1000);
      if (poll_result < 0 && (EAGAIN == errno || EINTR == errno)) {
        poll_result = 0;
      } else if (poll_result == 1) {
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
    } else {
      close(fd);
      return _rtm_log_error(rtm, RTM_ERR_CONNECT,
              "connection error – errno=%d message=%s", errno,
              strerror(errno));
    }
  }
  // should never come here.
  return _rtm_log_error(rtm, RTM_ERR_CONNECT,
          "connection error – errno=%d message=%s", errno,
          strerror(errno));
}


static rtm_status connect_to_host_and_port(rtm_client_t *rtm, const char *hostname, const char *port) {
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
    return _rtm_log_error(rtm, RTM_ERR_CONNECT, "Cannot find hostname=%s – reason=%s", hostname,
                         gai_strerror(getaddrinfo_result));
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
  pfd.events = (short) (((writable != 0) ? POLLOUT : 0) | ((readable != 0) ? POLLIN : 0));
  pfd.revents = 0;

  int poll_result, effective_timeout;
  int const ping_interval_ms = rtm->ws_ping_interval * 1000;
  unsigned ping_repeat;
  do {
    ping_repeat = FALSE;
    effective_timeout = timeout > ping_interval_ms || timeout < 0 ? ping_interval_ms : timeout;
    poll_result = poll(&pfd, 1, effective_timeout);
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
  } while (ping_repeat || (poll_result < 0 && (EAGAIN == errno || EINTR == errno)));

  if (poll_result < 0) {
    return _rtm_log_error(rtm, RTM_ERR_NETWORK, "error while waiting for socket – errno=%d error=%s",
                         errno,
                         strerror(errno));

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
    write_result = write(rtm->fd, (char*) output_buffer + written, output_size);
    if (write_result >= 0) {
      written += write_result;
      output_size -= write_result;
    } else if (EINTR == errno) {
      continue;
    } else if (EAGAIN == errno) {
      if (_rtm_io_wait(rtm, NO, YES, -1) != RTM_OK)
        return WRITE_FAILURE;
    } else {
      _rtm_log_error(rtm, RTM_ERR_WRITE, "Error writing to the socket – errno=%d message=%s", errno, strerror(errno));
      return WRITE_FAILURE;
    }
  }
  return written;
}

ssize_t _rtm_io_read(rtm_client_t *rtm, char *input_buffer, size_t input_size, int wait) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(input_buffer);
  ASSERT(input_size <= _RTM_MAX_BUFFER);
  if (input_size == 0)
    return 0;

  if (rtm->is_secure) {
    return _rtm_io_read_tls(rtm, input_buffer, input_size, wait);
  }

  ssize_t read_result;
  while (TRUE) {
    read_result = read(rtm->fd, input_buffer, input_size);
    if (read_result >= 0) {
      return read_result;
    } else if (EINTR == errno) {
      continue;
    } else if (EAGAIN == errno) {
      if (wait && _rtm_io_wait(rtm, YES, NO, -1) != RTM_OK)
        return READ_FAILURE;
      if (!wait)
        return 0;
    } else {
      _rtm_log_error(rtm, RTM_ERR_READ, "Error reading from the socket – errno=%d message=%s", errno, strerror(errno));
      return READ_FAILURE;
    }
  }
}

rtm_status _rtm_io_connect(rtm_client_t *rtm, const char *hostname, const char *port, unsigned use_tls) {
  ASSERT_NOT_NULL(rtm);
  ASSERT_NOT_NULL(hostname);
  ASSERT_NOT_NULL(port);

  rtm->fd = -1;

  rtm_status rc = connect_to_host_and_port(rtm, hostname, port);
  if (rc) {
    return rc;
  }

  rtm->is_secure = NO;
  if (use_tls) {
    rc = _rtm_io_open_tls_session(rtm, hostname);
    if (rc) {
      _rtm_io_close(rtm);
      return rc;
    }
    rtm->is_secure = YES;
  }
  return RTM_OK;
}

rtm_status _rtm_io_close(rtm_client_t *rtm) {
  ASSERT_NOT_NULL(rtm);

  if (rtm->is_secure) {
    _rtm_io_close_tls_session(rtm);
    rtm->is_secure = NO;
  }

  if (rtm->fd >= 0) {
    close(rtm->fd);
    rtm->fd = -1;
  }
  if (rtm->is_used) {
    rtm->is_closed = YES;
  }
  return RTM_OK;
}

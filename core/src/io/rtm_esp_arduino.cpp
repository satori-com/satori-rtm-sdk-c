#include <ESP8266WiFi.h>
#include <map>
#include <cstdlib>

// extern char *_rtm_ssl_cert;

/**
 * WiFiClientSecure extension that can be used for both encrypted and
 * unencrypted communication.
 *
 * Important note: The ESP8266 SDK does not make this perfectly clear, but the
 * contract actually is half-duplex and connected()/available() will read any
 * available data. Do _not_ call available(), then write(), and then try to
 * read().
 */
class RTMWiFiClient : public WiFiClientSecure {
  bool is_secure;

  public:
    RTMWiFiClient() : is_secure(false) {};

    int connect(IPAddress ip, uint16_t port) override {
      return WiFiClient::connect(ip, port);
    }

    int connect(const char *name, uint16_t port) override {
      IPAddress remote_addr;
      if (!WiFi.hostByName(name, remote_addr)) {
          return 0;
      }
      if (!WiFiClient::connect(remote_addr, port)) {
          return 0;
      }
      return 1;
    }

    size_t write(const uint8_t *buf, size_t size) override {
      if(is_secure) {
        return WiFiClientSecure::write(buf, size);
      }
      return WiFiClient::write(buf, size);
    }

    int read(uint8_t *buf, size_t size) override {
      if(is_secure) {
        return WiFiClientSecure::read(buf, size);
      }
      return WiFiClient::read(buf, size);
    }

    int available() override {
      if(is_secure) {
        return WiFiClientSecure::available();
      }
      return WiFiClient::available();
    }

    uint8_t connected() override {
      if(is_secure) {
        return WiFiClientSecure::connected();
      }
      return WiFiClient::connected();
    }

    virtual int ssl_handshake(const char *hostname) {
      int rc = _connectSSL(hostname);
      is_secure = rc == 1;
      return rc;
    }
};

static std::map<int, RTMWiFiClient *> connections; //!< fd to client map

extern "C" {
  #include <errno.h>
  #include <fcntl.h>
  #include <unistd.h>
  #include <stdio.h>
  #include <string.h>

  #include "rtm.h"
  #include "rtm_internal.h"

  rtm_status _rtm_io_connect_to_host_and_port(rtm_client_t *rtm, const char *hostname, const char *port) {
    int new_fd;
    if(connections.empty()) {
      new_fd = 1;
    }
    else {
      auto back_iter = --connections.end();
      new_fd = back_iter->first + 1;
    }
    connections.insert({new_fd, new RTMWiFiClient()});

    RTMWiFiClient &client = *connections[new_fd];
    rtm->fd = new_fd;

    // client.setCACert(_rtm_ssl_cert);

    rtm_status rv = client.connect(hostname, std::atoi(port)) ? RTM_OK : RTM_ERR_NETWORK;

    return rv;
  }

  rtm_status _rtm_io_wait(rtm_client_t *rtm, int readable, int writeable, int timeout) {
    auto cli_iter = connections.find(rtm->fd);
    if(cli_iter == connections.end()) {
      return RTM_ERR_CLOSED;
    }
    RTMWiFiClient &client = *cli_iter->second;

    if(!client.connected()) {
      return RTM_ERR_CLOSED;
    }

    if(writeable) {
      return RTM_OK;
    }

    int ping_timeout = rtm->ws_ping_interval * 1000;

    while(true) {
      if(client.available()) {
        return RTM_OK;
      }

      if(ping_timeout <= 0) {
          rtm_status rc = _rtm_check_interval_and_send_ws_ping(rtm);
          if (rc != RTM_OK) {
            return rc;
          }

          ping_timeout = rtm->ws_ping_interval * 1000;
      }

      if(timeout <= 0) {
        return RTM_ERR_TIMEOUT;
      }

      delay(10);
      ping_timeout -= 10;
      timeout -= 10;

      yield();
    }
  }

  ssize_t _rtm_io_write(rtm_client_t *rtm, const char *output_buffer, size_t output_size) {
    auto cli_iter = connections.find(rtm->fd);
    if(cli_iter == connections.end()) {
      return RTM_ERR_CLOSED;
    }
    RTMWiFiClient &client = *cli_iter->second;

    return client.write((uint8_t*)output_buffer, output_size);
  }

  ssize_t _rtm_io_read(rtm_client_t *rtm, char *input_buffer, size_t input_size, int wait) {
    auto cli_iter = connections.find(rtm->fd);
    if(cli_iter == connections.end()) {
      return RTM_ERR_CLOSED;
    }
    RTMWiFiClient &client = *cli_iter->second;

    if(!client.connected()) {
      return -1;
    }

    while(!client.available()) {
      if(!wait) return 0;
      yield();
    }

    int rc = client.read((uint8_t*)input_buffer, input_size);
    return rc;
  }

  rtm_status _rtm_io_close(rtm_client_t *rtm) {
    auto cli_iter = connections.find(rtm->fd);
    if(cli_iter == connections.end()) {
      return RTM_ERR_CLOSED;
    }
    RTMWiFiClient &client = *cli_iter->second;

    client.stop();
    connections.erase(cli_iter);
  }

  rtm_status _rtm_io_open_tls_session(rtm_client_t *rtm, const char *host) {
    auto cli_iter = connections.find(rtm->fd);
    if(cli_iter == connections.end()) {
      return RTM_ERR_CLOSED;
    }
    return cli_iter->second->ssl_handshake(host) ? RTM_OK : RTM_ERR_PROTOCOL;
  }

  rtm_status _rtm_io_close_tls_session(rtm_client_t *rtm) {
    return RTM_OK;
  }
}

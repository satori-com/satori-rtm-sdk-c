#include <gtest/gtest.h>
#include <algorithm>
#include <queue>
#include <chrono>
#include <cstdint>
#include <cstdlib> // alloca
#include <ctime>
#include <set>
#include <vector>

#ifdef _WIN32
#include <WinSock2.h>
#include <Windows.h>
#include <WS2tcpip.h>
#endif

#include <nlohmann_json/json.hpp>

#include <rtm.h>
#include <rtm_internal.h>

// Replace these values with your project's credentials
// from DevPortal (https://developer.satori.com/)
const char *endpoint = YOUR_ENDPOINT;
const char *appkey = YOUR_APPKEY;
const char *role_name = YOUR_ROLE;
const char *role_secret = YOUR_ROLE_SECRET;
const char *restricted_channel = YOUR_CHANNEL;

using json = nlohmann::json;

struct event_t {
  unsigned request_id = 0;
  rtm_action_t action;
  std::string info;
};

std::queue<event_t> event_queue;
std::queue<std::string> message_queue;
std::queue<std::string> error_message_queue;

void pdu_recorder(rtm_client_t *rtm, const rtm_pdu_t *pdu) {
  (void)rtm;

  event_t event;
  event.action = pdu->action;
  event.request_id = pdu->request_id;
  switch (event.action) {
    case RTM_ACTION_AUTHENTICATE_ERROR:
    case RTM_ACTION_DELETE_ERROR:
    case RTM_ACTION_HANDSHAKE_ERROR:
    case RTM_ACTION_PUBLISH_ERROR:
    case RTM_ACTION_READ_ERROR:
    case RTM_ACTION_SUBSCRIBE_ERROR:
    case RTM_ACTION_UNSUBSCRIBE_ERROR:
    case RTM_ACTION_WRITE_ERROR:
      event.info = std::string(pdu->error);
      break;
    case RTM_ACTION_HANDSHAKE_OK:
      event.info = std::string(pdu->nonce);
      break;
    case RTM_ACTION_SUBSCRIBE_OK:
    case RTM_ACTION_UNSUBSCRIBE_OK: {
      event.info = std::string(pdu->subscription_id);
      break;
    }
    case RTM_ACTION_READ_OK:
      event.info = std::string(pdu->message);
      break;
    case RTM_ACTION_UNKNOWN:
      if(pdu->body) {
        event.info = std::string(pdu->body);
      }
      break;
    case RTM_ACTION_SUBSCRIPTION_DATA: {
      char *message;
      while ((message = rtm_iterate(&pdu->message_iterator))) {
        event_t data = event;
        data.info = std::string(pdu->subscription_id) + ":" + std::string(message);
        event_queue.push(data);
      }
      return;
    }
    default:
      event.info = "";
      break;
  }
  event_queue.push(event);
}

void raw_pdu_recorder(rtm_client_t *rtm, char const *raw_pdu) {
  (void)rtm;

  event_t event{};
  event.info = std::string(raw_pdu);
  event_queue.push(event);
}

void error_message_recorder(const char *error_message) {
  error_message_queue.push(error_message);
}


rtm_status next_event(rtm_client_t *rtm, event_t* event) {
  rtm_status rc = RTM_OK;
  while (event_queue.size() == 0 && rc == RTM_OK) {
    rc = rtm_wait_timeout(rtm, 15);
  }
  if (event_queue.size() != 0) {
    *event = event_queue.front();
    event_queue.pop();
  }
  return rc;
}

static std::string make_channel(int len = 6) {
  std::string r = "";
  for (; len > 0; --len) {
    r += static_cast<char>(static_cast<int>('a') + rand() % 26);
  }
  return r;
}

TEST(rtm_test, init_ex) {
  size_t size = RTM_CLIENT_SIZE(2*10240);
  void *memory = alloca(size);

  rtm_client_t *rtm = rtm_init_ex(memory, size, rtm_default_pdu_handler, nullptr);

  ASSERT_NE(rtm, nullptr);
}

TEST(rtm_test, init_ex_fail_too_small) {
  size_t size = RTM_CLIENT_SIZE(0);
  void *memory = alloca(size);

  rtm_client_t *rtm = rtm_init_ex(memory, size, rtm_default_pdu_handler, nullptr);

  ASSERT_EQ(rtm_connect(rtm, endpoint, appkey), RTM_ERR_OOM);
}

TEST(rtm_test, test_allocators) {
  size_t size = RTM_CLIENT_SIZE(512);
  void *memory = alloca(size);

  struct alloc_t {
    std::set<char *> allocs;
    int number_of_allocs;
    int number_of_frees;

    alloc_t() { reset(); }
    ~alloc_t() {
      reset();
    }

    void reset() {
      number_of_allocs = 0;
      number_of_frees = 0;

      for(char *p : allocs) {
        delete[] p;
      }
      allocs.clear();
    }

    char *alloc(size_t size) {
      char *retval = new char[size];
      allocs.insert(retval);
      number_of_allocs++;
      return retval;
    }

    void free(char *mem) {
      auto this_alloc = allocs.find(mem);

      ASSERT_NE(this_alloc, allocs.end());

      allocs.erase(this_alloc);
      number_of_frees++;
      delete[] mem;
    }
  };

  alloc_t allocations {};

  rtm_client_t *rtm = rtm_init_ex(memory, size, pdu_recorder, &allocations);

  rtm_set_allocator(rtm,
      [](rtm_client_t *rtm, size_t amount) {
        alloc_t *alloc = static_cast<alloc_t *>(rtm_get_user_context(rtm));
        return (void*)alloc->alloc(amount);
      },
      [](rtm_client_t *rtm, void *mem) {
        alloc_t *alloc = static_cast<alloc_t *>(rtm_get_user_context(rtm));
        alloc->free((char*)mem);
      });

  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(0, allocations.number_of_allocs) << "Memory allocated for connect() call even though it wasn't needed.";

  std::vector<char> large_message(10000, 'A');
  large_message.back() = 0;

  std::string const channel = make_channel();

  rc = rtm_subscribe(rtm, channel.c_str(), nullptr);
  ASSERT_EQ(0, allocations.number_of_allocs) << "Memory allocated for subscribe() call even though it wasn't needed.";

  ASSERT_EQ(RTM_OK, rtm_publish_string(rtm, channel.c_str(), &large_message[0], nullptr));
  ASSERT_NE(0, allocations.number_of_allocs) << "No memory allocated even though we sent a large message.";
  ASSERT_EQ(allocations.number_of_frees, allocations.number_of_allocs) << "Memory allocated for subscribe(), but never free()d.";

  allocations.number_of_allocs = allocations.number_of_frees = 0;

  event_t event;
  rc = next_event(rtm, &event);
  if(rc != RTM_OK || event.action != RTM_ACTION_SUBSCRIPTION_DATA) {
    FAIL() << "Failed to receive subscription data.";
  }

  ASSERT_NE(allocations.number_of_allocs, 0) << "No memory allocated even though we received a large message.";
  ASSERT_EQ(allocations.number_of_frees, allocations.number_of_allocs) << "Memory allocated for rtm_poll(), but never free()d.";
}

TEST(rtm_test, subscribe) {
  unsigned int request_id;
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, rtm_default_pdu_handler, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";
  std::string const channel = make_channel();
  rc = rtm_subscribe(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while subscribe to channel";
  rtm_close(rtm);
}

TEST(rtm_test, publish_and_subscribe_with_history) {
  unsigned int request_id;
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  std::string const channel = make_channel();
  rc = rtm_publish_string(rtm, channel.c_str(), "my message", &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while publishing";

  event_t event;
  rc = next_event(rtm, &event);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait";
  ASSERT_EQ(RTM_ACTION_PUBLISH_OK, event.action);

  std::string const body = R"({"channel":")" + channel + R"(","history":{"count":1}})";
  rc = rtm_subscribe_with_body(rtm, body.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while subscribing";

  rc = next_event(rtm, &event);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait";
  ASSERT_EQ(RTM_ACTION_SUBSCRIBE_OK, event.action);
  ASSERT_EQ(channel, event.info);

  rc = next_event(rtm, &event);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait";
  ASSERT_EQ(RTM_ACTION_SUBSCRIPTION_DATA, event.action);
  ASSERT_EQ(channel + ":" + R"("my message")", event.info);

  rtm_close(rtm);
}

TEST(rtm_ssl_test, connect_ssl) {
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";
  rtm_close(rtm);
}

TEST(rtm_ssl_test, self_signed_ssl) {
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  int rc = rtm_connect(rtm, "wss://self-signed.badssl.com", "appkey");
  ASSERT_EQ(RTM_ERR_TLS, rc) << "Connection to self-signed SSL endpoint did not fail";
  rtm_close(rtm);
}

TEST(rtm_ssl_test, expired_ssl) {
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  int rc = rtm_connect(rtm, "wss://expired.badssl.com", "appkey");
  ASSERT_EQ(RTM_ERR_TLS, rc) << "Connection to SSL endpoint with expired certificate did not fail";
  rtm_close(rtm);
}

TEST(rtm_ssl_test, wrong_host_ssl) {
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  int rc = rtm_connect(rtm, "wss://wrong.host.badssl.com", "appkey");
  ASSERT_EQ(RTM_ERR_TLS, rc) << "Connection to SSL endpoint with wrong host did not fail";
  rtm_close(rtm);
}

TEST(rtm_test, publish) {
  void *memory = alloca(rtm_client_size);

  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";
  std::string const channel = make_channel();
  rc = rtm_publish_string(rtm, channel.c_str(), "my message", nullptr);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while publish to channel";

  rtm_close(rtm);
}

TEST(rtm_test, overflow) {
  void *memory = alloca(rtm_client_size);

  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  rtm_set_allocator(rtm, rtm_null_malloc, rtm_null_free);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";
  std::string const channel = make_channel();

  std::string big_body(16 * 1024 * 1024, 'a');
  rc = rtm_subscribe_with_body(rtm, big_body.c_str(), nullptr);
  ASSERT_EQ(RTM_ERR_OOM, rc)<< "Expected rtm_subscribe_with_body to fail";

  rtm_close(rtm);
}

TEST(rtm_test, publish_json_and_read) {
  unsigned int request_id;
  void *memory = alloca(rtm_client_size);

  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  std::string const channel = make_channel();
  const std::string msg = R"({"foo":"bar"})";
  rc = rtm_publish_json(rtm, channel.c_str(), msg.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while publish to channel";

  event_t event;
  rc = next_event(rtm, &event);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while wait PDU";
  ASSERT_EQ(RTM_ACTION_PUBLISH_OK, event.action);

  rc = rtm_read(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while publish to channel";

  rc = next_event(rtm, &event);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while wait event";
  ASSERT_EQ(RTM_ACTION_READ_OK, event.action);
  ASSERT_EQ(msg, event.info);

  rtm_close(rtm);
}

TEST(rtm_test, read_write_delete) {
  unsigned int request_id;
  void *memory = alloca(rtm_client_size);

  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  std::string const channel = make_channel();

  rc = rtm_read(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while publish to channel";

  event_t event;
  rc = next_event(rtm, &event);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while wait PDU";
  ASSERT_EQ(RTM_ACTION_READ_OK, event.action);
  ASSERT_EQ(request_id, event.request_id);
  ASSERT_EQ("null", event.info);


  rc = rtm_write_string(rtm, channel.c_str(), "msg", &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while write";

  rc = next_event(rtm, &event);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while wait PDU";
  ASSERT_EQ(RTM_ACTION_WRITE_OK, event.action);

  rc = rtm_read(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while read";

  rc = next_event(rtm, &event);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while wait PDU";
  ASSERT_EQ(RTM_ACTION_READ_OK, event.action);
  ASSERT_EQ(request_id, event.request_id);
  ASSERT_EQ("\"msg\"", event.info);

  rc = rtm_delete(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while delete";

  rc = next_event(rtm, &event);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while wait PDU";
  ASSERT_EQ(RTM_ACTION_DELETE_OK, event.action);

  rc = rtm_read(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while read";

  rc = next_event(rtm, &event);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while wait PDU";
  ASSERT_EQ(RTM_ACTION_READ_OK, event.action);
  ASSERT_EQ(request_id, event.request_id);
  ASSERT_EQ("null", event.info);

  rtm_close(rtm);
}

TEST(rtm_test, handshake_and_authenticate) {
  unsigned int request_id;
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  rc = rtm_handshake(rtm, role_name, &request_id);
  ASSERT_EQ(rc, RTM_OK) << "Failed to send rtm/handshake";

  event_t event;
  rc = next_event(rtm, &event);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait";
  ASSERT_EQ(RTM_ACTION_HANDSHAKE_OK, event.action);
  std::string nonce = event.info;
  rc = rtm_authenticate(rtm, role_secret, nonce.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to send auth/authenticate";

   rc = next_event(rtm, &event);
   ASSERT_EQ(rc, RTM_OK) << "Failed to wait";
   ASSERT_EQ(RTM_ACTION_AUTHENTICATE_OK, event.action);

  rtm_close(rtm);
}

TEST(rtm_test, publish_and_receive) {
  unsigned int request_id;
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  std::string const channel = make_channel();
  rc = rtm_subscribe(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(rc, RTM_OK) << "Failed to subscribe";

  event_t event;
  rc = next_event(rtm, &event);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait";
  ASSERT_EQ(RTM_ACTION_SUBSCRIBE_OK, event.action);
  ASSERT_EQ(channel, event.info);

  rc = rtm_publish_string(rtm, channel.c_str(), "my message", nullptr);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while publishing";

  rc = next_event(rtm, &event);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait";
  ASSERT_EQ(RTM_ACTION_SUBSCRIPTION_DATA, event.action);
  ASSERT_EQ(channel + ":" + R"("my message")", event.info);

  rtm_close(rtm);
}

TEST(rtm_test, publish_ws_frame_with_126_bytes_payload) {
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  // channel is hardcoded with fixed length to get 126 bytes payload for WS frame
  unsigned int request_id;
  rc = rtm_publish_json(rtm, "xxxxxxxxxxxxxxx", "{\n   \"cmd_data\" : \"1\",\n   \"cmd_type\" : \"ack\"\n}\n", &request_id);
  ASSERT_EQ(RTM_OK, rc) << "Failed while publishing";

  event_t event;
  rc = next_event(rtm, &event);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait publish response";
  ASSERT_EQ(RTM_ACTION_PUBLISH_OK, event.action);

  rtm_close(rtm);
}

TEST(rtm_test, disconnect) {
  unsigned int request_id;
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";
  rtm_close(rtm);
  std::string const channel = make_channel();
  rc = rtm_subscribe(rtm, channel.c_str(), &request_id);
  ASSERT_GT(RTM_OK, rc)<< "Susbcription succeeded, but RTM should have been closed";
}

TEST(rtm_test, rtm_poll_does_not_hang_ssl) {
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  ASSERT_EQ(RTM_WOULD_BLOCK, rtm_poll(rtm)) << "Failed to poll";

  rtm_close(rtm);
}


TEST(rtm_test, rtm_poll_does_not_hang_nossl) {
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  ASSERT_EQ(RTM_WOULD_BLOCK, rtm_poll(rtm)) << "Failed to poll";

  rtm_close(rtm);
}

TEST(rtm_test, rtm_wait_timeout) {
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  time_t before = time(nullptr);
  rc = rtm_wait_timeout(rtm, 2);
  time_t after = time(nullptr);

  ASSERT_EQ(RTM_ERR_TIMEOUT, rc) << "rtm_wait_timeout failed to report timeout";
  ASSERT_GT(after - before, 1) << "rtm_wait_timeout returned too quickly";
  ASSERT_LT(after - before, 4) << "rtm_wait_timeout returned too slowly";

  rtm_close(rtm);
}

TEST(rtm_test, verbose_logging) {
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);

  rtm_disable_verbose_logging(rtm);
  ASSERT_EQ(rtm->is_verbose, 0u) << "verbose_logging Unable to disable verbose loggin";

  rtm_enable_verbose_logging(rtm);
  ASSERT_EQ(rtm->is_verbose, 1u) << "verbose_logging Unable to enable verbose loggin";
}

TEST(rtm_test, error_handler) {
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);

  rtm_set_error_logger(rtm, error_message_recorder);
  ASSERT_EQ(error_message_queue.size(), 0u) << "Error message queue isn't empty to start with";

  rtm_connect(rtm, "thisisaninvalidendpoint", "thisisaninvalidkey");

  ASSERT_GT(error_message_queue.size(), 0u) << "Error message queue is empty even though an error occurred";
  ASSERT_NE(error_message_queue.front().find("Unsupported scheme in endpoint=thisisaninvalidendpoint"), std::string::npos) << "Unexpected error message: " << error_message_queue.front();

  error_message_queue.pop();
}

TEST(rtm_test, log_message) {
  const char *str = "Test log";

  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);

  _rtm_log_message(rtm, RTM_OK, str);
}

TEST(rtm_test, unsubscribe) {
  unsigned int request_id;

  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";
  std::string const channel = make_channel();
  rc = rtm_subscribe(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while subscribing to channel";

  event_t event;
  rc = next_event(rtm, &event);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait subscribe response";
  ASSERT_EQ(RTM_ACTION_SUBSCRIBE_OK, event.action);
  ASSERT_EQ(channel, event.info);

  rc = rtm_unsubscribe(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while unsubscribing from channel";

  rc = next_event(rtm, &event);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait unsibscribe response";
  ASSERT_EQ(RTM_ACTION_UNSUBSCRIBE_OK, event.action);
  ASSERT_EQ(channel, event.info);

  rtm_close(rtm);
}

TEST(rtm_test, check_rtm_fd) {
  int fd;
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";
  fd = rtm_get_fd(rtm);
  ASSERT_GT(fd, 0);

  rtm_close(rtm);
  fd = rtm_get_fd(rtm);
  ASSERT_EQ(fd, -1);
}

TEST(rtm_test, get_user_context) {
  struct u_context {
    int user_id;
    char *data;
  };

  u_context context = {12, (char *)"Hello"};

  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, &context);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  u_context *rtm_context = static_cast<u_context *>(rtm_get_user_context(rtm));
  ASSERT_EQ(context.user_id, rtm_context->user_id);
  ASSERT_EQ(context.data, rtm_context->data);

  rtm_close(rtm);
}

TEST(rtm_test, raw_pdu_handler) {
  std::string const channel = make_channel();
  void *memory = alloca(rtm_client_size);

  rtm_client_t *rtm = rtm_init(memory, rtm_default_pdu_handler, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);
  rtm_set_raw_pdu_handler(rtm, raw_pdu_recorder);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  unsigned int request_id;
  rc = rtm_write_string(rtm, channel.c_str(), "publish_msg", &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while write";
  
  rc = rtm_wait_timeout(rtm, 15);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while waiting rtm response";

  event_t event;
  rc = next_event(rtm, &event);

  ASSERT_LE(event.info.find(R"("action":"rtm/write/ok")"), std::string::npos);
  ASSERT_LE(event.info.find(R"("id":1)"), std::string::npos);

  ASSERT_EQ(RTM_OK, rc);
  rtm_close(rtm);
}

TEST(rtm_test, rtm_default_pdu_handler) {
  unsigned int request_id;
  std::string const channel = make_channel();
  void *memory = alloca(rtm_client_size);

  rtm_client_t *rtm = rtm_init(memory, rtm_default_pdu_handler, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  rc = rtm_write_string(rtm, channel.c_str(), "publish_msg", &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while write";
  
  rc = rtm_wait_timeout(rtm, 15);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while waiting rtm response";
  rtm_close(rtm);
}

TEST(rtm_test, read_with_body) {
  unsigned int request_id;
  void *memory = alloca(rtm_client_size);

  std::string const channel = make_channel();

  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  std::string const body = R"({"channel":")" + channel + R"("})";

  // Read from the non-existing channel
  rc = rtm_read_with_body(rtm, body.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to read with body";

  event_t event;
  rc = next_event(rtm, &event);
  ASSERT_EQ(RTM_OK, rc) << "Failed to get next PDU";
  ASSERT_EQ(RTM_ACTION_READ_OK, event.action);
  ASSERT_EQ("null", event.info);

  // Publish 3 messages
  for (int i = 0; i < 3; i++) {
    std::string message = "message-" + std::to_string(i);
    rc = rtm_publish_string(rtm, channel.c_str(), message.c_str(), &request_id);
    ASSERT_EQ(RTM_OK, rc)<< "Failed while write";
    rc = next_event(rtm, &event);
    ASSERT_EQ(RTM_OK, rc) << "Failed to get next PDU";
    ASSERT_EQ(RTM_ACTION_PUBLISH_OK, event.action);
  }

  rc = rtm_read_with_body(rtm, body.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to read with body";

  rc = next_event(rtm, &event);
  ASSERT_EQ(RTM_OK, rc) << "Failed to get next event";
  ASSERT_EQ(RTM_ACTION_READ_OK, event.action);
  ASSERT_EQ("\"message-2\"", event.info);

  rtm_close(rtm);
}

TEST(rtm_test, rtm_write_json) {
  json test_json;
  unsigned int request_id;
  void *memory = alloca(rtm_client_size);
  std::string const channel = make_channel();

  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  test_json["intval"] = 12345;
  test_json["bool"] = true;
  test_json["list"] = {1, 2, 3};
  test_json["object"] = {{"currency", "USD"}, {"value", 42.99}};

  rtm_write_json(rtm, channel.c_str(), test_json.dump().c_str(), &request_id);
  event_t event;
  rc = next_event(rtm, &event);
  ASSERT_EQ(RTM_OK, rc) << "Failed to get next PDU";
  ASSERT_EQ(RTM_ACTION_WRITE_OK, event.action);

  rtm_read(rtm, channel.c_str(), &request_id);
  rc = next_event(rtm, &event);
  ASSERT_EQ(RTM_OK, rc) << "Failed to get next PDU";
  ASSERT_EQ(RTM_ACTION_READ_OK, event.action);
  ASSERT_EQ(test_json, json::parse(event.info));

  rtm_close(rtm);
}

TEST(rtm_test, publish_and_receive_all_json_types) {
  unsigned int request_id;
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  std::string const channel = make_channel();
  rc = rtm_subscribe(rtm, channel.c_str(), &request_id);

  ASSERT_EQ(rc, RTM_OK) << "Failed to wait";

  event_t event;
  rc = next_event(rtm, &event);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait";
  ASSERT_EQ(RTM_ACTION_SUBSCRIBE_OK, event.action);
  ASSERT_EQ(channel, event.info);

  char const *messages[] =
      {"null", "42",
       "3.14159",
       R"("")", R"("hello")", "[]", "{}", "[null]", "[42]",
       "[3.14159]", R"(["\""])", R"(["hello"])",
       R"({"key":null})", R"({"key":42})", R"({"key":3.14159})",
       R"({"key":""})", R"({"key":"hello"})",
       R"({"key":[]})", R"({"key":{}})",
       R"({"key":[42,"foo"]})", R"({"key":{"foo":42}})",
       R"([{},null,{"key":"value"},null])",
      };

  for (char const *message : messages) {
      ASSERT_EQ(RTM_OK, rtm_publish_json(rtm, channel.c_str(), message, nullptr));

      rc = next_event(rtm, &event);
      ASSERT_EQ(rc, RTM_OK) << "Failed to wait";
      ASSERT_EQ(RTM_ACTION_SUBSCRIPTION_DATA, event.action);

      std::string coded_response = event.info;
      auto channel_sep = coded_response.find(":");
      ASSERT_NE(std::string::npos, channel_sep);

      auto response_channel = coded_response.substr(0, channel_sep);
      auto response = coded_response.substr(channel_sep + 1);

      ASSERT_EQ(channel, response_channel);

      auto normalized_template  = json::parse(message).dump();
      auto normalized_response = json::parse(response).dump();
      ASSERT_EQ(normalized_template, normalized_response);
  }

  rtm_close(rtm);
}

TEST(rtm_test, parse_endpoint_test) {
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);

  char hostname[255];
  char port[10];
  char path[255];
  unsigned use_tls;
  rtm_status rc;

  memset(hostname, 0, sizeof(hostname));
  memset(port, 0, sizeof(port));
  memset(path, 0, sizeof(path));
  rc = _rtm_test_parse_endpoint(
      rtm, "wss://example.com/", (enum rtm_url_scheme_t)(SCHEME_WSS | SCHEME_WS), hostname, port, path, &use_tls);
  ASSERT_EQ("example.com", std::string(hostname));
  ASSERT_EQ("443", std::string(port));
  ASSERT_EQ("/", std::string(path));
  ASSERT_EQ(1u, use_tls);
  ASSERT_EQ(RTM_OK, rc);

  memset(hostname, 0, sizeof(hostname));
  memset(port, 0, sizeof(port));
  memset(path, 0, sizeof(path));
  rc = _rtm_test_parse_endpoint(
      rtm, "ws://example.com/", (enum rtm_url_scheme_t)(SCHEME_WS | SCHEME_WSS), hostname, port, path, &use_tls);
  ASSERT_EQ("example.com", std::string(hostname));
  ASSERT_EQ("80", std::string(port));
  ASSERT_EQ("/", std::string(path));
  ASSERT_EQ(0u, use_tls);
  ASSERT_EQ(RTM_OK, rc);

  memset(hostname, 0, sizeof(hostname));
  memset(port, 0, sizeof(port));
  memset(path, 0, sizeof(path));
  rc = _rtm_test_parse_endpoint(rtm, "ws://example.com", SCHEME_WS, hostname, port, path, &use_tls);
  ASSERT_EQ("example.com", std::string(hostname));
  ASSERT_EQ("80", std::string(port));
  ASSERT_EQ("/", std::string(path));
  ASSERT_EQ(0u, use_tls);
  ASSERT_EQ(RTM_OK, rc);

  memset(hostname, 0, sizeof(hostname));
  memset(port, 0, sizeof(port));
  memset(path, 0, sizeof(path));
  rc = _rtm_test_parse_endpoint(
      rtm, "ws://example.com/v3", SCHEME_WS, hostname, port, path, &use_tls);
  ASSERT_EQ("example.com", std::string(hostname));
  ASSERT_EQ("80", std::string(port));
  ASSERT_EQ("/v3", std::string(path));
  ASSERT_EQ(0u, use_tls);
  ASSERT_EQ(RTM_OK, rc);

  memset(hostname, 0, sizeof(hostname));
  memset(port, 0, sizeof(port));
  memset(path, 0, sizeof(path));
  rc = _rtm_test_parse_endpoint(
      rtm, "ws://example.com:8080/v3", SCHEME_WS, hostname, port, path, &use_tls);
  ASSERT_EQ("example.com", std::string(hostname));
  ASSERT_EQ("8080", std::string(port));
  ASSERT_EQ("/v3", std::string(path));
  ASSERT_EQ(0u, use_tls);
  ASSERT_EQ(RTM_OK, rc);

  memset(hostname, 0, sizeof(hostname));
  memset(port, 0, sizeof(port));
  memset(path, 0, sizeof(path));
  rc = _rtm_test_parse_endpoint(
      rtm, "wss://example.com:8080/foo/bar/", SCHEME_WSS, hostname, port, path, &use_tls);
  ASSERT_EQ("example.com", std::string(hostname));
  ASSERT_EQ("8080", std::string(port));
  ASSERT_EQ("/foo/bar/", std::string(path));
  ASSERT_EQ(1u, use_tls);
  ASSERT_EQ(RTM_OK, rc);

  memset(hostname, 0, sizeof(hostname));
  memset(port, 0, sizeof(port));
  memset(path, 0, sizeof(path));
  rc = _rtm_test_parse_endpoint(
      rtm, "wss://example.com:8080/foo/bar", SCHEME_WSS, hostname, port, path, &use_tls);
  ASSERT_EQ("example.com", std::string(hostname));
  ASSERT_EQ("8080", std::string(port));
  ASSERT_EQ("/foo/bar", std::string(path));
  ASSERT_EQ(1u, use_tls);
  ASSERT_EQ(RTM_OK, rc);

  memset(hostname, 0, sizeof(hostname));
  memset(port, 0, sizeof(port));
  memset(path, 0, sizeof(path));
  rc = _rtm_test_parse_endpoint(
      rtm, "http://proxy.proxy:7711", SCHEME_HTTP, hostname, port, path, &use_tls);
  ASSERT_EQ("proxy.proxy", std::string(hostname));
  ASSERT_EQ("7711", std::string(port));
  ASSERT_EQ(0u, use_tls);
  ASSERT_EQ(RTM_OK, rc);

  memset(hostname, 0, sizeof(hostname));
  memset(port, 0, sizeof(port));
  memset(path, 0, sizeof(path));
  rc = _rtm_test_parse_endpoint(
      rtm, "http://proxy.proxy", SCHEME_HTTP, hostname, port, path, &use_tls);
  ASSERT_EQ("proxy.proxy", std::string(hostname));
  ASSERT_EQ("80", std::string(port));
  ASSERT_EQ(0u, use_tls);
  ASSERT_EQ(RTM_OK, rc);

  memset(hostname, 0, sizeof(hostname));
  memset(port, 0, sizeof(port));
  memset(path, 0, sizeof(path));
  rc = _rtm_test_parse_endpoint(
      rtm, "wss://example.com:8080/foo/bar", SCHEME_HTTP, hostname, port, path, &use_tls);
  ASSERT_EQ(RTM_ERR_PROTOCOL, rc);

  rc = _rtm_test_parse_endpoint(
      rtm, "http://example.com:8080/foo/bar", (enum rtm_url_scheme_t)(SCHEME_WS | SCHEME_WSS), hostname, port, path, &use_tls);
  ASSERT_EQ(RTM_ERR_PROTOCOL, rc);

  rc = _rtm_test_parse_endpoint(
      rtm, "ws://example.com:8080/foo/bar", SCHEME_HTTP, hostname, port, path, &use_tls);
  ASSERT_EQ(RTM_ERR_PROTOCOL, rc);

  rc = _rtm_test_parse_endpoint(
      rtm, "https://example.com:8080/foo/bar", SCHEME_HTTP, hostname, port, path, &use_tls);
  ASSERT_EQ(RTM_ERR_PROTOCOL, rc);
}

TEST(rtm_test, prepare_path_test) {
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);

  char path[255];
  rtm_status rc;

  strncpy(path, "/", sizeof(path));
  rc = _rtm_test_prepare_path(rtm, path, "zzzzzz");
  ASSERT_EQ(RTM_OK, rc);
  ASSERT_EQ("/v2?appkey=zzzzzz", std::string(path));

  strncpy(path, "/foo/bar", sizeof(path));
  rc = _rtm_test_prepare_path(rtm, path, "zzzzzz");
  ASSERT_EQ(RTM_OK, rc);
  ASSERT_EQ("/foo/bar/v2?appkey=zzzzzz", std::string(path));

  strncpy(path, "/foo/", sizeof(path));
  rc = _rtm_test_prepare_path(rtm, path, "zzzzzz");
  ASSERT_EQ(RTM_OK, rc);
  ASSERT_EQ("/foo/v2?appkey=zzzzzz", std::string(path));

  strncpy(path, "/foo", sizeof(path));
  rc = _rtm_test_prepare_path(rtm, path, "zzzzzz");
  ASSERT_EQ(RTM_OK, rc);
  ASSERT_EQ("/foo/v2?appkey=zzzzzz", std::string(path));
}

TEST(rtm_test, wait_ping) {
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  ASSERT_EQ(rtm_get_ws_ping_interval(rtm), 45);
  rtm_set_ws_ping_interval(rtm, 1);
  ASSERT_EQ(rtm_get_ws_ping_interval(rtm), 1);

  time_t last_ping_ts = rtm->last_ping_ts;
  rtm_wait_timeout(rtm, 3);
  ASSERT_GT(rtm->last_ping_ts, last_ping_ts);
}

TEST(rtm_test, publish_noack_ping) {
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";
  rtm_set_ws_ping_interval(rtm, 2);

  time_t last_ping_ts = rtm->last_ping_ts;
  std::string const channel = make_channel();

  time_t start = time(NULL);
  while (TRUE) {
    time_t now = time(NULL);
    if (now - start > 3) {
      break;
    }
    rc = rtm_publish_string(rtm, channel.c_str(), "my message", nullptr);
    ASSERT_EQ(RTM_OK, rc)<< "Failed while publish to channel";
  };

  ASSERT_GT(rtm->last_ping_ts, last_ping_ts);
}

TEST(rtm_test, rtm_client_size_test) {
  ASSERT_GE((size_t)RTM_CLIENT_SIZE(10), (size_t)_RTM_CLIENT_SIZE(10));
}

std::string _ws_encode(std::string message) {
  std::stringstream frame;

  size_t size = message.size();
  frame << "XX"; // Two bytes for minimal header
  if(size > 126) {
    if(size <= 0xFFFF) {
      frame << "XX"; // Four bytes for normal header
    }
    else {
      frame << "XXXXXXXX"; // Ten bytes for large header
    }
  }
  frame << message;
  std::string rv = frame.str();
  rv[0] = 0;
  if(size < 126) {
    rv[1] = size;
  }
  else if(size < 0xFFFF) {
    rv[1] = 126;
    for(int i=1+2; i>1; i--) {
      rv[i] = size & 0xFF;
      size >>= 8;
    }
  }
  else {
    rv[1] = 127;
    for(int i=1+8; i>1; i--) {
      rv[i] = size & 0xFF;
      size >>= 8;
    }
  }
  return rv;
}

TEST(rtm_ws_processing, normal_ws_frame) {
  char memory[RTM_CLIENT_SIZE(100)];
  rtm_client_t *rtm = rtm_init_ex(memory, sizeof(memory), pdu_recorder, nullptr);

  auto frame = _ws_encode("{\"action\":\"rtm/publish/ok\",\"id\":1}");
  frame[0] = (char)(0x80 | WS_TEXT); // Normal, unfragmented frame
  std::copy(frame.begin(), frame.end(), rtm->input_buffer);
  rtm->input_length = frame.size();

  ASSERT_EQ(RTM_OK, _rtm_handle_input(rtm));

  event_t event{};
  ASSERT_EQ(RTM_OK, next_event(rtm, &event));
  ASSERT_EQ(RTM_ACTION_PUBLISH_OK, event.action);
}

TEST(rtm_ws_processing, fragmented_ws_frame) {
  char memory[RTM_CLIENT_SIZE(100)];
  rtm_client_t *rtm = rtm_init_ex(memory, sizeof(memory), pdu_recorder, nullptr);

  auto frame = _ws_encode("{\"action\":\"rtm/publish/ok\"");
  frame[0] = (char)(WS_TEXT); // Normal, fragmented frame
  std::copy(frame.begin(), frame.end(), rtm->input_buffer);
  rtm->input_length = frame.size();

  frame = _ws_encode(",\"id\":");
  frame[0] = WS_CONTINUATION; // Fragment
  std::copy(frame.begin(), frame.end(), rtm->input_buffer + rtm->input_length);
  rtm->input_length += frame.size();

  frame = _ws_encode("1}");
  frame[0] = (char)(0x80 | WS_CONTINUATION); // Last fragment
  std::copy(frame.begin(), frame.end(), rtm->input_buffer + rtm->input_length);
  rtm->input_length += frame.size();

  ASSERT_EQ(RTM_OK, _rtm_handle_input(rtm));

  event_t event{};
  ASSERT_EQ(RTM_OK, next_event(rtm, &event));
  ASSERT_EQ(RTM_ACTION_PUBLISH_OK, event.action);
}

TEST(rtm_ws_processing, oom_single_frame_skip) {
  char memory[RTM_CLIENT_SIZE(100)];
  rtm_client_t *rtm = rtm_init_ex(memory, sizeof(memory), pdu_recorder, nullptr);

  rtm->input_length = 10;
  rtm->skip_next_n_input_bytes = 10;


  auto frame = _ws_encode("{\"action\":\"rtm/publish/ok\",\"id\":1}");
  frame[0] = (char)(0x80 | WS_TEXT); // Normal, unfragmented frame
  std::copy(frame.begin(), frame.end(), rtm->input_buffer + rtm->input_length);
  rtm->input_length += frame.size();

  ASSERT_EQ(RTM_OK, _rtm_handle_input(rtm));

  event_t event{};
  ASSERT_EQ(RTM_OK, next_event(rtm, &event));
  ASSERT_EQ(RTM_ACTION_PUBLISH_OK, event.action);
}

TEST(rtm_ws_processing, oom_fragments_skip) {
  char memory[RTM_CLIENT_SIZE(200)];
  rtm_client_t *rtm = rtm_init_ex(memory, sizeof(memory), pdu_recorder, nullptr);

  rtm->skip_current_fragmented_message = 1;

  auto frame = _ws_encode("invalid-stuff-that-wont-parse");
  frame[0] = WS_CONTINUATION; // Continuation frame
  std::copy(frame.begin(), frame.end(), rtm->input_buffer + rtm->input_length);
  rtm->input_length += frame.size();

  frame = _ws_encode("invalid-stuff-that-wont-parse");
  frame[0] = (char)(0x80 | WS_CONTINUATION); // Last fragment
  std::copy(frame.begin(), frame.end(), rtm->input_buffer + rtm->input_length);
  rtm->input_length += frame.size();

  frame = _ws_encode("{\"action\":\"rtm/publish/ok\",\"id\":1}");
  frame[0] = (char)(0x80 | WS_TEXT); // Normal, unfragmented frame
  std::copy(frame.begin(), frame.end(), rtm->input_buffer + rtm->input_length);
  rtm->input_length += frame.size();

  ASSERT_EQ(RTM_OK, _rtm_handle_input(rtm));

  event_t event{};
  ASSERT_EQ(RTM_OK, next_event(rtm, &event));
  ASSERT_EQ(RTM_ACTION_PUBLISH_OK, event.action);
}

TEST(rtm_ws_processing, oom_handle_large_input) {
  char memory[RTM_CLIENT_SIZE(50)];
  rtm_client_t *rtm = rtm_init_ex(memory, sizeof(memory), pdu_recorder, nullptr);
  rtm_set_allocator(rtm, rtm_system_malloc, rtm_system_free);

  std::stringstream large_message;
  large_message << "{\"action\":\"rtm/publish/ok\",\"id\":1,\"addl\":\"";
  for(int i=0; i<10000; i++) large_message << "A";
  large_message << "\"}";

  auto frame = _ws_encode(large_message.str());
  frame[0] = (char)(0x80 | WS_TEXT); // Normal, unfragmented frame

  std::copy(frame.begin(), frame.begin() + 50, rtm->input_buffer);
  rtm->input_length = 50;

  ASSERT_EQ(RTM_WOULD_BLOCK, _rtm_handle_input(rtm));
  ASSERT_NE(nullptr, rtm->dynamic_input_buffer);
  ASSERT_GE(rtm->dynamic_input_buffer_size, frame.size());

  std::copy(frame.begin() + 50, frame.end(), rtm->dynamic_input_buffer + rtm->input_length);
  rtm->input_length += frame.size() - 50;

  ASSERT_EQ(RTM_OK, _rtm_handle_input(rtm));

  ASSERT_EQ(nullptr, rtm->dynamic_input_buffer);

  event_t event{};
  ASSERT_EQ(RTM_OK, next_event(rtm, &event));
  ASSERT_EQ(RTM_ACTION_PUBLISH_OK, event.action);
}

TEST(rtm_ws_processing, oom_skip_fragmented_input) {
  char memory[RTM_CLIENT_SIZE(50)];
  rtm_client_t *rtm = rtm_init_ex(memory, sizeof(memory), pdu_recorder, nullptr);
  rtm_set_allocator(rtm, rtm_null_malloc, rtm_null_free);

  std::stringstream large_message;
  large_message << "{\"action\":\"rtm/publish/ok\",\"id\":1,\"addl\":\"";
  for(int i=0; i<10000; i++) large_message << "A";
  large_message << "\"}";

  for(int repeat=0; repeat<3; repeat++) {
    auto frame = _ws_encode(large_message.str());
    if(repeat == 0)
      frame[0] = (char)(WS_TEXT); // Fragmented frame
    else if(repeat == 1)
      frame[0] = (char)(WS_CONTINUATION); // Continuation frame
    else
      frame[0] = (char)(0x80 | WS_CONTINUATION); // Last frame

    for(size_t i=0; i<frame.size(); i += 50) {
      auto until = (std::min)(i+50, frame.size());
      std::copy(&frame[i], &frame[until], rtm->input_buffer);
      rtm->input_length = until - i;

      ASSERT_EQ(RTM_WOULD_BLOCK, _rtm_handle_input(rtm));
    }
  }

  auto frame = _ws_encode("{\"action\":\"rtm/publish/ok\",\"id\":1}");
  frame[0] = (char)(0x80 | 1); // Normal, unfragmented frame
  std::copy(frame.begin(), frame.end(), rtm->input_buffer + rtm->input_length);
  rtm->input_length += frame.size();
  ASSERT_EQ(RTM_OK, _rtm_handle_input(rtm));

  event_t event{};
  ASSERT_EQ(RTM_OK, next_event(rtm, &event));
  ASSERT_EQ(RTM_ACTION_PUBLISH_OK, event.action);
}


/////////////////////////

class RTMEnvironment: public ::testing::Environment {
  public:
    void TearDown() override {
      std::queue<event_t> event_queue_empty;
      std::swap(event_queue, event_queue_empty);

      std::queue<std::string> message_queue_empty;
      std::swap(message_queue, message_queue_empty);

      std::queue<std::string> error_message_queue_empty;
      std::swap(error_message_queue, error_message_queue_empty);
    }
};


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::AddGlobalTestEnvironment(new RTMEnvironment());

#ifdef _WIN32
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    wVersionRequested = MAKEWORD(2, 2);
    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        std::cerr << "WSAStartup failed with " << err << std::endl;
    }
#endif

  int64_t seed = std::chrono::system_clock::now().time_since_epoch() / std::chrono::milliseconds(1);
  srand(seed);

  return RUN_ALL_TESTS();
}
